// macOS Lima driver — invoked by `main.rs` on `target_os = "macos"` so
// that `psroot ...` on a Mac transparently forwards into the `psroot`
// Lima VM (Linux kernel) and brings up `ssh -L` tunnels for any
// --publish flags.
//
// This is the Rust port of the former `tools/mac/psroot-mac` bash
// wrapper. The user types the *same* commands on Mac, Linux and Windows.
//
// Escape hatch: set `PSROOT_BACKEND=native` to bypass Lima and use the
// in-process sandbox-exec + chroot backend (no per-container IPs).

#![cfg(target_os = "macos")]

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const VM_NAME_DEFAULT: &str = "psroot";
const LIMA_TEMPLATE: &str = include_str!("../../../tools/mac/lima.psroot.yaml");
// Path to the Linux psroot binary inside the VM. The Lima provision
// script copies the built binary here so it does NOT live in the
// virtiofs-shared `target/` (which would collide with the Mac build).
const VM_PSROOT_BIN: &str = "/usr/local/bin/psroot";

fn vm_name() -> String {
    env::var("PSROOT_VM_NAME").unwrap_or_else(|_| VM_NAME_DEFAULT.into())
}

fn home() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| "/tmp".into()))
}

fn ssh_config() -> PathBuf {
    home().join(".lima").join(vm_name()).join("ssh.config")
}

fn limactl_available() -> bool {
    Command::new("limactl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn vm_status() -> Option<String> {
    let out = Command::new("limactl")
        .args(["list", "--format", "{{.Status}}", &vm_name()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn ensure_vm() -> Result<(), String> {
    if !limactl_available() {
        return Err("limactl not found. Install with: brew install lima".into());
    }
    if vm_status().is_none() {
        eprintln!(">> creating Lima VM '{}' (one-time, ~5 min)…", vm_name());
        // Materialise the embedded template to a temp file so limactl
        // can read it even when psroot is installed without the repo.
        let tmpl_path = std::env::temp_dir().join(format!("psroot-lima-{}.yaml", vm_name()));
        fs::write(&tmpl_path, LIMA_TEMPLATE)
            .map_err(|e| format!("write template: {e}"))?;
        let st = Command::new("limactl")
            .args(["create", &format!("--name={}", vm_name())])
            .arg(&tmpl_path)
            .status()
            .map_err(|e| format!("limactl create: {e}"))?;
        if !st.success() {
            return Err(format!("limactl create exited {st}"));
        }
    }
    if vm_status().as_deref() != Some("Running") {
        eprintln!(">> starting Lima VM '{}'…", vm_name());
        let st = Command::new("limactl")
            .args(["start", &vm_name()])
            .status()
            .map_err(|e| format!("limactl start: {e}"))?;
        if !st.success() {
            return Err(format!("limactl start exited {st}"));
        }
    }
    Ok(())
}

/// Parse --publish HOST:CTR pairs and --name from argv.
fn extract_run_flags(argv: &[String]) -> (Vec<(u16, u16)>, Option<String>) {
    let mut pairs = Vec::new();
    let mut name = None;
    let mut prev: Option<&str> = None;
    for a in argv {
        let pair_val = if prev == Some("--publish") || prev == Some("-p") {
            Some(a.as_str())
        } else if let Some(v) = a.strip_prefix("--publish=") {
            Some(v)
        } else if let Some(v) = a.strip_prefix("-p=") {
            Some(v)
        } else {
            None
        };
        if let Some(v) = pair_val {
            if let Some((h, c)) = v.split_once(':') {
                if let (Ok(h), Ok(c)) = (h.parse(), c.parse()) {
                    pairs.push((h, c));
                }
            }
        }
        if prev == Some("--name") || prev == Some("-n") {
            name = Some(a.clone());
        } else if let Some(v) = a.strip_prefix("--name=") {
            name = Some(v.into());
        }
        prev = Some(a.as_str());
    }
    (pairs, name)
}

/// Synchronously shell into the VM, forwarding argv to /usr/local/bin/psroot
/// (or the dev path) inside, inheriting stdio.
fn vm_exec_foreground(argv: &[String]) -> i32 {
    let mut cmd = Command::new("limactl");
    cmd.args(["shell", "--workdir", "/", &vm_name(), "sudo", VM_PSROOT_BIN]);
    cmd.args(argv);
    cmd.status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or_else(|e| {
            eprintln!("limactl shell failed: {e}");
            1
        })
}

/// Spawn psroot in the VM in the background, returning the child handle.
fn vm_exec_background(argv: &[String], log_path: &PathBuf) -> std::io::Result<std::process::Child> {
    let log = fs::File::create(log_path)?;
    let log_err = log.try_clone()?;
    let mut cmd = Command::new("limactl");
    cmd.args(["shell", "--workdir", "/", &vm_name(), "sudo", VM_PSROOT_BIN])
        .args(argv)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log_err));
    cmd.spawn()
}

/// Poll the VM for the container's IP. The state JSON lives at
/// /root/.local/share/psroot/<uuid>/container.json.
fn lookup_container_ip(name: &str) -> Option<String> {
    let script = format!(
        r#"for f in $(find /root/.local/share/psroot -name container.json 2>/dev/null); do
            python3 -c "import sys,json; d=json.load(open(sys.argv[1])); ip=d.get('container_ip'); print(ip) if d.get('name')=='{name}' and ip else None" "$f" 2>/dev/null
          done"#
    );
    let out = Command::new("limactl")
        .args(["shell", "--workdir", "/", &vm_name(), "sudo", "bash", "-c", &script])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().trim_end_matches('\r'))
        .filter(|l| l.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false))
        .last()
        .map(|s| s.to_string())
}

fn open_tunnel(host_port: u16, ctr_ip: &str, ctr_port: u16) -> std::io::Result<()> {
    let cfg = ssh_config();
    let host = format!("lima-{}", vm_name());
    let l = format!("{host_port}:{ctr_ip}:{ctr_port}");
    let st = Command::new("ssh")
        .args(["-F", cfg.to_str().unwrap_or_default()])
        .args(["-o", "ExitOnForwardFailure=yes"])
        .args(["-fN", "-L", &l, &host])
        .status()?;
    if !st.success() {
        return Err(std::io::Error::other(format!("ssh -L {l} failed")));
    }
    Ok(())
}

fn close_tunnels(ctr_ip: &str) {
    // Best-effort: pkill matching ssh -L lines for this container's IP.
    let pat = format!("ssh -F .*-L .*:{ctr_ip}:");
    let _ = Command::new("pkill").args(["-f", &pat]).status();
}

/// Stop the in-VM container by name (best-effort).
fn vm_stop_container(name: &str) {
    let _ = Command::new("limactl")
        .args(["shell", "--workdir", "/", &vm_name(), "sudo", VM_PSROOT_BIN, "stop", name])
        .status();
}

/// Entry point called from main(). `argv` excludes argv[0].
pub fn dispatch(argv: Vec<String>) -> i32 {
    if let Err(e) = ensure_vm() {
        eprintln!("psroot: {e}");
        return 127;
    }

    let subcmd = argv.first().map(|s| s.as_str()).unwrap_or("");
    let needs_tunnels = matches!(subcmd, "run" | "create" | "start");
    let (pairs, name) = if needs_tunnels {
        extract_run_flags(&argv)
    } else {
        (Vec::new(), None)
    };

    if pairs.is_empty() {
        // No --publish flags: simple foreground passthrough.
        return vm_exec_foreground(&argv);
    }

    // We need a container name to look up its IP. Synthesize one if absent.
    let synth_name = name.clone().unwrap_or_else(|| {
        format!(
            "psroot-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        )
    });
    let mut argv = argv;
    if name.is_none() {
        argv.push("--name".into());
        argv.push(synth_name.clone());
    }
    let effective_name = synth_name;

    let tunnel_dir = home().join(".psroot").join("tunnels");
    let _ = fs::create_dir_all(&tunnel_dir);
    let log_path = tunnel_dir.join(format!("{effective_name}.log"));

    eprintln!(">> launching container in VM (log: {})", log_path.display());
    let mut child = match vm_exec_background(&argv, &log_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("psroot: spawn failed: {e}");
            return 1;
        }
    };

    // Poll up to 30s for the container IP.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut ctr_ip: Option<String> = None;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_secs(1));
        if let Some(ip) = lookup_container_ip(&effective_name) {
            ctr_ip = Some(ip);
            break;
        }
        // If the spawned psroot already exited, bail out.
        if let Ok(Some(st)) = child.try_wait() {
            // Print the log for diagnosis.
            if let Ok(s) = fs::read_to_string(&log_path) {
                let _ = std::io::stderr().write_all(s.as_bytes());
            }
            return st.code().unwrap_or(1);
        }
    }

    let ctr_ip = match ctr_ip {
        Some(ip) => ip,
        None => {
            eprintln!("warning: could not determine container IP; tunnels not established");
            return child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
        }
    };
    eprintln!(">> container IP: {ctr_ip}");

    for (h, c) in &pairs {
        eprintln!(">> mac:127.0.0.1:{h} -> vm -> container:{ctr_ip}:{c}");
        if let Err(e) = open_tunnel(*h, &ctr_ip, *c) {
            eprintln!("warning: {e}");
        }
    }

    // RAII guard tears down tunnels + stops the container on any exit
    // path (normal completion, panic, or SIGINT propagated by the shell).
    struct Cleanup<'a> {
        ip: &'a str,
        name: &'a str,
    }
    impl<'a> Drop for Cleanup<'a> {
        fn drop(&mut self) {
            close_tunnels(self.ip);
            vm_stop_container(self.name);
        }
    }
    let _guard = Cleanup { ip: &ctr_ip, name: &effective_name };

    child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1)
}
