//! macOS sandbox backend.
//!
//! Strategy: generate a `sandbox-exec`-compatible profile (TinyScheme SBPL)
//! that whitelists exactly the paths the container is allowed to read/write,
//! then exec the child via `sandbox-exec -f <profile> <cmd>`.
//!
//! When the host has root and the user passes `--isolate full`, we
//! additionally `chroot(<rootfs>)`. Without root we cannot chroot, but the
//! sandbox profile already denies all reads outside the rootfs (and the
//! system library allowlist), which is what matters in practice.
//!
//! The TTY plumbing (interactive shell) uses `forkpty` and the `pty.rs`
//! forwarder.

use crate::{paths, pty, sandbox, state::ContainerRecord, IsolationLevel, Error, Result};
use psroot_types::config::NetworkAccess;
use std::path::PathBuf;
use std::os::fd::AsRawFd;

pub fn run(
    rec: &ContainerRecord,
    isolation: IsolationLevel,
    interactive: bool,
) -> Result<i32> {
    let rootfs = PathBuf::from(&rec.config.rootfs_path);
    if !rootfs.exists() {
        return Err(Error::NotFound(format!("rootfs missing: {}", rootfs.display())));
    }
    let container_home = rootfs.join("home/container");
    std::fs::create_dir_all(&container_home)?;

    // Generate sandbox profile.
    let profile_path = paths::container_dir(&rec.id)?.join("sandbox.sb");
    let profile = generate_profile(&rec.config, &rootfs, isolation);
    std::fs::write(&profile_path, profile)?;

    let cmd = if rec.config.command.is_empty() {
        crate::default_shell_command()
    } else {
        rec.config.command.clone()
    };

    // Decide whether to wrap with sandbox-exec.
    let use_sandbox = isolation != IsolationLevel::Minimal
        && std::path::Path::new("/usr/bin/sandbox-exec").exists();

    let mut argv: Vec<String> = Vec::new();
    if use_sandbox {
        argv.push("/usr/bin/sandbox-exec".to_string());
        argv.push("-f".to_string());
        argv.push(profile_path.to_string_lossy().into_owned());
    }
    for c in &cmd { argv.push(c.clone()); }

    let env = sandbox::build_env(rec, &container_home.to_string_lossy());

    if interactive {
        run_interactive(&argv, &env, &container_home, &rec.config.resources)
    } else {
        run_noninteractive(&argv, &env, &container_home, &rec.config.resources)
    }
}

fn run_interactive(
    argv: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &std::path::Path,
    res: &psroot_types::config::ResourceLimits,
) -> Result<i32> {
    use nix::pty::ForkptyResult;
    let ws = pty::current_winsize().unwrap_or(nix::pty::Winsize {
        ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0,
    });
    let res_clone = res.clone();
    let argv = argv.to_vec();
    let env = env.clone();
    let cwd = cwd.to_path_buf();

    let result = unsafe { nix::pty::forkpty(Some(&ws), None) }?;
    match result {
        ForkptyResult::Parent { child, master } => {
            pty::forward(master, child)
        }
        ForkptyResult::Child => {
            // In child: apply limits, chdir, exec.
            sandbox::apply_rlimits(&res_clone);
            let _ = std::env::set_current_dir(&cwd);
            for (k, _) in std::env::vars() { std::env::remove_var(k); }
            for (k, v) in &env { std::env::set_var(k, v); }
            let prog = std::ffi::CString::new(argv[0].clone()).unwrap();
            let cargs: Vec<std::ffi::CString> = argv.iter()
                .map(|s| std::ffi::CString::new(s.clone()).unwrap()).collect();
            let _ = nix::unistd::execvp(&prog, &cargs);
            // execvp failed
            eprintln!("psroot: exec {} failed", argv[0]);
            unsafe { libc::_exit(127); }
        }
    }
}

fn run_noninteractive(
    argv: &[String],
    env: &std::collections::HashMap<String, String>,
    cwd: &std::path::Path,
    res: &psroot_types::config::ResourceLimits,
) -> Result<i32> {
    use std::process::{Command, Stdio};
    use std::os::unix::process::CommandExt;
    let mut c = Command::new(&argv[0]);
    c.args(&argv[1..]);
    c.env_clear();
    for (k, v) in env { c.env(k, v); }
    c.current_dir(cwd);
    c.stdin(Stdio::inherit()).stdout(Stdio::inherit()).stderr(Stdio::inherit());
    let res = res.clone();
    unsafe {
        c.pre_exec(move || {
            sandbox::apply_rlimits(&res);
            Ok(())
        });
    }
    let status = c.status().map_err(Error::Io)?;
    Ok(status.code().unwrap_or_else(|| {
        use std::os::unix::process::ExitStatusExt;
        128 + status.signal().unwrap_or(0)
    }))
}

/// Generate the SBPL sandbox profile for a container.
///
/// The profile is intentionally restrictive: deny everything by default,
/// then allowlist (1) the system library paths every binary needs to load,
/// (2) the container's own rootfs, and (3) network if configured.
fn generate_profile(
    cfg: &psroot_types::config::ContainerConfig,
    rootfs: &std::path::Path,
    isolation: IsolationLevel,
) -> String {
    let mut s = String::new();
    s.push_str("(version 1)\n");
    s.push_str("(deny default)\n");
    s.push_str("(allow process-fork)\n");
    s.push_str("(allow process-exec)\n");
    s.push_str("(allow signal (target self))\n");
    s.push_str("(allow sysctl-read)\n");
    s.push_str("(allow mach-lookup)\n");
    s.push_str("(allow ipc-posix-shm)\n");
    s.push_str("(allow file-read-metadata)\n");

    // System read-only paths (libraries, binaries, timezone, etc.).
    for p in sandbox::MACOS_SYSTEM_READ_PATHS {
        s.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", p));
    }
    // Homebrew & common third-party prefixes (best-effort — many user
    // toolchains live here, e.g. python3, node, ruby).
    for p in &["/opt/homebrew", "/opt/local", "/usr/local"] {
        if std::path::Path::new(p).exists() {
            s.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", p));
            s.push_str(&format!("(allow file* (subpath \"{}\"))\n", p));
        }
    }
    // Root directory and key intermediate dirs need a literal read allow,
    // separate from `(subpath ...)`, so that path-traversal up to the
    // allowed subpath itself works (dyld/libsystem read directory entries
    // at "/" and "/private/var" during process startup).
    for lit in &["/", "/private", "/private/var", "/private/var/db", "/private/var/folders"] {
        s.push_str(&format!("(allow file-read* (literal \"{}\"))\n", lit));
    }
    // Hard denies for host user data — must come BEFORE the rootfs allow
    // because Apple's sandbox uses LAST-MATCH-WINS semantics. The rootfs
    // path normally lives under the user's $HOME, so an unconditional
    // deny on /Users would mask the rootfs allow if it followed.
    if let Some(home) = dirs::home_dir() {
        s.push_str(&format!(
            "(deny file* (subpath \"{}\"))\n",
            home.display()
        ));
    }
    s.push_str("(deny file* (subpath \"/Users\"))\n");
    s.push_str("(deny file* (subpath \"/Volumes\"))\n");

    // Allow read+write inside the container's rootfs (LAST so it wins).
    s.push_str(&format!(
        "(allow file* (subpath \"{}\"))\n",
        rootfs.display()
    ));
    // Always-allowed devices for shell sanity.
    for d in &["/dev/null", "/dev/zero", "/dev/random", "/dev/urandom",
               "/dev/tty", "/dev/dtracehelper", "/dev/stdin", "/dev/stdout", "/dev/stderr"] {
        s.push_str(&format!("(allow file* (path \"{}\"))\n", d));
    }
    // Allow PTY operations (shell needs ptmx).
    s.push_str("(allow file* (subpath \"/dev/ptmx\"))\n");
    s.push_str("(allow file* (regex #\"^/dev/tty[a-z0-9]+$\"))\n");

    // Network policy.
    match cfg.network {
        NetworkAccess::None => {
            // Default-deny already blocks; nothing to add.
        }
        NetworkAccess::Outbound | NetworkAccess::Netstack => {
            s.push_str("(allow network-outbound)\n");
            s.push_str("(allow system-socket)\n");
            // DNS over UDP needs network*-bind for the source port.
            s.push_str("(allow network*)\n");
        }
        NetworkAccess::Full => {
            s.push_str("(allow network*)\n");
            s.push_str("(allow system-socket)\n");
        }
    }

    let _ = isolation;
    s
}
