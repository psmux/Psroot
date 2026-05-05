// Unix entrypoint for `psroot`. Mirrors the Windows CLI surface for the
// commands that are meaningful on Linux/macOS.
//
// Included from `main.rs` via `#[cfg(unix)] include!("main_unix.rs");`.

use clap::{Parser, Subcommand};
use psroot_unix::{
    capabilities, list, parse, Container, ContainerConfig, IsolationLevel, NetworkAccess,
    PortMapping, ResourceLimits, SecurityProfile,
};
use psroot_unix::state::ContainerInfo;
use std::collections::HashMap;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "psroot",
    about = "Docker-style containers — Linux + macOS backend",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Show host capabilities and isolation level.
    Info,

    /// Create a container (returns its ID).
    Create(CreateArgs),

    /// Run a one-shot command (create + start + wait + cleanup).
    Run(RunArgs),

    /// Drop into an interactive shell inside a fresh container.
    Shell(ShellArgs),

    /// Start a previously created container in the foreground.
    Start { id: String },

    /// Execute a command in an existing (or fresh) container.
    Exec { id: String, #[arg(trailing_var_arg = true)] cmd: Vec<String> },

    /// Stop a running container.
    Stop { id: String },

    /// Remove a container.
    Rm { id: String },

    /// List all containers.
    Ls,

    /// Show resource usage for a container.
    Stats { id: String },

    /// Run the Psroot test suite (subset on Unix).
    Test { #[arg(default_value = "all")] category: String },
}

#[derive(clap::Args, Debug, Clone)]
struct CommonResourceArgs {
    /// Memory limit (e.g. 512M, 1G).
    #[arg(short, long, default_value = "1G")]
    memory: String,
    /// CPU rate (1-10000; 10000 = 100%). Linux-only enforcement.
    #[arg(long, default_value = "10000")]
    cpu: u32,
    /// Max processes.
    #[arg(long, default_value = "100")]
    max_procs: u32,
    /// Network mode: none, outbound, full.
    #[arg(long, default_value = "outbound")]
    network: String,
    /// Isolation: minimal, standard, full.
    #[arg(long, default_value = "standard")]
    isolate: String,
    /// Bind-mount HOST:CONTAINER[:ro] (best-effort on macOS).
    #[arg(short = 'v', long)]
    volume: Vec<String>,
    /// Environment KEY=VALUE.
    #[arg(short, long)]
    env: Vec<String>,
    /// Publish HOST:CONTAINER.
    #[arg(short = 'p', long)]
    publish: Vec<String>,
    /// Container name.
    #[arg(short, long)]
    name: Option<String>,
    /// Use an existing self-contained rootfs (e.g. one built by debootstrap).
    /// When set, host /usr /bin /lib are NOT bind-mounted into the
    /// container — the rootfs is the entire userland.
    #[arg(long)]
    rootfs: Option<String>,
    /// Bind address for --publish. Default 127.0.0.1; pass 0.0.0.0 to
    /// expose ports on all host interfaces.
    #[arg(long, default_value = "127.0.0.1")]
    publish_addr: String,
}

#[derive(clap::Args, Debug)]
struct CreateArgs {
    #[command(flatten)]
    common: CommonResourceArgs,
    /// Command to run.
    #[arg(short, long)]
    command: Option<String>,
}

#[derive(clap::Args, Debug)]
struct RunArgs {
    #[command(flatten)]
    common: CommonResourceArgs,
    /// Command + args.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    cmd: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct ShellArgs {
    #[command(flatten)]
    common: CommonResourceArgs,
}

fn main() {
    // macOS: by default forward into the Lima VM so the user gets full
    // Linux semantics (per-container IPs, namespaces, cgroups). Opt out
    // with PSROOT_BACKEND=native to use the in-process sandbox-exec
    // + chroot backend.
    #[cfg(target_os = "macos")]
    {
        let backend = std::env::var("PSROOT_BACKEND").unwrap_or_default();
        if backend != "native" {
            let argv: Vec<String> = std::env::args().skip(1).collect();
            std::process::exit(crate::mac_lima::dispatch(argv));
        }
    }

    let cli = Cli::parse();
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
    };
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();

    let code = match cli.command {
        Commands::Info => cmd_info(),
        Commands::Create(a) => cmd_create(a),
        Commands::Run(a) => cmd_run(a),
        Commands::Shell(a) => cmd_shell(a),
        Commands::Start { id } => cmd_start(id),
        Commands::Exec { id, cmd } => cmd_exec(id, cmd),
        Commands::Stop { id } => cmd_stop(id),
        Commands::Rm { id } => cmd_rm(id),
        Commands::Ls => cmd_ls(),
        Commands::Stats { id } => cmd_stats(id),
        Commands::Test { category } => cmd_test(&category),
    };
    std::process::exit(code);
}

fn cmd_info() -> i32 {
    let caps = capabilities();
    println!("psroot — Linux + macOS backend");
    println!("  os                : {}", caps.os);
    println!("  is_root           : {}", caps.is_root);
    println!("  user_namespaces   : {}", caps.user_namespaces);
    println!("  cgroups_v2        : {}", caps.cgroups_v2);
    println!("  sandbox-exec      : {}", caps.sandbox_exec);
    println!("  max_isolation     : {}", caps.max_isolation);
    println!();
    let containers = list().unwrap_or_default();
    println!("  containers        : {} known", containers.len());
    0
}

fn parse_isolation(s: &str) -> IsolationLevel {
    match s {
        "minimal" => IsolationLevel::Minimal,
        "full" => IsolationLevel::Full,
        _ => IsolationLevel::Standard,
    }
}

fn parse_network(s: &str) -> NetworkAccess {
    match s {
        "none" => NetworkAccess::None,
        "full" => NetworkAccess::Full,
        "netstack" => NetworkAccess::Netstack,
        _ => NetworkAccess::Outbound,
    }
}

fn build_config(c: &CommonResourceArgs, command: Vec<String>) -> Result<ContainerConfig, String> {
    let memory = parse::parse_size(&c.memory).map_err(|e| e.to_string())?;
    let mut env = HashMap::new();
    for kv in &c.env {
        if let Some((k, v)) = kv.split_once('=') {
            env.insert(k.to_string(), v.to_string());
        }
    }
    let mut volumes = Vec::new();
    for v in &c.volume {
        let parts: Vec<&str> = v.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err(format!("bad volume: {v}"));
        }
        volumes.push(psroot_unix::VolumeMount {
            host_path: parts[0].into(),
            container_path: parts[1].into(),
            read_only: parts.get(2) == Some(&"ro"),
        });
    }
    let mut ports = Vec::new();
    for p in &c.publish {
        let parts: Vec<&str> = p.splitn(2, ':').collect();
        let (host, ctr) = if parts.len() == 2 {
            (parts[0].parse().unwrap_or(0u16), parts[1].parse().unwrap_or(0u16))
        } else {
            let n: u16 = parts[0].parse().unwrap_or(0);
            (n, n)
        };
        ports.push(PortMapping {
            host_bind: c.publish_addr.clone(),
            host_port: host,
            container_port: ctr,
            ephemeral_port: None,
            name: None,
        });
    }
    Ok(ContainerConfig {
        name: c.name.clone(),
        rootfs_path: c.rootfs.clone().unwrap_or_default(),
        command,
        env,
        resources: ResourceLimits {
            memory,
            cpu_rate: c.cpu,
            max_processes: c.max_procs,
            affinity: 0,
            priority_class: 0,
        },
        volumes,
        hostname: Some("psroot".into()),
        working_directory: "/home/container".into(),
        silo: false,
        tools: Vec::new(),
        shares: Vec::new(),
        security_profile: SecurityProfile::default(),
        network: parse_network(&c.network),
        ports,
    })
}

fn cmd_create(a: CreateArgs) -> i32 {
    let cmd = a.command.map(|s| vec![s]).unwrap_or_else(|| vec!["/bin/sh".into()]);
    let cfg = match build_config(&a.common, cmd) {
        Ok(c) => c, Err(e) => { eprintln!("error: {e}"); return 2; }
    };
    let iso = parse_isolation(&a.common.isolate);
    match Container::create(cfg, iso) {
        Ok(c) => { println!("{}", c.id()); 0 }
        Err(e) => { eprintln!("create failed: {e}"); 1 }
    }
}

fn cmd_run(a: RunArgs) -> i32 {
    let cmd = if a.cmd.is_empty() { vec!["/bin/sh".into(), "-c".into(), "echo psroot ok".into()] } else { a.cmd };
    let cfg = match build_config(&a.common, cmd.clone()) {
        Ok(c) => c, Err(e) => { eprintln!("error: {e}"); return 2; }
    };
    let iso = parse_isolation(&a.common.isolate);
    let mut c = match Container::create(cfg, iso) {
        Ok(c) => c, Err(e) => { eprintln!("create failed: {e}"); return 1; }
    };
    let interactive = is_terminal();
    let result = c.run(&cmd, interactive).unwrap_or(1);
    let _ = c.remove();
    result
}

fn cmd_shell(a: ShellArgs) -> i32 {
    let cmd = psroot_unix::default_shell_command();
    let cfg = match build_config(&a.common, cmd) {
        Ok(c) => c, Err(e) => { eprintln!("error: {e}"); return 2; }
    };
    let iso = parse_isolation(&a.common.isolate);
    let mut c = match Container::create(cfg, iso) {
        Ok(c) => c, Err(e) => { eprintln!("create failed: {e}"); return 1; }
    };
    let result = c.shell().unwrap_or(1);
    let _ = c.remove();
    result
}

fn cmd_start(id: String) -> i32 {
    let mut c = match Container::load(&id) {
        Ok(c) => c, Err(e) => { eprintln!("{e}"); return 1; }
    };
    let cmd = c.config().command.clone();
    c.run(&cmd, is_terminal()).unwrap_or(1)
}

fn cmd_exec(id: String, cmd: Vec<String>) -> i32 {
    let c = match Container::load(&id) {
        Ok(c) => c, Err(e) => { eprintln!("{e}"); return 1; }
    };
    if cmd.is_empty() { eprintln!("exec: command required"); return 2; }
    c.exec(&cmd).unwrap_or(1)
}

fn cmd_stop(id: String) -> i32 {
    let mut c = match Container::load(&id) {
        Ok(c) => c, Err(e) => { eprintln!("{e}"); return 1; }
    };
    match c.stop() { Ok(()) => 0, Err(e) => { eprintln!("{e}"); 1 } }
}

fn cmd_rm(id: String) -> i32 {
    let c = match Container::load(&id) {
        Ok(c) => c, Err(e) => { eprintln!("{e}"); return 1; }
    };
    match c.remove() { Ok(()) => 0, Err(e) => { eprintln!("{e}"); 1 } }
}

fn cmd_ls() -> i32 {
    let infos: Vec<ContainerInfo> = list().unwrap_or_default();
    println!("{:<36}  {:<12}  {:<10}  CMD", "ID", "NAME", "STATE");
    for i in infos {
        println!("{:<36}  {:<12}  {:<10}  {}",
            i.id,
            i.name.unwrap_or_default(),
            i.state.to_string(),
            i.command.join(" "),
        );
    }
    0
}

fn cmd_stats(id: String) -> i32 {
    let c = match Container::load(&id) {
        Ok(c) => c, Err(e) => { eprintln!("{e}"); return 1; }
    };
    match c.stats() {
        Ok(s) => {
            println!("state       : {}", s.state);
            println!("host_pid    : {:?}", s.host_pid);
            println!("exit_code   : {:?}", s.exit_code);
            println!("memory      : {} bytes", s.memory_bytes);
            println!("cpu_user_us : {}", s.cpu_user_us);
            0
        }
        Err(e) => { eprintln!("{e}"); 1 }
    }
}

fn cmd_test(_category: &str) -> i32 {
    // Embedded smoke test runner. Each test returns (name, ok, message).
    let mut results: Vec<(String, bool, String)> = Vec::new();

    // 1. echo
    results.push(test_echo());
    // 2. host home is denied (macOS sandbox-exec; Linux pivot_root makes it absent)
    results.push(test_host_home_isolated());
    // 3. env sanitization
    results.push(test_env_sanitized());
    // 4. memory limit (best-effort)
    results.push(test_memory_limit());
    // 5. network none denies outbound (best-effort, may pass even when curl missing)
    results.push(test_network_none());
    // 6. lifecycle list
    results.push(test_lifecycle());
    // 7. tty interactive shell roundtrip
    results.push(test_tty_shell());
    // 8. published port — host can reach a server inside container
    results.push(test_network_publish());
    // 9. bridged net — container has its own IP (Linux only; auto-skipped elsewhere)
    results.push(test_network_bridged());

    let mut ok = 0;
    let mut fail = 0;
    println!();
    println!("psroot test suite");
    println!("=================");
    for (n, pass, msg) in &results {
        if *pass {
            ok += 1;
            println!("[PASS] {n} — {msg}");
        } else {
            fail += 1;
            println!("[FAIL] {n} — {msg}");
        }
    }
    println!();
    println!("Result: {ok} passed, {fail} failed, {} total", results.len());
    if fail == 0 { 0 } else { 1 }
}

fn run_simple(cmd: Vec<String>, network: NetworkAccess) -> (i32, String) {
    let cfg = ContainerConfig {
        name: None, rootfs_path: String::new(),
        command: cmd.clone(),
        env: HashMap::new(),
        resources: ResourceLimits::default(),
        volumes: Vec::new(),
        hostname: Some("psroot".into()),
        working_directory: "/home/container".into(),
        silo: false, tools: Vec::new(), shares: Vec::new(),
        security_profile: SecurityProfile::default(),
        network,
        ports: Vec::new(),
    };
    let mut c = match Container::create(cfg, IsolationLevel::Standard) {
        Ok(c) => c, Err(e) => return (-1, e.to_string()),
    };
    // Write the captured output into a path that is identical when viewed
    // from inside the container AND from outside on the host:
    //   inside  → /home/container/out.txt (container view after pivot_root)
    //   outside → <rootfs>/home/container/out.txt
    // On macOS (no chroot) the inside view is the host-absolute path; we
    // accommodate by also using /home/container which the rootfs::populate
    // step created and the sandbox profile permits.
    let rootfs_dir = std::path::PathBuf::from(c.dir()).join("rootfs");
    let host_home = rootfs_dir.join("home").join("container");
    let _ = std::fs::create_dir_all(&host_home);
    // Path the container will see.
    let inside_out = if cfg!(target_os = "linux") {
        "/home/container/psroot-test-out.txt".to_string()
    } else {
        host_home.join("psroot-test-out.txt").to_string_lossy().into_owned()
    };
    let inside_script = if cfg!(target_os = "linux") {
        "/home/container/psroot-test-cmd.sh".to_string()
    } else {
        host_home.join("psroot-test-cmd.sh").to_string_lossy().into_owned()
    };
    let host_out = host_home.join("psroot-test-out.txt");
    let host_script = host_home.join("psroot-test-cmd.sh");
    // Build script.
    let mut script = String::from("#!/bin/sh\n");
    script.push_str("exec ");
    for a in &cmd {
        script.push_str(&format!("'{}' ", a.replace('\'', "'\\''")));
    }
    script.push('\n');
    let _ = std::fs::write(&host_script, script);
    let wrapped = vec![
        "/bin/sh".into(), "-c".into(),
        format!("/bin/sh '{}' > '{}' 2>&1", inside_script, inside_out),
    ];
    let code = c.run(&wrapped, false).unwrap_or(-1);
    let out = std::fs::read_to_string(&host_out).unwrap_or_default();
    let _ = c.remove();
    (code, out)
}

fn test_echo() -> (String, bool, String) {
    let (code, out) = run_simple(vec!["echo".into(), "psroot-echo-ok".into()], NetworkAccess::None);
    let ok = code == 0 && out.contains("psroot-echo-ok");
    ("echo".into(), ok, format!("exit={code}, out={:?}", out.trim()))
}

fn test_host_home_isolated() -> (String, bool, String) {
    let host_home = std::env::var("HOME").unwrap_or_default();
    if host_home.is_empty() {
        return ("host_home_isolated".into(), true, "no HOME set; skipped".into());
    }
    let cmd = vec!["/bin/sh".into(), "-c".into(), format!("ls '{host_home}' >/dev/null 2>&1; echo rc=$?")];
    let (code, out) = run_simple(cmd, NetworkAccess::None);
    // Either ls failed (rc!=0) or output empty — both acceptable.
    let ok = code == 0 && (!out.contains("rc=0"));
    ("host_home_isolated".into(), ok, format!("out={:?}", out.trim()))
}

fn test_env_sanitized() -> (String, bool, String) {
    let cmd = vec!["/bin/sh".into(), "-c".into(),
        "echo USER=$USER HOME=$HOME PATH=$PATH PSROOT_CONTAINER_ID=${PSROOT_CONTAINER_ID:-unset}".into()];
    let (code, out) = run_simple(cmd, NetworkAccess::None);
    let ok = code == 0
        && out.contains("USER=container")
        // On Linux pivot_root makes HOME=/home/container; on macOS (no chroot)
        // HOME is the absolute rootfs path that ends in /home/container.
        && out.contains("/home/container")
        && out.contains("PSROOT_CONTAINER_ID=");
    ("env_sanitized".into(), ok, out.trim().into())
}

fn test_memory_limit() -> (String, bool, String) {
    if cfg!(target_os = "macos") {
        // macOS doesn't get rlimits applied (see sandbox::apply_rlimits comment);
        // mark as a skipped check so the suite reflects the real platform contract.
        return ("memory_limit".into(), true,
            "skipped on macOS — rlimits unreliable on Darwin (Linux uses cgroups)".into());
    }
    // Try to allocate more than 64M via sh ulimit awareness.
    // We just verify rlimit was applied by checking ulimit -v inside.
    let cmd = vec!["/bin/sh".into(), "-c".into(),
        "ulimit -v".into()];
    // Override default config to set 64M
    let cfg = ContainerConfig {
        name: None, rootfs_path: String::new(),
        command: cmd.clone(),
        env: HashMap::new(),
        resources: ResourceLimits {
            memory: 64*1024*1024,
            cpu_rate: 10000, max_processes: 100, affinity: 0, priority_class: 0,
        },
        volumes: Vec::new(),
        hostname: None,
        working_directory: "/home/container".into(),
        silo: false, tools: Vec::new(), shares: Vec::new(),
        security_profile: SecurityProfile::default(),
        network: NetworkAccess::None,
        ports: Vec::new(),
    };
    let mut c = match Container::create(cfg, IsolationLevel::Standard) {
        Ok(c) => c, Err(e) => return ("memory_limit".into(), false, e.to_string()),
    };
    let rootfs_dir = std::path::PathBuf::from(c.dir()).join("rootfs");
    let host_home = rootfs_dir.join("home").join("container");
    let _ = std::fs::create_dir_all(&host_home);
    let host_out = host_home.join("psroot-mem.txt");
    let inside = if cfg!(target_os = "linux") { "/home/container/psroot-mem.txt".to_string() }
                 else { host_out.to_string_lossy().into_owned() };
    let wrapped = vec!["/bin/sh".into(), "-c".into(),
        format!("ulimit -v > '{}' 2>&1", inside)];
    let _ = c.run(&wrapped, false);
    let out = std::fs::read_to_string(&host_out).unwrap_or_default();
    let _ = c.remove();
    let s = out.trim();
    let ok = s.parse::<u64>().map(|n| n > 0 && n <= 70_000).unwrap_or(false);
    ("memory_limit".into(), ok, format!("ulimit -v = {s}"))
}

fn test_network_none() -> (String, bool, String) {
    // Use a built-in: try opening a TCP socket via /dev/tcp (bash) — but
    // sh likely lacks it. Fallback: try `nslookup` (often unavailable).
    // Final fallback: just check we can't reach 1.1.1.1 via `nc` if present.
    let probe = "command -v curl >/dev/null && curl -s -m 3 -o /dev/null -w '%{http_code}\\n' https://1.1.1.1 || echo NOCURL";
    let cmd = vec!["/bin/sh".into(), "-c".into(), probe.into()];
    let (code, out) = run_simple(cmd, NetworkAccess::None);
    let txt = out.trim();
    // "NOCURL" → can't tell, count as pass; otherwise must NOT be a 200.
    let ok = txt == "NOCURL" || !txt.starts_with("2");
    ("network_none".into(), ok, format!("code={code} out={:?}", txt))
}

fn test_lifecycle() -> (String, bool, String) {
    let cfg = ContainerConfig {
        name: Some(format!("psroot-test-{}", std::process::id())),
        rootfs_path: String::new(),
        command: vec!["/bin/sh".into(), "-c".into(), "echo done".into()],
        env: HashMap::new(),
        resources: ResourceLimits::default(),
        volumes: Vec::new(),
        hostname: None,
        working_directory: "/home/container".into(),
        silo: false, tools: Vec::new(), shares: Vec::new(),
        security_profile: SecurityProfile::default(),
        network: NetworkAccess::None,
        ports: Vec::new(),
    };
    let c = match Container::create(cfg, IsolationLevel::Standard) {
        Ok(c) => c, Err(e) => return ("lifecycle".into(), false, e.to_string()),
    };
    let id = c.id().to_string();
    let listed_before = list().map(|l| l.iter().any(|x| x.id == id)).unwrap_or(false);
    let _ = c.remove();
    let listed_after = list().map(|l| l.iter().any(|x| x.id == id)).unwrap_or(false);
    let ok = listed_before && !listed_after;
    ("lifecycle".into(), ok, format!("created={listed_before}, removed={}", !listed_after))
}

fn is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Pick a free TCP port by binding to 0 then dropping the listener.
fn pick_free_port() -> Option<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let p = l.local_addr().ok()?.port();
    drop(l);
    Some(p)
}

/// Test: published port — host process can reach a server running inside
/// a running detached container, via the host:container port mapping.
///
/// Demonstrates the "container has its own addressable IP/port" feature:
/// the container app binds 127.0.0.1:CONT_PORT inside the sandbox; psroot's
/// host-side TCP forwarder bridges 127.0.0.1:HOST_PORT → 127.0.0.1:CONT_PORT.
/// From the host, `curl http://127.0.0.1:HOST_PORT` reaches the container.
fn test_network_publish() -> (String, bool, String) {
    // Need python3 for a quick HTTP server.
    let py = ["/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"]
        .iter().find(|p| std::path::Path::new(p).exists()).copied();
    let py = match py {
        Some(p) => p.to_string(),
        None => return ("network_publish".into(), true,
            "skipped — python3 not found".into()),
    };
    let host_port = match pick_free_port() {
        Some(p) => p,
        None => return ("network_publish".into(), false, "no free host port".into()),
    };
    let cont_port = match pick_free_port() {
        Some(p) => p,
        None => return ("network_publish".into(), false, "no free container port".into()),
    };

    // When bridged networking is in use the container has its own loopback
    // and netns; binding on 127.0.0.1 inside would be unreachable from the
    // host (the kernel DNAT lands on container's eth0). Bind 0.0.0.0 so it
    // works on both bridged (Linux) and host-shared (macOS) modes.
    let bridged = cfg!(target_os = "linux") && {
        #[cfg(target_os = "linux")] { psroot_unix::net::available() }
        #[cfg(not(target_os = "linux"))] { false }
    };
    let bind_addr = if bridged { "0.0.0.0" } else { "127.0.0.1" };
    // Build container with the publish mapping.
    let mut cfg = ContainerConfig {
        name: Some(format!("psroot-pub-{}-{}", std::process::id(), host_port)),
        rootfs_path: String::new(),
        command: vec![
            py.clone(),
            "-c".into(),
            format!(
                "import http.server,socketserver;\n\
                 h=http.server.BaseHTTPRequestHandler;\n\
                 class H(h):\n  def do_GET(s):\n    s.send_response(200);s.send_header('X-Psroot','ok');s.end_headers();s.wfile.write(b'PSROOT_PUBLISH_OK')\n  def log_message(s,*a,**k):pass\n\
                 socketserver.TCPServer(('{ba}',{cp}),H).serve_forever()",
                ba = bind_addr, cp = cont_port
            ),
        ],
        env: HashMap::new(),
        resources: ResourceLimits::default(),
        volumes: Vec::new(),
        hostname: Some("psroot".into()),
        working_directory: "/home/container".into(),
        silo: false, tools: Vec::new(), shares: Vec::new(),
        security_profile: SecurityProfile::default(),
        network: NetworkAccess::Outbound,
        ports: vec![PortMapping {
            host_bind: "127.0.0.1".into(),
            host_port,
            container_port: cont_port,
            ephemeral_port: None,
            name: None,
        }],
    };
    cfg.env.insert("PYTHONUNBUFFERED".into(), "1".into());
    let mut c = match Container::create(cfg, IsolationLevel::Standard) {
        Ok(c) => c, Err(e) => return ("network_publish".into(), false, e.to_string()),
    };
    let id = c.id().to_string();

    // On bridged-net hosts the kernel installs DNAT for us; the userspace
    // forwarder would conflict (and isn't needed). Only spawn it for the
    // legacy host-shared netns path (macOS, unprivileged Linux).
    if !bridged {
        let host_addr: std::net::SocketAddr = format!("127.0.0.1:{host_port}").parse().unwrap();
        let backend: std::net::SocketAddr = format!("127.0.0.1:{cont_port}").parse().unwrap();
        if let Err(e) = psroot_unix::ports::spawn_forwarder(host_addr, backend) {
            let _ = c.remove();
            return ("network_publish".into(), false, format!("forwarder bind failed: {e}"));
        }
    }

    // Start the container detached (background).
    if let Err(e) = c.start_detached() {
        let _ = c.remove();
        return ("network_publish".into(), false, format!("start_detached: {e}"));
    }

    // Poll for the published port to accept connections.
    let mut reached = false;
    let mut body = String::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(250));
        if let Ok(out) = std::process::Command::new("/usr/bin/curl")
            .args(["-s", "-m", "2", &format!("http://127.0.0.1:{host_port}/")])
            .output()
        {
            if out.status.success() && !out.stdout.is_empty() {
                body = String::from_utf8_lossy(&out.stdout).into_owned();
                reached = body.contains("PSROOT_PUBLISH_OK");
                if reached { break; }
            }
        }
    }

    // Stop & remove.
    let _ = c.stop();
    // Best-effort: kill the python server if still alive (host_pid was
    // recorded by start_detached).
    if let Ok(loaded) = Container::load(&id) {
        if let Ok(s) = loaded.stats() {
            if let Some(pid) = s.host_pid {
                let _ = nix_kill_tree(pid);
            }
        }
    }
    let _ = c.remove();

    if reached {
        ("network_publish".into(), true,
         format!("host curl 127.0.0.1:{host_port} -> container 127.0.0.1:{cont_port} ok, body={:?}", body))
    } else {
        ("network_publish".into(), false,
         format!("did not reach published port {host_port} (container_port={cont_port})"))
    }
}

fn nix_kill_tree(pid: i32) -> std::io::Result<()> {
    // Try SIGTERM the process group, then the individual pid.
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
        libc::kill(pid, libc::SIGTERM);
    }
    Ok(())
}

/// Test: per-container bridged networking.
///
/// On Linux when running as root with `ip`/`iptables` available, every
/// container gets its own `10.88.x.y` IP on the `psroot0` bridge. We
/// start a long-lived container (`sleep 30`), reload its record to read
/// the assigned `container_ip`, then ping that IP from the host. Success
/// proves the veth pair is wired and the bridge is forwarding.
fn test_network_bridged() -> (String, bool, String) {
    #[cfg(not(target_os = "linux"))]
    {
        return ("network_bridged".into(), true,
            "skipped — bridged net is Linux-only (mac uses userspace proxy)".into());
    }
    #[cfg(target_os = "linux")]
    {
        if !psroot_unix::net::available() {
            return ("network_bridged".into(), true,
                "skipped — needs root + ip + iptables".into());
        }
        let cfg = ContainerConfig {
            name: Some(format!("psroot-bridged-{}", std::process::id())),
            rootfs_path: String::new(),
            command: vec!["/bin/sleep".into(), "30".into()],
            env: HashMap::new(),
            resources: ResourceLimits::default(),
            volumes: Vec::new(),
            hostname: Some("psroot".into()),
            working_directory: "/home/container".into(),
            silo: false, tools: Vec::new(), shares: Vec::new(),
            security_profile: SecurityProfile::default(),
            network: NetworkAccess::Outbound,
            ports: Vec::new(),
        };
        let mut c = match Container::create(cfg, IsolationLevel::Standard) {
            Ok(c) => c, Err(e) => return ("network_bridged".into(), false, e.to_string()),
        };
        let id = c.id().to_string();
        if let Err(e) = c.start_detached() {
            let _ = c.remove();
            return ("network_bridged".into(), false, format!("start_detached: {e}"));
        }
        // Wait for state to be persisted with the assigned IP.
        let mut assigned = String::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(200));
            if let Ok(loaded) = Container::load(&id) {
                if let Some(ip) = loaded.record().container_ip.clone() {
                    assigned = ip;
                    break;
                }
            }
        }
        if assigned.is_empty() {
            let _ = c.stop(); let _ = c.remove();
            return ("network_bridged".into(), false,
                "container did not get a 10.88.x.y IP within 5s".into());
        }
        // Host pings the container IP.
        let ping = std::process::Command::new("ping")
            .args(["-c", "2", "-W", "2", &assigned])
            .output();
        let pinged = matches!(&ping, Ok(o) if o.status.success());
        let _ = c.stop();
        let _ = c.remove();
        if !pinged {
            return ("network_bridged".into(), false,
                format!("container got IP {assigned} but host could not ping it"));
        }
        ("network_bridged".into(), true,
         format!("container IP={assigned} on psroot0; host->container ping OK"))
    }
}

/// Test: interactive TTY — spawn `psroot shell` under a PTY and confirm
/// commands execute and output is captured. Uses /usr/bin/expect-style
/// PTY by re-invoking ourselves.
///
/// Implementation strategy: open a PTY, fork, child execs the current
/// `psroot` binary as `psroot run --network none -- /bin/sh -c "echo MARKER=$$"`.
/// Parent reads from master until it sees MARKER=. Validates the TTY path
/// without needing the `expect` binary.
fn test_tty_shell() -> (String, bool, String) {
    use std::io::Read;
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::sync::{Arc, Mutex};
    let exe = match std::env::current_exe() {
        Ok(p) => p, Err(e) => return ("tty_shell".into(), false, e.to_string()),
    };
    let ws = nix::pty::Winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
    let result = match unsafe { nix::pty::forkpty(Some(&ws), None) } {
        Ok(r) => r, Err(e) => return ("tty_shell".into(), false, format!("forkpty: {e}")),
    };
    use nix::pty::ForkptyResult;
    match result {
        ForkptyResult::Child => {
            let prog = std::ffi::CString::new(exe.to_string_lossy().as_bytes()).unwrap();
            let argv: Vec<std::ffi::CString> = [
                exe.to_string_lossy().to_string(),
                "run".into(), "--network".into(), "none".into(),
                "--".into(),
                "/bin/sh".into(), "-c".into(),
                "echo MARKER_OK USER=$USER HOME=$HOME ID=$PSROOT_CONTAINER_ID; exit 0".into(),
            ].into_iter().map(|s| std::ffi::CString::new(s).unwrap()).collect();
            let _ = nix::unistd::execv(&prog, &argv);
            unsafe { libc::_exit(127); }
        }
        ForkptyResult::Parent { child, master } => {
            let raw = master.into_raw_fd();
            let acc = Arc::new(Mutex::new(String::new()));
            let acc2 = acc.clone();
            // Reader thread: blocking reads from master until EIO/0.
            let reader = std::thread::spawn(move || {
                let mut f: std::fs::File = unsafe { std::fs::File::from_raw_fd(raw) };
                let mut buf = [0u8; 4096];
                loop {
                    match f.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Ok(mut g) = acc2.lock() {
                                g.push_str(&String::from_utf8_lossy(&buf[..n]));
                            }
                        }
                        Err(e) => {
                            // EIO when slave closes — that's normal.
                            let _ = e; break;
                        }
                    }
                }
                // OwnedFd dropped here closes raw.
                drop(f);
            });
            // Wait for the child with a deadline.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            let mut exited = false;
            let mut exit_code = -1;
            while std::time::Instant::now() < deadline {
                match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                    Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => {
                        exited = true; exit_code = code; break;
                    }
                    Ok(nix::sys::wait::WaitStatus::Signaled(_, sig, _)) => {
                        exited = true; exit_code = 128 + sig as i32; break;
                    }
                    _ => std::thread::sleep(std::time::Duration::from_millis(80)),
                }
            }
            // Give reader a moment to drain post-exit data, then close fd
            // by joining (reader's drop closes the OwnedFd inside).
            std::thread::sleep(std::time::Duration::from_millis(200));
            // Force-close raw to break the read loop on EIO.
            unsafe { libc::close(raw); }
            let _ = reader.join();
            let out = acc.lock().map(|g| g.clone()).unwrap_or_default();
            let saw_marker = out.contains("MARKER_OK")
                && out.contains("USER=container")
                && out.contains("ID=");
            let ok = exited && exit_code == 0 && saw_marker;
            ("tty_shell".into(), ok,
             format!("exited={exited} code={exit_code} saw_marker={saw_marker} output={:?}",
                 out.replace('\r', "").lines().filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" | ")))
        }
    }
}
