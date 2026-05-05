//! Linux sandbox backend.
//!
//! Strategy: clone(2) with all available namespaces (NS, PID, UTS, IPC, NET,
//! USER), set up uid/gid maps, pivot_root into the container's rootfs, mount
//! `proc`/`sysfs`/`tmpfs`, drop into a child shell.
//!
//! When run as root we can omit USER and use full host networking via veth.
//! When run as an unprivileged user we lean entirely on user namespaces.
//!
//! Resource limits go through cgroup v2 when delegated; otherwise we fall
//! back to setrlimit (best-effort).

use crate::{paths, pty, sandbox, state::ContainerRecord, IsolationLevel, Error, Result};
use psroot_types::config::NetworkAccess;
use std::path::PathBuf;
use std::os::fd::{AsRawFd, OwnedFd};

/// Plan for per-container bridged networking, populated on the host side
/// before the child enters its new netns.
struct BridgedNet {
    /// Host-side veth interface attached to `psroot0`. Must be deleted on
    /// container teardown.
    host_if: String,
    /// Container-side veth interface name *before* it's renamed to `eth0`
    /// inside the new netns.
    peer_if: String,
    /// Address assigned to the container (also stored in the record).
    container_ip: String,
}

/// Decide and prepare bridged networking. Returns `None` when the system
/// can't support it (non-root, missing tools, network=None) — in that case
/// the legacy host-shared netns path is used.
fn try_prepare_bridged_net(rec: &ContainerRecord) -> Option<BridgedNet> {
    if rec.config.network == NetworkAccess::None { return None; }
    if !crate::net::available() { return None; }
    if let Err(e) = crate::net::bridge::ensure() {
        eprintln!("psroot: bridge setup failed ({e}); falling back to host-shared net");
        return None;
    }
    let ip = match crate::net::ipam::alloc() {
        Ok(a) => a,
        Err(e) => { eprintln!("psroot: ipam: {e}"); return None; }
    };
    let (host_if, peer_if) = match crate::net::veth::create_pair(&rec.id) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("psroot: veth: {e}");
            crate::net::ipam::release(&ip);
            return None;
        }
    };
    Some(BridgedNet { host_if, peer_if, container_ip: ip })
}

/// Install DNAT rules for every published port mapping. Best-effort; logs
/// and continues so a single bad mapping doesn't kill the container.
fn install_port_dnat(rec: &ContainerRecord, container_ip: &str) {
    for pm in &rec.config.ports {
        if let Err(e) = crate::net::nat::install(
            &rec.id, &pm.host_bind, pm.host_port, container_ip, pm.container_port,
        ) {
            eprintln!("psroot: DNAT {} -> {}:{} failed: {e}",
                pm.host_port, container_ip, pm.container_port);
        }
    }
}

pub fn run(
    rec: &ContainerRecord,
    isolation: IsolationLevel,
    interactive: bool,
) -> Result<i32> {
    let rootfs = PathBuf::from(&rec.config.rootfs_path);
    if !rootfs.exists() {
        return Err(Error::NotFound(format!("rootfs missing: {}", rootfs.display())));
    }

    // Best-effort cgroup setup if v2 is available + writable.
    let _ = setup_cgroup(rec);

    let cmd = if rec.config.command.is_empty() {
        crate::default_shell_command()
    } else {
        rec.config.command.clone()
    };

    if interactive {
        run_interactive(rec, &rootfs, &cmd, isolation)
    } else {
        run_noninteractive(rec, &rootfs, &cmd, isolation)
    }
}

fn run_interactive(
    rec: &ContainerRecord,
    rootfs: &std::path::Path,
    cmd: &[String],
    isolation: IsolationLevel,
) -> Result<i32> {
    use nix::pty::ForkptyResult;
    let bnet = try_prepare_bridged_net(rec);
    let (parent_rd, child_wr, child_rd, parent_wr) = make_sync_pipes()?;
    let ws = pty::current_winsize().unwrap_or(nix::pty::Winsize {
        ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0,
    });
    let result = unsafe { nix::pty::forkpty(Some(&ws), None) }?;
    match result {
        ForkptyResult::Parent { child, master } => {
            drop(child_wr); drop(child_rd);
            host_finalize_net(&bnet, child.as_raw(), parent_rd, parent_wr, rec);
            let r = pty::forward(master, child);
            cleanup_bridged_net(&bnet, rec);
            r
        }
        ForkptyResult::Child => {
            drop(parent_rd); drop(parent_wr);
            child_setup_and_exec(rec, rootfs, cmd, isolation, &bnet, child_rd, child_wr);
        }
    }
}

fn run_noninteractive(
    rec: &ContainerRecord,
    rootfs: &std::path::Path,
    cmd: &[String],
    isolation: IsolationLevel,
) -> Result<i32> {
    use nix::unistd::{fork, ForkResult};
    use nix::sys::wait::{waitpid, WaitStatus};
    let bnet = try_prepare_bridged_net(rec);
    let (parent_rd, child_wr, child_rd, parent_wr) = make_sync_pipes()?;
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            drop(child_wr); drop(child_rd);
            host_finalize_net(&bnet, child.as_raw(), parent_rd, parent_wr, rec);
            let r = match waitpid(child, None)? {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                _ => Ok(0),
            };
            cleanup_bridged_net(&bnet, rec);
            r
        }
        ForkResult::Child => {
            drop(parent_rd); drop(parent_wr);
            child_setup_and_exec(rec, rootfs, cmd, isolation, &bnet, child_rd, child_wr);
        }
    }
}

/// Create two unidirectional pipes for the host<->child handshake.
/// Returns `(parent_rd, child_wr, child_rd, parent_wr)`.
fn make_sync_pipes() -> Result<(OwnedFd, OwnedFd, OwnedFd, OwnedFd)> {
    let (p_rd, c_wr) = nix::unistd::pipe()?;
    let (c_rd, p_wr) = nix::unistd::pipe()?;
    Ok((p_rd, c_wr, c_rd, p_wr))
}

/// Host-side: wait for the child to signal "I have unshared", then move
/// the veth peer into its netns and install DNAT rules. Finally signal
/// "GO" so the child can configure its end and exec.
fn host_finalize_net(
    bnet: &Option<BridgedNet>,
    child_pid: i32,
    rd: OwnedFd,
    wr: OwnedFd,
    rec: &ContainerRecord,
) {
    // Wait for "READY\n" from child (regardless of bridged net, this gates
    // the GO signal).
    let mut buf = [0u8; 16];
    let _ = nix::unistd::read(rd.as_raw_fd(), &mut buf);
    if let Some(b) = bnet {
        if let Err(e) = crate::net::veth::move_peer_into_netns(&b.peer_if, child_pid) {
            eprintln!("psroot: {e}");
        }
        install_port_dnat(rec, &b.container_ip);
        // Persist the IP into the on-disk record so `psroot ls` shows it.
        if let Ok(mut r) = crate::state::load(&rec.id) {
            r.container_ip = Some(b.container_ip.clone());
            let _ = crate::state::save(&r);
        }
    }
    // Signal "GO".
    let _ = nix::unistd::write(&wr, b"GO\n");
    drop(wr); drop(rd);
}

/// Tear down per-container netfilter rules and veth on container exit.
fn cleanup_bridged_net(bnet: &Option<BridgedNet>, rec: &ContainerRecord) {
    if let Some(b) = bnet {
        crate::net::nat::cleanup(&rec.id);
        crate::net::veth::destroy(&b.host_if);
        crate::net::ipam::release(&b.container_ip);
        if let Ok(mut r) = crate::state::load(&rec.id) {
            r.container_ip = None;
            let _ = crate::state::save(&r);
        }
    }
}

fn child_setup_and_exec(
    rec: &ContainerRecord,
    rootfs: &std::path::Path,
    cmd: &[String],
    isolation: IsolationLevel,
    bnet: &Option<BridgedNet>,
    sync_rd: OwnedFd,
    sync_wr: OwnedFd,
) -> ! {
    use nix::sched::{unshare, CloneFlags};
    use nix::mount::{mount, umount2, MsFlags, MntFlags};

    // Try to enter as many namespaces as possible. If unshare fails (e.g.
    // no user-namespace support), fall back to the next-strongest mode.
    let mut flags = CloneFlags::empty();
    flags |= CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC;
    if isolation != IsolationLevel::Minimal {
        flags |= CloneFlags::CLONE_NEWPID;
        // Always enter a private netns when we have a bridged-net plan
        // OR when the user asked for `none`. Otherwise (legacy outbound
        // path with no bridge support) inherit the host's netns.
        if bnet.is_some()
            || rec.config.network == NetworkAccess::None
            || isolation == IsolationLevel::Full
        {
            flags |= CloneFlags::CLONE_NEWNET;
        }
        // User namespace last; if we're root we can skip it.
        let euid = unsafe { libc::geteuid() };
        if euid != 0 {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
    }
    if let Err(e) = unshare(flags) {
        eprintln!("psroot: unshare failed ({e}); falling back to minimal isolation");
    } else if flags.contains(CloneFlags::CLONE_NEWUSER) {
        write_uid_gid_maps();
    }

    // Bridged-net handshake: tell the host we're in our new netns so it
    // can move the veth peer in, then wait for GO. We DO NOT call
    // configure_inside here — that uses Command::spawn which would become
    // PID 1 in the new pidns and prevent subsequent forks. We defer the
    // veth configuration until after the fork-for-PID-1 below.
    let _ = nix::unistd::write(&sync_wr, b"READY\n");
    let mut buf = [0u8; 8];
    let _ = nix::unistd::read(sync_rd.as_raw_fd(), &mut buf);
    drop(sync_wr); drop(sync_rd);

    // unshare(CLONE_NEWPID) only takes effect for FUTURE children of this
    // process — the current process stays in the original PID namespace.
    // Fork once more so that the child becomes PID 1 inside the new PID NS
    // and any /proc mount it does sees only its own descendants.
    if flags.contains(CloneFlags::CLONE_NEWPID) {
        use nix::unistd::{fork, ForkResult};
        use nix::sys::wait::{waitpid, WaitStatus};
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Wait for the grandchild and propagate its exit status.
                let code = match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, c)) => c,
                    Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
                    _ => 0,
                };
                unsafe { libc::_exit(code); }
            }
            Ok(ForkResult::Child) => {
                // Continue setup as PID 1 in the new namespace.
            }
            Err(e) => {
                eprintln!("psroot: fork after unshare failed: {e}");
                unsafe { libc::_exit(125); }
            }
        }
    }

    // Now we're in the inner (PID 1) process — fork() works normally
    // because PID 1 is alive (us). Safe to spawn `ip` to configure the
    // veth peer that the host moved into our netns.
    if let Some(b) = bnet {
        if let Err(e) = crate::net::veth::configure_inside(&b.peer_if, &b.container_ip) {
            eprintln!("psroot: configure container netns: {e}");
        }
    }

    // Make our mounts private so they don't propagate.
    let _ = mount::<str, str, str, str>(
        Some("none"), "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None);

    // Bind-mount rootfs over itself (required for pivot_root).
    let rs = rootfs.to_string_lossy().to_string();
    let _ = mount::<str, str, str, str>(
        Some(&rs), &rs, Some("none"), MsFlags::MS_BIND | MsFlags::MS_REC, None);

    // Detect whether the user supplied a self-contained rootfs (e.g. an
    // Ubuntu base populated by debootstrap). If `/usr/bin/env` already
    // exists inside the rootfs we treat it as a "real" distro and DO NOT
    // bind-mount any host system directories — that would leak the host
    // filesystem and prevent the container's own package manager from
    // writing to /usr. Otherwise fall back to the legacy bind-mount-host
    // strategy used by the bare skeleton so basic commands still work.
    let self_contained = rootfs.join("usr/bin/env").exists()
        || rootfs.join("bin/sh").is_symlink()
        || rootfs.join("bin/sh").exists();
    if !self_contained {
        for src in &[
            "/bin", "/sbin", "/usr", "/lib", "/lib64", "/lib32", "/libx32",
            "/etc/ssl", "/etc/alternatives", "/etc/ld.so.cache", "/etc/ld.so.conf",
            "/etc/ld.so.conf.d", "/etc/nsswitch.conf", "/etc/passwd",
            "/etc/group", "/etc/shadow",
        ] {
            if !std::path::Path::new(src).exists() { continue; }
            let dst = format!("{rs}{src}");
            let is_dir = std::path::Path::new(src).is_dir();
            if is_dir {
                let _ = std::fs::create_dir_all(&dst);
            } else if let Some(parent) = std::path::Path::new(&dst).parent() {
                let _ = std::fs::create_dir_all(parent);
                let _ = std::fs::write(&dst, b"");
            }
            let _ = mount::<str, str, str, str>(
                Some(src), &dst, Some("none"),
                MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY, None);
            let _ = mount::<str, str, str, str>(
                None, &dst, None,
                MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY, None);
        }
    }
    // Make sure /etc/resolv.conf inside container has DNS (already populated
    // by rootfs::populate, but if user network=none we leave it alone).
    let _ = std::fs::create_dir_all(format!("{rs}/etc"));

    // pivot_root.
    let put_old = format!("{rs}/.psroot_old");
    let _ = std::fs::create_dir_all(&put_old);
    if nix::unistd::pivot_root(&rs[..], &put_old[..]).is_ok() {
        let _ = std::env::set_current_dir("/");
        let _ = umount2("/.psroot_old", MntFlags::MNT_DETACH);
        let _ = std::fs::remove_dir("/.psroot_old");
    }

    // Standard mounts.
    let _ = std::fs::create_dir_all("/proc");
    let _ = mount::<str, str, str, str>(Some("proc"), "/proc", Some("proc"), MsFlags::empty(), None);
    let _ = mount::<str, str, str, str>(Some("tmpfs"), "/tmp", Some("tmpfs"), MsFlags::empty(), None);
    // /dev: tmpfs + devpts so PTYs work (`/dev/ptmx`, `/dev/pts/*`).
    let _ = std::fs::create_dir_all("/dev");
    let _ = mount::<str, str, str, str>(
        Some("tmpfs"), "/dev", Some("tmpfs"),
        MsFlags::MS_NOSUID, Some("mode=755"));
    for n in &["null", "zero", "random", "urandom", "tty", "full"] {
        let p = format!("/dev/{n}");
        let _ = std::fs::write(&p, b"");
        let host = format!("/host-dev/{n}");
        let _ = host;
    }
    // Bind-mount the host's /dev/null etc. by remount-bind from /proc/1/root
    // is not available pre-pivot; instead create a devtmpfs-style with mknod
    // when running as root, otherwise bind individual char devices that we
    // saved in the rootfs's /dev before pivot. Simpler & portable: bind-mount
    // host /dev/{null,zero,random,urandom,tty,full} from the host namespace.
    // Since we already pivot_root'd, we can't reach the host fs. Mount devpts
    // for ptmx + tty (sufficient for pty.rs forwarder).
    let _ = std::fs::create_dir_all("/dev/pts");
    let _ = mount::<str, str, str, str>(
        Some("devpts"), "/dev/pts", Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"));
    // Symlink /dev/ptmx → /dev/pts/ptmx (standard layout).
    let _ = std::os::unix::fs::symlink("/dev/pts/ptmx", "/dev/ptmx");
    // mknod /dev/null etc. as root (best-effort).
    if unsafe { libc::geteuid() } == 0 {
        unsafe {
            let nodes: [(&str, libc::mode_t, libc::dev_t); 5] = [
                ("/dev/null",    libc::S_IFCHR | 0o666, libc::makedev(1, 3)),
                ("/dev/zero",    libc::S_IFCHR | 0o666, libc::makedev(1, 5)),
                ("/dev/full",    libc::S_IFCHR | 0o666, libc::makedev(1, 7)),
                ("/dev/random",  libc::S_IFCHR | 0o666, libc::makedev(1, 8)),
                ("/dev/urandom", libc::S_IFCHR | 0o666, libc::makedev(1, 9)),
            ];
            // Force 0666 regardless of umask so unprivileged users
            // (e.g. apt's `_apt` fetch helper) can write to /dev/null.
            let prev_umask = libc::umask(0);
            for (path, mode, dev) in nodes {
                let _ = std::fs::remove_file(path);
                let cstr = std::ffi::CString::new(path).unwrap();
                if libc::mknod(cstr.as_ptr(), mode, dev) == 0 {
                    libc::chmod(cstr.as_ptr(), mode & 0o7777);
                }
            }
            libc::umask(prev_umask);
        }
    }

    // Hostname.
    if let Some(h) = &rec.config.hostname {
        let _ = nix::unistd::sethostname(h);
    } else {
        let _ = nix::unistd::sethostname("psroot");
    }

    // Resource limits.
    sandbox::apply_rlimits(&rec.config.resources);

    // chdir to home.
    let _ = std::env::set_current_dir("/home/container");

    // Build env.
    let env = sandbox::build_env(rec, "/home/container");
    for (k, _) in std::env::vars() { std::env::remove_var(k); }
    for (k, v) in &env { std::env::set_var(k, v); }

    // exec.
    let prog = std::ffi::CString::new(cmd[0].clone()).unwrap();
    let cargs: Vec<std::ffi::CString> = cmd.iter()
        .map(|s| std::ffi::CString::new(s.clone()).unwrap()).collect();
    let _ = nix::unistd::execvp(&prog, &cargs);
    eprintln!("psroot: exec {} failed", cmd[0]);
    unsafe { libc::_exit(127); }
}

fn write_uid_gid_maps() {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let _ = std::fs::write("/proc/self/setgroups", b"deny");
    let _ = std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"));
    let _ = std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"));
}

fn setup_cgroup(rec: &ContainerRecord) -> Result<()> {
    use std::path::Path;
    let cg_root = Path::new("/sys/fs/cgroup");
    if !cg_root.join("cgroup.controllers").exists() {
        return Ok(()); // not v2
    }
    let dir = cg_root.join("psroot").join(&rec.id);
    if std::fs::create_dir_all(&dir).is_err() {
        return Ok(()); // unprivileged
    }
    if rec.config.resources.memory > 0 {
        let _ = std::fs::write(dir.join("memory.max"),
            format!("{}", rec.config.resources.memory));
    }
    if rec.config.resources.max_processes > 0 {
        let _ = std::fs::write(dir.join("pids.max"),
            format!("{}", rec.config.resources.max_processes));
    }
    if rec.config.resources.cpu_rate > 0 && rec.config.resources.cpu_rate < 10000 {
        // Map 1..10000 → quota microseconds out of 100000.
        let quota = (rec.config.resources.cpu_rate as u64) * 10;
        let _ = std::fs::write(dir.join("cpu.max"), format!("{quota} 100000"));
    }
    let _ = std::fs::write(dir.join("cgroup.procs"), format!("{}", std::process::id()));
    let _ = paths::container_dir(&rec.id)?.join("cgroup");
    Ok(())
}
