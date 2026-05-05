//! Psroot container backend for Linux and macOS.
//!
//! This crate is a parallel implementation of `psroot-container` that uses
//! POSIX primitives instead of Windows APIs. The public surface is kept
//! deliberately close to `psroot_container::Container` so the CLI can
//! dispatch to either backend by `cfg`.
//!
//! See `PRD/01-architecture.md` for the design.

#![cfg(unix)]

use std::path::{Path, PathBuf};

pub mod parse;
pub mod paths;
pub mod pty;
pub mod rootfs;
pub mod sandbox;
pub mod state;
pub mod ports;

#[cfg(target_os = "linux")]
pub mod net;

#[cfg(target_os = "linux")]
mod backend_linux;
#[cfg(target_os = "macos")]
mod backend_macos;

pub use psroot_types::config::{
    ContainerConfig, NetworkAccess, PortMapping, ResourceLimits, SecurityProfile, VolumeMount,
};
pub use psroot_types::state::ContainerState;
pub use state::{ContainerInfo, ContainerRecord, RuntimeState};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nix: {0}")]
    Nix(#[from] nix::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid argument: {0}")]
    Invalid(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IsolationLevel {
    /// Best-effort: rlimits + sanitized env. No kernel sandbox.
    Minimal,
    /// macOS: sandbox-exec profile. Linux: user-namespace only.
    #[default]
    Standard,
    /// macOS: sandbox-exec + chroot (root). Linux: full namespaces + cgroups.
    Full,
}

impl std::fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Minimal => f.write_str("minimal"),
            Self::Standard => f.write_str("standard"),
            Self::Full => f.write_str("full"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub os: &'static str,
    pub is_root: bool,
    pub user_namespaces: bool,
    pub cgroups_v2: bool,
    pub sandbox_exec: bool,
    pub max_isolation: IsolationLevel,
}

pub fn capabilities() -> Capabilities {
    let is_root = unsafe { libc::geteuid() == 0 };
    let os = std::env::consts::OS;
    let user_namespaces = cfg!(target_os = "linux") && Path::new("/proc/self/ns/user").exists();
    let cgroups_v2 = cfg!(target_os = "linux") && Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let sandbox_exec = cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").exists();
    let max_isolation = match (cfg!(target_os = "linux"), cfg!(target_os = "macos"), is_root) {
        (true, _, _) if user_namespaces => IsolationLevel::Full,
        (_, true, _) if sandbox_exec => IsolationLevel::Full,
        _ => IsolationLevel::Standard,
    };
    Capabilities {
        os,
        is_root,
        user_namespaces,
        cgroups_v2,
        sandbox_exec,
        max_isolation,
    }
}

/// A managed container.
pub struct Container {
    record: ContainerRecord,
    isolation: IsolationLevel,
}

impl Container {
    pub fn create(mut cfg: ContainerConfig, isolation: IsolationLevel) -> Result<Self> {
        let id = uuid::Uuid::new_v4().to_string();
        let dir = paths::container_dir(&id)?;
        std::fs::create_dir_all(&dir)?;
        let rootfs = if cfg.rootfs_path.is_empty() {
            dir.join("rootfs")
        } else {
            PathBuf::from(&cfg.rootfs_path)
        };
        std::fs::create_dir_all(&rootfs)?;
        rootfs::populate(&rootfs)?;
        cfg.rootfs_path = rootfs.to_string_lossy().into_owned();
        let record = ContainerRecord {
            id: id.clone(),
            name: cfg.name.clone(),
            config: cfg,
            state: ContainerState::Created,
            created_at: now_rfc3339(),
            started_at: None,
            stopped_at: None,
            exit_code: None,
            host_pid: None,
            container_ip: None,
            isolation: isolation.to_string(),
            dir: dir.to_string_lossy().into_owned(),
        };
        state::save(&record)?;
        Ok(Self { record, isolation })
    }

    pub fn load(id_or_name: &str) -> Result<Self> {
        let record = state::load(id_or_name)?;
        let isolation = match record.isolation.as_str() {
            "minimal" => IsolationLevel::Minimal,
            "full" => IsolationLevel::Full,
            _ => IsolationLevel::Standard,
        };
        Ok(Self { record, isolation })
    }

    pub fn id(&self) -> &str { &self.record.id }
    pub fn name(&self) -> Option<&str> { self.record.name.as_deref() }
    pub fn state(&self) -> ContainerState { self.record.state }
    pub fn config(&self) -> &ContainerConfig { &self.record.config }
    pub fn isolation(&self) -> IsolationLevel { self.isolation }
    pub fn dir(&self) -> &str { &self.record.dir }
    pub fn record(&self) -> &ContainerRecord { &self.record }

    /// Run a one-shot command synchronously, returning the exit code.
    /// Inherits the host TTY if `interactive` is true.
    pub fn run(&mut self, cmd: &[String], interactive: bool) -> Result<i32> {
        if !cmd.is_empty() {
            self.record.config.command = cmd.to_vec();
        }
        self.record.state = ContainerState::Running;
        self.record.started_at = Some(now_rfc3339());
        state::save(&self.record)?;

        let result = sandbox::run_synchronously(&self.record, self.isolation, interactive);

        self.record.state = ContainerState::Stopped;
        self.record.stopped_at = Some(now_rfc3339());
        if let Ok(code) = &result {
            self.record.exit_code = Some(*code);
        }
        state::save(&self.record)?;
        result
    }

    /// Same as `run` but with `interactive=true` and forces a shell command.
    pub fn shell(&mut self) -> Result<i32> {
        let cmd = if self.record.config.command.is_empty()
            || self.record.config.command == vec!["cmd.exe".to_string()]
        {
            default_shell_command()
        } else {
            self.record.config.command.clone()
        };
        self.run(&cmd, true)
    }

    /// Lifecycle: start (non-blocking detached). Currently runs synchronously
    /// in the foreground when invoked from the CLI without `--detach`. The
    /// non-blocking path is used by `psroot start`.
    pub fn start_detached(&mut self) -> Result<()> {
        // Fork a supervisor that runs the container and writes the exit code.
        use nix::unistd::{fork, ForkResult};
        match unsafe { fork()? } {
            ForkResult::Parent { child } => {
                self.record.host_pid = Some(child.as_raw());
                self.record.state = ContainerState::Running;
                self.record.started_at = Some(now_rfc3339());
                state::save(&self.record)?;
                Ok(())
            }
            ForkResult::Child => {
                // Detach from controlling terminal.
                let _ = nix::unistd::setsid();
                let cmd = self.record.config.command.clone();
                let _ = self.run(&cmd, false);
                std::process::exit(0);
            }
        }
    }

    pub fn exec(&self, cmd: &[String]) -> Result<i32> {
        // Spawn a sibling process under the same sandbox profile. We don't
        // try to "join" namespaces here on Linux yet — full support requires
        // setns(2) into the running container's nsfs handles. For now exec
        // re-applies the same sandbox profile.
        let mut tmp = self.record.clone();
        tmp.config.command = cmd.to_vec();
        sandbox::run_synchronously(&tmp, self.isolation, false)
    }

    pub fn stop(&mut self) -> Result<()> {
        if let Some(pid) = self.record.host_pid {
            let p = nix::unistd::Pid::from_raw(pid);
            let _ = nix::sys::signal::kill(p, nix::sys::signal::Signal::SIGTERM);
        }
        self.record.state = ContainerState::Stopped;
        self.record.stopped_at = Some(now_rfc3339());
        state::save(&self.record)?;
        Ok(())
    }

    pub fn remove(self) -> Result<()> {
        let dir = PathBuf::from(&self.record.dir);
        // Best-effort: clean up any leftover per-container networking
        // (veth, DNAT rules, IP lease) in case the container was killed
        // before its normal teardown ran.
        #[cfg(target_os = "linux")]
        {
            net::nat::cleanup(&self.record.id);
            let (host_if, _) = net::veth::iface_names(&self.record.id);
            net::veth::destroy(&host_if);
            if let Some(ip) = &self.record.container_ip {
                net::ipam::release(ip);
            }
        }
        if dir.exists() {
            // Best-effort recursive remove. Some files may be owned by other
            // uids if the container ran with mapped users; ignore EPERM.
            let _ = std::fs::remove_dir_all(&dir);
        }
        Ok(())
    }

    pub fn stats(&self) -> Result<Stats> {
        Ok(Stats {
            state: self.record.state,
            host_pid: self.record.host_pid,
            exit_code: self.record.exit_code,
            // Real numbers would come from cgroup files / proc; stubbed for
            // unprivileged + cross-platform.
            memory_bytes: 0,
            cpu_user_us: 0,
            cpu_system_us: 0,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Stats {
    pub state: ContainerState,
    pub host_pid: Option<i32>,
    pub exit_code: Option<i32>,
    pub memory_bytes: u64,
    pub cpu_user_us: u64,
    pub cpu_system_us: u64,
}

pub fn list() -> Result<Vec<ContainerInfo>> { state::list() }

pub fn default_shell_command() -> Vec<String> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
    vec![shell, "-i".to_string()]
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    // Don't pull chrono just for this — emit epoch seconds wrapped as a
    // recognisable string. Good enough for diagnostic purposes.
    format!("epoch:{secs}")
}
