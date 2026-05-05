//! Cross-platform spawn/sandbox front-end.
//!
//! This module delegates to `backend_macos` or `backend_linux` for the
//! OS-specific isolation. Common helpers (env sanitization, rlimit application)
//! live here.

use crate::{state::ContainerRecord, IsolationLevel, Result};
use std::collections::HashMap;

pub fn run_synchronously(
    rec: &ContainerRecord,
    isolation: IsolationLevel,
    interactive: bool,
) -> Result<i32> {
    #[cfg(target_os = "macos")]
    return crate::backend_macos::run(rec, isolation, interactive);
    #[cfg(target_os = "linux")]
    return crate::backend_linux::run(rec, isolation, interactive);
    #[allow(unreachable_code)]
    Err(crate::Error::Unsupported(std::env::consts::OS.into()))
}

/// Build the env that will be exposed inside the container.
///
/// We strip almost everything from the host env to prevent path leaks,
/// then set a small fixed allowlist plus user-supplied `cfg.env`.
pub fn build_env(rec: &ContainerRecord, container_home: &str) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("HOME".into(), container_home.into());
    env.insert("USER".into(), "container".into());
    env.insert("LOGNAME".into(), "container".into());
    env.insert("SHELL".into(), "/bin/sh".into());
    // Keep PATH minimal but functional. /usr/bin and /bin are accessible
    // (they're either symlinked or sandbox-allowed).
    env.insert(
        "PATH".into(),
        "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into(),
    );
    env.insert("PWD".into(), container_home.into());
    env.insert("PS1".into(), "psroot> ".into());
    env.insert("TERM".into(), std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".into()));
    env.insert("LANG".into(), "C.UTF-8".into());
    env.insert("PSROOT_CONTAINER_ID".into(), rec.id.clone());
    if let Some(name) = &rec.name {
        env.insert("PSROOT_CONTAINER_NAME".into(), name.clone());
    }
    for (k, v) in &rec.config.env {
        env.insert(k.clone(), v.clone());
    }
    env
}

/// Apply rlimits configured on the container.
///
/// On macOS we mostly skip these: `RLIMIT_AS` is unreliable on Darwin
/// (arm64 reserves dozens of GB of address space for system libraries
/// before main runs) and `RLIMIT_NPROC` is per-uid, so a 100-proc cap
/// would instantly kill the user's whole login session. We document
/// rlimits as Linux-only enforcement and rely on cgroups there.
pub fn apply_rlimits(res: &psroot_types::config::ResourceLimits) {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::resource::{setrlimit, Resource};
        if res.memory > 0 {
            let _ = setrlimit(Resource::RLIMIT_AS, res.memory, res.memory);
            let _ = setrlimit(Resource::RLIMIT_DATA, res.memory, res.memory);
        }
        if res.max_processes > 0 {
            let v = res.max_processes as libc::rlim_t;
            let rlim = libc::rlimit { rlim_cur: v, rlim_max: v };
            unsafe { libc::setrlimit(libc::RLIMIT_NPROC, &rlim); }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = res;
    }
}

/// Default allowed reads on macOS (system libraries that any binary needs).
pub const MACOS_SYSTEM_READ_PATHS: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/private/etc",
    "/private/var/db/timezone",
    "/private/var/db/dyld",
    "/private/var/select",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
];
