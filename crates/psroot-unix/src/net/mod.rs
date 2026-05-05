//! Per-container Linux networking: bridge + veth + NAT.
//!
//! When the host has root + `CAP_NET_ADMIN` + `ip`/`iptables` binaries,
//! containers get a real private IP on the `psroot0` bridge instead of
//! sharing the host network namespace. Outbound traffic is MASQUERADE'd;
//! published ports become real DNAT rules.
//!
//! On systems where any precondition fails, `available()` returns `false`
//! and the backend falls back to the legacy host-shared netns + userspace
//! TCP proxy.
//!
//! Shells out to `/sbin/ip` and `/sbin/iptables` (or `nft` if iptables is
//! missing). This avoids a heavy netlink dependency and matches Docker's
//! historical model.

pub mod ipam;
pub mod bridge;
pub mod veth;
pub mod nat;

use std::path::Path;
use std::process::Command;

/// Bridge name used for all psroot containers.
pub const BRIDGE_NAME: &str = "psroot0";
/// Bridge subnet (host gateway lives at `.1`).
pub const BRIDGE_CIDR: &str = "10.88.0.0/16";
pub const BRIDGE_GATEWAY: &str = "10.88.0.1";
pub const BRIDGE_NETMASK_BITS: u8 = 16;

/// Returns true if we can perform real bridged networking on this host.
///
/// Required: euid=0, `ip` and `iptables` (or `nft`) on PATH, kernel
/// supports `CONFIG_VETH` (we test by trying to add a probe link, but
/// only on the slow path — `available()` is cheap).
pub fn available() -> bool {
    if unsafe { libc::geteuid() } != 0 {
        return false;
    }
    if which("ip").is_none() {
        return false;
    }
    if which("iptables").is_none() && which("nft").is_none() {
        return false;
    }
    true
}

/// Locate a binary in `PATH` plus the standard sbin locations that some
/// minimal images omit from `PATH` for non-login shells.
pub fn which(name: &str) -> Option<String> {
    let path = std::env::var("PATH").unwrap_or_default();
    let mut candidates: Vec<String> = path.split(':').map(String::from).collect();
    for extra in ["/sbin", "/usr/sbin", "/usr/local/sbin", "/bin", "/usr/bin"] {
        candidates.push(extra.to_string());
    }
    for dir in candidates {
        let p = Path::new(&dir).join(name);
        if p.is_file() {
            return Some(p.to_string_lossy().into_owned());
        }
    }
    None
}

/// Run a command, returning Ok on success and a descriptive error on
/// non-zero exit. Captures stderr for diagnostics.
pub(crate) fn run(prog: &str, args: &[&str]) -> Result<String, String> {
    let bin = which(prog).unwrap_or_else(|| prog.to_string());
    let out = Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| format!("spawn {prog} failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{prog} {} -> exit {:?}: {}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Same as `run`, but treats EEXIST-like failures as success. Used for
/// idempotent setup steps (creating the bridge, NAT rule already present).
pub(crate) fn run_idempotent(prog: &str, args: &[&str]) -> Result<(), String> {
    match run(prog, args) {
        Ok(_) => Ok(()),
        Err(msg) => {
            let lc = msg.to_lowercase();
            if lc.contains("file exists") || lc.contains("already exists")
                || lc.contains("already a member") || lc.contains("rule already exists")
                || lc.contains("chain already exists")
                || lc.contains("already assigned")
            {
                Ok(())
            } else {
                Err(msg)
            }
        }
    }
}
