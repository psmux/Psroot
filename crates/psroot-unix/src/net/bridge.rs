//! One-time host bridge setup. Idempotent — safe to call before each
//! container start.
//!
//! Creates `psroot0` (10.88.0.1/16), brings it up, enables IPv4 forwarding,
//! and installs a single MASQUERADE rule for the bridge subnet so
//! containers can reach the outside world.

use super::{run, run_idempotent, BRIDGE_CIDR, BRIDGE_GATEWAY, BRIDGE_NAME, BRIDGE_NETMASK_BITS};

/// Ensure the host-side bridge is present and configured.
pub fn ensure() -> Result<(), String> {
    // 1. Create bridge (no-op if it already exists).
    run_idempotent("ip", &["link", "add", "name", BRIDGE_NAME, "type", "bridge"])?;
    // 2. Assign the gateway IP. Idempotent — `ip addr add` returns "File
    //    exists" when already set; we treat that as success.
    let with_mask = format!("{BRIDGE_GATEWAY}/{BRIDGE_NETMASK_BITS}");
    run_idempotent("ip", &["addr", "add", &with_mask, "dev", BRIDGE_NAME])?;
    // 3. Bring it up.
    run("ip", &["link", "set", BRIDGE_NAME, "up"])
        .map_err(|e| format!("bridge up: {e}"))?;
    // 4. Enable IPv4 forwarding.
    if let Err(e) = std::fs::write("/proc/sys/net/ipv4/ip_forward", b"1\n") {
        return Err(format!("enable ip_forward: {e}"));
    }
    // 4b. Allow DNAT from 127.0.0.1 to a non-loopback destination. Without
    //     this, packets that arrive on `lo` with a DNAT target get dropped
    //     during routing (martian source). Docker sets the same flag.
    let _ = std::fs::write("/proc/sys/net/ipv4/conf/lo/route_localnet", b"1\n");
    let _ = std::fs::write("/proc/sys/net/ipv4/conf/all/route_localnet", b"1\n");
    let path = format!("/proc/sys/net/ipv4/conf/{}/route_localnet", BRIDGE_NAME);
    let _ = std::fs::write(&path, b"1\n");
    // 4c. SNAT loopback-sourced DNATed traffic so the container can reply
    //     back through the bridge (a 127.0.0.1 source can't be routed off the
    //     bridge). Match traffic destined for the bridge subnet whose source
    //     is loopback and rewrite the source to the bridge gateway.
    let snat_check = run("iptables", &[
        "-t", "nat", "-C", "POSTROUTING",
        "-s", "127.0.0.0/8", "-d", BRIDGE_CIDR, "-j", "MASQUERADE",
    ]);
    if snat_check.is_err() {
        run("iptables", &[
            "-t", "nat", "-A", "POSTROUTING",
            "-s", "127.0.0.0/8", "-d", BRIDGE_CIDR, "-j", "MASQUERADE",
        ]).map_err(|e| format!("install loopback SNAT: {e}"))?;
    }
    // 5. MASQUERADE outbound traffic from the bridge subnet. Use
    //    -C (check) first so we don't add duplicates.
    let check = run("iptables", &[
        "-t", "nat", "-C", "POSTROUTING",
        "-s", BRIDGE_CIDR, "!", "-o", BRIDGE_NAME, "-j", "MASQUERADE",
    ]);
    if check.is_err() {
        run("iptables", &[
            "-t", "nat", "-A", "POSTROUTING",
            "-s", BRIDGE_CIDR, "!", "-o", BRIDGE_NAME, "-j", "MASQUERADE",
        ]).map_err(|e| format!("install MASQUERADE: {e}"))?;
    }
    // 6. Allow forwarding between bridge ports and out to the world.
    //    Some distros default FORWARD policy to DROP; add explicit ACCEPTs.
    for spec in [
        &["-i", BRIDGE_NAME, "-j", "ACCEPT"][..],
        &["-o", BRIDGE_NAME, "-j", "ACCEPT"][..],
    ] {
        let mut chk = vec!["-C", "FORWARD"]; chk.extend_from_slice(spec);
        if run("iptables", &chk).is_err() {
            let mut add = vec!["-A", "FORWARD"]; add.extend_from_slice(spec);
            run("iptables", &add).map_err(|e| format!("install FORWARD: {e}"))?;
        }
    }
    Ok(())
}
