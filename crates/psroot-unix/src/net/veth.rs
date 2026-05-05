//! Per-container veth pair management.
//!
//! Lifecycle:
//!   1. Host (before child enters its netns): `create_pair(id)` returns a
//!      `(host_if, peer_if)` tuple and attaches `host_if` to the bridge.
//!   2. Host: `move_peer_into_netns(peer, child_pid)` shoves the container
//!      end into the child's netns.
//!   3. Child (after `unshare(CLONE_NEWNET)`): `configure_inside(peer, ip)`
//!      assigns the address, brings up `lo` + the veth, installs default
//!      route via the bridge gateway.
//!   4. Host: `destroy(host_if)` on container removal.

use super::{run, BRIDGE_GATEWAY, BRIDGE_NAME, BRIDGE_NETMASK_BITS};

/// Build interface names from a container ID. Linux IFNAMSIZ is 15 chars.
pub fn iface_names(container_id: &str) -> (String, String) {
    // Take 8 chars of the UUID; "psh<id8>" + "psc<id8>" = 11 chars. Safe.
    let short: String = container_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(8).collect();
    (format!("psh{short}"), format!("psc{short}"))
}

/// Step 1 — create the veth pair on the host and attach the host end to
/// the bridge. Idempotent: if the pair already exists we delete + recreate
/// (containers are short-lived).
pub fn create_pair(container_id: &str) -> Result<(String, String), String> {
    let (host_if, peer_if) = iface_names(container_id);
    // Best-effort cleanup of any stale link with the same name.
    let _ = run("ip", &["link", "del", &host_if]);
    run("ip", &[
        "link", "add", &host_if, "type", "veth", "peer", "name", &peer_if,
    ]).map_err(|e| format!("create veth: {e}"))?;
    run("ip", &["link", "set", &host_if, "master", BRIDGE_NAME])
        .map_err(|e| format!("attach to bridge: {e}"))?;
    run("ip", &["link", "set", &host_if, "up"])
        .map_err(|e| format!("host veth up: {e}"))?;
    Ok((host_if, peer_if))
}

/// Step 2 — move the peer interface into the child's network namespace.
pub fn move_peer_into_netns(peer_if: &str, child_pid: i32) -> Result<(), String> {
    run("ip", &["link", "set", peer_if, "netns", &child_pid.to_string()])
        .map_err(|e| format!("move {peer_if} into netns {child_pid}: {e}"))?;
    Ok(())
}

/// Step 3 — run inside the child after it has entered the new netns.
/// Renames the peer to `eth0` so common app config works, brings up
/// `lo`+`eth0`, assigns the IP, installs default route.
pub fn configure_inside(peer_if: &str, addr_dotted: &str) -> Result<(), String> {
    // Sanity: peer should be present in this netns now.
    run("ip", &["link", "set", "lo", "up"])
        .map_err(|e| format!("lo up: {e}"))?;
    // Rename to eth0 (must be DOWN first).
    run("ip", &["link", "set", peer_if, "down"]).ok();
    run("ip", &["link", "set", peer_if, "name", "eth0"])
        .map_err(|e| format!("rename {peer_if}->eth0: {e}"))?;
    let with_mask = format!("{addr_dotted}/{BRIDGE_NETMASK_BITS}");
    run("ip", &["addr", "add", &with_mask, "dev", "eth0"])
        .map_err(|e| format!("assign addr: {e}"))?;
    run("ip", &["link", "set", "eth0", "up"])
        .map_err(|e| format!("eth0 up: {e}"))?;
    run("ip", &["route", "add", "default", "via", BRIDGE_GATEWAY])
        .map_err(|e| format!("default route: {e}"))?;
    Ok(())
}

/// Step 4 — tear down on container removal. Best-effort.
pub fn destroy(host_if: &str) {
    let _ = run("ip", &["link", "del", host_if]);
}
