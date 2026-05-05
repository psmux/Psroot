//! Per-port DNAT rules for `-p host:container` publishing.
//!
//! When a container has a real bridged IP we install kernel DNAT rules so
//! `host_bind:host_port` -> `<container_ip>:container_port`. We tag every
//! rule with a comment containing the container ID so cleanup is exact.

use super::run;

/// Install a DNAT rule. Tags the rule with the container ID for later
/// targeted cleanup.
pub fn install(
    container_id: &str,
    host_bind: &str,
    host_port: u16,
    container_ip: &str,
    container_port: u16,
) -> Result<(), String> {
    let comment = format!("psroot:{container_id}");
    let dest = format!("{container_ip}:{container_port}");
    let host_port_s = host_port.to_string();

    // Build PREROUTING rule (external traffic) and OUTPUT rule (host->container
    // via the published port; matches Docker behavior so `curl host_bind:host_port`
    // from the host itself also works).
    let bind_arg = if host_bind == "0.0.0.0" || host_bind.is_empty() {
        vec![]
    } else {
        vec!["-d".to_string(), host_bind.to_string()]
    };

    for chain in ["PREROUTING", "OUTPUT"] {
        let mut args: Vec<String> = vec![
            "-t".into(), "nat".into(), "-A".into(), chain.into(),
            "-p".into(), "tcp".into(),
        ];
        args.extend(bind_arg.iter().cloned());
        args.extend([
            "--dport".into(), host_port_s.clone(),
            "-m".into(), "comment".into(), "--comment".into(), comment.clone(),
            "-j".into(), "DNAT".into(), "--to-destination".into(), dest.clone(),
        ]);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        run("iptables", &refs)
            .map_err(|e| format!("DNAT install ({chain}): {e}"))?;
    }
    Ok(())
}

/// Remove every iptables rule tagged with this container ID across the
/// nat table. Best-effort; missing rules are silently ignored.
pub fn cleanup(container_id: &str) {
    let comment = format!("psroot:{container_id}");
    // List, find matching lines, delete by spec. iptables-save gives us the
    // exact rule spec we can pass back to `iptables -D`.
    let dump = match run("iptables-save", &["-t", "nat"]) {
        Ok(s) => s,
        Err(_) => return,
    };
    for line in dump.lines() {
        if !line.contains(&comment) || !line.starts_with("-A ") {
            continue;
        }
        // Convert "-A CHAIN ..." into ["-t","nat","-D","CHAIN", ...].
        let rest = &line[3..]; // drop "-A "
        let mut parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.is_empty() { continue; }
        let chain = parts.remove(0);
        let mut args: Vec<&str> = vec!["-t", "nat", "-D", chain];
        args.extend(parts);
        let _ = run("iptables", &args);
    }
}
