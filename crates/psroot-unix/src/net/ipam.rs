//! Tiny IPAM: persists a JSON file of leased IPs under the state dir,
//! hands out the next free /16 address.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::paths;

const FIRST_HOST: u32 = 2;          // 10.88.0.1 = bridge gateway
const LAST_HOST:  u32 = 65_534;     // .65535 = broadcast

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Leases {
    leased: BTreeSet<u32>, // host part only (1..65534)
}

fn lease_file() -> std::io::Result<PathBuf> {
    let root = paths::state_root().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let p = root.join("net");
    std::fs::create_dir_all(&p)?;
    Ok(p.join("leases.json"))
}

fn load() -> Leases {
    if let Ok(path) = lease_file() {
        if let Ok(b) = std::fs::read(&path) {
            return serde_json::from_slice(&b).unwrap_or_default();
        }
    }
    Leases::default()
}

fn save(l: &Leases) -> std::io::Result<()> {
    let path = lease_file()?;
    let bytes = serde_json::to_vec_pretty(l)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

/// Allocate a host address (host portion 2..=65533). Returns the dotted
/// quad ("10.88.x.y").
pub fn alloc() -> Result<String, String> {
    let mut l = load();
    for host in FIRST_HOST..=LAST_HOST - 1 {
        if !l.leased.contains(&host) {
            l.leased.insert(host);
            save(&l).map_err(|e| format!("save lease: {e}"))?;
            return Ok(host_to_dotted(host));
        }
    }
    Err("psroot: IP pool exhausted".into())
}

/// Release a previously-allocated address. Best-effort.
pub fn release(addr: &str) {
    let host = match dotted_to_host(addr) {
        Some(h) => h,
        None => return,
    };
    let mut l = load();
    l.leased.remove(&host);
    let _ = save(&l);
}

fn host_to_dotted(host: u32) -> String {
    // 10.88.<hi>.<lo>
    let hi = (host >> 8) & 0xff;
    let lo = host & 0xff;
    format!("10.88.{hi}.{lo}")
}

fn dotted_to_host(addr: &str) -> Option<u32> {
    let p: Vec<&str> = addr.split('.').collect();
    if p.len() != 4 || p[0] != "10" || p[1] != "88" { return None; }
    let hi: u32 = p[2].parse().ok()?;
    let lo: u32 = p[3].parse().ok()?;
    Some((hi << 8) | lo)
}
