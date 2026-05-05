use serde::{Deserialize, Serialize};
use psroot_types::config::ContainerConfig;
use psroot_types::state::ContainerState;
use std::path::PathBuf;
use crate::{paths, Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerRecord {
    pub id: String,
    pub name: Option<String>,
    pub config: ContainerConfig,
    pub state: ContainerState,
    pub created_at: String,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub exit_code: Option<i32>,
    pub host_pid: Option<i32>,
    pub container_ip: Option<String>,
    pub isolation: String,
    pub dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: Option<String>,
    pub state: ContainerState,
    pub command: Vec<String>,
    pub created_at: String,
    pub container_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeState {
    pub host_pid: Option<i32>,
    pub container_ip: Option<String>,
}

fn record_path(id: &str) -> Result<PathBuf> {
    Ok(paths::container_dir(id)?.join("container.json"))
}

pub fn save(rec: &ContainerRecord) -> Result<()> {
    let path = record_path(&rec.id)?;
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    let json = serde_json::to_string_pretty(rec)?;
    std::fs::write(&path, json)?;
    Ok(())
}

pub fn load(id_or_name: &str) -> Result<ContainerRecord> {
    // Try id directly.
    let direct = record_path(id_or_name).ok().filter(|p| p.exists());
    if let Some(p) = direct {
        let s = std::fs::read_to_string(&p)?;
        return Ok(serde_json::from_str(&s)?);
    }
    // Else search by name/short-id.
    for info in list()? {
        let matches_name = info.name.as_deref() == Some(id_or_name);
        let matches_short = info.id.starts_with(id_or_name);
        if matches_name || matches_short {
            let p = record_path(&info.id)?;
            let s = std::fs::read_to_string(&p)?;
            return Ok(serde_json::from_str(&s)?);
        }
    }
    Err(Error::NotFound(id_or_name.to_string()))
}

pub fn list() -> Result<Vec<ContainerInfo>> {
    let root = paths::state_root()?;
    let mut out = Vec::new();
    if !root.exists() { return Ok(out); }
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let p = entry.path().join("container.json");
        if !p.exists() { continue; }
        let s = std::fs::read_to_string(&p)?;
        if let Ok(rec) = serde_json::from_str::<ContainerRecord>(&s) {
            out.push(ContainerInfo {
                id: rec.id,
                name: rec.name,
                state: rec.state,
                command: rec.config.command,
                created_at: rec.created_at,
                container_ip: rec.container_ip,
            });
        }
    }
    Ok(out)
}
