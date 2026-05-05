use std::path::PathBuf;
use crate::Result;

pub fn state_root() -> Result<PathBuf> {
    let dir = if cfg!(target_os = "macos") {
        dirs::home_dir().map(|h| h.join("Library/Application Support/psroot"))
    } else {
        dirs::data_dir().map(|d| d.join("psroot"))
    }
    .ok_or_else(|| crate::Error::Other("cannot determine state dir".into()))?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn container_dir(id: &str) -> Result<PathBuf> {
    Ok(state_root()?.join(id))
}
