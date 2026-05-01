pub mod schema;

use schema::CatalogFile;
use std::collections::BTreeMap;

use crate::error::{Result, ShellResolverError};

/// Builtin catalog TOML strings, embedded at compile time.
const BUILTIN_PWSH: &str = include_str!("../../catalog/pwsh.toml");
const BUILTIN_CMD: &str = include_str!("../../catalog/cmd.toml");
const BUILTIN_POWERSHELL: &str = include_str!("../../catalog/powershell.toml");

/// Builtin PowerShell modules embedded at compile time.
const BUILTIN_PSROOTNET_PSM1: &str = include_str!("../../catalog/modules/PsrootNet/PsrootNet.psm1");
const BUILTIN_PSROOTNET_PSD1: &str = include_str!("../../catalog/modules/PsrootNet/PsrootNet.psd1");

/// Look up a compile-time embedded module resource by key.
/// Keys: `PsrootNet.psm1`, `PsrootNet.psd1`.
pub fn builtin_module(key: &str) -> Option<&'static str> {
    match key {
        "PsrootNet.psm1" => Some(BUILTIN_PSROOTNET_PSM1),
        "PsrootNet.psd1" => Some(BUILTIN_PSROOTNET_PSD1),
        _ => None,
    }
}

/// Merged catalog: name (lowercased) → entry. Aliases are also indexed.
#[derive(Debug, Clone, Default)]
pub struct Catalog {
    /// Stable list (insertion-ordered for `list_known`).
    entries: Vec<CatalogFile>,
    /// Index: lowercase name OR alias → position in `entries`.
    by_name: BTreeMap<String, usize>,
}

impl Catalog {
    /// Load only the embedded builtin catalogs.
    pub fn builtin() -> Self {
        let mut c = Self::default();
        for (path, src) in [
            ("builtin:cmd", BUILTIN_CMD),
            ("builtin:pwsh", BUILTIN_PWSH),
            ("builtin:powershell", BUILTIN_POWERSHELL),
        ] {
            match toml::from_str::<CatalogFile>(src) {
                Ok(entry) => c.add(entry),
                Err(e) => {
                    tracing::warn!(path, error = %e, "builtin catalog parse failed (skipping)");
                }
            }
        }
        c
    }

    /// Parse a single TOML string as a catalog entry.
    pub fn parse_entry(src: &str, src_label: &str) -> Result<CatalogFile> {
        toml::from_str::<CatalogFile>(src).map_err(|e| ShellResolverError::CatalogParse {
            path: src_label.to_string(),
            source: e,
        })
    }

    /// Merge another catalog on top of this one. Later wins per name.
    pub fn merge_file(&mut self, src: &str, src_label: &str) -> Result<()> {
        let entry = Self::parse_entry(src, src_label)?;
        self.add(entry);
        Ok(())
    }

    /// Walk a directory of `*.toml` user catalog overrides.
    pub fn merge_dir(&mut self, dir: &std::path::Path) {
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|s| s.to_str()) != Some("toml") {
                continue;
            }
            let label = p.display().to_string();
            match std::fs::read_to_string(&p) {
                Ok(src) => {
                    if let Err(e) = self.merge_file(&src, &label) {
                        tracing::warn!(path = %label, error = %e, "user catalog skipped");
                    } else {
                        tracing::info!(path = %label, "user catalog merged");
                    }
                }
                Err(e) => tracing::warn!(path = %label, error = %e, "user catalog read failed"),
            }
        }
    }

    fn add(&mut self, entry: CatalogFile) {
        // Replace by primary name if it already exists.
        let key = entry.name.to_lowercase();
        if let Some(&idx) = self.by_name.get(&key) {
            self.entries[idx] = entry.clone();
        } else {
            self.entries.push(entry.clone());
            let idx = self.entries.len() - 1;
            self.by_name.insert(key, idx);
        }

        // (Re-)index aliases.
        let idx = *self.by_name.get(&entry.name.to_lowercase()).expect("just inserted");
        for a in &entry.aliases {
            self.by_name.insert(a.to_lowercase(), idx);
        }
    }

    pub fn lookup(&self, name: &str) -> Option<&CatalogFile> {
        self.by_name
            .get(&name.to_lowercase())
            .map(|&i| &self.entries[i])
    }

    pub fn list_known(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    pub fn entries(&self) -> impl Iterator<Item = &CatalogFile> {
        self.entries.iter()
    }
}
