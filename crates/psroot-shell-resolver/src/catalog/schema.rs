//! TOML schema for catalog files (deserialization side).

use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct CatalogFile {
    pub name: String,
    #[serde(default)]
    pub display: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub prefer_global: bool,

    #[serde(default)]
    pub probe: Vec<ProbeRule>,

    #[serde(default)]
    pub stage: Vec<StageRule>,

    #[serde(default)]
    pub ace: Vec<AceRule>,

    pub launch: LaunchRule,

    #[serde(default)]
    pub caps_when_outbound: Vec<String>,
    #[serde(default)]
    pub caps_when_full: Vec<String>,

    #[serde(default)]
    pub version: Option<VersionRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProbeRule {
    /// Read an environment variable. If set and points to an existing file,
    /// use its parent dir as `shell_root`.
    Env { var: String },
    /// Resolve a glob (single concrete path supported in v1) and check exists.
    Path { glob: String },
    /// Look up registry value and treat result as `shell_root`.
    Registry {
        hive: String,
        key: String,
        value: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct StageRule {
    pub op: String, // "ensure_dir" | "hardlink_tree" | "copy_tree" | "junction" | "symlink" | "write_text"
    #[serde(default)]
    pub src: Option<String>,
    pub dst: String,
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Inline text content for `write_text` ops. May also use the special
    /// value `@builtin:<key>` to reference a compile-time embedded resource.
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AceRule {
    pub path: String,
    pub access: String, // "RX"
    #[serde(default)]
    pub inherit: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LaunchRule {
    pub entry: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VersionRule {
    #[serde(default = "default_detect")]
    pub detect: String, // "exe_version" | "none"
    #[serde(default)]
    pub min: Option<String>,
}

fn default_detect() -> String {
    "exe_version".to_string()
}
