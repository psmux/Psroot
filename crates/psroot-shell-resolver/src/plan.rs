//! Concrete launch plan produced by the resolver — consumed by the stager
//! and by `sandbox::spawn_interactive`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Capability SIDs that the AppContainer may request. Catalogs may only
/// declare known caps — anything else is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KnownCapability {
    InternetClient,
    InternetClientServer,
    PrivateNetworkClientServer,
}

impl KnownCapability {
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "internetClient" => Some(Self::InternetClient),
            "internetClientServer" => Some(Self::InternetClientServer),
            "privateNetworkClientServer" => Some(Self::PrivateNetworkClientServer),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMask {
    /// Read + Execute (the only mask we ever grant)
    ReadExecute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AceGrant {
    pub path: PathBuf,
    pub access: AccessMask,
    pub inherit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StageOp {
    EnsureDir { dst: PathBuf },
    HardlinkTree { src: PathBuf, dst: PathBuf, exclude: Vec<String> },
    CopyTree { src: PathBuf, dst: PathBuf, exclude: Vec<String> },
    /// NTFS directory junction — works without admin or Dev Mode.
    Junction { src: PathBuf, dst: PathBuf },
    /// NTFS symlink — needs SeCreateSymbolicLinkPrivilege OR Developer Mode.
    Symlink { src: PathBuf, dst: PathBuf },
    /// Write embedded text content to a file in the rootfs.
    WriteText { dst: PathBuf, content: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchPlan {
    /// Catalog entry name (e.g. "pwsh").
    pub shell_name: String,
    /// Host install version that probe found (e.g. "7.6.0").
    pub host_source_version: String,
    /// Per-cache directory key (used by stager).
    pub cache_key: String,
    /// Absolute path to the cache directory for this stage.
    pub cache_dir: PathBuf,

    /// Path the AppContainer process will execute (already inside rootfs).
    pub entry: PathBuf,
    /// Initial args (catalog + user appended).
    pub args: Vec<String>,
    /// Working directory inside rootfs.
    pub cwd: PathBuf,

    /// Env overrides applied AFTER apply_sandbox_env.
    /// Special keys consumed by the sandbox layer (and stripped before child sees them):
    ///   PATH_PREPEND   — prepended to PATH (semicolon-joined)
    ///   PATHEXT_APPEND — appended to PATHEXT
    pub env: Vec<(String, String)>,

    /// What the stager must do before spawn.
    pub stage: Vec<StageOp>,
    /// ACEs the stager must add (and `Container::remove` must revoke).
    pub aces: Vec<AceGrant>,
    /// Capability SIDs to attach.
    pub caps: Vec<KnownCapability>,
}
