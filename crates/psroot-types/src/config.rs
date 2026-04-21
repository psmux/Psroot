use serde::{Deserialize, Serialize};

/// Resource limits for a container (cgroups equivalent via Job Objects).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Job-wide memory limit in bytes. Default: 1 GB.
    #[serde(default = "default_memory")]
    pub memory: u64,
    /// CPU rate as 1–10000 (0.01%–100%). Default: 10000.
    #[serde(default = "default_cpu_rate")]
    pub cpu_rate: u32,
    /// Maximum active processes. Default: 100.
    #[serde(default = "default_max_processes")]
    pub max_processes: u32,
    /// CPU affinity bitmask. 0 = no restriction.
    #[serde(default)]
    pub affinity: u64,
    /// Priority class ceiling. 0 = no restriction.
    #[serde(default)]
    pub priority_class: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory: default_memory(),
            cpu_rate: default_cpu_rate(),
            max_processes: default_max_processes(),
            affinity: 0,
            priority_class: 0,
        }
    }
}

fn default_memory() -> u64 {
    1_073_741_824 // 1 GB
}
fn default_cpu_rate() -> u32 {
    10_000 // 100%
}
fn default_max_processes() -> u32 {
    100
}

/// Volume mount specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    /// Host-side path (backing).
    pub host_path: String,
    /// Container-side path (virtual).
    pub container_path: String,
    /// Mount as read-only.
    #[serde(default)]
    pub read_only: bool,
}

/// Full container configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Optional human-readable name.
    #[serde(default)]
    pub name: Option<String>,
    /// Filesystem root for the container.
    pub rootfs_path: String,
    /// Command + arguments to run.
    #[serde(default = "default_command")]
    pub command: Vec<String>,
    /// Environment variables.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    /// Resource limits.
    #[serde(default)]
    pub resources: ResourceLimits,
    /// Volume mounts.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    /// Hostname visible inside the container.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Working directory inside the container.
    #[serde(default = "default_workdir")]
    pub working_directory: String,
    /// Enable Server Silo namespace isolation (requires admin).
    #[serde(default)]
    pub silo: bool,
    /// Tools to install in the rootfs (e.g., "node", "winget").
    #[serde(default)]
    pub tools: Vec<String>,
    /// Security profile.
    #[serde(default)]
    pub security_profile: SecurityProfile,
    /// Network access level for AppContainer processes.
    #[serde(default)]
    pub network: NetworkAccess,
    /// Published port mappings (Docker `-p` style). Each entry reserves a
    /// random ephemeral loopback port inside the container and exposes it
    /// via a host-side TCP reverse proxy on `host_bind:host_port`.
    #[serde(default)]
    pub ports: Vec<PortMapping>,
}

fn default_command() -> Vec<String> {
    vec!["cmd.exe".into()]
}
fn default_workdir() -> String {
    "C:\\".into()
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    /// Job object only — no silo, no restricted token.
    Minimal,
    /// Silo + kill-on-close + resource limits.
    #[default]
    Default,
    /// Silo + restricted token + read-only rootfs + low integrity.
    Locked,
}

/// Network access level for AppContainer sandboxed processes.
///
/// AppContainer blocks all networking by default. Capabilities must be
/// explicitly granted via well-known SIDs in SECURITY_CAPABILITIES.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAccess {
    /// No network access (maximum isolation). Default.
    #[default]
    None,
    /// Outbound connections only (internetClient capability).
    /// Allows: npm install, pip install, curl, HTTP requests.
    /// Blocks: listening on ports, accepting inbound connections.
    Outbound,
    /// Full network: outbound + inbound + loopback exemption.
    /// Allows: dev servers (vite, webpack-dev-server), API servers.
    /// Host can reach container services on localhost:<port>.
    Full,
}

/// A published port mapping (Docker `-p` style).
///
/// Because Windows has no user-mode network namespaces, psroot cannot give a
/// container its own TCP port space. Instead, each mapping allocates a
/// random ephemeral port on `127.0.0.1` and injects it into the container as
/// `PORT` / `PSROOT_PORT_<container_port>` env vars. A host-side TCP proxy
/// then forwards `host_bind:host_port` to `127.0.0.1:ephemeral_port`.
///
/// End result: two containers can both declare `container_port = 3000` and
/// each gets its own mapped host port — no `EADDRINUSE`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Interface the host-side proxy binds to. Defaults to `127.0.0.1`;
    /// set to `0.0.0.0` to expose on every interface.
    #[serde(default = "default_host_bind")]
    pub host_bind: String,
    /// Port the host-side proxy listens on (what users connect to).
    pub host_port: u16,
    /// Logical container port. Used to name the env var
    /// (`PSROOT_PORT_<container_port>`) and for display purposes.
    pub container_port: u16,
    /// Actual loopback port the container process binds to. Filled in at
    /// runtime when the container starts.
    #[serde(default)]
    pub ephemeral_port: Option<u16>,
    /// Optional human-readable label.
    #[serde(default)]
    pub name: Option<String>,
}

fn default_host_bind() -> String {
    "127.0.0.1".into()
}
