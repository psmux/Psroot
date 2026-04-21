//! Container — full lifecycle orchestration.
//!
//! create → start → exec → stop → remove

use crate::detect::Capabilities;
use crate::rootfs;
use psroot_bindlink::{BindFilter, BindLinkOptions};
use psroot_job::JobObject;
use psroot_portmap::PortMapper;
use psroot_silo::Silo;
use psroot_types::config::{ContainerConfig, NetworkAccess, PortMapping};
use psroot_types::error::{PsrootError, Result};
use psroot_types::state::ContainerState;
use psroot_types::stats::ContainerStats;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use tracing::info;
use uuid::Uuid;

/// Persisted container state.
#[derive(Serialize, Deserialize)]
struct StateFile {
    status: ContainerState,
    created: String,
    pid: Option<u32>,
    silo_id: Option<u32>,
    #[serde(default)]
    ports: Vec<PortMapping>,
}

/// The data root for all Psroot containers.
fn psroot_root() -> PathBuf {
    std::env::var("PSROOT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\PsrootData".into());
            PathBuf::from(local).join("Psroot")
        })
}

/// Runtime state of a container (not persisted).
struct Runtime {
    job: Option<JobObject>,
    silo: Option<Silo>,
    bind_filter: Option<BindFilter>,
    port_mapper: Option<PortMapper>,
}

/// A Psroot container.
pub struct Container {
    pub id: String,
    pub dir: PathBuf,
    config: ContainerConfig,
    state: ContainerState,
    created: String,
    runtime: Runtime,
}

impl Container {
    // ────────────────────────────── create ──────────────────────────────

    /// Create a new container. Prepares rootfs and writes config to disk.
    pub fn create(mut config: ContainerConfig) -> Result<Self> {
        let id = format!("psroot-{}", &Uuid::new_v4().to_string()[..8]);
        let dir = psroot_root().join("containers").join(&id);
        fs::create_dir_all(&dir)?;

        // Default rootfs location
        if config.rootfs_path.is_empty() {
            config.rootfs_path = dir.join("rootfs").to_string_lossy().to_string();
        }

        // Prepare rootfs with essential binaries and optional tools
        if config.tools.is_empty() {
            rootfs::prepare_rootfs(&config.rootfs_path)?;
        } else {
            let tools_refs: Vec<&str> = config.tools.iter().map(|s| s.as_str()).collect();
            rootfs::prepare_rootfs_with_tools(&config.rootfs_path, &tools_refs)?;
        }

        // Write config
        let config_json = serde_json::to_string_pretty(&config)?;
        fs::write(dir.join("config.json"), &config_json)?;

        let created = chrono_now();
        let state_file = StateFile {
            status: ContainerState::Created,
            created: created.clone(),
            pid: None,
            silo_id: None,
            ports: config.ports.clone(),
        };
        fs::write(dir.join("state.json"), serde_json::to_string_pretty(&state_file)?)?;

        info!(id = %id, rootfs = %config.rootfs_path, "Container created");

        Ok(Self {
            id,
            dir,
            config,
            state: ContainerState::Created,
            created,
            runtime: Runtime {
                job: None,
                silo: None,
                bind_filter: None,                port_mapper: None,            },
        })
    }

    // ────────────────────────────── start ───────────────────────────────

    /// Start the container — create isolation layers and launch init process.
    pub fn start(&mut self) -> Result<()> {
        if self.state != ContainerState::Created {
            return Err(PsrootError::InvalidState {
                id: self.id.clone(),
                current: self.state.to_string(),
                expected: "created".into(),
            });
        }

        let caps = Capabilities::detect();

        // ── Port mappings: allocate ephemeral ports + start host proxies ──
        //
        // We do this BEFORE spawning the container process so the injected
        // `PORT` / `PSROOT_PORT_*` env vars reflect the real ephemeral ports.
        // Proxies are started first too, so the accept loops are ready by
        // the time the container's server issues its `listen()`.
        if !self.config.ports.is_empty() {
            if self.config.network != NetworkAccess::Full {
                tracing::warn!(
                    id = %self.id,
                    "Port mappings require --network full; publishing will not work with current network mode"
                );
            }
            for m in self.config.ports.iter_mut() {
                if m.ephemeral_port.is_none() {
                    let eph = PortMapper::allocate_ephemeral().map_err(|e| {
                        PsrootError::Other(format!("allocate ephemeral port: {}", e))
                    })?;
                    m.ephemeral_port = Some(eph);
                }
            }

            let mapper = PortMapper::new();
            for m in &self.config.ports {
                mapper.add(m.clone()).map_err(|e| {
                    PsrootError::Other(format!(
                        "publish {}:{} -> {}: {}",
                        m.host_bind, m.host_port, m.container_port, e
                    ))
                })?;
            }
            self.runtime.port_mapper = Some(mapper);

            // Inject PORT / PSROOT_PORT_<container_port> env vars.
            for (k, v) in psroot_portmap::env_for_mappings(&self.config.ports) {
                self.config.env.insert(k, v);
            }
        }

        if self.config.silo && caps.server_silos {
            // ── Full silo mode ──
            let mut silo = Silo::create(
                &self.config.rootfs_path,
                Some(&self.config.resources),
            )?;

            // Bind links for volumes (with rollback on failure)
            let bf = match self.setup_bind_links(&caps) {
                Ok(bf) => bf,
                Err(e) => {
                    let _ = silo.terminate(1);
                    drop(silo);
                    return Err(e);
                }
            };
            self.runtime.bind_filter = bf;

            // Spawn init process
            let env: Vec<(String, String)> = self.config.env.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let cmd = self.config.command.join(" ");
            let info = silo.spawn(
                &cmd,
                if env.is_empty() { None } else { Some(&env) },
                Some(&self.config.working_directory),
            )?;

            info!(id = %self.id, pid = info.pid, silo_id = silo.silo_id(), "Container started (silo mode)");
            self.runtime.silo = Some(silo);
        } else {
            // ── Job Object only mode ──
            let job = JobObject::new()?;
            job.enable_kill_on_close()?;
            job.apply_limits(&self.config.resources)?;

            let bf = self.setup_bind_links(&caps)?;
            self.runtime.bind_filter = bf;

            // Spawn sandboxed process (restricted token, low integrity, explicit env)
            let cmd = self.config.command.join(" ");
            let pid = crate::sandbox::spawn_sandboxed(&cmd, &self.config, &job)?;

            info!(id = %self.id, pid, "Container started (job mode)");
            self.runtime.job = Some(job);
        }

        self.state = ContainerState::Running;
        self.write_state()?;
        Ok(())
    }

    // ────────────────────────────── exec ────────────────────────────────

    /// Execute an additional process inside the running container.
    pub fn exec(&mut self, command_line: &str) -> Result<u32> {
        if self.state != ContainerState::Running {
            return Err(PsrootError::InvalidState {
                id: self.id.clone(),
                current: self.state.to_string(),
                expected: "running".into(),
            });
        }

        if let Some(ref mut silo) = self.runtime.silo {
            let env: Vec<(String, String)> = self.config.env.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let info = silo.spawn(
                command_line,
                if env.is_empty() { None } else { Some(&env) },
                Some(&self.config.working_directory),
            )?;
            Ok(info.pid)
        } else if let Some(ref job) = self.runtime.job {
            crate::sandbox::spawn_sandboxed(command_line, &self.config, job)
        } else {
            Err(PsrootError::Other("No runtime available".into()))
        }
    }

    // ────────────────────────────── shell (interactive) ─────────────────

    /// Launch an interactive shell inside the container's AppContainer sandbox.
    ///
    /// This blocks until the user exits the shell. The shell inherits the
    /// caller's console (stdin/stdout/stderr) so the user can type directly.
    /// Returns the shell's exit code.
    pub fn shell(&self, cmd: &str) -> Result<u32> {
        crate::sandbox::spawn_interactive(cmd, &self.config)
    }

    // ────────────────────────────── stats ───────────────────────────────

    pub fn stats(&self) -> Result<ContainerStats> {
        if self.state != ContainerState::Running {
            return Err(PsrootError::InvalidState {
                id: self.id.clone(),
                current: self.state.to_string(),
                expected: "running".into(),
            });
        }

        if let Some(ref silo) = self.runtime.silo {
            silo.stats()
        } else if let Some(ref job) = self.runtime.job {
            job.query_stats()
        } else {
            Err(PsrootError::Other("No runtime".into()))
        }
    }

    // ────────────────────────────── stop ────────────────────────────────

    pub fn stop(&mut self) -> Result<()> {
        if self.state != ContainerState::Running {
            return Ok(());
        }

        if let Some(silo) = self.runtime.silo.take() {
            drop(silo); // Silo::drop terminates + closes
        }
        if let Some(job) = self.runtime.job.take() {
            let _ = job.terminate(0);
            drop(job);
        }
        if let Some(mut bf) = self.runtime.bind_filter.take() {
            bf.remove_all();
        }
        if let Some(mapper) = self.runtime.port_mapper.take() {
            mapper.shutdown();
            drop(mapper);
        }

        self.state = ContainerState::Stopped;
        self.write_state()?;
        info!(id = %self.id, "Container stopped");
        Ok(())
    }

    // ────────────────────────────── remove ──────────────────────────────

    pub fn remove(mut self, force: bool) -> Result<()> {
        if self.state == ContainerState::Running {
            if force {
                self.stop()?;
            } else {
                return Err(PsrootError::InvalidState {
                    id: self.id.clone(),
                    current: "running".into(),
                    expected: "stopped or created".into(),
                });
            }
        }

        if self.dir.exists() {
            // Retry removal — processes may still be releasing file handles
            for attempt in 0..3 {
                match fs::remove_dir_all(&self.dir) {
                    Ok(_) => break,
                    Err(e) if attempt < 2 => {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        tracing::debug!(id = %self.id, attempt, error = %e, "Retrying removal");
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        info!(id = %self.id, "Container removed");
        Ok(())
    }

    // ────────────────────────────── load ────────────────────────────────

    /// Load a container from disk.
    pub fn load(id: &str) -> Result<Self> {
        let dir = psroot_root().join("containers").join(id);
        if !dir.exists() {
            return Err(PsrootError::NotFound { id: id.to_string() });
        }

        let config: ContainerConfig =
            serde_json::from_str(&fs::read_to_string(dir.join("config.json"))?)?;
        let state_file: StateFile =
            serde_json::from_str(&fs::read_to_string(dir.join("state.json"))?)?;

        // Running containers can't be resumed — mark as stopped
        let state = if state_file.status == ContainerState::Running {
            ContainerState::Stopped
        } else {
            state_file.status
        };

        Ok(Self {
            id: id.to_string(),
            dir,
            config,
            state,
            created: state_file.created,
            runtime: Runtime {
                job: None,
                silo: None,
                bind_filter: None,
                port_mapper: None,
            },
        })
    }

    /// List all containers.
    pub fn list() -> Result<Vec<(String, ContainerState, String)>> {
        let containers_dir = psroot_root().join("containers");
        if !containers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        for entry in fs::read_dir(&containers_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            let state_path = entry.path().join("state.json");
            if let Ok(content) = fs::read_to_string(&state_path) {
                if let Ok(state) = serde_json::from_str::<StateFile>(&content) {
                    result.push((id, state.status, state.created));
                }
            }
        }
        Ok(result)
    }

    /// List all containers with their persisted port mappings (for `ls`).
    pub fn list_with_ports() -> Result<Vec<(String, ContainerState, String, Vec<PortMapping>)>> {
        let containers_dir = psroot_root().join("containers");
        if !containers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        for entry in fs::read_dir(&containers_dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            let state_path = entry.path().join("state.json");
            if let Ok(content) = fs::read_to_string(&state_path) {
                if let Ok(state) = serde_json::from_str::<StateFile>(&content) {
                    result.push((id, state.status, state.created, state.ports));
                }
            }
        }
        Ok(result)
    }

    // Accessors
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn state(&self) -> ContainerState {
        self.state
    }
    pub fn config(&self) -> &ContainerConfig {
        &self.config
    }

    // ────────────────────────────── internal ────────────────────────────

    fn setup_bind_links(&self, caps: &Capabilities) -> Result<Option<BindFilter>> {
        if self.config.volumes.is_empty() {
            return Ok(None);
        }
        if !caps.bind_filter {
            tracing::warn!(
                id = %self.id,
                volumes = self.config.volumes.len(),
                "Bind filter unavailable — volume mounts will be skipped (need admin + build >= 26100)"
            );
            return Ok(None);
        }

        let mut bf = BindFilter::new();
        for vol in &self.config.volumes {
            bf.create(&vol.container_path, &vol.host_path, &BindLinkOptions {
                read_only: vol.read_only,
                ..Default::default()
            })?;
        }
        Ok(Some(bf))
    }

    fn write_state(&self) -> Result<()> {
        let sf = StateFile {
            status: self.state,
            created: self.created.clone(),
            pid: self.runtime.silo.as_ref().and_then(|s| s.init_pid()),
            silo_id: self.runtime.silo.as_ref().map(|s| s.silo_id()),
            ports: self.config.ports.clone(),
        };
        fs::write(
            self.dir.join("state.json"),
            serde_json::to_string_pretty(&sf)?,
        )?;
        Ok(())
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // Best-effort cleanup
        if self.state == ContainerState::Running {
            let _ = self.stop();
        }
    }
}

/// Spawn a process and assign to job (for non-silo mode).
fn spawn_and_assign(job: &JobObject, cmd: &str, config: &ContainerConfig) -> Result<u32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::*;

    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

    let cwd_wide: Vec<u16> = config
        .working_directory
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let flags = 0x00000004u32 | 0x08000000u32; // CREATE_SUSPENDED | CREATE_NO_WINDOW

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            std::ptr::null(),
            cwd_wide.as_ptr(),
            &si,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(PsrootError::last_win32("CreateProcessW"));
    }

    let result = job.assign_handle(pi.hProcess);
    if let Err(e) = result {
        unsafe {
            windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        return Err(e);
    }

    unsafe {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Ok(pi.dwProcessId)
}

fn chrono_now() -> String {
    // Simple ISO 8601 without chrono dependency
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("{}", now) // epoch seconds — simple but sufficient
}
