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
    /// ACEs the rootfs-stager added on behalf of this container — must be
    /// revoked on `remove`. Empty for legacy containers.
    #[serde(default)]
    ace_grants_applied: Vec<psroot_rootfs_stager::AceGrantRecord>,
    /// Cache directories whose refcount this container increments — must
    /// be decremented on `remove`.
    #[serde(default)]
    cache_refs: Vec<String>,
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
    #[cfg(windows)]
    netstack: Option<crate::netstack_runtime::NetstackRuntime>,
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
        if config.tools.is_empty() && config.shares.is_empty() {
            rootfs::prepare_rootfs(&config.rootfs_path)?;
        } else {
            let tools_refs: Vec<&str> = config.tools.iter().map(|s| s.as_str()).collect();
            let share_refs: Vec<&str> = config.shares.iter().map(|s| s.as_str()).collect();
            rootfs::prepare_rootfs_with_tools_and_shares(
                &config.rootfs_path,
                &tools_refs,
                &share_refs,
            )?;
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
            ace_grants_applied: Vec::new(),
            cache_refs: Vec::new(),
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
                bind_filter: None,                port_mapper: None,
                #[cfg(windows)]
                netstack: None,
            },
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
                &[],
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

            // Inject process-visibility shim into silo's init process.
            #[cfg(windows)]
            self.try_inject_procshim(info.pid);

            info!(id = %self.id, pid = info.pid, silo_id = silo.silo_id(), "Container started (silo mode)");
            self.runtime.silo = Some(silo);
        } else {
            // ── Job Object only mode ──
            let job = JobObject::new()?;
            job.enable_kill_on_close()?;
            job.apply_limits(&self.config.resources)?;

            let bf = self.setup_bind_links(&caps)?;
            self.runtime.bind_filter = bf;

            // ── Optional: spin up the userland netstack BEFORE spawn
            //    so the child process inherits PSROOT_NS_* env vars
            //    and `DllMain` can attach to our SHM immediately after
            //    `LoadLibraryW`. Failure here is non-fatal: we fall
            //    through to OS networking governed by the AppContainer
            //    caps configured in `build_network_capabilities`.
            #[cfg(windows)]
            let netstack = self.try_start_netstack();
            #[cfg(windows)]
            if let Some(ns) = netstack.as_ref() {
                for (k, v) in ns.child_env() {
                    self.config.env.insert(k.to_string(), v);
                }
            }

            // Spawn sandboxed process (restricted token, low integrity, explicit env)
            let cmd = self.config.command.join(" ");
            let pid = crate::sandbox::spawn_sandboxed(&cmd, &self.config, &job)?;

            #[cfg(windows)]
            if let Some(ns) = netstack {
                // Inject the shim DLL into the just-spawned child.
                // `spawn_sandboxed` returned only the pid — re-open
                // the process with the rights LoadLibraryW injection
                // needs. Injection is best-effort: on failure the
                // container still runs, it just uses OS networking.
                self.try_inject_netstack(pid, ns);
            }

            // Inject the process-visibility shim to hide host processes.
            #[cfg(windows)]
            self.try_inject_procshim(pid);

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

    /// Plan-aware interactive shell: stages the host shell + grants ACEs +
    /// spawns. Persists the applied ACEs and cache refcount to `state.json`
    /// so `remove` can revoke them.
    ///
    /// When `use_silo` is true, uses Server Silo for full filesystem isolation
    /// (process only sees rootfs as C:\). Falls back to AppContainer if silo
    /// creation fails.
    pub fn shell_with_plan(
        &self,
        plan: &psroot_shell_resolver::LaunchPlan,
        use_silo: bool,
    ) -> Result<u32> {
        let (_sid, exit_code) = if use_silo {
            crate::sandbox::spawn_interactive_plan_silo(plan, &self.config)?
        } else {
            crate::sandbox::spawn_interactive_plan(plan, &self.config)?
        };

        // Persist ACE records + cache ref into state.json.
        let state_path = self.dir.join("state.json");
        if let Ok(content) = fs::read_to_string(&state_path) {
            if let Ok(mut sf) = serde_json::from_str::<StateFile>(&content) {
                // We don't have the AceGrantRecord list here (stager applied
                // them), so re-derive from the plan + the SID we just got.
                for ace in &plan.aces {
                    let access = match ace.access {
                        psroot_shell_resolver::AccessMask::ReadExecute => "RX".to_string(),
                    };
                    sf.ace_grants_applied.push(psroot_rootfs_stager::AceGrantRecord {
                        path: ace.path.display().to_string(),
                        sid: _sid.clone(),
                        mask: access,
                        inherit: ace.inherit,
                    });
                }
                let cache_dir = plan.cache_dir.display().to_string();
                if !sf.cache_refs.contains(&cache_dir) {
                    sf.cache_refs.push(cache_dir);
                }
                let _ = fs::write(&state_path, serde_json::to_string_pretty(&sf)?);
            }
        }

        Ok(exit_code)
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
        #[cfg(windows)]
        if let Some(ns) = self.runtime.netstack.take() {
            // Drop shuts the daemon thread down via the stop flag.
            drop(ns);
        }

        self.state = ContainerState::Stopped;
        self.write_state()?;
        info!(id = %self.id, "Container stopped");
        Ok(())
    }

    // ─────────────────────── netstack wiring (Phase 3) ──────────────────

    #[cfg(windows)]
    fn try_start_netstack(&self) -> Option<crate::netstack_runtime::NetstackRuntime> {
        use crate::netstack_runtime::{
            default_dll_path, loopback_translator, virtual_ip_for, NetstackRuntime,
        };

        if self.config.network != NetworkAccess::Netstack {
            return None;
        }
        let dll = match default_dll_path() {
            Some(p) => p,
            None => {
                tracing::warn!(
                    id = %self.id,
                    "network=netstack requested but psroot_netshim.dll not found next to the psroot binary; falling back to OS networking"
                );
                return None;
            }
        };
        let virt = virtual_ip_for(&self.id);
        match NetstackRuntime::spawn(&self.id, dll, virt, Some(loopback_translator(virt))) {
            Ok(ns) => {
                info!(id = %self.id, virt = %virt, "Netstack daemon started");
                Some(ns)
            }
            Err(e) => {
                tracing::warn!(id = %self.id, error = %e, "Netstack daemon failed to start");
                None
            }
        }
    }

    #[cfg(windows)]
    fn try_inject_netstack(
        &mut self,
        pid: u32,
        ns: crate::netstack_runtime::NetstackRuntime,
    ) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        let rights = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE;
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        if handle.is_null() {
            tracing::warn!(
                id = %self.id,
                pid,
                "OpenProcess failed for netstack injection; keeping daemon alive (child may not have network)"
            );
            self.runtime.netstack = Some(ns);
            return;
        }
        // SAFETY: `handle` was just opened with the rights
        // `inject_dll` requires; we close it in all paths below.
        let result = unsafe { ns.inject_into(handle) };
        unsafe {
            CloseHandle(handle);
        }
        match result {
            Ok(()) => {
                info!(id = %self.id, pid, "Netstack shim DLL injected");
                self.runtime.netstack = Some(ns);
            }
            Err(e) => {
                tracing::warn!(
                    id = %self.id,
                    pid,
                    error = %e,
                    "Netstack DLL injection failed; dropping daemon"
                );
                // Dropping `ns` here shuts the daemon down cleanly.
            }
        }
    }

    // ──────────────── process-visibility shim injection ─────────────────

    #[cfg(windows)]
    fn try_inject_procshim(&mut self, pid: u32) {
        use crate::procshim_runtime::{default_procshim_path, inject_procshim, stage_into_rootfs};
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
            PROCESS_VM_READ, PROCESS_VM_WRITE,
        };

        let source_dll = match default_procshim_path() {
            Some(p) => p,
            None => {
                tracing::debug!(
                    id = %self.id,
                    "psroot_procshim.dll not found; host processes will be visible inside container"
                );
                return;
            }
        };

        // Stage the DLL into the rootfs so the AppContainer process can
        // actually load it (AppContainer can only read ACL'd paths).
        let inject_path = match stage_into_rootfs(&source_dll, &self.config.rootfs_path) {
            Some(p) => p,
            None => {
                // Fall back to the original path (works for non-AppContainer / silo mode)
                source_dll.clone()
            }
        };

        let rights = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE;
        let handle = unsafe { OpenProcess(rights, 0, pid) };
        if handle.is_null() {
            tracing::warn!(
                id = %self.id,
                pid,
                "OpenProcess failed for procshim injection"
            );
            return;
        }
        let result = unsafe { inject_procshim(handle, &inject_path) };
        unsafe { CloseHandle(handle); }
        match result {
            Ok(()) => {
                info!(id = %self.id, pid, "Process-visibility shim injected — host processes hidden");
            }
            Err(e) => {
                tracing::warn!(
                    id = %self.id,
                    pid,
                    error = ?e,
                    "Procshim DLL injection failed; host processes will remain visible"
                );
            }
        }
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

        // Revoke ACEs the stager added (and decrement cache refcounts).
        let state_path = self.dir.join("state.json");
        if let Ok(content) = fs::read_to_string(&state_path) {
            if let Ok(sf) = serde_json::from_str::<StateFile>(&content) {
                for rec in &sf.ace_grants_applied {
                    let _ = psroot_rootfs_stager::revoke_ace_record(rec);
                }
                for cache_dir in &sf.cache_refs {
                    let _ = psroot_rootfs_stager::unreference_cache(
                        std::path::Path::new(cache_dir),
                        &self.id,
                    );
                }
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
                #[cfg(windows)]
                netstack: None,
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
        // Preserve ace_grants_applied + cache_refs from existing state.json (if any).
        let (existing_aces, existing_refs) = {
            let p = self.dir.join("state.json");
            match fs::read_to_string(&p) {
                Ok(s) => match serde_json::from_str::<StateFile>(&s) {
                    Ok(sf) => (sf.ace_grants_applied, sf.cache_refs),
                    Err(_) => (Vec::new(), Vec::new()),
                },
                Err(_) => (Vec::new(), Vec::new()),
            }
        };
        let sf = StateFile {
            status: self.state,
            created: self.created.clone(),
            pid: self.runtime.silo.as_ref().and_then(|s| s.init_pid()),
            silo_id: self.runtime.silo.as_ref().map(|s| s.silo_id()),
            ports: self.config.ports.clone(),
            ace_grants_applied: existing_aces,
            cache_refs: existing_refs,
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
