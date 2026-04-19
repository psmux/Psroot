//! Server Silo — full namespace isolation for Windows.
//!
//! Combines a Job Object (for resource limits + kill-on-close) with
//! an NT namespace (for filesystem root remap, object isolation, etc.)
//! to create a chroot-equivalent container.
//!
//! Requires Administrator privileges and Windows 10 1809+.
//! No VTx, no Hyper-V, no Docker — pure kernel primitives.

mod process;

use psroot_job::JobObject;
use psroot_namespace::SiloNamespace;
use psroot_types::config::ResourceLimits;
use psroot_types::error::Result;
use psroot_types::stats::ContainerStats;
use tracing::{debug, info, instrument};
use windows_sys::Win32::Foundation::HANDLE;

pub use process::ProcessInfo;

// Silo-specific JOBOBJECTINFOCLASS values not in windows-sys
const JOB_OBJECT_CREATE_SILO: u32 = 35;
const JOB_OBJECT_SILO_BASIC_INFO: u32 = 36;
const JOB_OBJECT_SILO_ROOT_DIR: u32 = 37;
const JOB_OBJECT_SERVER_SILO_INIT: u32 = 40;

/// Silo basic information returned by the kernel.
#[repr(C)]
#[derive(Default)]
struct SiloBasicInfo {
    silo_id: u32,
    silo_parent_id: u32,
    number_of_processes: u32,
    is_in_server_silo: u8,
}

/// Silo root directory assignment struct.
#[repr(C)]
struct SiloRootDirectory {
    root_directory: HANDLE,
}

/// A running Server Silo with full namespace isolation.
pub struct Silo {
    job: JobObject,
    silo_id: u32,
    namespace: SiloNamespace,
    container_root: String,
    init_pid: Option<u32>,
}

impl Silo {
    /// Create a fully isolated Server Silo.
    ///
    /// Sequence:
    ///  1. Create Job Object + resource limits + kill-on-close
    ///  2. Convert to Server Silo (JobObjectCreateSilo)
    ///  3. Build NT namespace (directories + symlinks)
    ///  4. Set silo root directory
    ///  5. Initialize silo (marks it ready for processes)
    #[instrument(level = "info", skip(resources), fields(root = %container_root))]
    pub fn create(container_root: &str, resources: Option<&ResourceLimits>) -> Result<Self> {
        // 1. Job Object
        let job = JobObject::new()?;
        job.enable_kill_on_close()?;
        if let Some(limits) = resources {
            job.apply_limits(limits)?;
        }
        debug!("Job Object created with limits");

        // 2. Convert to silo
        job.set_info_null(JOB_OBJECT_CREATE_SILO as i32)?;
        debug!("Job converted to silo");

        // 3. Query silo ID
        let silo_info: SiloBasicInfo = job.query_info(JOB_OBJECT_SILO_BASIC_INFO as i32)?;
        let silo_id = silo_info.silo_id;
        info!(silo_id, "Silo created");

        // 4. Build namespace
        let namespace = SiloNamespace::build(silo_id, container_root)?;

        // 5. Set silo root directory
        let root_dir = SiloRootDirectory {
            root_directory: namespace.root_handle() as HANDLE,
        };
        job.set_info(JOB_OBJECT_SILO_ROOT_DIR as i32, &root_dir)?;
        debug!(silo_id, "Silo root directory set");

        // 6. Initialize
        job.set_info_null(JOB_OBJECT_SERVER_SILO_INIT as i32)?;
        info!(silo_id, "Silo initialized — ready for processes");

        Ok(Self {
            job,
            silo_id,
            namespace,
            container_root: container_root.to_string(),
            init_pid: None,
        })
    }

    /// Kernel-assigned silo ID.
    pub fn silo_id(&self) -> u32 {
        self.silo_id
    }

    /// PID of the first process spawned.
    pub fn init_pid(&self) -> Option<u32> {
        self.init_pid
    }

    /// Container root filesystem path.
    pub fn container_root(&self) -> &str {
        &self.container_root
    }

    /// Access the underlying Job Object.
    pub fn job(&self) -> &JobObject {
        &self.job
    }

    /// Spawn a process inside the silo.
    ///
    /// Creates suspended, assigns to job, resumes.
    pub fn spawn(
        &mut self,
        command_line: &str,
        env: Option<&[(String, String)]>,
        cwd: Option<&str>,
    ) -> Result<ProcessInfo> {
        let info = process::create_in_silo(&self.job, command_line, env, cwd)?;
        if self.init_pid.is_none() {
            self.init_pid = Some(info.pid);
        }
        Ok(info)
    }

    /// Query resource usage.
    pub fn stats(&self) -> Result<ContainerStats> {
        self.job.query_stats()
    }

    /// Terminate all processes in the silo.
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        self.job.terminate(exit_code)
    }
}

impl Drop for Silo {
    fn drop(&mut self) {
        // Terminate all processes first
        let _ = self.job.terminate(0);
        // namespace handles dropped automatically
        // job handle dropped automatically (kill-on-close finishes the rest)
    }
}
