#![cfg(windows)]
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
use psroot_types::error::{PsrootError, Result};
use psroot_types::stats::ContainerStats;
use tracing::{debug, info, instrument, warn};
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub use process::ProcessInfo;

// Silo-specific JOBOBJECTINFOCLASS values not in windows-sys
const JOB_OBJECT_CREATE_SILO: u32 = 35;
const JOB_OBJECT_SILO_BASIC_INFO: u32 = 36;
const JOB_OBJECT_SILO_ROOT_DIR: u32 = 37;
const JOB_OBJECT_SILO_SYSTEM_ROOT: u32 = 38;
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

/// Silo root directory shapes — kernel layout varies between Windows builds.
/// We try multiple at runtime in `Silo::create`.
#[allow(dead_code)]
const SILOOBJECT_ROOT_DIRECTORY_INITIALIZE: u32 = 0x1;
#[allow(dead_code)]
const SILOOBJECT_ROOT_DIRECTORY_SHADOW_GLOBAL: u32 = 0x2;

/// Build a 24-byte SILOOBJECT_ROOT_DIRECTORY: ControlFlags + UNICODE_STRING.
fn build_silo_root(flags: u32, byte_len: u16, max_byte_len: u16, buf: *const u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    out.extend_from_slice(&flags.to_ne_bytes());          // ControlFlags
    out.extend_from_slice(&0u32.to_ne_bytes());           // padding to align UNICODE_STRING
    out.extend_from_slice(&byte_len.to_ne_bytes());       // Length
    out.extend_from_slice(&max_byte_len.to_ne_bytes());   // MaximumLength
    out.extend_from_slice(&0u32.to_ne_bytes());           // padding before pointer
    out.extend_from_slice(&(buf as usize).to_ne_bytes()); // Buffer (PWSTR)
    debug_assert_eq!(out.len(), 24);
    out
}

/// Build a 16-byte bare UNICODE_STRING (legacy Win10 silo shape).
fn build_unicode_string(byte_len: u16, max_byte_len: u16, buf: *const u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&byte_len.to_ne_bytes());
    out.extend_from_slice(&max_byte_len.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&(buf as usize).to_ne_bytes());
    debug_assert_eq!(out.len(), 16);
    out
}

/// Build an 8-byte raw HANDLE buffer.
fn build_handle(h: isize) -> Vec<u8> {
    h.to_ne_bytes().to_vec()
}

/// Build a 16-byte { HANDLE; u64 padding } buffer.
fn build_handle_padded(h: isize) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&h.to_ne_bytes());
    out.extend_from_slice(&0u64.to_ne_bytes());
    out
}

/// Build a 16-byte { u32 flags; HANDLE } buffer.
fn build_flags_handle(flags: u32, h: isize) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&h.to_ne_bytes());
    out
}

/// Build a 16-byte { PWSTR buffer; ULONG flags; pad } buffer.
fn build_pwstr_flags(buf: *const u16, flags: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&(buf as usize).to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out
}

/// Build a 16-byte { ULONG flags; pad; PWSTR buffer } buffer.
fn build_flags_pwstr(flags: u32, buf: *const u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&(buf as usize).to_ne_bytes());
    out
}

/// Try multiple shapes for ServerSiloInit (class 40).
/// SERVERSILO_INIT_INFORMATION is documented as { HANDLE DeleteEvent; BOOLEAN IsDownlevelContainer; }
/// — 16 bytes on x64 with padding.
fn try_server_silo_init(job: &JobObject, silo_id: u32) -> Result<()> {
    use windows_sys::Win32::System::JobObjects::SetInformationJobObject;
    // Buffer shapes to try: (size, bytes)
    let shapes: Vec<(usize, Vec<u8>)> = vec![
        // 16-byte SERVERSILO_INIT_INFORMATION { HANDLE=0, BOOLEAN=0, pad }
        (16, {
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&0isize.to_ne_bytes()); // DeleteEvent
            v.extend_from_slice(&[0u8; 8]);              // BOOLEAN + 7 pad
            v
        }),
        // 16-byte SERVERSILO_INIT_INFORMATION { HANDLE=0, BOOLEAN=1, pad }
        (16, {
            let mut v = Vec::with_capacity(16);
            v.extend_from_slice(&0isize.to_ne_bytes());
            v.extend_from_slice(&[1u8, 0, 0, 0, 0, 0, 0, 0]);
            v
        }),
        // 8-byte HANDLE only
        (8, 0isize.to_ne_bytes().to_vec()),
        // 4-byte BOOL=0
        (4, 0u32.to_ne_bytes().to_vec()),
        // 4-byte BOOL=1
        (4, 1u32.to_ne_bytes().to_vec()),
        // empty buffer
        (0, Vec::new()),
    ];
    for (i, (size, buf)) in shapes.iter().enumerate() {
        let ok = unsafe {
            SetInformationJobObject(
                job.handle(),
                JOB_OBJECT_SERVER_SILO_INIT as i32,
                if *size == 0 { std::ptr::null() } else { buf.as_ptr() as *const _ },
                *size as u32,
            )
        };
        if ok != 0 {
            info!(silo_id, shape = i, size, "ServerSiloInit accepted");
            return Ok(());
        }
        let err = unsafe { GetLastError() };
        debug!(silo_id, shape = i, size, err, "ServerSiloInit rejected");
    }
    let err = unsafe { GetLastError() };
    Err(PsrootError::win32("SetInformationJobObject(ServerSiloInit)", err))
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
    #[instrument(level = "info", skip(resources, extra_drives), fields(root = %container_root))]
    pub fn create(
        container_root: &str,
        resources: Option<&ResourceLimits>,
        extra_drives: &[(&str, &str)],
    ) -> Result<Self> {
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

        // 4. Build namespace (optional — set PSROOT_SKIP_NAMESPACE=1 to let kernel do it)
        let skip_ns = std::env::var("PSROOT_SKIP_NAMESPACE").ok().as_deref() == Some("1");
        let namespace = if skip_ns {
            info!("Skipping namespace build (PSROOT_SKIP_NAMESPACE=1)");
            SiloNamespace::build_with_extra_drives(silo_id, container_root, &[])?
        } else {
            SiloNamespace::build_with_extra_drives(silo_id, container_root, extra_drives)?
        };

        // 5. Set silo root directory — requires SeTcbPrivilege.
        //    First try enabling it in our own token (works if account already
        //    has the right). If that fails, fall back to impersonating SYSTEM
        //    on this thread for the JobObjectSiloRootDirectory call. We're
        //    Admin, so we can grab a token from winlogon.exe.
        let used_impersonation = match enable_privilege("SeTcbPrivilege") {
            Ok(()) => false,
            Err(e1) => {
                debug!("SeTcbPrivilege not in current token ({}); trying SYSTEM impersonation", e1);
                impersonate_system_token().map_err(|e2| {
                    PsrootError::Other(format!(
                        "Server Silo requires SeTcbPrivilege. Tried current token ({}). \
                         Tried SYSTEM impersonation fallback ({}). Run as Administrator, \
                         or run `psroot setup` once and re-login.",
                        e1, e2
                    ))
                })?;
                true
            }
        };

        // Kernel expects a UNICODE_STRING with the NT path to the
        // silo root directory object (\Silos\<id>).
        let silo_path_wide: Vec<u16> = format!("\\Silos\\{}", silo_id)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let byte_len = ((silo_path_wide.len() - 1) * 2) as u16; // exclude null
        let max_byte_len = (silo_path_wide.len() * 2) as u16;   // include null

        // Alternative path formats to probe for class 37 (SiloRootDirectory)
        // Some builds may want "\??\<path>", or with trailing backslash, etc.
        let alt1_wide: Vec<u16> = format!("\\??\\Silos\\{}", silo_id)
            .encode_utf16().chain(std::iter::once(0)).collect();
        let alt1_byte_len = ((alt1_wide.len() - 1) * 2) as u16;
        let alt1_max_byte_len = (alt1_wide.len() * 2) as u16;
        let alt2_wide: Vec<u16> = format!("\\GLOBAL??\\Silos\\{}", silo_id)
            .encode_utf16().chain(std::iter::once(0)).collect();
        let alt2_byte_len = ((alt2_wide.len() - 1) * 2) as u16;
        let alt2_max_byte_len = (alt2_wide.len() * 2) as u16;

        // Try multiple struct shapes — kernel layout varies between Win10 builds.
        use windows_sys::Win32::System::JobObjects::SetInformationJobObject;
        let root_h: isize = namespace.root_handle();

        // NT path for class 38 (SiloSystemRoot) — the host filesystem path
        // prefixed with \??\  e.g. "\??\C:\Users\gj\AppData\Local\Psroot\..."
        let sysroot_nt = format!("\\??\\{}", container_root);
        let sysroot_wide: Vec<u16> = sysroot_nt
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let sysroot_byte_len = ((sysroot_wide.len() - 1) * 2) as u16;
        let sysroot_max_byte_len = (sysroot_wide.len() * 2) as u16;

        // Each entry: (tag, info_class, buffer-builder)
        // First entry is a NOP ("skip") — try ServerSiloInit without setting root dir,
        // because on some Win10 builds the kernel auto-associates the silo.
        let try_shapes: [(u32, u32, Box<dyn Fn() -> Vec<u8>>); 15] = [
            // Class 37, 16-byte UNICODE_STRING — alternate paths
            (371691, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_unicode_string(alt1_byte_len, alt1_max_byte_len, alt1_wide.as_ptr()))),
            (371692, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_unicode_string(alt2_byte_len, alt2_max_byte_len, alt2_wide.as_ptr()))),
            // Class 38 (SiloSystemRoot) with UNICODE_STRING pointing at host rootfs
            (3816, JOB_OBJECT_SILO_SYSTEM_ROOT, Box::new(|| build_unicode_string(sysroot_byte_len, sysroot_max_byte_len, sysroot_wide.as_ptr()))),
            // Class 37, 24-byte SILOOBJECT_ROOT_DIRECTORY with various ControlFlags
            (372403, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_silo_root(SILOOBJECT_ROOT_DIRECTORY_INITIALIZE | SILOOBJECT_ROOT_DIRECTORY_SHADOW_GLOBAL, byte_len, max_byte_len, silo_path_wide.as_ptr()))),
            (372401, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_silo_root(SILOOBJECT_ROOT_DIRECTORY_INITIALIZE, byte_len, max_byte_len, silo_path_wide.as_ptr()))),
            (372402, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_silo_root(SILOOBJECT_ROOT_DIRECTORY_SHADOW_GLOBAL, byte_len, max_byte_len, silo_path_wide.as_ptr()))),
            (372400, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_silo_root(0, byte_len, max_byte_len, silo_path_wide.as_ptr()))),
            // Class 37, 16-byte bare UNICODE_STRING to \Silos\<id>
            (371600, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_unicode_string(byte_len, max_byte_len, silo_path_wide.as_ptr()))),
            // Class 37, 8-byte HANDLE
            (370800, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_handle(root_h))),
            // Class 37, 16-byte handle variants
            (371601, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_handle_padded(root_h))),
            (371602, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_flags_handle(0, root_h))),
            (371603, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_flags_handle(SILOOBJECT_ROOT_DIRECTORY_INITIALIZE, root_h))),
            (371604, JOB_OBJECT_SILO_ROOT_DIR, Box::new(|| build_flags_handle(SILOOBJECT_ROOT_DIRECTORY_INITIALIZE | SILOOBJECT_ROOT_DIRECTORY_SHADOW_GLOBAL, root_h))),
            // Class 38 with UNICODE_STRING pointing at \Silos\<id> NT path
            (381602, JOB_OBJECT_SILO_SYSTEM_ROOT, Box::new(|| build_unicode_string(byte_len, max_byte_len, silo_path_wide.as_ptr()))),
            // Class 38 with 24-byte SILOOBJECT_ROOT_DIRECTORY shape pointing at host rootfs
            (382403, JOB_OBJECT_SILO_SYSTEM_ROOT, Box::new(|| build_silo_root(SILOOBJECT_ROOT_DIRECTORY_INITIALIZE | SILOOBJECT_ROOT_DIRECTORY_SHADOW_GLOBAL, sysroot_byte_len, sysroot_max_byte_len, sysroot_wide.as_ptr()))),
        ];

        let mut set_result: Result<()> = Err(PsrootError::Other("no shape attempted".into()));
        let mut accepted_tag: u32 = 0;
        let mut accepted_class: u32 = 0;
        for (tag, class, build) in &try_shapes {
            // Special tag 0 = skip SetSiloRootDirectory entirely, try ServerSiloInit directly
            if *class == u32::MAX {
                let init_ok = job.set_info_null(JOB_OBJECT_SERVER_SILO_INIT as i32);
                if init_ok.is_ok() {
                    set_result = Ok(());
                    accepted_tag = *tag;
                    accepted_class = 0;
                    info!(silo_id, "ServerSiloInit accepted without SetSiloRootDirectory");
                    // We've already done SiloInit — mark to skip below
                    break;
                } else {
                    debug!(silo_id, ?init_ok, "ServerSiloInit without SetSiloRoot rejected");
                    continue;
                }
            }
            let buf = build();
            let ok = unsafe {
                SetInformationJobObject(
                    job.handle(),
                    *class as i32,
                    buf.as_ptr() as *const _,
                    buf.len() as u32,
                )
            };
            if ok != 0 {
                set_result = Ok(());
                accepted_tag = *tag;
                accepted_class = *class;
                info!(silo_id, tag, class, size = buf.len(), "Silo root accepted");
                break;
            } else {
                let err = unsafe { GetLastError() };
                debug!(silo_id, tag, class, size = buf.len(), err, "shape rejected");
                set_result = Err(PsrootError::win32("SetInformationJobObject(SiloRoot)", err));
            }
        }
        if let Err(ref e) = set_result {
            warn!(silo_id, "All silo-root shapes rejected: {:?}", e);
        }
        // If class=0 was accepted (skip path), we already ran ServerSiloInit.
        // Otherwise try a sequence of ServerSiloInit call shapes.
        let init_result = if set_result.is_ok() && accepted_class != 0 {
            try_server_silo_init(&job, silo_id)
        } else {
            Ok(())
        };

        // Always revert impersonation immediately after the privileged calls
        if used_impersonation {
            revert_to_self();
        }
        set_result?;
        init_result?;
        debug!(silo_id, accepted_tag, accepted_class, "Silo root directory set");
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

    /// Spawn an interactive process inside the silo (inherits parent console).
    pub fn spawn_interactive(
        &mut self,
        command_line: &str,
        env: Option<&[(String, String)]>,
        cwd: Option<&str>,
    ) -> Result<ProcessInfo> {
        let info = process::create_in_silo_interactive(&self.job, command_line, env, cwd)?;
        if self.init_pid.is_none() {
            self.init_pid = Some(info.pid);
        }
        Ok(info)
    }

    /// Return the process handle for WaitForSingleObject. The process
    /// is re-opened from its PID so the caller owns the HANDLE.
    pub fn open_init_process(&self) -> Result<HANDLE> {
        let pid = self.init_pid.ok_or_else(|| {
            PsrootError::Other("No process spawned yet".into())
        })?;
        let h = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                0x00100000 | 0x001F0FFF, // SYNCHRONIZE | PROCESS_ALL_ACCESS
                0,
                pid,
            )
        };
        if h.is_null() || h == -1isize as HANDLE {
            return Err(PsrootError::last_win32("OpenProcess"));
        }
        Ok(h)
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

// ── Privilege management ────────────────────────────────────────────

/// Enable a named privilege in the current process token.
///
/// Returns `Ok(())` if the privilege was successfully enabled.
/// Returns `Err` if the privilege is not in the token (standard admin
/// accounts do NOT have SeTcbPrivilege by default).
fn enable_privilege(priv_name: &str) -> std::result::Result<(), String> {
    let mut token: HANDLE = std::ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    };
    if ok == 0 {
        return Err("Failed to open process token".into());
    }

    let name_wide: Vec<u16> = priv_name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid: LUID = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let ok = unsafe { LookupPrivilegeValueW(std::ptr::null(), name_wide.as_ptr(), &mut luid) };
    if ok == 0 {
        unsafe { CloseHandle(token) };
        return Err(format!("LookupPrivilegeValue({}) failed", priv_name));
    }

    // TOKEN_PRIVILEGES with one entry — repr(C) layout
    #[repr(C)]
    struct TokenPrivileges1 {
        privilege_count: u32,
        privileges: [LUID_AND_ATTRIBUTES; 1],
    }
    let tp = TokenPrivileges1 {
        privilege_count: 1,
        privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let ok = unsafe {
        AdjustTokenPrivileges(
            token,
            0, // DisableAllPrivileges = FALSE
            &tp as *const _ as *const TOKEN_PRIVILEGES,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(token) };

    if ok == 0 {
        return Err(format!(
            "AdjustTokenPrivileges failed (error {})",
            err
        ));
    }
    // ERROR_NOT_ALL_ASSIGNED = 1300 means the privilege isn't in the token
    if err == 1300 {
        return Err(format!(
            "{} is not assigned to this account",
            priv_name
        ));
    }

    info!("{} enabled", priv_name);
    Ok(())
}

// ── SYSTEM token impersonation fallback ─────────────────────────────
//
// When the current account doesn't have SeTcbPrivilege, we (as Admin)
// can briefly impersonate a SYSTEM process token on the current thread
// to make privileged calls. winlogon.exe runs as SYSTEM and is always
// present on a desktop session. SYSTEM has SeTcbPrivilege natively.
//
// Sequence:
//   1. Enable SeDebugPrivilege in our token (admins have it by default)
//   2. Find winlogon.exe via toolhelp snapshot
//   3. OpenProcess + OpenProcessToken (TOKEN_DUPLICATE | TOKEN_QUERY)
//   4. DuplicateTokenEx → SecurityImpersonation token
//   5. SetThreadToken(NULL, dup_token) — impersonate
//
// Caller must call revert_to_self() after the privileged work.

pub fn impersonate_system_token() -> std::result::Result<(), String> {
    use windows_sys::Win32::Security::{
        DuplicateTokenEx, SecurityDelegation, TokenImpersonation,
        SECURITY_ATTRIBUTES, TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY as T_QUERY,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, SetThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // 1. Enable SeDebugPrivilege so we can OpenProcessToken on SYSTEM procs
    enable_privilege("SeDebugPrivilege")
        .map_err(|e| format!("SeDebugPrivilege: {} (run as Administrator)", e))?;

    // 2. Find winlogon.exe
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap.is_null() || snap == -1isize as HANDLE {
        return Err("CreateToolhelp32Snapshot failed".into());
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut target_pid: u32 = 0;
    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        loop {
            let name_end = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(0);
            let name = String::from_utf16_lossy(&entry.szExeFile[..name_end]);
            if name.eq_ignore_ascii_case("winlogon.exe") {
                target_pid = entry.th32ProcessID;
                break;
            }
            if unsafe { Process32NextW(snap, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snap) };
    if target_pid == 0 {
        return Err("winlogon.exe not found in process list".into());
    }

    // 3. OpenProcess + OpenProcessToken
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, target_pid) };
    if proc.is_null() {
        let err = unsafe { GetLastError() };
        return Err(format!("OpenProcess(winlogon, pid {}) failed (err {})", target_pid, err));
    }
    let mut sys_token: HANDLE = std::ptr::null_mut();
    let ok = unsafe { OpenProcessToken(proc, TOKEN_DUPLICATE | T_QUERY, &mut sys_token) };
    unsafe { CloseHandle(proc) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("OpenProcessToken(winlogon) failed (err {})", err));
    }

    // 4. DuplicateTokenEx → impersonation token
    let mut dup_token: HANDLE = std::ptr::null_mut();
    let sa: *const SECURITY_ATTRIBUTES = std::ptr::null();
    let ok = unsafe {
        DuplicateTokenEx(
            sys_token,
            TOKEN_ALL_ACCESS,
            sa,
            SecurityDelegation,
            TokenImpersonation,
            &mut dup_token,
        )
    };
    unsafe { CloseHandle(sys_token) };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("DuplicateTokenEx failed (err {})", err));
    }

    // 5. Impersonate on current thread
    let ok = unsafe { SetThreadToken(std::ptr::null(), dup_token) };
    let err = unsafe { GetLastError() };
    unsafe { CloseHandle(dup_token) };
    if ok == 0 {
        return Err(format!("SetThreadToken failed (err {})", err));
    }

    info!("Impersonating SYSTEM token for privileged silo setup");
    Ok(())
}

pub fn revert_to_self() {
    extern "system" {
        fn RevertToSelf() -> i32;
    }
    unsafe { RevertToSelf() };
    debug!("Reverted from SYSTEM impersonation");
}
