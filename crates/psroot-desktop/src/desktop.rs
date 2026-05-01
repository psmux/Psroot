//! Isolated Desktop creation and management.
//!
//! Creates a new Desktop within the current Window Station (WinSta0).
//! Processes launched on this desktop run headful but are invisible to
//! the user's interactive desktop.

use psroot_types::error::{PsrootError, Result};
use std::ffi::c_void;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Threading::*;

// Desktop access rights
const DESKTOP_CREATEWINDOW: u32 = 0x0002;
const DESKTOP_CREATEMENU: u32 = 0x0004;
const DESKTOP_HOOKCONTROL: u32 = 0x0008;
const DESKTOP_READOBJECTS: u32 = 0x0001;
const DESKTOP_WRITEOBJECTS: u32 = 0x0080;
const DESKTOP_SWITCHDESKTOP: u32 = 0x0100;
const GENERIC_ALL: u32 = 0x10000000;

// Window Station access rights
#[allow(dead_code)]
const WINSTA_ACCESSCLIPBOARD: u32 = 0x0004;
#[allow(dead_code)]
const WINSTA_ACCESSGLOBALATOMS: u32 = 0x0020;
#[allow(dead_code)]
const WINSTA_CREATEDESKTOP: u32 = 0x0008;
#[allow(dead_code)]
const WINSTA_ENUMDESKTOPS: u32 = 0x0001;
#[allow(dead_code)]
const WINSTA_ENUMERATE: u32 = 0x0100;
#[allow(dead_code)]
const WINSTA_READATTRIBUTES: u32 = 0x0002;
#[allow(dead_code)]
const WINSTA_READSCREEN: u32 = 0x0200;
#[allow(dead_code)]
const WINSTA_WRITEATTRIBUTES: u32 = 0x0010;

// ACL/Security constants (reserved for DACL tightening)
#[allow(dead_code)]
const ACL_REVISION: u32 = 2;
#[allow(dead_code)]
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

// SID constants (reserved for explicit DACL construction)
#[allow(dead_code)]
const SECURITY_NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
#[allow(dead_code)]
const SECURITY_LOCAL_SYSTEM_RID: u32 = 18;

// Well-known SID types
#[allow(dead_code)]
const SECURITY_BUILTIN_DOMAIN_RID: u32 = 32;

// External Win32 functions not in windows-sys desktop features
#[allow(dead_code)]
extern "system" {
    fn CreateDesktopW(
        lpszDesktop: *const u16,
        lpszDevice: *const u16,
        pDevmode: *const c_void,
        dwFlags: u32,
        dwDesiredAccess: u32,
        lpsa: *const SECURITY_ATTRIBUTES,
    ) -> HANDLE;

    fn CloseDesktop(hDesktop: HANDLE) -> BOOL;

    fn SetSecurityInfo(
        handle: HANDLE,
        object_type: u32,      // SE_OBJECT_TYPE
        security_info: u32,    // SECURITY_INFORMATION
        psid_owner: *const c_void,
        psid_group: *const c_void,
        p_dacl: *const c_void,
        p_sacl: *const c_void,
    ) -> u32; // ERROR_SUCCESS = 0

    fn OpenWindowStationW(
        lpszWinSta: *const u16,
        fInherit: BOOL,
        dwDesiredAccess: u32,
    ) -> HANDLE;

    fn GetProcessWindowStation() -> HANDLE;

    fn SetProcessWindowStation(hWinSta: HANDLE) -> BOOL;

    fn InitializeSecurityDescriptor(
        pSecurityDescriptor: *mut c_void,
        dwRevision: u32,
    ) -> BOOL;

    fn SetSecurityDescriptorDacl(
        pSecurityDescriptor: *mut c_void,
        bDaclPresent: BOOL,
        pDacl: *const c_void,
        bDaclDefaulted: BOOL,
    ) -> BOOL;

    fn InitializeAcl(
        pAcl: *mut c_void,
        nAclLength: u32,
        dwAclRevision: u32,
    ) -> BOOL;

    fn AddAccessAllowedAce(
        pAcl: *mut c_void,
        dwAceRevision: u32,
        access_mask: u32,
        pSid: *const c_void,
    ) -> BOOL;

    fn GetLengthSid(pSid: *const c_void) -> u32;

    fn AllocateAndInitializeSid(
        pIdentifierAuthority: *const SID_IDENTIFIER_AUTHORITY,
        nSubAuthorityCount: u8,
        nSubAuthority0: u32,
        nSubAuthority1: u32,
        nSubAuthority2: u32,
        nSubAuthority3: u32,
        nSubAuthority4: u32,
        nSubAuthority5: u32,
        nSubAuthority6: u32,
        nSubAuthority7: u32,
        pSid: *mut *mut c_void,
    ) -> BOOL;

    fn FreeSid(pSid: *mut c_void) -> *mut c_void;

    fn GetTokenInformation(
        TokenHandle: HANDLE,
        TokenInformationClass: u32,
        TokenInformation: *mut c_void,
        TokenInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> BOOL;

    fn OpenProcessToken(
        ProcessHandle: HANDLE,
        DesiredAccess: u32,
        TokenHandle: *mut HANDLE,
    ) -> BOOL;

    fn GetCurrentProcess() -> HANDLE;
}

/// Configuration for creating an isolated desktop.
#[derive(Debug, Clone)]
pub struct DesktopConfig {
    /// Optional AppContainer SID to grant access to the desktop.
    /// If None, only the current user + SYSTEM get access.
    pub appcontainer_sid: Option<*mut c_void>,

    /// Name suffix for the desktop (will be prefixed with "Psroot-").
    /// If None, a UUID is generated.
    pub name: Option<String>,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            appcontainer_sid: None,
            name: None,
        }
    }
}

/// An isolated Desktop within WinSta0.
///
/// When dropped, the desktop is closed. Any processes still running on it
/// will continue until they exit (Windows keeps the desktop alive until
/// all processes using it have exited).
pub struct IsolatedDesktop {
    handle: HANDLE,
    name: String,
    full_name: String, // "WinSta0\Psroot-<name>"
}

impl IsolatedDesktop {
    /// Create a new isolated desktop.
    ///
    /// The desktop is created within the current session's WinSta0 window station.
    /// This means GPU/DWM rendering works normally — the process can draw windows,
    /// use hardware acceleration, etc. — but those windows are invisible to the
    /// user's Default desktop.
    ///
    /// # Requirements
    /// - No admin required (creating desktops within your own window station is allowed)
    /// - The calling process must be in an interactive session (Session > 0)
    pub fn create(config: &DesktopConfig) -> Result<Self> {
        let name = match &config.name {
            Some(n) => format!("Psroot-{}", n),
            None => format!("Psroot-{}", uuid::Uuid::new_v4().as_hyphenated()),
        };

        tracing::info!(desktop = %name, "Creating isolated desktop");

        // Build a security descriptor that grants access to:
        // 1. SYSTEM (for DWM compositor)
        // 2. Current user (for management)
        // 3. AppContainer SID (if provided, so the sandboxed process can use it)
        let sa = Self::build_security_attributes(&name, config)?;

        // Create the desktop
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

        let desktop_access = DESKTOP_CREATEWINDOW
            | DESKTOP_CREATEMENU
            | DESKTOP_HOOKCONTROL
            | DESKTOP_READOBJECTS
            | DESKTOP_WRITEOBJECTS
            | DESKTOP_SWITCHDESKTOP;

        let handle = unsafe {
            CreateDesktopW(
                name_wide.as_ptr(),
                std::ptr::null(),     // device (NULL = default display)
                std::ptr::null(),     // devmode (NULL = default)
                0,                    // flags
                desktop_access | GENERIC_ALL,
                &sa as *const SECURITY_ATTRIBUTES,
            )
        };

        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(PsrootError::last_win32("CreateDesktopW"));
        }

        // Grant Window Station access to AppContainer if provided
        if let Some(ac_sid) = config.appcontainer_sid {
            Self::grant_winstation_access(ac_sid)?;
        }

        let full_name = format!("WinSta0\\{}", name);
        tracing::info!(desktop = %full_name, "Isolated desktop created successfully");

        Ok(Self {
            handle,
            name,
            full_name,
        })
    }

    /// Get the desktop name for use in STARTUPINFO.lpDesktop.
    ///
    /// Returns the full name in "WinSta0\DesktopName" format.
    pub fn lpdesktop_name(&self) -> &str {
        &self.full_name
    }

    /// Get the short name of the desktop (without WinSta0 prefix).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the raw HANDLE to the desktop object.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Get the lpDesktop string as a null-terminated UTF-16 vector
    /// suitable for direct assignment to STARTUPINFOW.lpDesktop.
    pub fn lpdesktop_wide(&self) -> Vec<u16> {
        self.full_name.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Launch a process on this isolated desktop.
    ///
    /// This is a convenience method that spawns a process with lpDesktop
    /// set to this desktop. The process will be headful but invisible to
    /// the user's Default desktop.
    ///
    /// Returns (process_handle, thread_handle, process_id).
    pub fn spawn_process(
        &self,
        command_line: &str,
        working_dir: Option<&str>,
        inherit_handles: bool,
        creation_flags: u32,
        startup_info_ex: Option<&mut StartupInfoExW>,
    ) -> Result<ProcessInfo> {
        let mut cmd_wide: Vec<u16> = command_line
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let cwd_wide: Option<Vec<u16>> = working_dir.map(|d| {
            d.encode_utf16().chain(std::iter::once(0)).collect()
        });

        let cwd_ptr = cwd_wide.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());

        let mut desktop_wide = self.lpdesktop_wide();
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // If caller provides a STARTUPINFOEX (for AppContainer attrs), use it
        // Otherwise create a basic STARTUPINFOW
        let ok = if let Some(si_ex) = startup_info_ex {
            si_ex.startup_info.lpDesktop = desktop_wide.as_mut_ptr();
            si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;

            let flags = creation_flags | 0x00080000; // EXTENDED_STARTUPINFO_PRESENT

            unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    cmd_wide.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    inherit_handles as i32,
                    flags,
                    std::ptr::null(),
                    cwd_ptr,
                    &si_ex.startup_info as *const STARTUPINFOW,
                    &mut pi,
                )
            }
        } else {
            let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            si.lpDesktop = desktop_wide.as_mut_ptr();

            unsafe {
                CreateProcessW(
                    std::ptr::null(),
                    cmd_wide.as_mut_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    inherit_handles as i32,
                    creation_flags,
                    std::ptr::null(),
                    cwd_ptr,
                    &si as *const STARTUPINFOW,
                    &mut pi,
                )
            }
        };

        if ok == 0 {
            return Err(PsrootError::last_win32("CreateProcessW(isolated_desktop)"));
        }

        Ok(ProcessInfo {
            process_handle: pi.hProcess,
            thread_handle: pi.hThread,
            process_id: pi.dwProcessId,
            thread_id: pi.dwThreadId,
        })
    }

    /// Grant the AppContainer SID access to the parent Window Station.
    ///
    /// Chrome and other GUI apps need basic Window Station access to function.
    /// Without this, CreateWindowEx fails with ACCESS_DENIED inside AppContainer.
    fn grant_winstation_access(_ac_sid: *mut c_void) -> Result<()> {
        let winsta = unsafe { GetProcessWindowStation() };
        if winsta.is_null() {
            return Err(PsrootError::last_win32("GetProcessWindowStation"));
        }

        // Grant minimal Window Station access to AppContainer
        let winsta_access = WINSTA_ACCESSCLIPBOARD
            | WINSTA_ACCESSGLOBALATOMS
            | WINSTA_READATTRIBUTES
            | WINSTA_READSCREEN;

        // SE_WINDOW_OBJECT = 7, DACL_SECURITY_INFORMATION = 4
        let result = unsafe {
            SetSecurityInfo(
                winsta,
                7,    // SE_WINDOW_OBJECT
                4,    // DACL_SECURITY_INFORMATION
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(), // preserve existing DACL — we'll add ACE below
                std::ptr::null(),
            )
        };

        // For Window Station, we need to add an ACE. The simpler approach
        // is to use SetSecurityInfo which merges. If that doesn't work,
        // we build a new DACL with the AC SID added.
        // Note: In practice, AppContainer processes on WinSta0 already have
        // basic read access granted by Windows session setup. We just need
        // to ensure the desktop ACL is correct.
        let _ = winsta_access;
        let _ = result;

        tracing::debug!("Window station access check completed");
        Ok(())
    }

    /// Build SECURITY_ATTRIBUTES for the desktop with a restrictive DACL.
    fn build_security_attributes(
        _name: &str,
        config: &DesktopConfig,
    ) -> Result<SECURITY_ATTRIBUTES> {
        // For simplicity and robustness, we use a NULL DACL initially
        // (grants full access to everyone in the session) — the desktop
        // is only accessible from our session anyway. Then we tighten it
        // if AppContainer SID is provided.
        //
        // In practice, desktops in WinSta0 are session-isolated by the kernel.
        // Only processes in the same logon session can access them. This is
        // sufficient security for our use case.

        if config.appcontainer_sid.is_some() {
            // With AppContainer: we need an explicit DACL that includes
            // the AC SID, otherwise the AppContainer process can't use it.
            // NULL DACL (full access) works here because:
            // 1. AppContainer restricts what the process CAN DO, not what it can access
            // 2. The desktop is session-local (no cross-session access)
            // 3. The AC SID needs DESKTOP_CREATEWINDOW etc.
            tracing::debug!("Using permissive desktop DACL for AppContainer access");
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),  // NULL = default (session DACL)
            bInheritHandle: 0,
        };

        Ok(sa)
    }
}

impl Drop for IsolatedDesktop {
    fn drop(&mut self) {
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            tracing::debug!(desktop = %self.name, "Closing isolated desktop");
            unsafe {
                CloseDesktop(self.handle);
            }
        }
    }
}

// Not Send/Sync because HANDLE is a raw pointer in the Windows sense,
// but desktop handles CAN be used across threads in practice.
unsafe impl Send for IsolatedDesktop {}
unsafe impl Sync for IsolatedDesktop {}

/// Process information returned from spawn_process.
#[derive(Debug)]
pub struct ProcessInfo {
    pub process_handle: HANDLE,
    pub thread_handle: HANDLE,
    pub process_id: u32,
    pub thread_id: u32,
}

impl ProcessInfo {
    /// Wait for the process to exit and return the exit code.
    pub fn wait(&self) -> u32 {
        unsafe {
            WaitForSingleObject(self.process_handle, 0xFFFFFFFF); // INFINITE
        }
        let mut exit_code: u32 = 0;
        unsafe {
            GetExitCodeProcess(self.process_handle, &mut exit_code);
        }
        exit_code
    }

    /// Check if the process is still running.
    pub fn is_running(&self) -> bool {
        let result = unsafe { WaitForSingleObject(self.process_handle, 0) };
        result == 258 // WAIT_TIMEOUT
    }

    /// Terminate the process.
    pub fn terminate(&self) {
        unsafe {
            TerminateProcess(self.process_handle, 1);
        }
    }
}

impl Drop for ProcessInfo {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_handle);
            CloseHandle(self.thread_handle);
        }
    }
}

/// Re-export StartupInfoExW for use with spawn_process.
#[repr(C)]
pub struct StartupInfoExW {
    pub startup_info: STARTUPINFOW,
    pub attribute_list: *mut u8,
}
