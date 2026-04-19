//! Process sandbox: AppContainer isolation + restricted token + env sanitization.
//!
//! **AppContainer** is Windows' true filesystem boundary (same as Chrome tab sandboxing).
//! A process inside an AppContainer CANNOT access ANY file/registry/named-object
//! unless it is explicitly granted via ACL with the AppContainer SID.
//!
//! Layers:
//! 1. AppContainer profile — creates isolated identity (SID), denies all access by default
//! 2. ACL grants — rootfs directories get the AppContainer SID added (read+write)
//! 3. Network capabilities — optional internetClient / internetClientServer SIDs
//! 4. Environment sanitization — host PATH/USERNAME/PROMPT replaced with sandbox values
//! 5. STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES — applies AppContainer
//!
//! **Admin-aware tiers:**
//! - Non-admin: AppContainer + env sanitization (access denied + paths hidden)
//! - Admin: adds bind filter path remapping, server silo namespace isolation

use psroot_types::config::{ContainerConfig, NetworkAccess};
use psroot_types::error::{PsrootError, Result};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Threading::*;

/// Maximum SID size (for stack allocation)
const MAX_SID_SIZE: usize = 68;

// ═══════════════════════════════════════════════════════════════════
//  ISOLATION LEVEL — admin-aware feature detection
// ═══════════════════════════════════════════════════════════════════

/// Active isolation features for the current environment.
#[derive(Debug, Clone)]
pub struct IsolationLevel {
    pub appcontainer: bool,
    pub env_sanitized: bool,
    pub bind_filter: bool,
    pub server_silo: bool,
    pub is_admin: bool,
    pub build_number: u32,
}

impl IsolationLevel {
    /// Detect what isolation features are available right now.
    pub fn detect() -> Self {
        let caps = crate::detect::Capabilities::detect();
        Self {
            appcontainer: appcontainer_available(),
            env_sanitized: true, // always applied
            bind_filter: caps.bind_filter,
            server_silo: caps.server_silos,
            is_admin: caps.is_admin,
            build_number: caps.build_number,
        }
    }

    /// Human-readable tier name.
    pub fn tier_name(&self) -> &'static str {
        if self.server_silo {
            "Full (Silo + AppContainer + Env)"
        } else if self.bind_filter {
            "Enhanced (AppContainer + BindFilter + Env)"
        } else if self.appcontainer {
            "Standard (AppContainer + Env)"
        } else {
            "Basic (Restricted Token + Env)"
        }
    }

    /// Print warnings about what's missing and how to improve.
    pub fn print_warnings(&self) {
        if !self.is_admin {
            eprintln!("  ⚠ Non-admin: some isolation features unavailable");
            eprintln!("    Run as Administrator for: bind filter, server silos");
        }
        if !self.appcontainer {
            eprintln!("  ⚠ AppContainer APIs unavailable — using restricted token fallback");
        }
        if self.is_admin && !self.bind_filter {
            eprintln!("  ℹ Bind filter needs Windows 11 24H2+ (build 26100, current: {})", self.build_number);
        }
        if self.is_admin && !self.server_silo {
            eprintln!("  ℹ Server silos need Windows 10 1809+ (build 17763, current: {})", self.build_number);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  APPCONTAINER API (dynamically loaded from userenv.dll)
// ═══════════════════════════════════════════════════════════════════

type FnCreateAppContainerProfile = unsafe extern "system" fn(
    container_name: *const u16,   // PCWSTR
    display_name: *const u16,     // PCWSTR
    description: *const u16,      // PCWSTR
    capabilities: *const SID_AND_ATTRIBUTES,
    capability_count: u32,
    sid_out: *mut *mut std::ffi::c_void, // PSID*
) -> i32; // HRESULT

type FnDeleteAppContainerProfile = unsafe extern "system" fn(
    container_name: *const u16,
) -> i32;

type FnDeriveAppContainerSidFromAppContainerName = unsafe extern "system" fn(
    container_name: *const u16,
    sid_out: *mut *mut std::ffi::c_void,
) -> i32;

type FnFreeSid = unsafe extern "system" fn(sid: *mut std::ffi::c_void) -> *mut std::ffi::c_void;

struct AppContainerApis {
    create_profile: FnCreateAppContainerProfile,
    delete_profile: FnDeleteAppContainerProfile,
    derive_sid: FnDeriveAppContainerSidFromAppContainerName,
    free_sid: FnFreeSid,
}

static AC_APIS: OnceLock<Option<AppContainerApis>> = OnceLock::new();

fn load_ac_apis() -> &'static Option<AppContainerApis> {
    AC_APIS.get_or_init(|| {
        unsafe {
            let name: Vec<u16> = "userenv.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let lib = LoadLibraryW(name.as_ptr());
            if lib.is_null() { return None; }

            let create = GetProcAddress(lib, b"CreateAppContainerProfile\0".as_ptr());
            let delete = GetProcAddress(lib, b"DeleteAppContainerProfile\0".as_ptr());
            let derive = GetProcAddress(lib, b"DeriveAppContainerSidFromAppContainerName\0".as_ptr());

            // FreeSid is in advapi32
            let advapi_name: Vec<u16> = "advapi32.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let advapi = LoadLibraryW(advapi_name.as_ptr());
            let free = if !advapi.is_null() {
                GetProcAddress(advapi, b"FreeSid\0".as_ptr())
            } else {
                None
            };

            if let (Some(c), Some(d), Some(dr), Some(f)) = (create, delete, derive, free) {
                Some(AppContainerApis {
                    create_profile: std::mem::transmute(c),
                    delete_profile: std::mem::transmute(d),
                    derive_sid: std::mem::transmute(dr),
                    free_sid: std::mem::transmute(f),
                })
            } else {
                None
            }
        }
    })
}

/// Check if AppContainer APIs are available.
pub fn appcontainer_available() -> bool {
    load_ac_apis().is_some()
}

// ═══════════════════════════════════════════════════════════════════
//  APPCONTAINER PROFILE
// ═══════════════════════════════════════════════════════════════════

/// An AppContainer profile with its SID.
pub struct AppContainerProfile {
    name: Vec<u16>,
    sid: *mut std::ffi::c_void,
}

// SAFETY: AppContainer SID is a kernel-managed object, safe to send across threads
unsafe impl Send for AppContainerProfile {}
unsafe impl Sync for AppContainerProfile {}

impl AppContainerProfile {
    /// Create (or reuse) an AppContainer profile for a container.
    pub fn create(container_id: &str) -> Result<Self> {
        let apis = load_ac_apis()
            .as_ref()
            .ok_or_else(|| PsrootError::Other("AppContainer APIs not available".into()))?;

        let profile_name = format!("psroot.container.{}", container_id);
        let name_wide: Vec<u16> = profile_name.encode_utf16().chain(std::iter::once(0)).collect();
        let display: Vec<u16> = format!("Psroot Container {}", container_id)
            .encode_utf16().chain(std::iter::once(0)).collect();
        let desc: Vec<u16> = "Psroot sandboxed container"
            .encode_utf16().chain(std::iter::once(0)).collect();

        let mut sid: *mut std::ffi::c_void = std::ptr::null_mut();

        unsafe {
            // Try to create — if already exists, derive the SID
            let hr = (apis.create_profile)(
                name_wide.as_ptr(),
                display.as_ptr(),
                desc.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid,
            );

            if hr != 0 {
                // Profile may already exist (HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) = 0x800700B7)
                // Try to derive SID from existing profile
                if !sid.is_null() {
                    (apis.free_sid)(sid);
                    sid = std::ptr::null_mut();
                }
                let hr2 = (apis.derive_sid)(name_wide.as_ptr(), &mut sid);
                if hr2 != 0 {
                    // Delete and recreate
                    (apis.delete_profile)(name_wide.as_ptr());
                    let hr3 = (apis.create_profile)(
                        name_wide.as_ptr(),
                        display.as_ptr(),
                        desc.as_ptr(),
                        std::ptr::null(),
                        0,
                        &mut sid,
                    );
                    if hr3 != 0 {
                        return Err(PsrootError::hr("CreateAppContainerProfile", hr3 as u32));
                    }
                }
            }

            if sid.is_null() {
                return Err(PsrootError::Other("AppContainer SID is null".into()));
            }
        }

        Ok(Self {
            name: name_wide,
            sid,
        })
    }

    pub fn sid(&self) -> *mut std::ffi::c_void {
        self.sid
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if let Some(apis) = load_ac_apis() {
            unsafe {
                if !self.sid.is_null() {
                    (apis.free_sid)(self.sid);
                }
                // Delete the profile when container is done
                (apis.delete_profile)(self.name.as_ptr());
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  NETWORK CAPABILITIES — Well-known SIDs for AppContainer
// ═══════════════════════════════════════════════════════════════════

/// Well-known capability SID values (WinCapability*Sid):
/// - internetClient        = S-1-15-3-1  (outbound TCP/UDP)
/// - internetClientServer  = S-1-15-3-2  (outbound + listen on ports)
///
/// We use CreateWellKnownSid with:
///   WinCapabilityInternetClientSid       = 86
///   WinCapabilityInternetClientServerSid = 87

const WIN_CAPABILITY_INTERNET_CLIENT: i32 = 86;
const WIN_CAPABILITY_INTERNET_CLIENT_SERVER: i32 = 87;

/// SE_GROUP_ENABLED — the capability is enabled in the token.
const SE_GROUP_ENABLED: u32 = 0x00000004;

/// Stack-allocated SID buffer for a capability.
struct CapabilitySid {
    buf: [u8; MAX_SID_SIZE],
    size: u32,
}

impl CapabilitySid {
    /// Create a well-known capability SID.
    fn create(well_known_type: i32) -> Result<Self> {
        let mut sid = Self {
            buf: [0u8; MAX_SID_SIZE],
            size: MAX_SID_SIZE as u32,
        };
        let ok = unsafe {
            CreateWellKnownSid(
                well_known_type,
                std::ptr::null_mut(),
                sid.buf.as_mut_ptr() as *mut _,
                &mut sid.size,
            )
        };
        if ok == 0 {
            return Err(PsrootError::last_win32("CreateWellKnownSid(capability)"));
        }
        Ok(sid)
    }

    fn as_ptr(&self) -> *mut std::ffi::c_void {
        self.buf.as_ptr() as *mut _
    }
}

/// Build the SID_AND_ATTRIBUTES array for the requested network access level.
///
/// Returns capability SIDs (pinned in a Vec) and a Vec of SID_AND_ATTRIBUTES
/// with pointers into the first Vec. The caller MUST keep the SID Vec alive
/// while the attributes are in use.
///
/// Two-phase build: allocate SIDs first (so they're pinned in the Vec's heap
/// allocation), then build the attribute pointers from the stable locations.
fn build_network_capabilities(
    network: NetworkAccess,
) -> Result<(Vec<CapabilitySid>, Vec<SID_AND_ATTRIBUTES>)> {
    // Phase 1: Create SIDs into the Vec (heap-allocated, stable addresses)
    let sids: Vec<CapabilitySid> = match network {
        NetworkAccess::None => Vec::new(),
        NetworkAccess::Outbound => {
            vec![CapabilitySid::create(WIN_CAPABILITY_INTERNET_CLIENT)?]
        }
        NetworkAccess::Full => {
            // internetClientServer implies internetClient on Windows,
            // but we include both for explicitness and compatibility.
            vec![
                CapabilitySid::create(WIN_CAPABILITY_INTERNET_CLIENT)?,
                CapabilitySid::create(WIN_CAPABILITY_INTERNET_CLIENT_SERVER)?,
            ]
        }
    };

    // Phase 2: Build SID_AND_ATTRIBUTES pointing into the now-stable Vec
    let attrs: Vec<SID_AND_ATTRIBUTES> = sids.iter()
        .map(|s| SID_AND_ATTRIBUTES {
            Sid: s.as_ptr(),
            Attributes: SE_GROUP_ENABLED,
        })
        .collect();

    Ok((sids, attrs))
}

/// Add a loopback exemption for an AppContainer profile so localhost traffic works.
/// This allows: host browser → container dev server on localhost:<port>.
///
/// Uses CheckNetIsolation.exe (built into Windows 10+).
/// Non-admin: works if user has permissions to the AppContainer profile.
fn add_loopback_exemption(profile_name: &str) -> Result<()> {
    tracing::debug!(profile = %profile_name, "Adding loopback exemption");
    let result = std::process::Command::new("CheckNetIsolation.exe")
        .args(["LoopbackExempt", "-a", &format!("-n={}", profile_name)])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match result {
        Ok(output) if output.status.success() => {
            tracing::debug!("Loopback exemption added");
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Non-fatal: container still works, just can't reach from host
            tracing::warn!(%stderr, "CheckNetIsolation failed (loopback may not work from host)");
            Ok(())
        }
        Err(e) => {
            tracing::warn!(error = %e, "CheckNetIsolation.exe not found");
            Ok(())
        }
    }
}

/// Remove a loopback exemption for an AppContainer profile.
fn remove_loopback_exemption(profile_name: &str) {
    let _ = std::process::Command::new("CheckNetIsolation.exe")
        .args(["LoopbackExempt", "-d", &format!("-n={}", profile_name)])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

// ═══════════════════════════════════════════════════════════════════
//  ACL — GRANT APPCONTAINER ACCESS TO ROOTFS
// ═══════════════════════════════════════════════════════════════════

/// Grant the AppContainer SID read+write+execute access to a directory (and children).
/// Uses icacls for simplicity — sets an ACL entry for the AppContainer SID.
pub fn grant_appcontainer_access(dir: &str, sid: *mut std::ffi::c_void) -> Result<()> {
    // Convert SID to string (S-1-15-2-...)
    let sid_string = unsafe { sid_to_string(sid) }?;

    tracing::debug!(dir, sid = %sid_string, "Granting AppContainer access");

    // Grant full access to this SID on the directory tree
    // (OI)(CI) = object inherit + container inherit (applies to all files and subdirs)
    let result = std::process::Command::new("icacls")
        .args([
            dir,
            "/grant",
            &format!("*{}:(OI)(CI)(F)", sid_string),
            "/T",  // recurse
            "/Q",  // quiet
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match result {
        Ok(output) if output.status.success() => {
            tracing::debug!("icacls grant succeeded");
            Ok(())
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            tracing::error!(%stderr, %stdout, "icacls grant failed");
            Err(PsrootError::Other(format!(
                "icacls failed to grant AppContainer access to {}: {}",
                dir, stderr.trim()
            )))
        }
        Err(e) => Err(PsrootError::Io(e)),
    }
}

/// Convert a SID pointer to its string form (e.g., "S-1-15-2-1234...")
unsafe fn sid_to_string(sid: *mut std::ffi::c_void) -> Result<String> {
    // ConvertSidToStringSidW is in advapi32
    type FnConvertSid = unsafe extern "system" fn(
        sid: *mut std::ffi::c_void,
        string_sid: *mut *mut u16,
    ) -> i32;

    let advapi_name: Vec<u16> = "advapi32.dll".encode_utf16().chain(std::iter::once(0)).collect();
    let advapi = LoadLibraryW(advapi_name.as_ptr());
    if advapi.is_null() {
        return Err(PsrootError::Other("advapi32.dll not found".into()));
    }

    let func: FnConvertSid = std::mem::transmute(
        GetProcAddress(advapi, b"ConvertSidToStringSidW\0".as_ptr())
            .ok_or_else(|| PsrootError::Other("ConvertSidToStringSidW not found".into()))?,
    );

    let mut str_ptr: *mut u16 = std::ptr::null_mut();
    if func(sid, &mut str_ptr) == 0 {
        return Err(PsrootError::last_win32("ConvertSidToStringSidW"));
    }

    // Read wide string
    let mut len = 0;
    while *str_ptr.add(len) != 0 { len += 1; }
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(str_ptr, len));

    // Free with LocalFree
    type FnLocalFree = unsafe extern "system" fn(h: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    let kernel32_name: Vec<u16> = "kernel32.dll".encode_utf16().chain(std::iter::once(0)).collect();
    let kernel32 = LoadLibraryW(kernel32_name.as_ptr());
    if !kernel32.is_null() {
        if let Some(local_free) = GetProcAddress(kernel32, b"LocalFree\0".as_ptr()) {
            let local_free: FnLocalFree = std::mem::transmute(local_free);
            local_free(str_ptr as *mut _);
        }
    }

    Ok(s)
}

// ═══════════════════════════════════════════════════════════════════
//  RESTRICTED TOKEN (same as before)
// ═══════════════════════════════════════════════════════════════════

/// Token integrity level structure
#[repr(C)]
struct TokenMandatoryLabel {
    label: SID_AND_ATTRIBUTES,
}

/// Create a restricted + low-integrity token.
fn create_restricted_token() -> Result<HANDLE> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY,
            &mut token,
        ) == 0
        {
            return Err(PsrootError::last_win32("OpenProcessToken"));
        }

        // DISABLE_MAX_PRIVILEGE = 0x1, WRITE_RESTRICTED = 0x4
        let mut restricted: HANDLE = std::ptr::null_mut();
        if CreateRestrictedToken(
            token,
            0x1 | 0x4,
            0, std::ptr::null(),
            0, std::ptr::null(),
            0, std::ptr::null(),
            &mut restricted,
        ) == 0
        {
            CloseHandle(token);
            return Err(PsrootError::last_win32("CreateRestrictedToken"));
        }
        CloseHandle(token);

        // Set Low integrity
        let mut sid_buf = [0u8; MAX_SID_SIZE];
        let sid = sid_buf.as_mut_ptr() as *mut _;
        let mut sid_size = MAX_SID_SIZE as u32;
        if CreateWellKnownSid(66, std::ptr::null_mut(), sid, &mut sid_size) == 0 {
            CloseHandle(restricted);
            return Err(PsrootError::last_win32("CreateWellKnownSid(LowLabel)"));
        }

        let label = TokenMandatoryLabel {
            label: SID_AND_ATTRIBUTES {
                Sid: sid,
                Attributes: 0x20, // SE_GROUP_INTEGRITY
            },
        };

        if SetTokenInformation(
            restricted,
            25, // TokenIntegrityLevel
            &label as *const _ as *const _,
            std::mem::size_of::<TokenMandatoryLabel>() as u32 + sid_size,
        ) == 0
        {
            CloseHandle(restricted);
            return Err(PsrootError::last_win32("SetTokenInformation(IntegrityLevel)"));
        }

        Ok(restricted)
    }
}

// ═══════════════════════════════════════════════════════════════════
//  ENV BLOCK
// ═══════════════════════════════════════════════════════════════════

/// Build a null-terminated Unicode environment block from explicit key=value pairs.
/// Build a null-terminated Unicode environment block from explicit key=value pairs.
/// Windows requires env blocks to be sorted case-insensitively.
pub fn build_env_block(config: &ContainerConfig) -> Vec<u16> {
    let mut entries = Vec::new();

    // Add configured env vars
    for (k, v) in &config.env {
        entries.push(format!("{}={}", k, v));
    }

    // Add essential baseline vars that processes need
    let rootfs = &config.rootfs_path;
    let essentials = [
        ("SystemRoot", format!("{}\\Windows", rootfs)),
        ("SystemDrive", "C:".to_string()),
        ("TEMP", format!("{}\\Temp", rootfs)),
        ("TMP", format!("{}\\Temp", rootfs)),
        ("USERPROFILE", format!("{}\\Users\\ContainerUser", rootfs)),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD".to_string()),
        ("PATH", format!("{}\\Windows\\System32;{}\\nodejs", rootfs, rootfs)),
    ];

    for (k, v) in &essentials {
        if !config.env.contains_key(*k) {
            entries.push(format!("{}={}", k, v));
        }
    }

    // Sort case-insensitively (Windows requirement for env blocks)
    entries.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()));

    let mut block = Vec::new();
    for entry in &entries {
        block.extend(entry.encode_utf16());
        block.push(0);
    }
    block.push(0); // double null terminator
    block
}

// ═══════════════════════════════════════════════════════════════════
//  ENV SANITIZATION — hide host paths from sandboxed processes
// ═══════════════════════════════════════════════════════════════════

/// Environment variables that leak host information and should be replaced.
const SANITIZED_VARS: &[&str] = &[
    "PATH", "PATHEXT", "TEMP", "TMP",
    "USERPROFILE", "HOMEPATH", "HOMEDRIVE", "HOMEDIR",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA",
    "USERNAME", "USERDOMAIN", "USERDOMAIN_ROAMINGPROFILE",
    "SystemRoot", "windir", "SystemDrive",
    "COMPUTERNAME", "LOGONSERVER",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
    "NUMBER_OF_PROCESSORS", "OS",
    "PROMPT",
    // VS Code / editor / tool vars that leak host paths
    "TERM_PROGRAM", "TERM_PROGRAM_VERSION",
    "VSCODE_GIT_IPC_HANDLE", "VSCODE_GIT_ASKPASS_MAIN",
    "VSCODE_GIT_ASKPASS_NODE", "VSCODE_INJECTION",
    "GIT_ASKPASS", "ELECTRON_RUN_AS_NODE",
    "CHROME_CRASHPAD_PIPE_NAME",
    "PSModulePath", "PSMODULEPATH",
    "CARGO_HOME", "RUSTUP_HOME",
    "NVM_HOME", "NVM_SYMLINK",
    "GOPATH", "GOROOT",
    "JAVA_HOME", "PYTHONPATH",
    "PNPM_HOME", "npm_config_cache",
    "CONDA_PREFIX",
];

/// Save the current process environment, apply sanitized values for the sandbox,
/// and return the saved original values so they can be restored.
///
/// This is needed because AppContainer inherits the parent's env block
/// (custom lpEnvironment causes error 203). So we temporarily modify our own
/// process env, spawn the child, then restore.
fn apply_sandbox_env(config: &ContainerConfig) -> Vec<(String, Option<String>)> {
    let rootfs = &config.rootfs_path;
    let mut saved = Vec::new();

    // Phase 1: Save and remove ALL vars that leak host info
    for var in SANITIZED_VARS {
        let old = std::env::var(var).ok();
        saved.push((var.to_string(), old));
        std::env::remove_var(var);
    }

    // Also remove vars with host paths (dynamic detection)
    for (key, val) in std::env::vars() {
        // Skip vars we already handled
        if SANITIZED_VARS.iter().any(|v| v.eq_ignore_ascii_case(&key)) {
            continue;
        }
        // Remove vars containing host-specific path patterns
        let val_lower = val.to_lowercase();
        if val_lower.contains("\\users\\") && !val_lower.contains(&rootfs.to_lowercase())
            || val_lower.contains("\\appdata\\")
            || val_lower.contains("program files")
        {
            saved.push((key.clone(), Some(val)));
            std::env::remove_var(&key);
        }
    }

    // Phase 2: Set clean sandbox values
    let mut path_dirs = vec![
        format!("{}\\Windows\\System32", rootfs),
    ];
    // Add rootfs\bin if it exists (rust-bin tools)
    let bin_dir = format!("{}\\bin", rootfs);
    if std::path::Path::new(&bin_dir).exists() {
        path_dirs.push(bin_dir);
    }
    // Add rootfs\nodejs if it exists
    let node_dir = format!("{}\\nodejs", rootfs);
    if std::path::Path::new(&node_dir).exists() {
        path_dirs.push(node_dir);
    }

    let sandbox_vars = [
        ("PATH", path_dirs.join(";")),
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD".into()),
        ("TEMP", format!("{}\\Temp", rootfs)),
        ("TMP", format!("{}\\Temp", rootfs)),
        ("USERPROFILE", format!("{}\\Users\\ContainerUser", rootfs)),
        ("HOMEPATH", "\\Users\\ContainerUser".into()),
        ("HOMEDRIVE", "C:".into()),
        ("APPDATA", format!("{}\\Users\\ContainerUser\\AppData\\Roaming", rootfs)),
        ("LOCALAPPDATA", format!("{}\\Users\\ContainerUser\\AppData\\Local", rootfs)),
        ("SystemRoot", format!("{}\\Windows", rootfs)),
        ("windir", format!("{}\\Windows", rootfs)),
        ("SystemDrive", "C:".into()),
        ("USERNAME", "ContainerUser".into()),
        ("COMPUTERNAME", "PSROOT".into()),
        ("OS", "Windows_NT".into()),
        ("PROMPT", "psroot$G ".into()), // Clean prompt: "psroot> "
    ];

    for (k, v) in &sandbox_vars {
        std::env::set_var(k, v);
    }

    // Phase 3: Apply user-configured env vars (overrides)
    for (k, v) in &config.env {
        std::env::set_var(k, v);
    }

    saved
}

/// Restore the original process environment from saved values.
fn restore_env(saved: Vec<(String, Option<String>)>) {
    // First, remove any sandbox vars we added
    let sandbox_keys = [
        "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOMEPATH",
        "HOMEDRIVE", "APPDATA", "LOCALAPPDATA", "SystemRoot", "windir",
        "SystemDrive", "USERNAME", "COMPUTERNAME", "OS", "PROMPT",
    ];
    for k in &sandbox_keys {
        std::env::remove_var(k);
    }

    // Restore original values
    for (key, val) in saved {
        match val {
            Some(v) => std::env::set_var(&key, &v),
            None => std::env::remove_var(&key),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  SPAWN — THE MAIN ENTRY POINT
// ═══════════════════════════════════════════════════════════════════

/// SECURITY_CAPABILITIES structure for AppContainer
#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: *mut std::ffi::c_void, // PSID
    capabilities: *const SID_AND_ATTRIBUTES,
    capability_count: u32,
    reserved: u32,
}

/// STARTUPINFOEXW with extended attributes
#[repr(C)]
struct StartupInfoExW {
    startup_info: STARTUPINFOW,
    attribute_list: *mut u8, // LPPROC_THREAD_ATTRIBUTE_LIST
}

/// Spawn a process inside an AppContainer sandbox.
///
/// The process can ONLY access:
/// - Its own rootfs (ACL grants AppContainer SID)
/// - Nothing else — no host files, no host registry, no host named objects
///
/// Falls back to restricted-token-only if AppContainer APIs are unavailable.
pub fn spawn_sandboxed(
    cmd: &str,
    config: &ContainerConfig,
    job: &psroot_job::JobObject,
) -> Result<u32> {
    if appcontainer_available() {
        spawn_with_appcontainer(cmd, config, job)
    } else {
        // Fallback: restricted token only (weaker — can still READ host files)
        tracing::warn!("AppContainer not available — falling back to restricted token (read isolation limited)");
        spawn_with_restricted_token(cmd, config, job)
    }
}

/// Spawn an **interactive** shell inside an AppContainer sandbox.
///
/// Unlike `spawn_sandboxed`, this:
/// - Inherits the parent console (stdin/stdout/stderr) — user can type commands
/// - Does NOT use CREATE_NO_WINDOW — shares the current terminal
/// - Blocks until the shell process exits
/// - Returns the process exit code
pub fn spawn_interactive(
    cmd: &str,
    config: &ContainerConfig,
) -> Result<u32> {
    if !appcontainer_available() {
        return Err(PsrootError::Other("Interactive shell requires AppContainer support".into()));
    }

    // 1. Create AppContainer profile
    let container_id = config.rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("unknown");
    let ac_profile = AppContainerProfile::create(container_id)?;

    // 2. Grant the AppContainer SID access to the rootfs
    grant_appcontainer_access(&config.rootfs_path, ac_profile.sid())?;

    // 3. Build network capabilities
    let (_cap_sids, cap_attrs) = build_network_capabilities(config.network)?;
    let cap_count = cap_attrs.len() as u32;
    let cap_ptr = if cap_attrs.is_empty() { std::ptr::null() } else { cap_attrs.as_ptr() };

    let sec_caps = SecurityCapabilities {
        app_container_sid: ac_profile.sid(),
        capabilities: cap_ptr,
        capability_count: cap_count,
        reserved: 0,
    };

    // 4. Loopback exemption for full network mode
    let profile_name = format!("psroot.container.{}", container_id);
    if config.network == NetworkAccess::Full {
        add_loopback_exemption(&profile_name)?;
    }

    // 5. Proc thread attribute list
    const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x00020009;

    let mut attr_size: usize = 0;
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size); }

    let mut attr_list = vec![0u8; attr_size];
    let attr_ptr = attr_list.as_mut_ptr() as *mut _;

    unsafe {
        if InitializeProcThreadAttributeList(attr_ptr, 1, 0, &mut attr_size) == 0 {
            return Err(PsrootError::last_win32("InitializeProcThreadAttributeList"));
        }
        if UpdateProcThreadAttribute(
            attr_ptr, 0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &sec_caps as *const _ as *const _,
            std::mem::size_of::<SecurityCapabilities>(),
            std::ptr::null_mut(), std::ptr::null(),
        ) == 0 {
            DeleteProcThreadAttributeList(attr_ptr);
            return Err(PsrootError::last_win32("UpdateProcThreadAttribute"));
        }
    }

    // 6. Sanitize environment — hide host paths from the child process.
    //    AppContainer can't accept a custom env block (error 203), so we
    //    temporarily modify our own process env, spawn, then restore.
    let saved_env = apply_sandbox_env(config);

    // 7. Build command and cwd — start at rootfs root, not rootfs\Temp
    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = config.rootfs_path.clone();
    let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();

    // 8. Create process — INTERACTIVE: no CREATE_NO_WINDOW, inherit handles
    let mut si_ex: StartupInfoExW = unsafe { std::mem::zeroed() };
    si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    si_ex.attribute_list = attr_list.as_mut_ptr();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // EXTENDED_STARTUPINFO_PRESENT only — no SUSPENDED, no NO_WINDOW
    let flags = 0x00080000u32; // EXTENDED_STARTUPINFO_PRESENT

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // bInheritHandles = TRUE — inherit console
            flags,
            std::ptr::null(), // inherit (now-sanitized) parent env
            cwd_wide.as_ptr(),
            &si_ex as *const _ as *const STARTUPINFOW,
            &mut pi,
        )
    };

    unsafe { DeleteProcThreadAttributeList(attr_ptr); }

    // Restore our env immediately after CreateProcess — child already inherited
    restore_env(saved_env);

    if ok == 0 {
        let err = unsafe { GetLastError() };
        if config.network == NetworkAccess::Full {
            remove_loopback_exemption(&profile_name);
        }
        drop(ac_profile);
        return Err(PsrootError::win32("CreateProcessW(interactive)", err));
    }

    // 9. Wait for the shell to exit (blocking)
    unsafe {
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF); // INFINITE
    }

    // 10. Get exit code
    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Cleanup
    if config.network == NetworkAccess::Full {
        remove_loopback_exemption(&profile_name);
    }
    drop(ac_profile);

    Ok(exit_code)
}

/// Spawn using AppContainer — true filesystem isolation.
///
/// AppContainer processes:
/// - CANNOT access files outside explicitly ACL'd paths (rootfs)
/// - CANNOT access user data (C:\Users\*)
/// - CANNOT write anywhere outside rootfs
/// - Env is sanitized: PATH, USERNAME, PROMPT all point to rootfs (no host leaks)
fn spawn_with_appcontainer(
    cmd: &str,
    config: &ContainerConfig,
    job: &psroot_job::JobObject,
) -> Result<u32> {
    // 1. Create AppContainer profile
    let container_id = config.rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("unknown");
    let ac_profile = AppContainerProfile::create(container_id)?;

    // 2. Grant the AppContainer SID access to the entire rootfs tree
    grant_appcontainer_access(&config.rootfs_path, ac_profile.sid())?;

    // 3. Build network capabilities based on config.network
    let (_cap_sids, cap_attrs) = build_network_capabilities(config.network)?;
    let cap_count = cap_attrs.len() as u32;
    let cap_ptr = if cap_attrs.is_empty() {
        std::ptr::null()
    } else {
        cap_attrs.as_ptr()
    };

    tracing::debug!(
        network = ?config.network,
        capabilities = cap_count,
        "AppContainer network capabilities"
    );

    // 4. Build SECURITY_CAPABILITIES with network capabilities
    let sec_caps = SecurityCapabilities {
        app_container_sid: ac_profile.sid(),
        capabilities: cap_ptr,
        capability_count: cap_count,
        reserved: 0,
    };

    // 5. Add loopback exemption for Full network mode (host → container on localhost)
    let profile_name = format!("psroot.container.{}", container_id);
    if config.network == NetworkAccess::Full {
        add_loopback_exemption(&profile_name)?;
    }

    // 6. Initialize proc thread attribute list
    const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x00020009;

    let mut attr_size: usize = 0;
    unsafe {
        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut attr_size);
    }

    let mut attr_list = vec![0u8; attr_size];
    let attr_ptr = attr_list.as_mut_ptr() as *mut _;

    unsafe {
        if InitializeProcThreadAttributeList(attr_ptr, 1, 0, &mut attr_size) == 0 {
            return Err(PsrootError::last_win32("InitializeProcThreadAttributeList"));
        }

        if UpdateProcThreadAttribute(
            attr_ptr,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            &sec_caps as *const _ as *const _,
            std::mem::size_of::<SecurityCapabilities>(),
            std::ptr::null_mut(),
            std::ptr::null(),
        ) == 0
        {
            DeleteProcThreadAttributeList(attr_ptr);
            return Err(PsrootError::last_win32("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)"));
        }
    }

    // 7. Build command and cwd
    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = if config.working_directory.starts_with(&config.rootfs_path) {
        config.working_directory.clone()
    } else {
        format!("{}\\Temp", config.rootfs_path)
    };
    let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();

    // 8. Sanitize environment — hide host paths from the child.
    //    AppContainer can't accept lpEnvironment (error 203), so we
    //    temporarily modify our own process env, spawn, then restore.
    let saved_env = apply_sandbox_env(config);

    // 9. Create process with STARTUPINFOEX + AppContainer
    let mut si_ex: StartupInfoExW = unsafe { std::mem::zeroed() };
    si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    si_ex.attribute_list = attr_list.as_mut_ptr();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT
    // (no CREATE_UNICODE_ENVIRONMENT — inherit parent env)
    let flags = 0x00000004u32 | 0x08000000u32 | 0x00080000u32;

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0, // bInheritHandles = FALSE
            flags,
            std::ptr::null(), // inherit parent env
            cwd_wide.as_ptr(),
            &si_ex as *const _ as *const STARTUPINFOW,
            &mut pi,
        )
    };

    unsafe { DeleteProcThreadAttributeList(attr_ptr) };

    // Restore our env immediately — child already inherited the sanitized version
    restore_env(saved_env);

    if ok == 0 {
        let err = unsafe { GetLastError() };
        // If AppContainer fails, fall back to restricted token
        if err != 0 {
            tracing::warn!(error = err, "AppContainer CreateProcess failed, falling back to restricted token");
            if config.network == NetworkAccess::Full {
                remove_loopback_exemption(&profile_name);
            }
            drop(ac_profile);
            return spawn_with_restricted_token(cmd, config, job);
        }
        return Err(PsrootError::win32("CreateProcessW(AppContainer)", err));
    }

    // Assign to job before resuming
    let result = job.assign_handle(pi.hProcess);
    if let Err(e) = result {
        unsafe {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        if config.network == NetworkAccess::Full {
            remove_loopback_exemption(&profile_name);
        }
        drop(ac_profile);
        return Err(e);
    }

    unsafe {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Leak the profile intentionally — it'll be cleaned up when the container is removed.
    std::mem::forget(ac_profile);

    Ok(pi.dwProcessId)
}

/// Fallback: spawn with restricted token only (no filesystem read isolation).
fn spawn_with_restricted_token(
    cmd: &str,
    config: &ContainerConfig,
    job: &psroot_job::JobObject,
) -> Result<u32> {
    let token = create_restricted_token()?;

    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = if config.working_directory.starts_with(&config.rootfs_path) {
        config.working_directory.clone()
    } else {
        format!("{}\\Temp", config.rootfs_path)
    };
    let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();
    let env_block = build_env_block(config);

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let flags = 0x00000004u32 | 0x08000000u32 | 0x00000400u32;

    let ok = unsafe {
        CreateProcessAsUserW(
            token,
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            env_block.as_ptr() as *const _,
            cwd_wide.as_ptr(),
            &si,
            &mut pi,
        )
    };

    unsafe { CloseHandle(token) };

    if ok == 0 {
        return Err(PsrootError::last_win32("CreateProcessAsUserW"));
    }

    let result = job.assign_handle(pi.hProcess);
    if let Err(e) = result {
        unsafe {
            TerminateProcess(pi.hProcess, 1);
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
