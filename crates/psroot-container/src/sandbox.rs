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
const WIN_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER: i32 = 88;

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
            // privateNetworkClientServer is required for loopback inbound
            // from non-AC processes (e.g. host browser → AC dev server).
            vec![
                CapabilitySid::create(WIN_CAPABILITY_INTERNET_CLIENT)?,
                CapabilitySid::create(WIN_CAPABILITY_INTERNET_CLIENT_SERVER)?,
                CapabilitySid::create(WIN_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER)?,
            ]
        }
        NetworkAccess::Netstack => {
            // Phase 1: Netstack mirrors Outbound capability-wise. The
            // userland daemon exists but isn't auto-injected yet. See
            // `docs/netstack.md` for the Phase 2 plan.
            vec![CapabilitySid::create(WIN_CAPABILITY_INTERNET_CLIENT)?]
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
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(%stderr, "CheckNetIsolation -a failed (loopback may not work from host)");
        }
        Err(e) => {
            tracing::warn!(error = %e, "CheckNetIsolation.exe not found");
            return Ok(());
        }
    }

    // Also enable inbound. `-is` is implemented as a long-running
    // "Network Isolation Debug Session" that holds the inbound exemption
    // open until it exits (Ctrl-C). We spawn it detached and intentionally
    // do NOT wait — the child stays alive holding the exemption for as
    // long as we (or the user) need it. Tracked in a global registry so
    // `remove_loopback_exemption` can kill it during container teardown.
    match std::process::Command::new("CheckNetIsolation.exe")
        .args(["LoopbackExempt", "-is", &format!("-n={}", profile_name)])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => {
            tracing::debug!(pid = child.id(), profile = %profile_name, "CheckNetIsolation -is session started");
            register_inbound_session(profile_name, child);
        }
        Err(e) => {
            tracing::warn!(error = %e, "CheckNetIsolation -is spawn failed (inbound may not work)");
        }
    }
    Ok(())
}

/// Global registry of long-running `CheckNetIsolation -is` debug sessions
/// keyed by AppContainer profile name. The child must stay alive for the
/// inbound exemption to remain in effect.
fn inbound_session_registry()
    -> &'static std::sync::Mutex<std::collections::HashMap<String, std::process::Child>>
{
    static REG: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, std::process::Child>>,
    > = std::sync::OnceLock::new();
    REG.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn register_inbound_session(profile: &str, child: std::process::Child) {
    if let Ok(mut map) = inbound_session_registry().lock() {
        if let Some(mut prev) = map.insert(profile.to_string(), child) {
            let _ = prev.kill();
            let _ = prev.wait();
        }
    }
}

fn kill_inbound_session(profile: &str) {
    if let Ok(mut map) = inbound_session_registry().lock() {
        if let Some(mut child) = map.remove(profile) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Remove a loopback exemption for an AppContainer profile.
fn remove_loopback_exemption(profile_name: &str) {
    kill_inbound_session(profile_name);
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

    // Grant the AppContainer SID access to the rootfs tree.
    //
    // We deliberately DO NOT use `/T` recursion on the rootfs root, because
    // the rootfs contains junctions (`Windows`, `Program Files`,
    // `ProgramData`) that point to the host's real directories. icacls's
    // `/T` follows mount-point reparse points (the `/L` flag only affects
    // *symbolic* links, not junctions), which would either:
    //   * descend into the host's real `C:\Windows` tree (huge, slow,
    //     thousands of files), or
    //   * hit a permission-denied entry (e.g. `C:\Program Files\AdGuard`)
    //     and abort the whole grant — preventing the container from booting.
    //
    // Strategy: grant on the rootfs root itself (no /T), then enumerate
    // top-level children and recurse only into REAL directories — skipping
    // any reparse points. The junction *targets* are host system folders
    // that already grant ALL APPLICATION PACKAGES read+execute, so we don't
    // need to ACL them.
    let dir_path = std::path::Path::new(dir);

    // Step 1: grant on the rootfs root itself with inheritance, no /T.
    // (OI)(CI) sets default ACL inheritance for new children written by
    // the container at runtime.
    let result = std::process::Command::new("icacls")
        .args([
            dir,
            "/grant",
            &format!("*{}:(OI)(CI)(F)", sid_string),
            "/Q",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match result {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::error!(%stderr, "icacls grant on rootfs root failed");
            return Err(PsrootError::Other(format!(
                "icacls failed to grant AppContainer access to {}: {}",
                dir, stderr.trim()
            )));
        }
        Err(e) => return Err(PsrootError::Io(e)),
    }

    // Step 2: recurse only into real (non-reparse) subdirectories.
    if let Ok(rd) = std::fs::read_dir(dir_path) {
        for entry in rd.flatten() {
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            // Skip symlinks. Junctions are not reported as symlinks by
            // std on Windows, so we also check the reparse-point attribute
            // below.
            if ft.is_symlink() {
                continue;
            }
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    continue;
                }
            }
            if !md.is_dir() {
                continue;
            }
            let child = entry.path();
            let child_str = match child.to_str() {
                Some(s) => s,
                None => continue,
            };
            let r = std::process::Command::new("icacls")
                .args([
                    child_str,
                    "/grant",
                    &format!("*{}:(OI)(CI)(F)", sid_string),
                    "/T",
                    "/C",
                    "/Q",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output();
            match r {
                Ok(o) if o.status.success() => {
                    tracing::debug!(child = %child_str, "icacls grant ok");
                }
                Ok(o) => {
                    let se = String::from_utf8_lossy(&o.stderr);
                    tracing::warn!(child = %child_str, %se, "icacls grant on subtree had errors (continuing)");
                }
                Err(e) => {
                    tracing::warn!(child = %child_str, error = %e, "icacls spawn failed (continuing)");
                }
            }
        }
    }

    tracing::debug!("icacls grant succeeded");
    Ok(())
}

/// Public: convert an AppContainer SID pointer to its string form.
/// Used by callers that need to pass the SID to icacls.
pub fn appcontainer_sid_string(sid: *mut std::ffi::c_void) -> Result<String> {
    unsafe { sid_to_string(sid) }
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

    // Add essential baseline vars that processes need.
    //
    // NOTE: in non-admin AppContainer mode there is no real chroot — the
    // container's `C:\` is the actual host `C:\` with ACLs limiting
    // access. The "rootfs" lives at a host path like
    // `C:\Users\<u>\AppData\Local\Psroot\containers\<id>\rootfs`,
    // and PATH/USERPROFILE/etc. must use that host-view path so PATH
    // lookups inside the container actually find files we put there
    // (e.g. the `winget.ps1` shim under `<rootfs>\bin`).
    let rootfs = &config.rootfs_path;
    let essentials = [
        ("SystemRoot", format!("{}\\Windows", rootfs)),
        ("SystemDrive", "C:".to_string()),
        ("TEMP", format!("{}\\Temp", rootfs)),
        ("TMP", format!("{}\\Temp", rootfs)),
        ("USERPROFILE", format!("{}\\Users\\ContainerUser", rootfs)),
        // Include .PS1 so PATH lookups surface the `winget.ps1` shim and
        // other PowerShell helpers we install into <rootfs>\bin.
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD;.PS1".to_string()),
        ("PATH", format!("{}\\Windows\\System32;{}\\bin;{}\\nodejs", rootfs, rootfs, rootfs)),
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

    // Phase 2: Set clean sandbox values.
    //
    // In non-admin AppContainer mode there is no real chroot — `C:\`
    // inside the container is the host's real `C:\`. So PATH and other
    // path-bearing vars must point at the rootfs via its HOST-view path
    // (e.g. `C:\Users\<u>\AppData\Local\Psroot\containers\<id>\rootfs\bin`)
    // so lookups actually resolve. Container-view (`C:\bin`) would
    // resolve to the wrong place (the host's `C:\bin`, which doesn't exist).
    let mut path_dirs = vec![
        format!("{}\\Windows\\System32", rootfs),
    ];
    let bin_dir = format!("{}\\bin", rootfs);
    if std::path::Path::new(&bin_dir).exists() {
        path_dirs.push(bin_dir);
    }
    let node_dir = format!("{}\\nodejs", rootfs);
    if std::path::Path::new(&node_dir).exists() {
        path_dirs.push(node_dir);
    }

    let sandbox_vars = [
        ("PATH", path_dirs.join(";")),
        // Include .PS1 so cmd.exe's PATH lookup surfaces .ps1 shims
        // (e.g. the winget wrapper). cmd still won't *run* .ps1 directly,
        // but `where winget` and pwsh-as-default will both find it.
        ("PATHEXT", ".COM;.EXE;.BAT;.CMD;.PS1".into()),
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

    // 2b. Grant access to user-supplied bind mounts so the AppContainer
    // can read/write inside them (e.g. ContainerUser home dir mounted from
    // the host). Without this the host directories are reachable via
    // junction but writes fail with ERROR_ACCESS_DENIED.
    for vm in &config.volumes {
        if std::path::Path::new(&vm.host_path).exists() {
            if let Err(e) = grant_appcontainer_access(&vm.host_path, ac_profile.sid()) {
                tracing::warn!(host = %vm.host_path, error = %e, "bind ACL grant failed");
            }
        }
    }

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
    let saved_env = apply_sandbox_env(config);

    // 7. Build command and cwd — start at rootfs root, not rootfs\Temp
    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = config.rootfs_path.clone();
    let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();
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

// ═══════════════════════════════════════════════════════════════════
//  GUI ISOLATION — headful process on an isolated Desktop
// ═══════════════════════════════════════════════════════════════════

/// Spawn a **GUI process** (e.g. Chrome) on an isolated Desktop.
///
/// The process runs headful — it can create windows, render via GPU/DWM,
/// use hardware acceleration — but all windows are invisible to the user's
/// interactive desktop. No cross-desktop message passing or window enumeration
/// is possible.
///
/// This combines:
/// - AppContainer isolation (filesystem/registry boundary)
/// - Desktop isolation (GUI boundary — invisible, no input injection)
/// - Environment sanitization (hide host paths)
///
/// # Use Cases
/// - Browser automation (Puppeteer/Playwright) without `--headless`
/// - Untrusted web content rendering
/// - GUI app testing in CI/CD without visible windows
/// - Screenshot/recording capture from sandboxed apps
///
/// # Returns
/// The AppContainer SID string and the process exit code.
pub fn spawn_gui_isolated(
    cmd: &str,
    config: &ContainerConfig,
) -> Result<(String, u32)> {
    if !appcontainer_available() {
        return Err(PsrootError::Other(
            "GUI isolation requires AppContainer support".into(),
        ));
    }

    // 1. Create AppContainer profile.
    let container_id = config
        .rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("gui-unknown");
    let ac_profile = AppContainerProfile::create(container_id)?;

    // 2. Grant rootfs access.
    grant_appcontainer_access(&config.rootfs_path, ac_profile.sid())?;

    // 3. Network capabilities (GUI apps usually need network).
    let (_cap_sids, cap_attrs) = build_network_capabilities(config.network)?;
    let cap_count = cap_attrs.len() as u32;
    let cap_ptr = if cap_attrs.is_empty() {
        std::ptr::null()
    } else {
        cap_attrs.as_ptr()
    };
    let sec_caps = SecurityCapabilities {
        app_container_sid: ac_profile.sid(),
        capabilities: cap_ptr,
        capability_count: cap_count,
        reserved: 0,
    };

    // 4. Loopback exemption.
    let profile_name = format!("psroot.gui.{}", container_id);
    if config.network == NetworkAccess::Full {
        add_loopback_exemption(&profile_name)?;
    }

    // 5. Attribute list with SECURITY_CAPABILITIES.
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
            return Err(PsrootError::last_win32("UpdateProcThreadAttribute"));
        }
    }

    // 6. Create isolated desktop — GUI processes render here, invisible to user.
    let desktop_config = psroot_desktop::DesktopConfig {
        appcontainer_sid: Some(ac_profile.sid()),
        name: Some(container_id.to_string()),
    };
    let desktop = psroot_desktop::IsolatedDesktop::create(&desktop_config)?;

    tracing::info!(
        desktop = %desktop.lpdesktop_name(),
        cmd = %cmd,
        "Spawning GUI process on isolated desktop"
    );

    // 7. Sanitize environment.
    let saved_env = apply_sandbox_env(config);

    // 8. Build command + cwd.
    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = config.rootfs_path.clone();
    let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();

    // 9. STARTUPINFOEX with lpDesktop set to the isolated desktop.
    let mut desktop_wide = desktop.lpdesktop_wide();
    let mut si_ex: StartupInfoExW = unsafe { std::mem::zeroed() };
    si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    si_ex.startup_info.lpDesktop = desktop_wide.as_mut_ptr();
    si_ex.attribute_list = attr_list.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // EXTENDED_STARTUPINFO_PRESENT — no CREATE_NO_WINDOW (we WANT window creation)
    let flags = 0x00080000u32;

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0, // Don't inherit handles — GUI process doesn't need console
            flags,
            std::ptr::null(),
            cwd_wide.as_ptr(),
            &si_ex as *const _ as *const STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attr_ptr);
    }
    restore_env(saved_env);

    if ok == 0 {
        let err = unsafe { GetLastError() };
        if config.network == NetworkAccess::Full {
            remove_loopback_exemption(&profile_name);
        }
        drop(ac_profile);
        return Err(PsrootError::win32("CreateProcessW(gui_isolated)", err));
    }

    let sid_str = unsafe { sid_to_string(ac_profile.sid()) }?;
    tracing::info!(
        pid = pi.dwProcessId,
        desktop = %desktop.lpdesktop_name(),
        "GUI process started on isolated desktop"
    );

    // 10. Wait for process exit.
    unsafe {
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
    }
    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    // Cleanup — desktop auto-closes via Drop.
    if config.network == NetworkAccess::Full {
        remove_loopback_exemption(&profile_name);
    }
    drop(ac_profile);
    drop(desktop);

    Ok((sid_str, exit_code))
}

/// Spawn a GUI process on an isolated Desktop WITHOUT blocking.
///
/// Same as `spawn_gui_isolated` but returns immediately with handles
/// instead of waiting for exit. Caller is responsible for waiting/terminating.
///
/// Returns (SID string, process handle, isolated desktop).
pub fn spawn_gui_isolated_async(
    cmd: &str,
    config: &ContainerConfig,
) -> Result<(String, psroot_desktop::IsolatedDesktop, u32)> {
    if !appcontainer_available() {
        return Err(PsrootError::Other(
            "GUI isolation requires AppContainer support".into(),
        ));
    }

    let container_id = config
        .rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("gui-unknown");
    let ac_profile = AppContainerProfile::create(container_id)?;
    grant_appcontainer_access(&config.rootfs_path, ac_profile.sid())?;

    let (_cap_sids, cap_attrs) = build_network_capabilities(config.network)?;
    let cap_count = cap_attrs.len() as u32;
    let cap_ptr = if cap_attrs.is_empty() {
        std::ptr::null()
    } else {
        cap_attrs.as_ptr()
    };
    let sec_caps = SecurityCapabilities {
        app_container_sid: ac_profile.sid(),
        capabilities: cap_ptr,
        capability_count: cap_count,
        reserved: 0,
    };

    let profile_name = format!("psroot.gui.{}", container_id);
    if config.network == NetworkAccess::Full {
        add_loopback_exemption(&profile_name)?;
    }

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
            return Err(PsrootError::last_win32("UpdateProcThreadAttribute"));
        }
    }

    let desktop_config = psroot_desktop::DesktopConfig {
        appcontainer_sid: Some(ac_profile.sid()),
        name: Some(container_id.to_string()),
    };
    let desktop = psroot_desktop::IsolatedDesktop::create(&desktop_config)?;

    let saved_env = apply_sandbox_env(config);
    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = config.rootfs_path.clone();
    let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();

    let mut desktop_wide = desktop.lpdesktop_wide();
    let mut si_ex: StartupInfoExW = unsafe { std::mem::zeroed() };
    si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    si_ex.startup_info.lpDesktop = desktop_wide.as_mut_ptr();
    si_ex.attribute_list = attr_list.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let flags = 0x00080000u32; // EXTENDED_STARTUPINFO_PRESENT

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
            &si_ex as *const _ as *const STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attr_ptr);
    }
    restore_env(saved_env);

    if ok == 0 {
        let err = unsafe { GetLastError() };
        if config.network == NetworkAccess::Full {
            remove_loopback_exemption(&profile_name);
        }
        drop(ac_profile);
        return Err(PsrootError::win32("CreateProcessW(gui_isolated_async)", err));
    }

    let sid_str = unsafe { sid_to_string(ac_profile.sid()) }?;

    // Close thread handle (not needed), keep process handle for caller
    unsafe {
        CloseHandle(pi.hThread);
    }

    // NOTE: ac_profile is intentionally leaked here — the caller must
    // ensure cleanup by calling remove_loopback_exemption when done.
    std::mem::forget(ac_profile);

    Ok((sid_str, desktop, pi.dwProcessId))
}

// ═══════════════════════════════════════════════════════════════════
//  GUI + PLAN — staged binary inside AppContainer + isolated Desktop
// ═══════════════════════════════════════════════════════════════════

/// Spawn a GUI application from a `LaunchPlan` on an isolated Desktop.
///
/// This is the **correct** way to run a browser in psroot:
/// 1. The resolver probes the host for Chrome/Edge
/// 2. The stager hardlinks the browser files INTO the container's rootfs
/// 3. AppContainer restricts filesystem access to ONLY the rootfs
/// 4. An isolated Desktop hides the GUI from the user
///
/// The browser binary runs from INSIDE the container (e.g. `{rootfs}\Chrome\chrome.exe`),
/// NOT from the host path. It cannot access host files, registry, or named objects.
///
/// # Returns
/// (AppContainer SID string, exit code)
pub fn spawn_gui_plan(
    plan: &psroot_shell_resolver::LaunchPlan,
    config: &ContainerConfig,
) -> Result<(String, u32)> {
    if !appcontainer_available() {
        return Err(PsrootError::Other(
            "GUI isolation requires AppContainer support".into(),
        ));
    }

    // 1. Create AppContainer profile.
    let container_id = config
        .rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("gui-unknown");
    let ac_profile = AppContainerProfile::create(container_id)?;
    let sid_str = unsafe { sid_to_string(ac_profile.sid()) }?;

    // 2. Grant base rootfs access.
    grant_appcontainer_access(&config.rootfs_path, ac_profile.sid())?;

    // 3. ★ STAGE the plan — hardlinks Chrome into rootfs, applies ACEs.
    let outcome = psroot_rootfs_stager::apply_plan(plan, &sid_str, container_id)
        .map_err(|e| PsrootError::Other(format!("stager.apply_plan: {}", e)))?;
    tracing::info!(
        cache_dir = %outcome.cache_dir.display(),
        cache_hit = outcome.cache_hit,
        ops_run = outcome.stage_ops_run,
        ops_skipped = outcome.stage_ops_skipped,
        aces = outcome.aces_applied.len(),
        "gui stager done"
    );

    // 4. Network capabilities (browsers need network).
    let (_cap_sids, cap_attrs) = build_network_capabilities(config.network)?;
    let cap_count = cap_attrs.len() as u32;
    let cap_ptr = if cap_attrs.is_empty() {
        std::ptr::null()
    } else {
        cap_attrs.as_ptr()
    };
    let sec_caps = SecurityCapabilities {
        app_container_sid: ac_profile.sid(),
        capabilities: cap_ptr,
        capability_count: cap_count,
        reserved: 0,
    };

    let profile_name = format!("psroot.gui.{}", container_id);
    if config.network == NetworkAccess::Full {
        add_loopback_exemption(&profile_name)?;
    }

    // 5. Attribute list with SECURITY_CAPABILITIES.
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
            return Err(PsrootError::last_win32("UpdateProcThreadAttribute"));
        }
    }

    // 6. Create isolated desktop — the browser renders here, invisible to user.
    let desktop_config = psroot_desktop::DesktopConfig {
        appcontainer_sid: Some(ac_profile.sid()),
        name: Some(container_id.to_string()),
    };
    let desktop = psroot_desktop::IsolatedDesktop::create(&desktop_config)?;

    tracing::info!(
        desktop = %desktop.lpdesktop_name(),
        entry = %plan.entry.display(),
        "Spawning staged GUI on isolated desktop"
    );

    // 7. Sanitize environment + layer plan env.
    let saved_env = apply_sandbox_env_with_plan(config, plan);

    // 8. Build command line from plan.
    let mut cmdline = quote_arg(&plan.entry.display().to_string());
    for arg in &plan.args {
        cmdline.push(' ');
        cmdline.push_str(&quote_arg(arg));
    }
    let mut cmd_wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd_str = plan.cwd.display().to_string();
    let cwd_wide: Vec<u16> = cwd_str.encode_utf16().chain(std::iter::once(0)).collect();

    // 9. STARTUPINFOEX with lpDesktop pointing to isolated desktop.
    let mut desktop_wide = desktop.lpdesktop_wide();
    let mut si_ex: StartupInfoExW = unsafe { std::mem::zeroed() };
    si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    si_ex.startup_info.lpDesktop = desktop_wide.as_mut_ptr();
    si_ex.attribute_list = attr_list.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // EXTENDED_STARTUPINFO_PRESENT — no CREATE_NO_WINDOW (GUI needs windows)
    let flags = 0x00080000u32;

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0, // Don't inherit handles — GUI process doesn't need console
            flags,
            std::ptr::null(),
            cwd_wide.as_ptr(),
            &si_ex as *const _ as *const STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attr_ptr);
    }
    restore_env(saved_env);

    if ok == 0 {
        let err = unsafe { GetLastError() };
        if config.network == NetworkAccess::Full {
            remove_loopback_exemption(&profile_name);
        }
        drop(ac_profile);
        return Err(PsrootError::win32("CreateProcessW(gui_plan)", err));
    }

    tracing::info!(
        pid = pi.dwProcessId,
        desktop = %desktop.lpdesktop_name(),
        entry = %plan.entry.display(),
        "Staged GUI process started on isolated desktop"
    );

    // 10. Wait for process exit.
    unsafe {
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
    }
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
    drop(desktop);

    Ok((sid_str, exit_code))
}

// ═══════════════════════════════════════════════════════════════════
//  PLAN-AWARE SPAWN — uses a resolver `LaunchPlan`
// ═══════════════════════════════════════════════════════════════════

/// Build env for a plan: standard sandbox env + plan.env on top, with special
/// handling for `PATH_PREPEND` and `PATHEXT_APPEND`.
fn apply_sandbox_env_with_plan(
    config: &ContainerConfig,
    plan: &psroot_shell_resolver::LaunchPlan,
) -> Vec<(String, Option<String>)> {
    let mut saved = apply_sandbox_env(config);

    // Layer plan env vars on top.
    for (k, v) in &plan.env {
        match k.as_str() {
            "PATH_PREPEND" => {
                let cur = std::env::var("PATH").unwrap_or_default();
                let new = if cur.is_empty() {
                    v.clone()
                } else {
                    format!("{};{}", v, cur)
                };
                saved.push(("PATH".to_string(), Some(cur)));
                std::env::set_var("PATH", &new);
            }
            "PATHEXT_APPEND" => {
                let cur = std::env::var("PATHEXT").unwrap_or_default();
                let new = if cur.is_empty() {
                    v.clone()
                } else {
                    format!("{};{}", cur, v)
                };
                saved.push(("PATHEXT".to_string(), Some(cur)));
                std::env::set_var("PATHEXT", &new);
            }
            _ => {
                let prev = std::env::var(k).ok();
                saved.push((k.clone(), prev));
                std::env::set_var(k, v);
            }
        }
    }
    saved
}

/// Quote a path for inclusion in a Windows command-line.
fn quote_arg(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    if s.chars().any(|c| c.is_whitespace() || c == '"') {
        let mut q = String::from("\"");
        for c in s.chars() {
            if c == '"' {
                q.push('\\');
            }
            q.push(c);
        }
        q.push('"');
        q
    } else {
        s.to_string()
    }
}

/// Spawn an **interactive** shell from a `LaunchPlan`.
///
/// Same isolation guarantees as `spawn_interactive` but uses the plan's
/// entry path / args / cwd / env instead of a single command string.
///
/// Returns the AppContainer SID string (so the caller can persist it for
/// later ACE revocation) and the shell's exit code.
pub fn spawn_interactive_plan(
    plan: &psroot_shell_resolver::LaunchPlan,
    config: &ContainerConfig,
) -> Result<(String, u32)> {
    if !appcontainer_available() {
        return Err(PsrootError::Other(
            "Interactive shell requires AppContainer support".into(),
        ));
    }

    // 1. Create AppContainer profile.
    let container_id = config
        .rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("unknown");
    let ac_profile = AppContainerProfile::create(container_id)?;
    let sid_str = unsafe { sid_to_string(ac_profile.sid()) }?;

    // 2. Grant base rootfs access (so the container can read its own rootfs).
    grant_appcontainer_access(&config.rootfs_path, ac_profile.sid())?;

    // 3. Stage the plan (cache, ACEs).
    let outcome = psroot_rootfs_stager::apply_plan(plan, &sid_str, container_id)
        .map_err(|e| PsrootError::Other(format!("stager.apply_plan: {}", e)))?;
    tracing::info!(
        cache_dir = %outcome.cache_dir.display(),
        cache_hit = outcome.cache_hit,
        ops_run = outcome.stage_ops_run,
        ops_skipped = outcome.stage_ops_skipped,
        aces = outcome.aces_applied.len(),
        "stager done"
    );

    // 4. Network capabilities.
    let (_cap_sids, cap_attrs) = build_network_capabilities(config.network)?;
    let cap_count = cap_attrs.len() as u32;
    let cap_ptr = if cap_attrs.is_empty() {
        std::ptr::null()
    } else {
        cap_attrs.as_ptr()
    };
    let sec_caps = SecurityCapabilities {
        app_container_sid: ac_profile.sid(),
        capabilities: cap_ptr,
        capability_count: cap_count,
        reserved: 0,
    };

    let profile_name = format!("psroot.container.{}", container_id);
    if config.network == NetworkAccess::Full {
        add_loopback_exemption(&profile_name)?;
    }

    // 5. Attribute list.
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
            return Err(PsrootError::last_win32("UpdateProcThreadAttribute"));
        }
    }

    // 6. Apply env (sandbox base + plan env on top).
    let saved_env = apply_sandbox_env_with_plan(config, plan);

    // 7. Build command line + cwd.
    let mut cmdline = quote_arg(&plan.entry.display().to_string());
    for arg in &plan.args {
        cmdline.push(' ');
        cmdline.push_str(&quote_arg(arg));
    }
    let mut cmd_wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd_str = plan.cwd.display().to_string();
    let cwd_wide: Vec<u16> = cwd_str.encode_utf16().chain(std::iter::once(0)).collect();

    // 8. CreateProcess (interactive — inherit handles, no NO_WINDOW).
    let mut si_ex: StartupInfoExW = unsafe { std::mem::zeroed() };
    si_ex.startup_info.cb = std::mem::size_of::<StartupInfoExW>() as u32;
    si_ex.attribute_list = attr_list.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let flags = 0x00080000u32; // EXTENDED_STARTUPINFO_PRESENT

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            flags,
            std::ptr::null(),
            cwd_wide.as_ptr(),
            &si_ex as *const _ as *const STARTUPINFOW,
            &mut pi,
        )
    };
    unsafe {
        DeleteProcThreadAttributeList(attr_ptr);
    }
    restore_env(saved_env);

    if ok == 0 {
        let err = unsafe { GetLastError() };
        if config.network == NetworkAccess::Full {
            remove_loopback_exemption(&profile_name);
        }
        drop(ac_profile);
        return Err(PsrootError::win32(
            "CreateProcessW(interactive_plan)",
            err,
        ));
    }

    unsafe {
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
    }
    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    if config.network == NetworkAccess::Full {
        remove_loopback_exemption(&profile_name);
    }
    drop(ac_profile);

    Ok((sid_str, exit_code))
}

/// Spawn an **interactive** shell using a **Server Silo** for full filesystem
/// isolation. The process sees ONLY the rootfs as `C:\`, no host filesystem
/// paths are visible — like Docker.
///
/// Requires **Administrator** and **Windows 10 1809+** (build 17763).
///
/// Falls back to `spawn_interactive_plan` (AppContainer-only) if admin/silo
/// is not available.
pub fn spawn_interactive_plan_silo(
    plan: &psroot_shell_resolver::LaunchPlan,
    config: &ContainerConfig,
) -> Result<(String, u32)> {
    use psroot_silo::Silo;

    let iso = IsolationLevel::detect();
    if !iso.server_silo {
        tracing::warn!(
            "Server Silo not available (admin={}, build={}). Using per-process device map for filesystem isolation.",
            iso.is_admin,
            iso.build_number
        );
        return spawn_interactive_plan_devicemap(plan, config);
    }

    tracing::info!("Using Server Silo for full filesystem isolation");

    let container_id = config
        .rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("unknown");

    // 1. Stage the plan FIRST (before silo creation). We use the generic
    //    ALL APPLICATION PACKAGES SID here because the silo process doesn't
    //    run in an AppContainer — it runs as a normal user but inside a
    //    silo namespace. The `psroot setup` command already granted
    //    S-1-15-2-1 on the cache root, so we don't need per-container ACEs.
    let outcome = psroot_rootfs_stager::apply_plan(
        plan,
        crate::setup::ALL_APP_PACKAGES_SID,
        container_id,
    )
    .map_err(|e| PsrootError::Other(format!("stager.apply_plan: {}", e)))?;
    tracing::info!(
        cache_dir = %outcome.cache_dir.display(),
        cache_hit = outcome.cache_hit,
        ops_run = outcome.stage_ops_run,
        "stager done (silo mode)"
    );

    // 2. Apply sandbox environment variables.
    let saved_env = apply_sandbox_env_with_plan(config, plan);

    // 3. Collect env as tuples, translating host-absolute rootfs paths
    //    to silo-relative (C:\) paths. Inside the silo, C: = rootfs.
    //    Cache dir maps to P:\<shell-name> via the extra P: drive.
    let rootfs = &config.rootfs_path;
    let cache_parent = plan.cache_dir.parent()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| plan.cache_dir.display().to_string());
    let env_tuples: Vec<(String, String)> = std::env::vars()
        .map(|(k, v)| {
            // Replace cache parent path → P:, then rootfs → C:
            let translated = v.replace(&cache_parent, "P:")
                              .replace(rootfs, "C:");
            (k, translated)
        })
        .collect();

    // 4. Build command line (host-absolute, we'll translate below).
    let mut cmdline = quote_arg(&plan.entry.display().to_string());
    for arg in &plan.args {
        cmdline.push(' ');
        cmdline.push_str(&quote_arg(arg));
    }

    // 5. Create the Server Silo. The namespace maps C: → rootfs.
    //    Also map P: → cache root so the shell binaries are accessible.
    let resources = config.resources.clone();
    let extra_drives: Vec<(&str, &str)> = vec![("P:", &cache_parent)];
    let mut silo = match Silo::create(&config.rootfs_path, Some(&resources), &extra_drives) {
        Ok(s) => s,
        Err(e) => {
            let msg = format!("{}", e);
            // Kernel refuses to set the silo root directory — most common cause
            // on Win10/11 client SKUs is that the Containers optional feature
            // is not enabled, which leaves the Server Silo filesystem-isolation
            // path disabled in the kernel.
            if msg.contains("SetInformationJobObject(SiloRoot)") {
                tracing::warn!(
                    "Server Silo filesystem isolation unavailable on this system ({}). \
                     Falling back to per-process device map (no Windows feature required).",
                    msg
                );
                // Restore env before fallback path re-applies its own env.
                restore_env(saved_env);
                return spawn_interactive_plan_devicemap(plan, config);
            }
            return Err(PsrootError::Other(format!("Silo::create: {}", e)));
        }
    };
    tracing::info!(silo_id = silo.silo_id(), rootfs = %config.rootfs_path, "Silo ready");

    // 6. Spawn interactive process inside the silo.
    let cwd_str = plan.cwd.display().to_string();
    // Inside the silo, C: = rootfs, P: = cache parent.
    // Translate absolute host paths to silo-relative paths.
    // Note: <rootfs>\PSH is a junction to cache_dir, so paths under
    // rootfs\PSH should be translated to P:\<shell-ver>\...
    let cache_dir_str = plan.cache_dir.display().to_string();
    let psh_prefix = format!("{}\\PSH", &config.rootfs_path);
    let translate = |s: &str| -> String {
        // rootfs\PSH\foo → cache_dir\foo → P:\<ver>\foo
        if s.starts_with(&psh_prefix) {
            let suffix = &s[psh_prefix.len()..];
            let translated = format!("{}{}", cache_dir_str, suffix);
            // Now translate cache_dir to P:
            if translated.starts_with(&cache_parent) {
                let p_suffix = &translated[cache_parent.len()..];
                return format!("P:{}", if p_suffix.is_empty() { "\\" } else { p_suffix });
            }
            return translated;
        }
        if s.starts_with(&cache_parent) {
            let suffix = &s[cache_parent.len()..];
            format!("P:{}", if suffix.is_empty() { "\\" } else { suffix })
        } else if s.starts_with(&config.rootfs_path) {
            let suffix = &s[config.rootfs_path.len()..];
            format!("C:{}", if suffix.is_empty() { "\\" } else { suffix })
        } else {
            s.to_string()
        }
    };

    let silo_cwd = translate(&cwd_str);
    let entry_str = plan.entry.display().to_string();
    let silo_entry = translate(&entry_str);

    // Rebuild the command with silo-relative paths.
    let mut silo_cmdline = quote_arg(&silo_entry);
    for arg in &plan.args {
        silo_cmdline.push(' ');
        silo_cmdline.push_str(&quote_arg(arg));
    }

    let _pinfo = silo.spawn_interactive(
        &silo_cmdline,
        Some(&env_tuples),
        Some(&silo_cwd),
    )?;

    // 7. Wait for the shell to exit.
    let proc_handle = silo.open_init_process()?;

    // Restore env before blocking so the host doesn't keep sandbox vars.
    restore_env(saved_env);

    unsafe {
        WaitForSingleObject(proc_handle, 0xFFFFFFFF);
    }
    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(proc_handle, &mut exit_code);
        CloseHandle(proc_handle);
    }

    // 8. Silo is dropped here — terminates remaining processes + cleans namespace.
    let sid_str = format!("silo-{}", silo.silo_id());
    Ok((sid_str, exit_code))
}

/// Docker-like filesystem isolation **without** the Windows Containers
/// optional feature. Implemented via a per-process DOS device map
/// (NtSetInformationProcess(ProcessDeviceMap)): the child sees `C:\` as
/// the container rootfs while inheriting all other devices from the host
/// global namespace.
///
/// Requires admin (to set DOS device map on a different process). Does NOT
/// require Server Silo, Bind Filter, or any optional feature.
pub fn spawn_interactive_plan_devicemap(
    plan: &psroot_shell_resolver::LaunchPlan,
    config: &ContainerConfig,
) -> Result<(String, u32)> {
    use psroot_namespace::ProcessDeviceMap;

    tracing::info!(
        rootfs = %config.rootfs_path,
        "Using per-process device map for filesystem isolation"
    );

    let container_id = config
        .rootfs_path
        .rsplit('\\')
        .nth(1)
        .unwrap_or("unknown");

    // 1. Stage the plan first.
    let outcome = psroot_rootfs_stager::apply_plan(
        plan,
        crate::setup::ALL_APP_PACKAGES_SID,
        container_id,
    )
    .map_err(|e| PsrootError::Other(format!("stager.apply_plan: {}", e)))?;
    tracing::info!(
        cache_dir = %outcome.cache_dir.display(),
        cache_hit = outcome.cache_hit,
        ops_run = outcome.stage_ops_run,
        "stager done (devicemap mode)"
    );

    // 1b. The stager normally creates `<rootfs>\PSH` as a junction targeting
    //     the shared cache (`<cache_parent>\<shell-name>`). That works for
    //     silo mode (where the host C: is still visible alongside the silo
    //     root), but in devicemap mode our private map makes C: → rootfs and
    //     the junction's stored target (`C:\Users\...\.psroot\cache\...`)
    //     would be re-resolved against our private C:, which doesn't contain
    //     the cache. Worse, even if we add a P: drive symlink to the cache
    //     and rewrite the entry path, .NET-based shells (pwsh) reject the
    //     resulting path during their own canonicalization and abort with
    //     "Failed to resolve full path of the current executable".
    //
    //     Solution: blow away the junction and replace it with a directory of
    //     hardlinked files mirroring the cache contents. Hardlinks are nearly
    //     free (NTFS just bumps a refcount) and they live on the same volume
    //     as the rootfs, so `<rootfs>\PSH\<shell>.exe` is a *real* file path
    //     that resolves naturally to `C:\PSH\<shell>.exe` after the swap with
    //     no symlink games and no path-canonicalization headaches.
    let psh_dir_host = std::path::PathBuf::from(&config.rootfs_path).join("PSH");
    materialize_psh_via_hardlinks(&plan.cache_dir, &psh_dir_host)
        .map_err(|e| PsrootError::Other(format!("materialize_psh_via_hardlinks: {}", e)))?;
    tracing::info!(
        psh_dir = %psh_dir_host.display(),
        cache = %plan.cache_dir.display(),
        "PSH materialised as hardlink mirror inside rootfs"
    );

    // 2. Apply sandbox env vars and translate paths the same way silo mode does.
    let saved_env = apply_sandbox_env_with_plan(config, plan);
    let rootfs = &config.rootfs_path;

    let env_tuples: Vec<(String, String)> = std::env::vars()
        .map(|(k, v)| {
            let translated = v.replace(rootfs, "C:");
            (k, translated)
        })
        .collect();

    // Path translation host → in-container view. With PSH materialised inside
    // the rootfs, every shell-related path lives under the rootfs prefix and
    // maps cleanly to C:.
    let translate = |s: &str| -> String {
        if s.starts_with(&config.rootfs_path) {
            let suffix = &s[config.rootfs_path.len()..];
            format!("C:{}", if suffix.is_empty() { "\\" } else { suffix })
        } else {
            s.to_string()
        }
    };

    let cwd_str = plan.cwd.display().to_string();
    let entry_str = plan.entry.display().to_string();
    let in_cwd = translate(&cwd_str);
    let in_entry = translate(&entry_str);

    // After the device-map swap, `C:` resolves to the rootfs. We must pass the
    // **in-container** entry path on the command line; otherwise the host path
    // we baked in would be re-resolved against the new C: by the child's own
    // GetModuleFileName/path-canonicalization logic and fail (e.g. pwsh prints
    // "Failed to resolve full path of the current executable").
    let mut cmdline = quote_arg(&in_entry);
    for arg in &plan.args {
        cmdline.push(' ');
        cmdline.push_str(&quote_arg(arg));
    }

    // 3. Build the private device map BEFORE spawning so we fail fast.
    //    User --bind mounts with a drive-letter target (e.g. `M:`) become
    //    extra_drives entries. Path-targeted binds are materialised as
    //    volume-GUID junctions in the rootfs below.
    let mut extra_drives: Vec<(String, String)> = Vec::new();
    for vm in &config.volumes {
        let cp = vm.container_path.trim();
        // Drive-letter target: `X:` (len 2) or `X:\` (trailing slash only).
        let is_drive_letter = cp.len() == 2
            && cp.as_bytes()[0].is_ascii_alphabetic()
            && cp.as_bytes()[1] == b':';
        let is_drive_letter_slash = cp.len() == 3
            && cp.as_bytes()[0].is_ascii_alphabetic()
            && cp.as_bytes()[1] == b':'
            && (cp.as_bytes()[2] == b'\\' || cp.as_bytes()[2] == b'/');
        if is_drive_letter || is_drive_letter_slash {
            extra_drives.push((cp[..2].to_string(), vm.host_path.clone()));
            tracing::info!(
                letter = %&cp[..2],
                host = %vm.host_path,
                "bind (drive-letter target)"
            );
        } else {
            // Path target: create a junction inside the rootfs with a
            // volume-GUID target so it survives the device-map swap.
            // container_path should be of form `C:\some\path` — we strip
            // the leading `C:` and join against rootfs.
            let in_rootfs_suffix = if cp.len() >= 2 && cp.as_bytes()[1] == b':' {
                &cp[2..]
            } else {
                cp
            };
            let suffix_trim = in_rootfs_suffix.trim_start_matches('\\').trim_start_matches('/');
            let junction_path =
                std::path::Path::new(&config.rootfs_path).join(suffix_trim);
            if let Err(e) = create_volume_guid_junction(&junction_path, &vm.host_path) {
                tracing::warn!(
                    host = %vm.host_path,
                    container = %cp,
                    error = %e,
                    "bind (path target): junction failed"
                );
            } else {
                tracing::info!(
                    host = %vm.host_path,
                    container = %cp,
                    "bind (path target) junction created"
                );
            }
        }
    }
    let extra_drives_refs: Vec<(&str, &str)> = extra_drives
        .iter()
        .map(|(l, h)| (l.as_str(), h.as_str()))
        .collect();
    let device_map = match ProcessDeviceMap::build(&config.rootfs_path, &extra_drives_refs) {
        Ok(m) => m,
        Err(e) => {
            restore_env(saved_env);
            return Err(PsrootError::Other(format!("ProcessDeviceMap::build: {}", e)));
        }
    };

    // 4. Apply the device map to OURSELVES first. CreateProcess opens the
    //    EXE using the calling process's path resolution, so passing
    //    `C:\PSH\<shell>.exe` after the swap correctly resolves to the rootfs.
    //    `ObSetDeviceMap` requires `SeTcbPrivilege` — we don't have it on a
    //    plain admin token, so impersonate SYSTEM (winlogon token dup) for the
    //    set call. Note: this changes the device map for the rest of *this*
    //    process's lifetime, which is fine for `psroot shell` (it exits when
    //    the child exits).
    let impersonated = psroot_silo::impersonate_system_token().is_ok();
    if !impersonated {
        tracing::warn!("Could not impersonate SYSTEM — device map call may fail");
    }
    let assign_self_res = device_map.assign_to_current();
    if impersonated {
        psroot_silo::revert_to_self();
    }
    if let Err(e) = assign_self_res {
        restore_env(saved_env);
        return Err(PsrootError::Other(format!(
            "ProcessDeviceMap::assign_to_current: {} (run psroot elevated; \
             SYSTEM impersonation status: {})",
            e, impersonated
        )));
    }
    tracing::info!(
        rootfs = %config.rootfs_path,
        "device map applied to self; child will inherit"
    );

    // 5. Now CreateProcess against the in-container path. The EXE file is
    //    opened via the (just-swapped) device map → resolves to the rootfs.
    let mut cmd_wide: Vec<u16> = cmdline.encode_utf16().chain(std::iter::once(0)).collect();
    let env_block = build_env_block_w(&env_tuples);
    let cwd_wide: Vec<u16> = in_cwd
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // inherit handles for interactive console
            CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            env_block.as_ptr() as *const _,
            cwd_wide.as_ptr(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        restore_env(saved_env);
        return Err(PsrootError::Win32 {
            op: "CreateProcessW(devicemap)".into(),
            code: err,
        });
    }

    // CRITICAL: The DOS device map is NOT inherited by child processes — it
    // is a per-process property. Without explicitly assigning it to the
    // child, the child sees the global C: (host filesystem) for all its
    // FS operations, even though our process opened the image through the
    // private map. Apply now while the child is suspended so the loader
    // sees our private map from its first instruction.
    let imp2 = psroot_silo::impersonate_system_token().is_ok();
    let assign_child_res = device_map.assign_to_process(pi.hProcess as isize);
    if imp2 {
        psroot_silo::revert_to_self();
    }
    if let Err(e) = assign_child_res {
        unsafe {
            // Best effort: kill the orphaned suspended child.
            let _ = windows_sys::Win32::System::Threading::TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        restore_env(saved_env);
        return Err(PsrootError::Other(format!(
            "ProcessDeviceMap::assign_to_process(child): {}",
            e
        )));
    }
    tracing::info!(pid = pi.dwProcessId, "device map assigned to child process");

    unsafe {
        ResumeThread(pi.hThread);
    }
    tracing::info!(
        pid = pi.dwProcessId,
        rootfs = %config.rootfs_path,
        "child started inside private device map: C:\\ = rootfs"
    );

    // 7. Wait for exit.
    restore_env(saved_env);
    let mut exit_code: u32 = 0;
    unsafe {
        WaitForSingleObject(pi.hProcess, 0xFFFFFFFF);
        GetExitCodeProcess(pi.hProcess, &mut exit_code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Ok((format!("devicemap-{}", pi.dwProcessId), exit_code))
}

/// Replace `<rootfs>\PSH` (which the stager creates as a junction pointing
/// at the shared cache) with a directory of hardlinked files mirroring the
/// cache contents. Used by devicemap mode so that shell binaries are
/// physically resident on the rootfs volume and resolve via `C:\PSH\...`
/// after the device-map swap, with no symlink hop.
///
/// Hardlinks across directories on the same volume are O(1) on NTFS. Falls
/// back to a copy if hardlink fails (e.g. cross-volume rootfs).
fn materialize_psh_via_hardlinks(
    cache_dir: &std::path::Path,
    psh_dst: &std::path::Path,
) -> std::io::Result<()> {
    use std::fs;

    // Remove existing PSH (junction or directory).
    if psh_dst.exists() || psh_dst.symlink_metadata().is_ok() {
        // Try as directory first (works for both real dir and junction on
        // Windows because remove_dir doesn't follow junctions).
        let _ = fs::remove_dir(psh_dst);
        // If still there (real dir with contents), nuke recursively.
        if psh_dst.exists() {
            fs::remove_dir_all(psh_dst)?;
        }
    }
    fs::create_dir_all(psh_dst)?;

    fn walk(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            let s = entry.path();
            let d = dst.join(entry.file_name());
            if ft.is_dir() {
                std::fs::create_dir_all(&d)?;
                walk(&s, &d)?;
            } else if ft.is_file() {
                if std::fs::hard_link(&s, &d).is_err() {
                    std::fs::copy(&s, &d)?;
                }
            } else if ft.is_symlink() {
                // Best-effort: copy through the symlink.
                if std::fs::copy(&s, &d).is_err() {
                    // ignore broken symlinks
                }
            }
        }
        Ok(())
    }
    walk(cache_dir, psh_dst)
}

/// UTF-16LE env block: KEY=VAL\0KEY=VAL\0\0.
fn build_env_block_w(vars: &[(String, String)]) -> Vec<u16> {
    let mut block = Vec::new();
    for (k, v) in vars {
        let entry = format!("{}={}", k, v);
        block.extend(entry.encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// Create an NTFS directory junction whose target is stored as a
/// **volume-GUID path** (`\??\Volume{GUID}\path\relative`) rather than a
/// drive-letter DOS path. Volume-GUID symlinks are resolved by the NTFS
/// driver via the global object manager and therefore survive an
/// `NtSetInformationProcess(ProcessDeviceMap)` swap — a drive-letter
/// junction (created by `mklink /J`) would be resolved through the
/// PRIVATE device map after the swap and end up nowhere.
///
/// This is what makes Docker-style `--bind C:\host\path:C:\container\path`
/// actually work in device-map mode.
pub fn create_volume_guid_junction(
    link_path: &std::path::Path,
    host_target: &str,
) -> std::io::Result<()> {
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, GetVolumeNameForVolumeMountPointW, GetVolumePathNameW,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const FILE_SHARE_READ: u32 = 0x1;
    const FILE_SHARE_WRITE: u32 = 0x2;
    const FILE_SHARE_DELETE: u32 = 0x4;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FSCTL_SET_REPARSE_POINT: u32 = 0x000900A4;
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;
    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

    // Resolve volume GUID for the host target.
    let host_target_w: Vec<u16> = std::ffi::OsStr::new(host_target)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut vol_path_buf = [0u16; 260];
    let ok = unsafe {
        GetVolumePathNameW(
            host_target_w.as_ptr(),
            vol_path_buf.as_mut_ptr(),
            vol_path_buf.len() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("GetVolumePathNameW('{}') failed", host_target),
        ));
    }
    let mut vol_guid_buf = [0u16; 260];
    let ok = unsafe {
        GetVolumeNameForVolumeMountPointW(
            vol_path_buf.as_ptr(),
            vol_guid_buf.as_mut_ptr(),
            vol_guid_buf.len() as u32,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "GetVolumeNameForVolumeMountPointW failed",
        ));
    }
    // vol_guid_buf is like `\\?\Volume{GUID}\` — strip `\\?\` and trailing `\`.
    let vol_guid: String = {
        let len = vol_guid_buf.iter().position(|&c| c == 0).unwrap_or(vol_guid_buf.len());
        String::from_utf16_lossy(&vol_guid_buf[..len])
    };
    let vol_guid_trimmed = vol_guid
        .strip_prefix("\\\\?\\")
        .unwrap_or(&vol_guid)
        .trim_end_matches('\\');
    // vol_path (mount point, drive root) is something like `C:\`.
    let vol_path_str = {
        let len = vol_path_buf.iter().position(|&c| c == 0).unwrap_or(vol_path_buf.len());
        String::from_utf16_lossy(&vol_path_buf[..len])
    };
    // Compute the relative path from volume root to host target.
    let host_canonical = fs::canonicalize(host_target)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("canonicalize: {}", e)))?;
    let host_canonical_str = host_canonical.to_string_lossy().replace("\\\\?\\", "");
    let rel = host_canonical_str
        .strip_prefix(&vol_path_str)
        .unwrap_or(host_canonical_str.trim_start_matches(|c: char| c.is_ascii_alphabetic())
            .trim_start_matches(':')
            .trim_start_matches('\\'))
        .trim_start_matches('\\');

    // Final print-name + substitute-name for the reparse point.
    // Substitute name (kernel target) is `\??\Volume{GUID}\<rel>` — the
    // `\??\` is the current process's DOS device map root, but
    // `Volume{GUID}` is a GLOBAL alias resolved directly by the object
    // manager / NTFS driver, so it bypasses any per-process remapping.
    let substitute = format!("\\??\\{}\\{}", vol_guid_trimmed, rel);
    let print_name = format!("{}{}", vol_path_str, rel);

    // Ensure parent dir exists + link dir exists (empty) before issuing
    // the reparse-point IOCTL.
    if let Some(parent) = link_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if link_path.exists() {
        // Remove existing file/dir (ignore errors for junctions).
        let _ = fs::remove_dir(link_path);
        if link_path.exists() {
            let _ = fs::remove_dir_all(link_path);
        }
    }
    fs::create_dir_all(link_path)?;

    // Open the link with FILE_FLAG_OPEN_REPARSE_POINT to issue IOCTL.
    let link_w: Vec<u16> = link_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            link_w.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            0 as HANDLE,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    // Build REPARSE_DATA_BUFFER for mount-point (junction).
    // Layout (mount point):
    //   ULONG  ReparseTag = IO_REPARSE_TAG_MOUNT_POINT
    //   USHORT ReparseDataLength
    //   USHORT Reserved = 0
    //   USHORT SubstituteNameOffset
    //   USHORT SubstituteNameLength
    //   USHORT PrintNameOffset
    //   USHORT PrintNameLength
    //   WCHAR  PathBuffer[] = Substitute\0Print\0
    let substitute_u16: Vec<u16> = substitute.encode_utf16().collect();
    let print_u16: Vec<u16> = print_name.encode_utf16().collect();
    let sub_len_bytes = (substitute_u16.len() * 2) as u16;
    let prt_len_bytes = (print_u16.len() * 2) as u16;
    let sub_off: u16 = 0;
    let prt_off: u16 = sub_len_bytes + 2;
    let path_buffer_total = (sub_len_bytes + 2 + prt_len_bytes + 2) as usize;
    // MountPointBuffer fields start after ReparseTag+Length+Reserved (8 bytes).
    // MountPointBuffer itself is 8 bytes of header + path buffer.
    let data_len = 8 + path_buffer_total;
    let mut buf = vec![0u8; 8 + data_len]; // full: reparse tag+len+reserved
    // Header
    buf[0..4].copy_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    buf[4..6].copy_from_slice(&(data_len as u16).to_le_bytes());
    buf[6..8].copy_from_slice(&0u16.to_le_bytes());
    // MountPointReparseBuffer
    buf[8..10].copy_from_slice(&sub_off.to_le_bytes());
    buf[10..12].copy_from_slice(&sub_len_bytes.to_le_bytes());
    buf[12..14].copy_from_slice(&prt_off.to_le_bytes());
    buf[14..16].copy_from_slice(&prt_len_bytes.to_le_bytes());
    // PathBuffer
    let mut off = 16;
    for w in &substitute_u16 {
        buf[off..off + 2].copy_from_slice(&w.to_le_bytes());
        off += 2;
    }
    off += 2; // NUL
    for w in &print_u16 {
        buf[off..off + 2].copy_from_slice(&w.to_le_bytes());
        off += 2;
    }

    let mut bytes_returned: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(
            handle,
            FSCTL_SET_REPARSE_POINT,
            buf.as_ptr() as *const _,
            buf.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    let err = if ok == 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
    // silence unused var when Path trait used only for link_path reference
    let _ = Path::new(".");
    if let Some(e) = err {
        return Err(e);
    }
    Ok(())
}


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
