//! One-time machine setup for psroot AppContainer compatibility.
//!
//! AppContainer processes use a restricted token. Many Windows volume and
//! filesystem operations check for the well-known "ALL APPLICATION PACKAGES"
//! SID (`S-1-15-2-1`) on the volume root. Without it,
//! [System.IO.DriveInfo]::IsReady returns `false` for `C:\`, which prevents
//! PowerShell from registering a `C:` PSDrive — and that breaks every
//! cmdlet whose discovery uses absolute paths (Get-Location, Import-Module,
//! Format-List, etc.).
//!
//! This module performs idempotent, additive ACE grants that match the
//! pattern Microsoft itself uses on system folders like `C:\Windows\System32`
//! and `C:\Program Files`. Nothing is revoked or replaced.

use psroot_types::error::{PsrootError, Result};
use std::path::Path;
use std::process::Command;

/// `S-1-15-2-1` — the well-known SID for "ALL APPLICATION PACKAGES".
pub const ALL_APP_PACKAGES_SID: &str = "S-1-15-2-1";/// Result of a single setup probe.
#[derive(Debug, Clone)]
pub struct SetupCheck {
    pub path: String,
    pub has_all_app_packages: bool,
    pub note: String,
}

/// Run all setup checks without modifying anything. Returns a list of paths
/// that need an ACE grant.
pub fn check_status(cache_root: &Path) -> Vec<SetupCheck> {
    let mut out = Vec::new();

    // Volume roots — only fixed drives present on this machine.
    for drive in enumerate_fixed_drive_roots() {
        let has = path_grants_all_app_packages(&drive);
        out.push(SetupCheck {
            path: drive.clone(),
            has_all_app_packages: has,
            note: if has {
                "ok".into()
            } else {
                "needed for DriveInfo.IsReady → enables PSDrive C: in pwsh".into()
            },
        });
    }

    // Cache root — needed so AppContainer can read staged shells.
    let cache_str = cache_root.to_string_lossy().to_string();
    let cache_has = if cache_root.exists() {
        path_grants_all_app_packages(&cache_str)
    } else {
        false
    };
    out.push(SetupCheck {
        path: cache_str,
        has_all_app_packages: cache_has,
        note: if cache_has {
            "ok".into()
        } else {
            "needed so cached shells (pwsh, etc.) are readable inside containers".into()
        },
    });

    out
}

/// Idempotently apply all required ACE grants. Requires admin for grants on
/// volume roots like `C:\`. Returns the list of paths that were modified.
pub fn apply(cache_root: &Path) -> Result<Vec<String>> {
    let mut applied = Vec::new();

    // 1) Volume roots: grant (R) — single ACE, no inherit, just enough so
    //    GetVolumeInformationW succeeds for AppContainer processes.
    for drive in enumerate_fixed_drive_roots() {
        if path_grants_all_app_packages(&drive) {
            continue;
        }
        grant_ace(&drive, ALL_APP_PACKAGES_SID, "(R)", false)?;
        applied.push(drive);
    }

    // 2) Cache root: grant (RX) with object+container inherit so every
    //    staged shell underneath is automatically readable. This eliminates
    //    the need to grant per-AppContainer SIDs on each stage.
    if !cache_root.exists() {
        std::fs::create_dir_all(cache_root)?;
    }
    let cache_str = cache_root.to_string_lossy().to_string();
    if !path_grants_all_app_packages(&cache_str) {
        grant_ace(&cache_str, ALL_APP_PACKAGES_SID, "(OI)(CI)(RX)", true)?;
        applied.push(cache_str);
    }

    // 3) Grant SeTcbPrivilege to the current user — required for
    //    Server Silo (JobObjectSiloRootDirectory). Only needed when
    //    using `--isolate full`, but apply unconditionally during setup
    //    so it's there when the user opts in.
    match grant_se_tcb_privilege_to_current_user() {
        Ok(true) => applied.push("SeTcbPrivilege (LSA)".into()),
        Ok(false) => {} // already had it
        Err(e) => {
            // Don't fail setup — silo mode is optional, but warn.
            eprintln!("WARN: Could not grant SeTcbPrivilege: {}", e);
            eprintln!("      Server Silo (--isolate full) will not work until this is fixed.");
            eprintln!("      Manual fix: secpol.msc → Local Policies → User Rights Assignment");
            eprintln!("                  → \"Act as part of the operating system\" → add your account");
        }
    }

    Ok(applied)
}

/// Detect whether the system is set up for AppContainer shells. Returns
/// `Ok(())` when ready; `Err` with a human-readable hint otherwise.
pub fn require_ready(cache_root: &Path) -> Result<()> {
    let checks = check_status(cache_root);
    let missing: Vec<&SetupCheck> = checks.iter().filter(|c| !c.has_all_app_packages).collect();
    if missing.is_empty() {
        return Ok(());
    }
    let mut msg = String::from(
        "psroot setup required (one-time, needs admin):\n",
    );
    for c in &missing {
        msg.push_str(&format!("  - {} : {}\n", c.path, c.note));
    }
    msg.push_str("\nRun (in elevated pwsh):  psroot setup\n");
    Err(PsrootError::Other(msg))
}

fn path_grants_all_app_packages(path: &str) -> bool {
    let out = match Command::new("icacls").arg(path).output() {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // Match either the friendly name or the SID.
    text.contains("ALL APPLICATION PACKAGES") || text.contains(ALL_APP_PACKAGES_SID)
}

fn grant_ace(path: &str, sid: &str, perms: &str, recurse: bool) -> Result<()> {
    let mut args: Vec<String> = vec![
        path.to_string(),
        "/grant".into(),
        format!("*{}:{}", sid, perms),
        "/Q".into(),
    ];
    if recurse {
        args.push("/T".into());
    }
    let out = Command::new("icacls")
        .args(&args)
        .output()
        .map_err(PsrootError::Io)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let combined = format!("{} {}", stdout.trim(), stderr.trim());
        return Err(PsrootError::Other(format!(
            "icacls grant failed for {}: {}",
            path,
            combined.trim()
        )));
    }
    Ok(())
}

fn enumerate_fixed_drive_roots() -> Vec<String> {
    // GetLogicalDriveStringsW would be ideal; for simplicity scan A..Z.
    // Filter to drives that actually exist and are fixed (have a System32
    // is a reasonable proxy when we can't query the type).
    let mut out = Vec::new();
    for c in b'A'..=b'Z' {
        let root = format!("{}:\\", c as char);
        if Path::new(&root).exists() {
            // Heuristic: only worry about C: by default (almost always the
            // system volume). Other letters are usually optical/removable
            // and don't need pwsh-module access.
            if c == b'C' {
                out.push(root);
            }
        }
    }
    out
}

// ── SeTcbPrivilege grant (LSA) ──────────────────────────────────────
//
// Server Silo's JobObjectSiloRootDirectory requires SeTcbPrivilege
// ("Act as part of the operating system"), which is NOT in standard
// admin tokens by default. We grant it to the current user account
// via the LSA policy database. Effect persists across reboots; user
// must log out and back in for the new token to include it.

/// Grant SeTcbPrivilege to the current user via LSA.
/// Returns `Ok(true)` if newly granted, `Ok(false)` if already present.
fn grant_se_tcb_privilege_to_current_user() -> Result<bool> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaAddAccountRights, LsaClose, LsaNtStatusToWinError, LsaOpenPolicy,
        LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, POLICY_CREATE_ACCOUNT,
        POLICY_LOOKUP_NAMES,
    };
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    type PSID = *mut std::ffi::c_void;

    // 1. Get current user's SID from process token.
    let mut token: HANDLE = ptr::null_mut();
    let ok = unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
    };
    if ok == 0 {
        return Err(PsrootError::last_win32("OpenProcessToken"));
    }

    // Query buffer size for TokenUser
    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    let mut buf: Vec<u8> = vec![0; needed as usize];
    let ok = unsafe {
        GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut _, needed, &mut needed)
    };
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(PsrootError::last_win32("GetTokenInformation(TokenUser)"));
    }
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid: PSID = token_user.User.Sid;

    // 2. Open LSA policy with rights needed to add account rights.
    let object_attrs: LSA_OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut policy: isize = 0;
    let status = unsafe {
        LsaOpenPolicy(
            ptr::null(),
            &object_attrs,
            (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32,
            &mut policy,
        )
    };
    if status != 0 {
        let err = unsafe { LsaNtStatusToWinError(status) };
        return Err(PsrootError::win32("LsaOpenPolicy", err));
    }

    // 3. Check if SeTcbPrivilege is already granted.
    let already = check_account_has_privilege(policy, sid, "SeTcbPrivilege");

    if already {
        unsafe { LsaClose(policy) };
        return Ok(false);
    }

    // 4. Build LSA_UNICODE_STRING for "SeTcbPrivilege".
    let priv_wide: Vec<u16> = "SeTcbPrivilege".encode_utf16().collect();
    let priv_lsa = LSA_UNICODE_STRING {
        Length: (priv_wide.len() * 2) as u16,
        MaximumLength: (priv_wide.len() * 2) as u16,
        Buffer: priv_wide.as_ptr() as *mut u16,
    };

    let status = unsafe {
        LsaAddAccountRights(policy, sid, &priv_lsa, 1)
    };
    unsafe { LsaClose(policy) };

    if status != 0 {
        let err = unsafe { LsaNtStatusToWinError(status) };
        return Err(PsrootError::win32("LsaAddAccountRights(SeTcbPrivilege)", err));
    }

    Ok(true)
}

/// Returns true if the account already has the named privilege.
fn check_account_has_privilege(
    policy: isize,
    sid: *mut std::ffi::c_void,
    priv_name: &str,
) -> bool {
    use std::ptr;
    use windows_sys::Win32::Security::Authentication::Identity::{
        LsaEnumerateAccountRights, LsaFreeMemory, LSA_UNICODE_STRING,
    };

    let mut rights_ptr: *mut LSA_UNICODE_STRING = ptr::null_mut();
    let mut count: u32 = 0;
    let status = unsafe {
        LsaEnumerateAccountRights(policy, sid, &mut rights_ptr, &mut count)
    };
    if status != 0 || rights_ptr.is_null() {
        return false;
    }
    let rights = unsafe { std::slice::from_raw_parts(rights_ptr, count as usize) };
    let want_lower = priv_name.to_lowercase();
    let mut found = false;
    for r in rights {
        let slice = unsafe {
            std::slice::from_raw_parts(r.Buffer, (r.Length / 2) as usize)
        };
        let s = String::from_utf16_lossy(slice);
        if s.to_lowercase() == want_lower {
            found = true;
            break;
        }
    }
    unsafe { LsaFreeMemory(rights_ptr as *mut _) };
    found
}
