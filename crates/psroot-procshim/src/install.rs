//! Hook installation: patches ntdll.dll imports across all loaded
//! modules so that NtQuerySystemInformation and NtOpenProcess route
//! through our filtering hooks.
//!
//! Unlike the netshim (which patches only ws2_32 in the main exe),
//! we patch EVERY loaded module — especially `kernelbase.dll` and
//! `kernel32.dll`, because high-level APIs like `CreateToolhelp32Snapshot`,
//! `K32EnumProcesses`, etc. live there and call ntdll internally.

#![cfg(windows)]

use core::ffi::c_void;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
    TH32CS_SNAPMODULE,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

use crate::hooks::{hook_nt_open_process, hook_nt_query_system_information};
use crate::iat::{patch_module, restore_module, HookEntry};
use crate::state::{BypassGuard, ShimState, STATE};

#[derive(Debug)]
pub enum InstallError {
    AlreadyInstalled,
    NoImportsFound,
}

/// RAII guard: dropping reverts IAT patches in all modules.
pub struct HookGuard {
    modules: Vec<HMODULE>,
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        let Some(state) = STATE.get() else { return };
        let entries = build_entries(state);
        for m in &self.modules {
            unsafe {
                restore_module(*m, b"ntdll.dll", &entries);
            }
        }
    }
}

/// Install process-visibility hooks across all loaded modules.
///
/// # Safety
/// IAT patching writes to executable memory. No other thread should be
/// concurrently calling NtQuerySystemInformation or NtOpenProcess
/// through the patched modules while this runs. In practice this is
/// safe because we call this from a DllMain init thread before the
/// target application has finished initializing.
pub unsafe fn install() -> Result<HookGuard, InstallError> {
    if STATE.get().is_some() {
        return Err(InstallError::AlreadyInstalled);
    }

    let root_pid = GetCurrentProcessId();
    let _ = STATE.set(ShimState::new(root_pid));
    let state = STATE.get().expect("just set");
    let entries = build_entries(state);

    let _g = BypassGuard::enter();

    // Enumerate all modules loaded in our process and patch each one's
    // ntdll.dll imports.
    let modules = enumerate_modules();
    let mut patched_modules = Vec::new();
    let mut total_hits = 0;

    for module in &modules {
        let hits = patch_module(*module, b"ntdll.dll", &entries);
        if hits > 0 {
            patched_modules.push(*module);
            total_hits += hits;
        }
    }

    if total_hits == 0 {
        // Fallback: try the main exe and well-known system DLLs directly.
        let main = GetModuleHandleW(core::ptr::null());
        let hits = patch_module(main, b"ntdll.dll", &entries);
        if hits > 0 {
            patched_modules.push(main);
            total_hits += hits;
        }

        // kernelbase.dll — this is where the real implementations live
        // on modern Windows (kernel32 is mostly a forwarder).
        let kernelbase = GetModuleHandleW(
            wide_str("kernelbase.dll").as_ptr(),
        );
        if !kernelbase.is_null() {
            let hits = patch_module(kernelbase, b"ntdll.dll", &entries);
            if hits > 0 {
                patched_modules.push(kernelbase);
                total_hits += hits;
            }
        }

        // kernel32.dll — for older APIs.
        let kernel32 = GetModuleHandleW(
            wide_str("kernel32.dll").as_ptr(),
        );
        if !kernel32.is_null() {
            let hits = patch_module(kernel32, b"ntdll.dll", &entries);
            if hits > 0 {
                patched_modules.push(kernel32);
                total_hits += hits;
            }
        }
    }

    if total_hits == 0 {
        return Err(InstallError::NoImportsFound);
    }

    tracing::info!(
        root_pid,
        modules = patched_modules.len(),
        hooks = total_hits,
        "procshim: process visibility hooks installed"
    );

    Ok(HookGuard {
        modules: patched_modules,
    })
}

fn build_entries(state: &'static ShimState) -> [HookEntry; 2] {
    use core::sync::atomic::AtomicUsize;

    fn as_slot(a: &AtomicUsize) -> *mut *const c_void {
        a as *const AtomicUsize as *mut *const c_void
    }

    let o = &state.originals;
    [
        HookEntry {
            name: b"NtQuerySystemInformation\0",
            replacement: hook_nt_query_system_information as *const c_void,
            original: as_slot(&o.nt_query_system_information),
        },
        HookEntry {
            name: b"NtOpenProcess\0",
            replacement: hook_nt_open_process as *const c_void,
            original: as_slot(&o.nt_open_process),
        },
    ]
}

/// Enumerate all modules loaded in the current process using
/// Toolhelp32. Returns module base addresses that can be passed to
/// `patch_module`.
fn enumerate_modules() -> Vec<HMODULE> {
    let mut result = Vec::new();
    let pid = unsafe { GetCurrentProcessId() };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid) };
    if snap == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return result;
    }

    let mut entry: MODULEENTRY32W = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;

    if unsafe { Module32FirstW(snap, &mut entry) } != 0 {
        result.push(entry.hModule);
        while unsafe { Module32NextW(snap, &mut entry) } != 0 {
            result.push(entry.hModule);
        }
    }

    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(snap);
    }

    result
}

/// Convert a &str to a null-terminated wide string.
fn wide_str(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut v: Vec<u16> = std::ffi::OsStr::new(s).encode_wide().collect();
    v.push(0);
    v
}
