//! DllMain for the `cdylib` build of psroot-procshim.
//!
//! When loaded into a target process (via `CreateRemoteThread(LoadLibraryW)`
//! from `psroot-netinject`), Windows calls this `DllMain` on
//! `DLL_PROCESS_ATTACH`. We keep work inside DllMain minimal to avoid
//! loader-lock deadlocks — just `DisableThreadLibraryCalls` and spawning
//! a dedicated init thread.
//!
//! The init thread records the current PID as the container root and
//! installs IAT hooks on all loaded modules to intercept ntdll process
//! enumeration exports.

#![cfg(windows)]

use core::ffi::c_void;

use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, TRUE};
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    inst: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            DisableThreadLibraryCalls(inst);
        }
        // Move real work off the loader-locked path.
        let _ = std::thread::Builder::new()
            .name("psroot-procshim-init".to_string())
            .spawn(|| {
                let _ = try_init();
            });
    }
    TRUE
}

/// Install process-visibility hooks. Returns `None` on any failure —
/// we never panic inside an injected DLL.
fn try_init() -> Option<()> {
    let guard = unsafe { crate::install::install() }.ok()?;
    // Leak the guard: we want hooks installed for the lifetime of the
    // process. Dropping would restore the IAT and re-expose host
    // processes.
    core::mem::forget(guard);
    Some(())
}
