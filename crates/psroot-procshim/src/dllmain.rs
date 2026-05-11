//! DllMain for the `cdylib` build of psroot-procshim.
//!
//! When loaded into a target process (via `CreateRemoteThread(LoadLibraryW)`
//! from `psroot-netinject`), Windows calls this `DllMain` on
//! `DLL_PROCESS_ATTACH`. 
//!
//! Unlike the netshim (which defers to an init thread because it needs to
//! open SHM handles — which may trigger DLL loads), the procshim's work
//! is pure pointer writes (IAT patching + VirtualProtect). This is safe
//! to do directly under the loader lock because:
//!
//! - `VirtualProtect` is an ntdll syscall (no DLL load)
//! - Reading PE headers is just pointer arithmetic
//! - `GetCurrentProcessId` is an ntdll call (always loaded)
//! - `CreateToolhelp32Snapshot` is NOT called during install
//! - No heap allocation beyond what the IAT walker does (Vec on our stack)
//!
//! By installing hooks synchronously in DllMain, we guarantee that by
//! the time `LoadLibraryW` returns to the injector, the hooks are LIVE.
//! The child process cannot race past us.

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
        // Install hooks SYNCHRONOUSLY under loader lock.
        // This is safe because IAT patching is just pointer writes.
        // By the time DllMain returns → LoadLibraryW returns → the
        // injector resumes the main thread, hooks are guaranteed active.
        let _ = try_init();
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
