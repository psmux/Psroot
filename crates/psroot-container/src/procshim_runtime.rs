//! Process-visibility shim: inject psroot_procshim.dll into the
//! container's init process to hide host processes from enumeration.
//!
//! Works alongside the netstack shim — both are injected via the same
//! `CreateRemoteThread(LoadLibraryW)` mechanism from `psroot-netinject`.
//! The procshim DLL is stateless (no SHM, no daemon) — it reads its
//! own PID on attach and filters from there.

#![cfg(windows)]

use std::path::PathBuf;

/// Locate the procshim DLL next to the current executable. Matches the
/// same layout as the netshim DLL — cargo puts both cdylib outputs in
/// `target/<profile>/`.
pub fn default_procshim_path() -> Option<PathBuf> {
    let mut exe = std::env::current_exe().ok()?;
    exe.pop();
    let candidate = exe.join("psroot_procshim.dll");
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

/// Inject the procshim DLL into the given process.
///
/// # Safety
/// `process` must be a valid handle with `PROCESS_CREATE_THREAD |
/// PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
/// PROCESS_QUERY_INFORMATION` rights.
pub unsafe fn inject_procshim(
    process: windows_sys::Win32::Foundation::HANDLE,
    dll_path: &std::path::Path,
) -> Result<(), psroot_netinject::InjectError> {
    psroot_netinject::inject_dll(process, dll_path)
}
