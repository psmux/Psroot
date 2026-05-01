//! Minimal DLL injector for the psroot netshim.
//!
//! # Scope
//!
//! This crate implements exactly **one** injection technique — the
//! classic `CreateRemoteThread(kernel32!LoadLibraryW)` pattern. It is:
//!
//! * **Reliable** for every non-AppContainer Windows process that has
//!   `kernel32.dll` loaded (i.e. every process).
//! * **Small** — ~100 lines of unsafe code, no C++ toolchain, no
//!   vendored dependencies.
//! * **Cross-session safe** — works from a normal-integrity parent to a
//!   normal-integrity child. Injecting across integrity levels (e.g.
//!   from medium IL to low IL AppContainer) requires `SeDebugPrivilege`
//!   and a loader-less shellcode thunk; out of scope here.
//!
//! Phase 3 explicitly defers **AppContainer** injection, which needs
//! Microsoft Detours' `DetourCreateProcessWithDllEx` (patches the
//! target's import table before its first instruction runs). See the
//! tracking issue in `docs/netstack.md`.
//!
//! # Thread-safety & loader lock
//!
//! The technique pushes `LoadLibraryW` onto a fresh thread created
//! inside the target process. The target's loader lock is taken by that
//! thread, so callers on our side don't need to care about loader
//! deadlocks. The target's `DllMain` receives `DLL_PROCESS_ATTACH` on
//! that same thread.
//!
//! # Security
//!
//! * The caller must already have `PROCESS_CREATE_THREAD`,
//!   `PROCESS_VM_OPERATION`, `PROCESS_VM_WRITE`, `PROCESS_VM_READ` and
//!   `PROCESS_QUERY_INFORMATION` on the target. Spawning the child via
//!   `CreateProcessW` / `std::process::Command` gives you all of these.
//! * We allocate `MEM_COMMIT | MEM_RESERVE` with `PAGE_READWRITE` in
//!   the target for the DLL path string only — never `EXECUTE`. The
//!   thread's start routine is `LoadLibraryW`, which lives in the
//!   already-mapped `kernel32.dll`.
//! * We free the path allocation after the thread exits.

#![cfg(windows)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows_sys::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject, INFINITE,
    LPTHREAD_START_ROUTINE,
};

/// All the ways injection can fail.
#[derive(Debug)]
pub enum InjectError {
    /// `kernel32.dll` was not loaded in our own process (impossible in
    /// practice, but we keep the error for completeness).
    KernelNotLoaded,
    /// `GetProcAddress(kernel32, "LoadLibraryW")` returned NULL.
    LoadLibraryNotFound,
    /// The DLL path contained a NUL byte, which Windows rejects.
    PathHasNul,
    /// A Win32 API call failed. Carries the `GetLastError` value.
    Win32(&'static str, io::Error),
    /// The remote thread exited with code 0 — `LoadLibraryW` returned
    /// NULL inside the target, i.e. the DLL did not load. The target
    /// process's `GetLastError` is not observable here; enable
    /// `tracing` to see the usual suspects (path wrong, arch mismatch,
    /// missing dependencies).
    LoadLibraryFailed,
}

/// Inject `dll_path` into the process referred to by `process` using
/// `CreateRemoteThread(LoadLibraryW)`.
///
/// # Arguments
///
/// * `process` — an owned `HANDLE` with at least the rights listed in
///   the crate docs. The caller retains ownership; we do not close it.
/// * `dll_path` — an absolute path to a DLL that the target can load.
///   The DLL must match the target's architecture (x64 → x64). Relative
///   paths are resolved by `LoadLibraryW` using the target's search
///   order, which is usually not what you want.
///
/// # Safety
///
/// The caller must ensure `process` is a live, valid process handle
/// with the necessary access rights, and that injecting a DLL into it
/// is authorised. This function performs no privilege check.
pub unsafe fn inject_dll(process: HANDLE, dll_path: &Path) -> Result<(), InjectError> {
    // ── 1. Resolve LoadLibraryW in OUR process. Because kernel32 is
    // loaded at the same base in every process on the same boot (ASLR
    // is per-boot, not per-process, for system DLLs), the address in
    // our process == its address in the target.
    let kernel32 = unsafe { GetModuleHandleA(b"kernel32.dll\0".as_ptr()) };
    if kernel32.is_null() {
        return Err(InjectError::KernelNotLoaded);
    }
    let load_library_w = unsafe { GetProcAddress(kernel32, b"LoadLibraryW\0".as_ptr()) };
    let Some(load_library_w) = load_library_w else {
        return Err(InjectError::LoadLibraryNotFound);
    };

    // ── 2. Encode the path as a NUL-terminated wide string.
    let mut wide: Vec<u16> = OsStr::new(dll_path).encode_wide().collect();
    if wide.iter().any(|&c| c == 0) {
        return Err(InjectError::PathHasNul);
    }
    wide.push(0);
    let bytes = wide.len() * std::mem::size_of::<u16>();

    // ── 3. Allocate a writable buffer in the target for the path.
    let remote_buf = unsafe {
        VirtualAllocEx(
            process,
            core::ptr::null(),
            bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote_buf.is_null() {
        return Err(InjectError::Win32(
            "VirtualAllocEx",
            io::Error::last_os_error(),
        ));
    }

    // Helper to unconditionally free `remote_buf` on exit paths.
    struct RemoteBuf {
        process: HANDLE,
        ptr: *mut core::ffi::c_void,
    }
    impl Drop for RemoteBuf {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe {
                    VirtualFreeEx(self.process, self.ptr, 0, MEM_RELEASE);
                }
            }
        }
    }
    let _owner = RemoteBuf {
        process,
        ptr: remote_buf,
    };

    // ── 4. Write the path into the target.
    let mut written: usize = 0;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            remote_buf,
            wide.as_ptr() as *const _,
            bytes,
            &mut written,
        )
    };
    if ok == FALSE || written != bytes {
        return Err(InjectError::Win32(
            "WriteProcessMemory",
            io::Error::last_os_error(),
        ));
    }

    // ── 5. Spawn the remote thread at LoadLibraryW.
    //
    // The ABI mismatch is a well-known tolerated hack:
    //   LPTHREAD_START_ROUTINE : fn(*mut c_void) -> u32
    //   LoadLibraryW           : fn(*const u16)  -> HMODULE (u64 on x64)
    // We lose the high 32 bits of HMODULE, but we only need to know
    // whether it was non-zero (success). On Win64 this works because
    // the first argument is passed in RCX in both cases and a non-NULL
    // return produces a non-zero low DWORD for standard .DLL base
    // addresses.
    let start: LPTHREAD_START_ROUTINE = Some(unsafe {
        core::mem::transmute::<
            unsafe extern "system" fn() -> isize,
            unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
        >(load_library_w)
    });
    let thread = unsafe {
        CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            start,
            remote_buf,
            0,
            core::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return Err(InjectError::Win32(
            "CreateRemoteThread",
            io::Error::last_os_error(),
        ));
    }

    // ── 6. Wait for LoadLibraryW to return.
    let wait = unsafe { WaitForSingleObject(thread, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        unsafe { CloseHandle(thread) };
        return Err(InjectError::Win32(
            "WaitForSingleObject",
            io::Error::last_os_error(),
        ));
    }
    let mut exit_code: u32 = 0;
    let got = unsafe { GetExitCodeThread(thread, &mut exit_code) };
    unsafe { CloseHandle(thread) };
    if got == FALSE {
        return Err(InjectError::Win32(
            "GetExitCodeThread",
            io::Error::last_os_error(),
        ));
    }
    if exit_code == 0 {
        // LoadLibraryW returned NULL → DLL failed to load in target.
        return Err(InjectError::LoadLibraryFailed);
    }

    tracing::debug!(exit_code, "netinject: LoadLibraryW ok");
    Ok(())
}
