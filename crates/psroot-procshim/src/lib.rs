#![cfg(windows)]
//! Container-side process-visibility shim for psroot.
//!
//! When injected into a sandboxed process, this DLL hooks
//! `NtQuerySystemInformation` (the single ntdll export behind every
//! Windows process-enumeration API) to filter out host processes. The
//! sandboxed program sees only its own process tree — exactly like a
//! Linux PID namespace.
//!
//! # What this catches
//!
//! - `tasklist.exe`
//! - PowerShell `Get-Process`
//! - `wmic process list`
//! - .NET `System.Diagnostics.Process.GetProcesses()`
//! - Toolhelp32 (`CreateToolhelp32Snapshot` / `Process32First/Next`)
//! - WMI COM queries
//! - Any direct `NtQuerySystemInformation(SystemProcessInformation)` call
//!
//! All of these ultimately go through `ntdll!NtQuerySystemInformation`
//! which we intercept via IAT patching of every loaded module.
//!
//! # How it works
//!
//! 1. On `DLL_PROCESS_ATTACH`, record our own PID as the container root.
//! 2. Patch `ntdll.dll` imports in all loaded modules (kernelbase,
//!    kernel32, psapi, the main exe, etc.).
//! 3. When `NtQuerySystemInformation` is called with
//!    `SystemProcessInformation` (class 5), call the real function,
//!    then walk the linked list of `SYSTEM_PROCESS_INFORMATION` structs
//!    and unlink any entry whose PID is not the container root or a
//!    descendant.
//! 4. Hook `NtOpenProcess` to deny handle access to host PIDs.
//!
//! # Integration
//!
//! The psroot container runtime injects this DLL via the same
//! `CreateRemoteThread(LoadLibraryW)` mechanism used by
//! `psroot-netinject` for the network shim.

#[cfg(windows)]
pub mod dllmain;
#[cfg(windows)]
pub mod hooks;
#[cfg(windows)]
pub mod iat;
#[cfg(windows)]
pub mod install;
#[cfg(windows)]
pub mod state;

// Stub so non-Windows `cargo check` still passes.
#[cfg(not(windows))]
pub struct ProcShim;
