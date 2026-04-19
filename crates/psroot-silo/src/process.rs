//! Process creation inside a Server Silo.
//!
//! Creates a suspended process, assigns it to the silo job,
//! then resumes it. The process inherits the silo namespace.

use psroot_job::JobObject;
use psroot_types::error::{PsrootError, Result};
use tracing::debug;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::*;

const CREATE_SUSPENDED: u32 = 0x00000004;
const CREATE_NO_WINDOW: u32 = 0x08000000;
const CREATE_UNICODE_ENVIRONMENT: u32 = 0x00000400;

/// Information about a spawned process.
#[derive(Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub tid: u32,
}

/// Create a process inside the silo job.
pub fn create_in_silo(
    job: &JobObject,
    command_line: &str,
    env: Option<&[(String, String)]>,
    cwd: Option<&str>,
) -> Result<ProcessInfo> {
    // Command line must be mutable wide buffer
    let mut cmd_wide: Vec<u16> = command_line.encode_utf16().chain(std::iter::once(0)).collect();

    // Environment block (double-null terminated UTF-16)
    let env_block = env.map(build_env_block);

    // Current directory
    let cwd_wide: Option<Vec<u16>> = cwd.map(|s| s.encode_utf16().chain(std::iter::once(0)).collect());

    // STARTUPINFOW (zeroed = defaults)
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let flags = CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),           // lpApplicationName
            cmd_wide.as_mut_ptr(),      // lpCommandLine (mutable!)
            std::ptr::null(),           // lpProcessAttributes
            std::ptr::null(),           // lpThreadAttributes
            0,                          // bInheritHandles = FALSE
            flags,                      // dwCreationFlags
            env_block
                .as_ref()
                .map(|b| b.as_ptr() as *const _)
                .unwrap_or(std::ptr::null()),
            cwd_wide
                .as_ref()
                .map(|w| w.as_ptr())
                .unwrap_or(std::ptr::null()),
            &si,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(PsrootError::last_win32("CreateProcessW"));
    }

    debug!(pid = pi.dwProcessId, tid = pi.dwThreadId, "Process created (suspended)");

    // Assign to silo job
    let assign_result = job.assign_handle(pi.hProcess);
    if let Err(e) = assign_result {
        unsafe {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        return Err(e);
    }

    // Resume
    unsafe { ResumeThread(pi.hThread) };
    debug!(pid = pi.dwProcessId, "Process resumed in silo");

    let info = ProcessInfo {
        pid: pi.dwProcessId,
        tid: pi.dwThreadId,
    };

    // Close our copies of the handles
    unsafe {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    Ok(info)
}

/// Build a UTF-16LE environment block: "KEY=VALUE\0KEY=VALUE\0\0"
fn build_env_block(vars: &[(String, String)]) -> Vec<u16> {
    let mut block = Vec::new();
    for (key, value) in vars {
        let entry = format!("{}={}", key, value);
        block.extend(entry.encode_utf16());
        block.push(0); // null between entries
    }
    block.push(0); // double-null terminator
    block
}
