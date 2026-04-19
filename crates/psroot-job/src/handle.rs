//! Safe RAII wrapper around a Win32 Job Object handle.

use psroot_types::error::{PsrootError, Result};
use std::ptr;
use tracing::{debug, instrument};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::OpenProcess;

/// RAII wrapper for a Win32 Job Object.
///
/// Automatically closes the handle on drop.
/// If kill-on-close is enabled, all processes in the job die on drop.
pub struct JobObject {
    handle: HANDLE,
}

// SAFETY: HANDLE is a raw pointer but Job Objects are thread-safe kernel objects.
unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}

impl JobObject {
    /// Create a new anonymous Job Object.
    #[instrument(level = "debug")]
    pub fn new() -> Result<Self> {
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(PsrootError::last_win32("CreateJobObjectW"));
        }
        debug!("Job Object created");
        Ok(Self { handle })
    }

    /// Create a named Job Object.
    pub fn new_named(name: &str) -> Result<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { CreateJobObjectW(ptr::null(), wide.as_ptr()) };
        if handle.is_null() {
            return Err(PsrootError::last_win32("CreateJobObjectW"));
        }
        Ok(Self { handle })
    }

    /// Raw kernel handle.
    #[inline]
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    /// Assign an already-opened process handle to this job.
    pub fn assign_handle(&self, process_handle: HANDLE) -> Result<()> {
        let ok = unsafe { AssignProcessToJobObject(self.handle, process_handle) };
        if ok == 0 {
            return Err(PsrootError::last_win32("AssignProcessToJobObject"));
        }
        Ok(())
    }

    /// Assign a process by PID.
    pub fn assign_pid(&self, pid: u32) -> Result<()> {
        const PROCESS_SET_QUOTA: u32 = 0x0100;
        const PROCESS_TERMINATE: u32 = 0x0001;
        let h = unsafe { OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, 0, pid) };
        if h.is_null() {
            return Err(PsrootError::last_win32("OpenProcess"));
        }
        let result = self.assign_handle(h);
        unsafe { CloseHandle(h) };
        result
    }

    /// Terminate all processes in the job.
    pub fn terminate(&self, exit_code: u32) -> Result<()> {
        let ok = unsafe { TerminateJobObject(self.handle, exit_code) };
        if ok == 0 {
            // Ignore error if job is already empty
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err != 0 {
                return Err(PsrootError::win32("TerminateJobObject", err));
            }
        }
        Ok(())
    }

    /// Set information on the job (raw).
    pub fn set_info<T>(
        &self,
        class: JOBOBJECTINFOCLASS,
        info: &T,
    ) -> Result<()> {
        let ok = unsafe {
            SetInformationJobObject(
                self.handle,
                class,
                info as *const T as *const _,
                std::mem::size_of::<T>() as u32,
            )
        };
        if ok == 0 {
            return Err(PsrootError::last_win32("SetInformationJobObject"));
        }
        Ok(())
    }

    /// Set information with null data (e.g., CreateSilo).
    pub fn set_info_null(&self, class: JOBOBJECTINFOCLASS) -> Result<()> {
        let ok = unsafe {
            SetInformationJobObject(self.handle, class, ptr::null(), 0)
        };
        if ok == 0 {
            return Err(PsrootError::last_win32("SetInformationJobObject"));
        }
        Ok(())
    }

    /// Query information from the job (raw).
    pub fn query_info<T>(
        &self,
        class: JOBOBJECTINFOCLASS,
    ) -> Result<T> {
        let mut info: T = unsafe { std::mem::zeroed() };
        let mut ret_len: u32 = 0;
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle,
                class,
                &mut info as *mut T as *mut _,
                std::mem::size_of::<T>() as u32,
                &mut ret_len,
            )
        };
        if ok == 0 {
            return Err(PsrootError::last_win32("QueryInformationJobObject"));
        }
        Ok(info)
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { CloseHandle(self.handle) };
        }
    }
}
