//! PEB ImagePathName / CommandLine patcher.
//!
//! When a process is created via `CreateProcessW`, the kernel canonicalises
//! the image path it stored in `PEB.ProcessParameters.ImagePathName` via the
//! **global** DOS device map. With our private device map (where `C:` →
//! `<rootfs>`), the resulting host path (e.g.
//! `C:\Users\gj\AppData\Local\Psroot\containers\<id>\rootfs\PSH\pwsh.exe`)
//! becomes nonsensical when the child re-resolves it through its own
//! device map. .NET-based hosts (pwsh, dotnet) call
//! `GetModuleFileNameW` → `realpath`, find the file doesn't exist, and
//! abort with "Failed to resolve full path of the current executable".
//!
//! We work around this by spawning the child suspended and overwriting the
//! `ImagePathName` (and `CommandLine`) UNICODE_STRING in the child's PEB to
//! the in-container path before the loader runs. The loader then propagates
//! our value into `LDR_DATA_TABLE_ENTRY`, and `GetModuleFileNameW` returns
//! the in-container path which resolves correctly.
//!
//! Only x64 layouts are handled (we only ship x64 builds).

#![allow(non_snake_case, non_camel_case_types)]

use psroot_types::error::{PsrootError, Result};
use std::ffi::c_void;

type NTSTATUS = i32;
type HANDLE = isize;
type ULONG = u32;
type SIZE_T = usize;

const STATUS_SUCCESS: NTSTATUS = 0;

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    ExitStatus: NTSTATUS,
    PebBaseAddress: *mut c_void,
    AffinityMask: usize,
    BasePriority: i32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: u64, // remote pointer
}

extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: ULONG,
        ReturnLength: *mut ULONG,
    ) -> NTSTATUS;

    fn ReadProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: *const c_void,
        lpBuffer: *mut c_void,
        nSize: SIZE_T,
        lpNumberOfBytesRead: *mut SIZE_T,
    ) -> i32;

    fn WriteProcessMemory(
        hProcess: HANDLE,
        lpBaseAddress: *mut c_void,
        lpBuffer: *const c_void,
        nSize: SIZE_T,
        lpNumberOfBytesWritten: *mut SIZE_T,
    ) -> i32;

    fn VirtualAllocEx(
        hProcess: HANDLE,
        lpAddress: *mut c_void,
        dwSize: SIZE_T,
        flAllocationType: u32,
        flProtect: u32,
    ) -> *mut c_void;

    fn GetLastError() -> u32;
}

const ProcessBasicInformation: u32 = 0;

// PEB / RTL_USER_PROCESS_PARAMETERS field offsets (x64, Windows 10+).
const PEB_OFFSET_PROCESS_PARAMETERS: usize = 0x20;
const RUP_OFFSET_IMAGE_PATH_NAME: usize = 0x60;
const RUP_OFFSET_COMMAND_LINE: usize = 0x70;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;

fn read_mem<T: Copy>(process: HANDLE, addr: u64) -> Result<T> {
    let mut out: T = unsafe { std::mem::zeroed() };
    let mut got: SIZE_T = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            addr as *const c_void,
            &mut out as *mut T as *mut c_void,
            std::mem::size_of::<T>(),
            &mut got,
        )
    };
    if ok == 0 || got != std::mem::size_of::<T>() {
        let err = unsafe { GetLastError() };
        return Err(PsrootError::Other(format!(
            "ReadProcessMemory(@0x{:x}) failed: win32 err {}",
            addr, err
        )));
    }
    Ok(out)
}

fn write_mem(process: HANDLE, addr: u64, data: &[u8]) -> Result<()> {
    let mut wrote: SIZE_T = 0;
    let ok = unsafe {
        WriteProcessMemory(
            process,
            addr as *mut c_void,
            data.as_ptr() as *const c_void,
            data.len(),
            &mut wrote,
        )
    };
    if ok == 0 || wrote != data.len() {
        let err = unsafe { GetLastError() };
        return Err(PsrootError::Other(format!(
            "WriteProcessMemory(@0x{:x}, {} bytes) failed: win32 err {}",
            addr,
            data.len(),
            err
        )));
    }
    Ok(())
}

/// Overwrite the suspended child's `PEB.ProcessParameters.ImagePathName`
/// (and optionally `CommandLine`) with the supplied in-container strings.
///
/// The new buffers are allocated in the child via `VirtualAllocEx` so that
/// the loader, which copies these strings into its own structures, sees
/// valid memory. We do NOT free the old buffers — they live in the child's
/// process-parameters region and are managed by ntdll.
pub fn patch_image_path(
    process: HANDLE,
    new_image_path: &str,
    new_command_line: Option<&str>,
) -> Result<()> {
    // 1. Get PEB address.
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut ret_len: ULONG = 0;
    let st = unsafe {
        NtQueryInformationProcess(
            process,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        )
    };
    if st != STATUS_SUCCESS {
        return Err(PsrootError::Other(format!(
            "NtQueryInformationProcess(ProcessBasicInformation) -> 0x{:08x}",
            st as u32
        )));
    }
    let peb_addr = pbi.PebBaseAddress as u64;
    if peb_addr == 0 {
        return Err(PsrootError::Other(
            "NtQueryInformationProcess returned NULL PebBaseAddress".into(),
        ));
    }

    // 2. Read PEB.ProcessParameters pointer.
    let pp_addr: u64 = read_mem::<u64>(process, peb_addr + PEB_OFFSET_PROCESS_PARAMETERS as u64)?;
    if pp_addr == 0 {
        return Err(PsrootError::Other(
            "child PEB.ProcessParameters is NULL (process not yet initialized?)".into(),
        ));
    }

    // 3. Helper: write a new wide-string + UNICODE_STRING header.
    let patch_field = |field_offset: usize, new_str: &str| -> Result<()> {
        let mut wide: Vec<u16> = new_str.encode_utf16().collect();
        wide.push(0); // NUL terminator
        let bytes_with_nul = wide.len() * 2;
        let length_bytes = (wide.len() - 1) * 2; // excludes NUL
        // Allocate buffer in child.
        let remote_buf = unsafe {
            VirtualAllocEx(
                process,
                std::ptr::null_mut(),
                bytes_with_nul,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_buf.is_null() {
            let err = unsafe { GetLastError() };
            return Err(PsrootError::Other(format!(
                "VirtualAllocEx(child PEB string) failed: win32 err {}",
                err
            )));
        }
        let buf_bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(wide.as_ptr() as *const u8, bytes_with_nul)
        };
        write_mem(process, remote_buf as u64, buf_bytes)?;

        // Write UNICODE_STRING header.
        let us = UNICODE_STRING {
            Length: length_bytes as u16,
            MaximumLength: bytes_with_nul as u16,
            Buffer: remote_buf as u64,
        };
        let us_bytes: [u8; 16] = unsafe { std::mem::transmute(us) };
        write_mem(process, pp_addr + field_offset as u64, &us_bytes)?;
        Ok(())
    };

    patch_field(RUP_OFFSET_IMAGE_PATH_NAME, new_image_path)?;
    if let Some(cl) = new_command_line {
        patch_field(RUP_OFFSET_COMMAND_LINE, cl)?;
    }
    Ok(())
}
