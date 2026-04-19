//! Raw ntdll.dll FFI for NT object directory and symbolic link operations.
//!
//! These are undocumented but stable NT APIs used by Windows itself
//! for silo construction. No SDK header covers them directly.

use psroot_types::error::{PsrootError, Result};
use std::ptr;

// ── NT types ────────────────────────────────────────────────────────

type NTSTATUS = i32;
type HANDLE = isize;
type PVOID = *mut std::ffi::c_void;
type ACCESS_MASK = u32;
type ULONG = u32;

const STATUS_SUCCESS: NTSTATUS = 0;
const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;
const OBJ_OPENIF: ULONG = 0x00000080;
const DIRECTORY_ALL_ACCESS: ACCESS_MASK = 0x000F000F;
const SYMBOLIC_LINK_ALL_ACCESS: ACCESS_MASK = 0x000F0001;

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    length: ULONG,
    root_directory: HANDLE,
    object_name: *const UNICODE_STRING,
    attributes: ULONG,
    security_descriptor: PVOID,
    security_quality_of_service: PVOID,
}

// ── ntdll imports ───────────────────────────────────────────────────

extern "system" {
    fn NtCreateDirectoryObjectEx(
        directory_handle: *mut HANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: *const OBJECT_ATTRIBUTES,
        shadow_directory: HANDLE,
        flags: ULONG,
    ) -> NTSTATUS;

    fn NtCreateSymbolicLinkObject(
        link_handle: *mut HANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: *const OBJECT_ATTRIBUTES,
        target_name: *const UNICODE_STRING,
    ) -> NTSTATUS;

    fn NtClose(handle: HANDLE) -> NTSTATUS;
}

// ── RAII handle ─────────────────────────────────────────────────────

/// RAII wrapper for NT object handles.
pub struct NtHandle(HANDLE);

impl NtHandle {
    pub fn raw(&self) -> isize {
        self.0
    }
}

impl Drop for NtHandle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { NtClose(self.0) };
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn make_unicode_string(s: &[u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        length: ((s.len() - 1) * 2) as u16, // exclude null, in bytes
        maximum_length: (s.len() * 2) as u16,
        buffer: s.as_ptr(),
    }
}

fn make_object_attributes(
    name: &UNICODE_STRING,
    root: Option<HANDLE>,
    open_if: bool,
) -> OBJECT_ATTRIBUTES {
    let mut attrs = OBJ_CASE_INSENSITIVE;
    if open_if {
        attrs |= OBJ_OPENIF;
    }
    OBJECT_ATTRIBUTES {
        length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as ULONG,
        root_directory: root.unwrap_or(0),
        object_name: name,
        attributes: attrs,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ── Public API ──────────────────────────────────────────────────────

/// Create an NT directory object (e.g., `\Silos\7` or `BaseNamedObjects`).
pub fn create_directory(name: &str, root: Option<HANDLE>) -> Result<NtHandle> {
    let wide = to_wide(name);
    let ustr = make_unicode_string(&wide);
    let oa = make_object_attributes(&ustr, root, true);

    let mut handle: HANDLE = 0;
    let status = unsafe {
        NtCreateDirectoryObjectEx(&mut handle, DIRECTORY_ALL_ACCESS, &oa, 0, 0)
    };

    // Accept STATUS_SUCCESS and STATUS_OBJECT_NAME_EXISTS (0x40000000)
    if status != STATUS_SUCCESS && status != 0x40000000_u32 as i32 {
        return Err(PsrootError::nt("NtCreateDirectoryObjectEx", status as u32));
    }

    Ok(NtHandle(handle))
}

/// Create an NT symbolic link object.
pub fn create_symlink(
    name: &str,
    target: &str,
    root: Option<HANDLE>,
) -> Result<NtHandle> {
    let name_wide = to_wide(name);
    let target_wide = to_wide(target);

    let name_ustr = make_unicode_string(&name_wide);
    let target_ustr = make_unicode_string(&target_wide);
    let oa = make_object_attributes(&name_ustr, root, false);

    let mut handle: HANDLE = 0;
    let status = unsafe {
        NtCreateSymbolicLinkObject(&mut handle, SYMBOLIC_LINK_ALL_ACCESS, &oa, &target_ustr)
    };

    if status != STATUS_SUCCESS {
        return Err(PsrootError::nt("NtCreateSymbolicLinkObject", status as u32));
    }

    Ok(NtHandle(handle))
}
