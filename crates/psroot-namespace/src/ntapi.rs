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

    fn NtOpenDirectoryObject(
        directory_handle: *mut HANDLE,
        desired_access: ACCESS_MASK,
        object_attributes: *const OBJECT_ATTRIBUTES,
    ) -> NTSTATUS;

    fn NtSetInformationProcess(
        process_handle: HANDLE,
        process_information_class: u32,
        process_information: PVOID,
        process_information_length: ULONG,
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

const DIRECTORY_QUERY: ACCESS_MASK = 0x0001;
const DIRECTORY_TRAVERSE: ACCESS_MASK = 0x0002;

/// Open an existing NT directory object (e.g. `\GLOBAL??`) for use as
/// a shadow/parent.
pub fn open_directory(name: &str) -> Result<NtHandle> {
    let wide = to_wide(name);
    let ustr = make_unicode_string(&wide);
    let oa = make_object_attributes(&ustr, None, false);

    let mut handle: HANDLE = 0;
    let status = unsafe {
        NtOpenDirectoryObject(&mut handle, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa)
    };
    if status != STATUS_SUCCESS {
        return Err(PsrootError::nt("NtOpenDirectoryObject", status as u32));
    }
    Ok(NtHandle(handle))
}

/// Create an unnamed NT directory object that shadows another directory
/// (lookups not satisfied locally fall through to the shadow). Used to
/// build private DOS device maps that inherit the global one.
pub fn create_directory_shadowed(shadow: HANDLE) -> Result<NtHandle> {
    // Unnamed object: ObjectName == NULL. We still need a valid OA struct.
    let oa = OBJECT_ATTRIBUTES {
        length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as ULONG,
        root_directory: 0,
        object_name: ptr::null(),
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };

    let mut handle: HANDLE = 0;
    let status = unsafe {
        NtCreateDirectoryObjectEx(&mut handle, DIRECTORY_ALL_ACCESS, &oa, shadow, 0)
    };
    if status != STATUS_SUCCESS {
        return Err(PsrootError::nt("NtCreateDirectoryObjectEx(shadow)", status as u32));
    }
    Ok(NtHandle(handle))
}

/// Create a NAMED NT directory object that shadows another directory.
/// `ObSetDeviceMap` requires named directories on Win10/11 client SKUs;
/// unnamed shadowed directories are rejected with STATUS_INVALID_PARAMETER.
pub fn create_directory_named_shadowed(name: &str, shadow: HANDLE) -> Result<NtHandle> {
    let wide = to_wide(name);
    let ustr = make_unicode_string(&wide);
    // OPENIF so re-runs don't fail.
    let oa = make_object_attributes(&ustr, None, true);

    let mut handle: HANDLE = 0;
    let status = unsafe {
        NtCreateDirectoryObjectEx(&mut handle, DIRECTORY_ALL_ACCESS, &oa, shadow, 0)
    };
    if status != STATUS_SUCCESS && status != 0x40000000_u32 as i32 {
        return Err(PsrootError::nt("NtCreateDirectoryObjectEx(named-shadow)", status as u32));
    }
    Ok(NtHandle(handle))
}

/// `PROCESS_DEVICEMAP_INFORMATION` — set form is a single HANDLE.
const PROCESS_INFO_CLASS_DEVICE_MAP: u32 = 23;

/// Assign the given directory handle as the target process's DOS device map.
/// All `\??\` lookups in that process now resolve through `device_map_dir`.
pub fn set_process_device_map(process: HANDLE, device_map_dir: HANDLE) -> Result<()> {
    // PROCESS_DEVICEMAP_INFORMATION is a union of {HANDLE} (set, 8 bytes) and
    // {ULONG DriveMap; UCHAR DriveType[32]} (query, 36 bytes). The kernel
    // validates `Length == sizeof(union)` = 36 bytes regardless of operation.
    #[repr(C)]
    struct DeviceMapInfo {
        handle_or_drivemap: usize, // 8 bytes — first 8 hold the handle on SET
        drive_type: [u8; 32],      // padding for query form
    }
    let mut info = DeviceMapInfo {
        handle_or_drivemap: device_map_dir as usize,
        drive_type: [0u8; 32],
    };

    // Try the full 40-byte (8+32, padded to 40 for alignment) form first.
    let len = std::mem::size_of::<DeviceMapInfo>() as ULONG;
    let status = unsafe {
        NtSetInformationProcess(
            process,
            PROCESS_INFO_CLASS_DEVICE_MAP,
            &mut info as *mut _ as PVOID,
            len,
        )
    };
    if status == STATUS_SUCCESS {
        return Ok(());
    }

    // Fallback: the legacy 8-byte SET-only form (just a HANDLE).
    let mut just_handle: HANDLE = device_map_dir;
    let status2 = unsafe {
        NtSetInformationProcess(
            process,
            PROCESS_INFO_CLASS_DEVICE_MAP,
            &mut just_handle as *mut HANDLE as PVOID,
            std::mem::size_of::<HANDLE>() as ULONG,
        )
    };
    if status2 == STATUS_SUCCESS {
        return Ok(());
    }

    Err(PsrootError::Other(format!(
        "NtSetInformationProcess(DeviceMap) [tried len={} -> 0x{:08x}, len=8 -> 0x{:08x}]",
        len, status as u32, status2 as u32,
    )))
}
