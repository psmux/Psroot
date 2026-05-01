//! Windows shared-memory backing for netstack rings.
//!
//! A single file mapping named `Local\psroot-ns-<container-id>` (or
//! unnamed, handle passed via `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) hosts
//! both ring buffers and the data region. The host side creates the
//! mapping; the shim opens or inherits it.

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile, FILE_MAP_ALL_ACCESS,
    PAGE_READWRITE,
};

/// Owned shared memory region.
///
/// Safe to move between threads; both views point into the same physical
/// pages so the consuming `Ring` can be re-created on the mapped view in
/// any thread that owns an exclusive slice.
pub struct SharedMemory {
    handle: HANDLE,
    view: *mut c_void,
    size: usize,
    owns_mapping: bool,
}

unsafe impl Send for SharedMemory {}
unsafe impl Sync for SharedMemory {}

impl SharedMemory {
    /// Create a new named, readable-writable mapping.
    ///
    /// `name` is usually `Local\psroot-ns-<id>`. The backing pages are
    /// page-aligned (guaranteed by Windows), so the embedded `RingHeader`
    /// satisfies its 64-byte alignment requirement for free.
    pub fn create(name: &str, size: usize) -> io::Result<Self> {
        let wname = to_wide(name);
        // SAFETY: parameters validated; Win32 contract.
        let handle = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                null_mut(),
                PAGE_READWRITE,
                (size >> 32) as u32,
                size as u32,
                wname.as_ptr(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size) };
        if view.Value.is_null() {
            let e = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(e);
        }
        Ok(Self {
            handle,
            view: view.Value,
            size,
            owns_mapping: true,
        })
    }

    /// Open an existing named mapping (shim side, when using named SHM).
    pub fn open(name: &str, size: usize) -> io::Result<Self> {
        let wname = to_wide(name);
        let handle = unsafe { OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, wname.as_ptr()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size) };
        if view.Value.is_null() {
            let e = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(e);
        }
        Ok(Self {
            handle,
            view: view.Value,
            size,
            owns_mapping: false,
        })
    }

    /// Attach to a mapping via an already-owned inheritable handle (the
    /// recommended path for AppContainer children — no named-object
    /// namespace gymnastics).
    ///
    /// `handle` ownership is transferred into the returned `SharedMemory`.
    pub fn from_handle(handle: HANDLE, size: usize) -> io::Result<Self> {
        let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size) };
        if view.Value.is_null() {
            let e = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(e);
        }
        Ok(Self {
            handle,
            view: view.Value,
            size,
            owns_mapping: false,
        })
    }

    /// Size of the mapped region, in bytes.
    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Raw handle (for `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` inheritance).
    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    /// Borrow the mapped region as an immutable slice.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: `view` points to `size` mapped bytes.
        unsafe { core::slice::from_raw_parts(self.view as *const u8, self.size) }
    }

    /// Borrow the mapped region as a mutable slice. Caller guarantees
    /// exclusive access (the ring protocol is SPSC so each side writes
    /// only its own producer index & slot region).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.view as *mut u8, self.size) }
    }
}

impl Drop for SharedMemory {
    fn drop(&mut self) {
        unsafe {
            if !self.view.is_null() {
                let _ = UnmapViewOfFile(windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                    Value: self.view,
                });
            }
            if !self.handle.is_null() {
                let _ = CloseHandle(self.handle);
            }
        }
        let _ = self.owns_mapping; // silence unused-field warning
    }
}

fn to_wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

// ───────────────────────────── tests ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::{ring_bytes, Ring};
    use psroot_netstack_proto::{OpCode, SlotHeader};

    /// End-to-end create / attach across a named mapping in the same
    /// process. Sufficient to validate that the SHM plumbing is correct;
    /// the cross-process path uses the same kernel object.
    #[test]
    fn create_and_open_named_same_process() {
        let name = format!("Local\\psroot-ns-test-{}", std::process::id());
        let size = ring_bytes(16);

        let mut creator = SharedMemory::create(&name, size).unwrap();
        Ring::create(creator.as_mut_slice(), 16).unwrap();

        // Push a message from the "host" view.
        {
            let r = Ring::attach(creator.as_slice()).unwrap();
            r.try_push(SlotHeader::new(OpCode::Hello, 7), b"hi").unwrap();
        }

        // Open a second view (would be the "shim" in another process).
        let opener = SharedMemory::open(&name, size).unwrap();
        let r = Ring::attach(opener.as_slice()).unwrap();
        let (h, data) = r.try_pop().unwrap();
        assert_eq!(h.correlation, 7);
        assert_eq!(&data, b"hi");
    }
}
