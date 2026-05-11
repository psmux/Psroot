//! Import Address Table (IAT) patching for ntdll hooks.
//!
//! Adapted from psroot-netshim's IAT patcher. Walks a loaded PE
//! module's import table, finds entries that reference the target DLL
//! (e.g. `ntdll.dll`), and rewrites IAT slots to point at our hook
//! functions. 100 % stable Rust, no inline disasm.

#![cfg(windows)]

use core::ffi::{c_char, c_void};
use core::slice;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS64,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_IMPORT_DESCRIPTOR,
    IMAGE_NT_SIGNATURE,
};
use windows_sys::Win32::System::WindowsProgramming::IMAGE_THUNK_DATA64;

/// One hook target: the exact export name (null-terminated ASCII) and
/// the replacement pointer.
#[derive(Copy, Clone)]
pub struct HookEntry {
    pub name: &'static [u8],
    pub replacement: *const c_void,
    /// Set by [`patch_module`] to the original function address so hooks
    /// can call back into the real ntdll.
    pub original: *mut *const c_void,
}

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Patch one loaded module's imports from `target_dll`. Returns the
/// number of IAT slots successfully rewritten.
///
/// # Safety
///
/// * `module` must be a valid, loaded PE image.
/// * All `replacement` pointers must be ABI-compatible with the
///   function they replace.
/// * `HookEntry::original` must point to writable storage the caller
///   owns.
pub unsafe fn patch_module(
    module: HMODULE,
    target_dll: &[u8],
    hooks: &[HookEntry],
) -> usize {
    if module.is_null() {
        return 0;
    }
    let base = module as *const u8;

    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return 0;
    }
    let nt = &*(base.offset(dos.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return 0;
    }

    let import_dir: &IMAGE_DATA_DIRECTORY =
        &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.VirtualAddress == 0 || import_dir.Size == 0 {
        return 0;
    }

    let mut import_ptr = base.offset(import_dir.VirtualAddress as isize)
        as *const IMAGE_IMPORT_DESCRIPTOR;
    let mut hits = 0usize;

    loop {
        let desc = &*import_ptr;
        if desc.Name == 0 && desc.FirstThunk == 0 {
            break;
        }
        let name_ptr = base.offset(desc.Name as isize) as *const c_char;
        let name_bytes = cstr_bytes(name_ptr);
        if ascii_eq_ignore_case(name_bytes, target_dll) {
            hits += patch_descriptor(base, desc, hooks);
        }
        import_ptr = import_ptr.add(1);
    }
    hits
}

unsafe fn patch_descriptor(
    base: *const u8,
    desc: &IMAGE_IMPORT_DESCRIPTOR,
    hooks: &[HookEntry],
) -> usize {
    let name_thunks = if desc.Anonymous.OriginalFirstThunk != 0 {
        base.offset(desc.Anonymous.OriginalFirstThunk as isize) as *const IMAGE_THUNK_DATA64
    } else {
        base.offset(desc.FirstThunk as isize) as *const IMAGE_THUNK_DATA64
    };
    let iat_thunks =
        base.offset(desc.FirstThunk as isize) as *mut IMAGE_THUNK_DATA64;

    let mut i = 0isize;
    let mut hits = 0usize;
    loop {
        let nt = name_thunks.offset(i);
        let nt_val = (*nt).u1.AddressOfData;
        if nt_val == 0 {
            break;
        }
        if nt_val & IMAGE_ORDINAL_FLAG64 == 0 {
            let name_struct = base.offset(nt_val as isize)
                .offset(2) // skip Hint: u16
                as *const c_char;
            let name = cstr_bytes(name_struct);
            for h in hooks {
                let expected = strip_nul(h.name);
                if name == expected {
                    let slot: *mut *const c_void =
                        &mut (*iat_thunks.offset(i)).u1.Function as *mut _ as *mut *const c_void;
                    let original = *slot;
                    *h.original = original;
                    if write_protected(slot as *mut c_void, h.replacement as *const c_void) {
                        hits += 1;
                    }
                }
            }
        }
        i += 1;
    }
    hits
}

unsafe fn write_protected(slot: *mut c_void, value: *const c_void) -> bool {
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    let size = core::mem::size_of::<*const c_void>();
    if VirtualProtect(slot, size, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
        return false;
    }
    *(slot as *mut *const c_void) = value;
    let mut discard: PAGE_PROTECTION_FLAGS = 0;
    VirtualProtect(slot, size, old, &mut discard);
    true
}

/// Restore previously-patched IAT slots.
pub unsafe fn restore_module(
    module: HMODULE,
    target_dll: &[u8],
    hooks: &[HookEntry],
) -> usize {
    if module.is_null() {
        return 0;
    }
    let base = module as *const u8;
    let dos = &*(base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != IMAGE_DOS_SIGNATURE {
        return 0;
    }
    let nt = &*(base.offset(dos.e_lfanew as isize) as *const IMAGE_NT_HEADERS64);
    if nt.Signature != IMAGE_NT_SIGNATURE {
        return 0;
    }

    let import_dir: &IMAGE_DATA_DIRECTORY =
        &nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.VirtualAddress == 0 || import_dir.Size == 0 {
        return 0;
    }

    let mut import_ptr = base.offset(import_dir.VirtualAddress as isize)
        as *const IMAGE_IMPORT_DESCRIPTOR;
    let mut hits = 0usize;
    loop {
        let desc = &*import_ptr;
        if desc.Name == 0 && desc.FirstThunk == 0 {
            break;
        }
        let name_ptr = base.offset(desc.Name as isize) as *const c_char;
        let name_bytes = cstr_bytes(name_ptr);
        if ascii_eq_ignore_case(name_bytes, target_dll) {
            hits += restore_descriptor(base, desc, hooks);
        }
        import_ptr = import_ptr.add(1);
    }
    hits
}

unsafe fn restore_descriptor(
    base: *const u8,
    desc: &IMAGE_IMPORT_DESCRIPTOR,
    hooks: &[HookEntry],
) -> usize {
    let name_thunks = if desc.Anonymous.OriginalFirstThunk != 0 {
        base.offset(desc.Anonymous.OriginalFirstThunk as isize) as *const IMAGE_THUNK_DATA64
    } else {
        base.offset(desc.FirstThunk as isize) as *const IMAGE_THUNK_DATA64
    };
    let iat_thunks =
        base.offset(desc.FirstThunk as isize) as *mut IMAGE_THUNK_DATA64;

    let mut i = 0isize;
    let mut hits = 0usize;
    loop {
        let nt = name_thunks.offset(i);
        let nt_val = (*nt).u1.AddressOfData;
        if nt_val == 0 {
            break;
        }
        if nt_val & IMAGE_ORDINAL_FLAG64 == 0 {
            let name_struct = base.offset(nt_val as isize).offset(2) as *const c_char;
            let name = cstr_bytes(name_struct);
            for h in hooks {
                let expected = strip_nul(h.name);
                if name == expected {
                    let slot: *mut *const c_void =
                        &mut (*iat_thunks.offset(i)).u1.Function as *mut _ as *mut *const c_void;
                    let original = *h.original;
                    if !original.is_null() {
                        write_protected(slot as *mut c_void, original);
                        hits += 1;
                    }
                }
            }
        }
        i += 1;
    }
    hits
}

// ─────────────────────── helpers ───────────────────────

unsafe fn cstr_bytes(ptr: *const c_char) -> &'static [u8] {
    if ptr.is_null() {
        return &[];
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    slice::from_raw_parts(ptr as *const u8, len)
}

fn strip_nul(s: &[u8]) -> &[u8] {
    if s.last() == Some(&0) {
        &s[..s.len() - 1]
    } else {
        s
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != strip_nul(b).len() {
        return false;
    }
    let b = strip_nul(b);
    a.iter()
        .zip(b.iter())
        .all(|(&x, &y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}
