//! Import Address Table (IAT) patching.
//!
//! The "hook" mechanism used by Phase 2: we walk the PE header of a
//! loaded module, find entries in its import table that reference
//! `ws2_32.dll`, and rewrite the IAT slot to point at our replacement
//! function. Calls to `connect`, `send`, etc. from that module then land
//! in our code instead of Winsock.
//!
//! # Why not inline detours?
//!
//! Inline trampolines (the `retour` / minhook approach) require disasm-
//! level instruction rewriting and currently pull in a nightly-only dep
//! chain. IAT patching needs **only pointer writes**, is 100% stable
//! Rust, and scopes the effect to exactly the modules we walk — which is
//! precisely the isolation we want: we only patch the container's
//! imports, never ws2_32 globally.
//!
//! # Limitations (documented, accepted for Phase 2)
//!
//! * Code that resolves Winsock exports at runtime via `GetProcAddress`
//!   (or `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`) is **not**
//!   intercepted by IAT patching. Full coverage would need additionally
//!   hooking `GetProcAddress` itself, which is out of scope for this
//!   slice.
//! * We patch **only** the modules passed to [`patch_module`]. Callers
//!   walk the module list themselves so they can decide which modules
//!   are "inside the container" and which are system DLLs.

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

/// One hook target: the exact export name (case-sensitive, as Winsock
/// uses it in its export table) and the replacement pointer.
#[derive(Copy, Clone)]
pub struct HookEntry {
    pub name: &'static [u8], // null-terminated ASCII
    pub replacement: *const c_void,
    /// Set by [`patch_module`] to the original function address so hooks
    /// can call back into the real Winsock.
    pub original: *mut *const c_void,
}

// Thin, explicit layout for the imports directory we actually care about.
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// Patch one loaded module. Returns the number of successful hooks.
///
/// # Safety
///
/// * `module` must be a valid, loaded PE image (e.g. from
///   `GetModuleHandleW` or `LoadLibraryW`).
/// * All `replacement` pointers in `hooks` must be ABI-compatible with
///   the Winsock function they replace.
/// * `HookEntry::original` must point to a `*const c_void` that the
///   caller owns and is willing to have overwritten.
pub unsafe fn patch_module(
    module: HMODULE,
    target_dll: &[u8], // e.g. b"ws2_32.dll" (ASCII, lowercase)
    hooks: &[HookEntry],
) -> usize {
    if module.is_null() {
        return 0;
    }
    let base = module as *const u8;

    // DOS header
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
        // Sentinel: all-zero descriptor.
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
    // The OriginalFirstThunk (aka Characteristics) holds name hints; the
    // FirstThunk is the actual IAT slot we want to overwrite. They run
    // in parallel.
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
        // Ordinal-only imports have the high bit set; no name available.
        if nt_val & IMAGE_ORDINAL_FLAG64 == 0 {
            let name_struct = base.offset(nt_val as isize)
                .offset(2) // skip Hint: u16
                as *const c_char;
            let name = cstr_bytes(name_struct);
            for h in hooks {
                // Strip trailing NUL from our side for the comparison.
                let expected = strip_nul(h.name);
                if name == expected {
                    let slot: *mut *const c_void =
                        &mut (*iat_thunks.offset(i)).u1.Function as *mut _ as *mut *const c_void;
                    // Capture original before we overwrite it.
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

/// Write `value` into `slot` after temporarily making the page writable.
/// Returns `true` on success.
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

/// Restore a previously-patched slot. Used by [`unpatch_all`].
///
/// # Safety
/// Same invariants as [`patch_module`], plus `original` must be the
/// value captured during the matching `patch_module` call.
pub unsafe fn restore_module(
    module: HMODULE,
    target_dll: &[u8],
    hooks: &[HookEntry],
) -> usize {
    // Reuse patch_module logic but swap replacement/original intent:
    // we rewrite IAT slots back to the stored originals.
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
    if import_dir.VirtualAddress == 0 {
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
        if ascii_eq_ignore_case(cstr_bytes(name_ptr), target_dll) {
            let iat_thunks = base.offset(desc.FirstThunk as isize)
                as *mut IMAGE_THUNK_DATA64;
            let name_thunks = if desc.Anonymous.OriginalFirstThunk != 0 {
                base.offset(desc.Anonymous.OriginalFirstThunk as isize)
                    as *const IMAGE_THUNK_DATA64
            } else {
                iat_thunks as *const IMAGE_THUNK_DATA64
            };
            let mut i = 0isize;
            loop {
                let v = (*name_thunks.offset(i)).u1.AddressOfData;
                if v == 0 {
                    break;
                }
                if v & IMAGE_ORDINAL_FLAG64 == 0 {
                    let n = base.offset(v as isize).offset(2) as *const c_char;
                    let name = cstr_bytes(n);
                    for h in hooks {
                        if name == strip_nul(h.name) {
                            let slot: *mut *const c_void = &mut (*iat_thunks.offset(i))
                                .u1
                                .Function as *mut _
                                as *mut *const c_void;
                            if write_protected(slot as *mut c_void, *h.original) {
                                hits += 1;
                            }
                        }
                    }
                }
                i += 1;
            }
        }
        import_ptr = import_ptr.add(1);
    }
    hits
}

// ───────────────────────────── tiny utils ──────────────────────────────

unsafe fn cstr_bytes(p: *const c_char) -> &'static [u8] {
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    slice::from_raw_parts(p as *const u8, len)
}

fn strip_nul(b: &[u8]) -> &[u8] {
    if let Some(&0) = b.last() {
        &b[..b.len() - 1]
    } else {
        b
    }
}

fn ascii_eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(x, y)| x.to_ascii_lowercase() == y.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_cmp_is_case_insensitive() {
        assert!(ascii_eq_ignore_case(b"WS2_32.dll", b"ws2_32.dll"));
        assert!(!ascii_eq_ignore_case(b"ws2_32.dll", b"kernel32.dll"));
    }

    #[test]
    fn strip_nul_removes_trailing() {
        assert_eq!(strip_nul(b"connect\0"), b"connect");
        assert_eq!(strip_nul(b"connect"), b"connect");
    }
}
