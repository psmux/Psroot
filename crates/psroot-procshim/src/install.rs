//! Hook installation via INLINE FUNCTION PATCHING.
//!
//! IAT hooking doesn't work for ntdll functions because kernelbase and
//! other system modules resolve them via direct syscall stubs, not
//! through an IAT entry we can replace. The ONLY reliable way to
//! intercept NtQuerySystemInformation for ALL callers is to patch the
//! first bytes of the function itself with a `jmp` to our hook.
//!
//! Technique (x64): 
//!   jmp qword ptr [rip+0]    ; FF 25 00 00 00 00   (6 bytes)
//!   <absolute hook address>  ; 8 bytes
//! Total: 14 bytes. Padded to 16 with 2x NOP (90 90).
//!
//! Windows ntdll syscall stubs are exactly:
//!   mov r10, rcx      ; 3 bytes
//!   mov eax, <num>    ; 5 bytes  
//!   test byte [..], 1 ; 8 bytes  (ends at offset 16)
//!   ...
//! So 16 bytes gives us a clean instruction boundary.
//!
//! The trampoline saves the full 24-byte syscall stub and executes
//! it to call the real function.
//!
//! # Loader lock safety
//!
//! This is safe under loader lock because:
//! - `GetModuleHandleA` is loader-lock-safe
//! - `GetProcAddress` is loader-lock-safe  
//! - `VirtualProtect` / `VirtualAlloc` are direct syscalls
//! - The actual patching is just memcpy

#![cfg(windows)]

use core::ffi::c_void;
use core::sync::atomic::Ordering;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

use crate::hooks::{hook_nt_open_process, hook_nt_query_system_information};
use crate::state::{BypassGuard, ShimState, STATE};

/// Size of an ntdll syscall stub on x64 Windows 10/11.
const SYSCALL_STUB_SIZE: usize = 24;
/// How many bytes we overwrite with our jump (14 + 2 NOP = 16).
const PATCH_SIZE: usize = 16;

#[derive(Debug)]
pub enum InstallError {
    AlreadyInstalled,
    NtdllNotFound,
    FunctionNotFound(&'static str),
    PatchFailed(&'static str),
}

/// Executable trampoline that contains the original syscall stub.
/// Calling this trampoline executes the real ntdll function.
struct Trampoline {
    code: *mut u8,
}

impl Trampoline {
    fn as_fn_ptr(&self) -> *const c_void {
        self.code as *const c_void
    }
}

/// RAII guard: on drop, restores the original function bytes.
pub struct HookGuard {
    patches: Vec<PatchRecord>,
}

struct PatchRecord {
    target: *mut u8,
    original_bytes: [u8; PATCH_SIZE],
    #[allow(dead_code)]
    trampoline: Trampoline,
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        for p in &self.patches {
            unsafe { restore_patch(p.target, &p.original_bytes); }
        }
    }
}

/// Install process-visibility hooks via inline patching of ntdll exports.
///
/// # Safety
/// Modifies executable code in ntdll.dll. Must be called when no other
/// thread is executing the target functions (e.g., from DllMain of an
/// injected DLL into a suspended process).
pub unsafe fn install() -> Result<HookGuard, InstallError> {
    if STATE.get().is_some() {
        return Err(InstallError::AlreadyInstalled);
    }

    let root_pid = GetCurrentProcessId();
    let _ = STATE.set(ShimState::new(root_pid));
    let state = STATE.get().expect("just set");

    let _g = BypassGuard::enter();

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
    if ntdll.is_null() {
        return Err(InstallError::NtdllNotFound);
    }

    let mut patches = Vec::new();

    // Hook NtQuerySystemInformation
    let nqsi = GetProcAddress(ntdll, b"NtQuerySystemInformation\0".as_ptr());
    let Some(nqsi) = nqsi else {
        return Err(InstallError::FunctionNotFound("NtQuerySystemInformation"));
    };
    let nqsi_ptr = nqsi as *mut u8;
    let trampoline = apply_inline_hook(
        nqsi_ptr,
        hook_nt_query_system_information as *const u8,
    ).ok_or(InstallError::PatchFailed("NtQuerySystemInformation"))?;

    state.originals.nt_query_system_information.store(
        trampoline.as_fn_ptr() as usize,
        Ordering::Release,
    );
    let mut original_bytes = [0u8; PATCH_SIZE];
    // We already saved these in the trampoline — grab from there
    core::ptr::copy_nonoverlapping(trampoline.code, original_bytes.as_mut_ptr(), PATCH_SIZE);
    patches.push(PatchRecord {
        target: nqsi_ptr,
        original_bytes,
        trampoline,
    });

    // Hook NtOpenProcess
    let nop = GetProcAddress(ntdll, b"NtOpenProcess\0".as_ptr());
    let Some(nop) = nop else {
        return Err(InstallError::FunctionNotFound("NtOpenProcess"));
    };
    let nop_ptr = nop as *mut u8;
    let trampoline = apply_inline_hook(
        nop_ptr,
        hook_nt_open_process as *const u8,
    ).ok_or(InstallError::PatchFailed("NtOpenProcess"))?;

    state.originals.nt_open_process.store(
        trampoline.as_fn_ptr() as usize,
        Ordering::Release,
    );
    let mut original_bytes = [0u8; PATCH_SIZE];
    core::ptr::copy_nonoverlapping(trampoline.code, original_bytes.as_mut_ptr(), PATCH_SIZE);
    patches.push(PatchRecord {
        target: nop_ptr,
        original_bytes,
        trampoline,
    });

    Ok(HookGuard { patches })
}

/// Apply an inline hook: overwrite the first PATCH_SIZE bytes of `target`
/// with a jump to `hook`. Returns a Trampoline that contains the entire
/// original syscall stub (executable, so calling it invokes the real function).
unsafe fn apply_inline_hook(target: *mut u8, hook: *const u8) -> Option<Trampoline> {
    // Allocate executable memory for the trampoline.
    // We copy the FULL syscall stub (24 bytes) so the trampoline is a
    // complete, self-contained implementation of the original function.
    let trampoline_mem = VirtualAlloc(
        core::ptr::null(),
        SYSCALL_STUB_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if trampoline_mem.is_null() {
        return None;
    }

    // Copy the entire original syscall stub into the trampoline
    core::ptr::copy_nonoverlapping(target, trampoline_mem, SYSCALL_STUB_SIZE);

    // Now overwrite target with our jump:
    //   FF 25 00 00 00 00    jmp qword ptr [rip+0]
    //   <8-byte addr>        absolute address of our hook
    //   90 90                2x NOP padding to reach 16 bytes
    let hook_addr = hook as u64;
    let mut patch = [0x90u8; PATCH_SIZE]; // fill with NOP
    patch[0] = 0xFF;
    patch[1] = 0x25;
    patch[2] = 0x00;
    patch[3] = 0x00;
    patch[4] = 0x00;
    patch[5] = 0x00;
    patch[6..14].copy_from_slice(&hook_addr.to_le_bytes());
    // bytes 14, 15 are NOP (already set)

    // Make target writable, apply patch, restore protection
    let mut old_protect: PAGE_PROTECTION_FLAGS = 0;
    if VirtualProtect(target as *const c_void, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
        return None;
    }
    core::ptr::copy_nonoverlapping(patch.as_ptr(), target, PATCH_SIZE);
    let mut discard: PAGE_PROTECTION_FLAGS = 0;
    VirtualProtect(target as *const c_void, PATCH_SIZE, old_protect, &mut discard);

    Some(Trampoline { code: trampoline_mem })
}

/// Restore the original bytes of a hooked function.
unsafe fn restore_patch(target: *mut u8, original: &[u8; PATCH_SIZE]) {
    let mut old_protect: PAGE_PROTECTION_FLAGS = 0;
    if VirtualProtect(target as *const c_void, PATCH_SIZE, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
        return;
    }
    core::ptr::copy_nonoverlapping(original.as_ptr(), target, PATCH_SIZE);
    let mut discard: PAGE_PROTECTION_FLAGS = 0;
    VirtualProtect(target as *const c_void, PATCH_SIZE, old_protect, &mut discard);
}
