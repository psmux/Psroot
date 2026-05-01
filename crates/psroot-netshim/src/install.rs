//! Public hook installation API for Phase 2.
//!
//! Callers construct a [`Client`] (usually from a shared-memory channel
//! attached to the host-side daemon), hand it to [`install`], and every
//! subsequent Winsock call made by this module — `socket`, `connect`,
//! `send`, `recv`, `closesocket`, `bind`, `listen`, `getsockname`,
//! `getpeername` — is transparently routed through the daemon.
//!
//! The returned [`HookGuard`] restores the IAT on drop. Tests use it to
//! guarantee cleanup even on panic; production (Phase 3) code will
//! simply `mem::forget` it for the lifetime of the injected process.

#![cfg(windows)]

use core::ffi::c_void;
use core::sync::atomic::Ordering;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

use crate::client::Client;
use crate::hooks::{
    hook_bind, hook_closesocket, hook_connect, hook_getpeername, hook_getsockname, hook_listen,
    hook_recv, hook_recvfrom, hook_send, hook_sendto, hook_socket,
};
use crate::iat::{patch_module, restore_module, HookEntry};
use crate::state::{BypassGuard, ShimState, STATE};

/// Error returned by [`install`].
#[derive(Debug)]
pub enum InstallError {
    /// `install` has already been called on this process.
    AlreadyInstalled,
    /// The IAT walker found zero Winsock imports in the target module.
    /// Usually means the target module does not link ws2_32.dll at all.
    NoImportsFound,
}

/// RAII guard: dropping this reverts the IAT to the captured originals.
pub struct HookGuard {
    modules: Vec<HMODULE>,
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        let Some(state) = STATE.get() else { return };
        let entries = build_entries(state);
        for m in &self.modules {
            unsafe {
                restore_module(*m, b"ws2_32.dll", &entries);
            }
        }
    }
}

/// Install Winsock hooks on the given `modules`. Pass
/// `&[GetModuleHandleW(ptr::null())]` to hook only the main exe — which
/// is the common case for tests.
///
/// # Safety
/// IAT patching writes to executable memory. The caller must guarantee
/// no other thread is concurrently calling the targeted Winsock exports
/// through those modules while this function runs.
pub unsafe fn install(client: Client, modules: &[HMODULE]) -> Result<HookGuard, InstallError> {
    // One-shot: refuse re-install so tests can't accidentally share state.
    if STATE.get().is_some() {
        return Err(InstallError::AlreadyInstalled);
    }
    let _ = STATE.set(ShimState::new(client));
    let state = STATE.get().expect("just set");
    let entries = build_entries(state);

    // Even the patching step may transitively call Winsock loaders;
    // belt-and-braces guard it.
    let _g = BypassGuard::enter();
    let mut hit_any = false;
    for m in modules {
        let hits = patch_module(*m, b"ws2_32.dll", &entries);
        if hits > 0 {
            hit_any = true;
        }
    }
    if !hit_any {
        return Err(InstallError::NoImportsFound);
    }
    Ok(HookGuard {
        modules: modules.to_vec(),
    })
}

/// Convenience: hook the main executable only.
///
/// # Safety
/// See [`install`].
pub unsafe fn install_main_exe(client: Client) -> Result<HookGuard, InstallError> {
    let main = GetModuleHandleW(core::ptr::null());
    install(client, &[main])
}

/// Build the table the IAT patcher uses. Each entry's `original` field
/// points at an `AtomicUsize` inside the shared [`ShimState`] so the
/// hook bodies can read the original pointer back at call time.
fn build_entries(state: &'static ShimState) -> [HookEntry; 11] {
    use core::sync::atomic::AtomicUsize;
    // We hand the patcher `*mut *const c_void`, but it's actually the
    // address of an AtomicUsize inside ShimState. The layouts are
    // compatible (usize == *const c_void on all Windows targets).
    fn as_slot(a: &AtomicUsize) -> *mut *const c_void {
        a as *const AtomicUsize as *mut *const c_void
    }
    let o = &state.originals;
    [
        HookEntry {
            name: b"socket\0",
            replacement: hook_socket as *const c_void,
            original: as_slot(&o.socket),
        },
        HookEntry {
            name: b"connect\0",
            replacement: hook_connect as *const c_void,
            original: as_slot(&o.connect),
        },
        HookEntry {
            name: b"send\0",
            replacement: hook_send as *const c_void,
            original: as_slot(&o.send),
        },
        HookEntry {
            name: b"recv\0",
            replacement: hook_recv as *const c_void,
            original: as_slot(&o.recv),
        },
        HookEntry {
            name: b"closesocket\0",
            replacement: hook_closesocket as *const c_void,
            original: as_slot(&o.closesocket),
        },
        HookEntry {
            name: b"bind\0",
            replacement: hook_bind as *const c_void,
            original: as_slot(&o.bind),
        },
        HookEntry {
            name: b"listen\0",
            replacement: hook_listen as *const c_void,
            original: as_slot(&o.listen),
        },
        HookEntry {
            name: b"getsockname\0",
            replacement: hook_getsockname as *const c_void,
            original: as_slot(&o.getsockname),
        },
        HookEntry {
            name: b"getpeername\0",
            replacement: hook_getpeername as *const c_void,
            original: as_slot(&o.getpeername),
        },
        HookEntry {
            name: b"sendto\0",
            replacement: hook_sendto as *const c_void,
            original: as_slot(&o.sendto),
        },
        HookEntry {
            name: b"recvfrom\0",
            replacement: hook_recvfrom as *const c_void,
            original: as_slot(&o.recvfrom),
        },
    ]
}

// One shared fact both install and HookGuard rely on: the AtomicUsize
// storage inside `Originals` is what the IAT patcher writes and what the
// hook bodies read.
#[allow(dead_code)]
fn _layout_check() {
    let _ = Ordering::Acquire;
}
