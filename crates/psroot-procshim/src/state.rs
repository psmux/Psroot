//! Global shim state — the container root PID and original function
//! pointers captured during IAT patching.

#![cfg(windows)]

use core::cell::Cell;
use core::sync::atomic::AtomicUsize;

use once_cell::sync::OnceCell;

thread_local! {
    /// Counter: >0 means "this thread is inside a hook; pass through
    /// to the real ntdll function to avoid infinite recursion".
    static BYPASS: Cell<u32> = const { Cell::new(0) };
}

/// RAII guard. Increment on construct, decrement on drop.
pub struct BypassGuard;

impl BypassGuard {
    pub fn enter() -> Self {
        BYPASS.with(|b| b.set(b.get() + 1));
        Self
    }
}

impl Drop for BypassGuard {
    fn drop(&mut self) {
        BYPASS.with(|b| b.set(b.get().saturating_sub(1)));
    }
}

/// True if the current thread should skip procshim hooks.
pub fn is_bypassed() -> bool {
    BYPASS.with(|b| b.get() > 0)
}

/// Original ntdll function pointers captured during IAT patching.
#[derive(Default)]
pub struct Originals {
    pub nt_query_system_information: AtomicUsize,
    pub nt_open_process: AtomicUsize,
}

pub(crate) struct ShimState {
    /// PID of the container's root process (the one we were injected into).
    pub container_root_pid: u32,
    /// Captured originals so hook bodies can call back to the real ntdll.
    pub originals: Originals,
}

pub(crate) static STATE: OnceCell<ShimState> = OnceCell::new();

impl ShimState {
    pub fn new(root_pid: u32) -> Self {
        Self {
            container_root_pid: root_pid,
            originals: Originals::default(),
        }
    }
}
