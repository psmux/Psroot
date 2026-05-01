//! Global hook state — the Client, socket ID translation table, and the
//! TLS bypass flag that prevents the daemon's own Winsock calls from
//! recursing through the hooks.

#![cfg(windows)]

use core::cell::Cell;
use std::collections::HashMap;

use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use windows_sys::Win32::Networking::WinSock::SOCKET;

use crate::client::Client;

thread_local! {
    /// Counter: >0 means "this thread is inside the daemon or a hook;
    /// pass through Winsock calls to the real OS stack instead of
    /// recursing into ourselves".
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

/// True if the current thread should skip netshim hooks.
pub fn is_bypassed() -> bool {
    BYPASS.with(|b| b.get() > 0)
}

/// Global shim state — set once during `install_hooks`.
pub(crate) struct ShimState {
    pub client: Client,
    /// Map real `SOCKET` returned to the caller → our virtual socket_id
    /// inside the daemon.
    pub sockets: Mutex<HashMap<usize, u32>>,
    /// Monotonic counter for synthetic SOCKET values we hand back.
    pub next_fake: Mutex<usize>,
    /// Originals of hooked Winsock functions (pointers filled in by the
    /// IAT patcher). Each hook implementation reads its pointer through
    /// this struct to fall back to the real OS stack when bypassed.
    pub originals: Originals,
}

/// Original Winsock function pointers captured during IAT patching.
#[derive(Default)]
pub struct Originals {
    pub socket: core::sync::atomic::AtomicUsize,
    pub connect: core::sync::atomic::AtomicUsize,
    pub send: core::sync::atomic::AtomicUsize,
    pub recv: core::sync::atomic::AtomicUsize,
    pub closesocket: core::sync::atomic::AtomicUsize,
    pub bind: core::sync::atomic::AtomicUsize,
    pub listen: core::sync::atomic::AtomicUsize,
    pub getsockname: core::sync::atomic::AtomicUsize,
    pub getpeername: core::sync::atomic::AtomicUsize,
    pub sendto: core::sync::atomic::AtomicUsize,
    pub recvfrom: core::sync::atomic::AtomicUsize,
}

pub(crate) static STATE: OnceCell<ShimState> = OnceCell::new();

impl ShimState {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            sockets: Mutex::new(HashMap::new()),
            next_fake: Mutex::new(0x10000_0000), // start high so unlikely to collide
            originals: Originals::default(),
        }
    }

    /// Allocate a fake Winsock `SOCKET` handle bound to a virtual
    /// socket_id. The real OS never sees this handle.
    pub fn alloc_fake(&self, virt: u32) -> SOCKET {
        let mut next = self.next_fake.lock();
        let v = *next;
        *next += 1;
        self.sockets.lock().insert(v, virt);
        v as SOCKET
    }

    /// Resolve a real `SOCKET` back to our virtual socket id.
    /// Returns `None` if this handle was not created by us (e.g. it's a
    /// genuine OS socket used inside the daemon).
    pub fn lookup(&self, s: SOCKET) -> Option<u32> {
        self.sockets.lock().get(&(s as usize)).copied()
    }

    pub fn forget(&self, s: SOCKET) -> Option<u32> {
        self.sockets.lock().remove(&(s as usize))
    }
}
