#![cfg(windows)]
//! Container-side shim for the psroot userland netstack.

//!
//! This crate has two roles:
//!
//! 1. **Rust library** (`rlib`) — used by unit and integration tests so
//!    the full request/reply path can be exercised in-process without
//!    any DLL injection machinery.
//! 2. **Dynamic library** (`cdylib`) — Phase 2 target. Will be injected
//!    into AppContainer processes (via Detours / `DetourCreateProcess
//!    WithDllEx`) and hook `ws2_32.dll` exports so unmodified Windows
//!    apps transparently talk to the host daemon instead of the kernel
//!    TCP/IP stack.
//!
//! # Phase 1 (this file)
//!
//! The only API shipped today is the pure-Rust [`Client`]. It owns one
//! [`Channel`] (shim side) and exposes Winsock-shaped methods. Unit tests
//! pair it with a real [`psroot_netstack_host::Daemon`] over a named
//! shared-memory mapping — giving us full coverage of the wire protocol
//! without any unsafe DLL tricks.
//!
//! # Phase 2 TODO (DO NOT REMOVE — this is the handoff list)
//!
//! * `hooks` module: `DetourAttach` / `DetourDetach` for `socket`, `bind`,
//!   `connect`, `listen`, `accept`, `send`, `recv`, `closesocket`,
//!   `WSAStartup`, `WSAIoctl` (to trap `SIO_GET_EXTENSION_FUNCTION_POINTER`
//!   and return our own `ConnectEx`/`AcceptEx`), `getaddrinfo`,
//!   `getsockname`, `getpeername`, `shutdown`, `setsockopt`, `getsockopt`.
//! * `dllmain`: `DLL_PROCESS_ATTACH` → read `PSROOT_NETSTACK_HANDLE` from
//!   env, build [`Client`] from inherited handle, install hooks.
//! * IOCP trapping: replace `CreateIoCompletionPort` + overlapped ops so
//!   `WSARecv`/`WSASend` work. Non-trivial; quarantined in its own file.
//! * Thread-safety: Winsock is multi-threaded; put the [`Client`] behind
//!   a `Mutex` and add batched send/recv APIs to avoid contention.

#[cfg(windows)]
pub mod client;
#[cfg(windows)]
pub mod dllmain;
#[cfg(windows)]
pub mod hooks;
#[cfg(windows)]
pub mod iat;
#[cfg(windows)]
pub mod install;
#[cfg(windows)]
pub mod state;

#[cfg(windows)]
pub use client::{Client, ClientError};
#[cfg(windows)]
pub use install::{install, install_main_exe, HookGuard, InstallError};

// Stub so non-Windows `cargo check` still passes on dev machines.
#[cfg(not(windows))]
pub struct Client;
