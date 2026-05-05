#![cfg(windows)]
//! Lock-free shared-memory IPC for the psroot netstack.
//!
//! Two processes — the AppContainer **shim** and the host **daemon** —
//! exchange fixed-size messages via a pair of single-producer / single-
//! consumer ring buffers mapped into shared memory. A third shared word
//! acts as a futex that both sides can `WaitOnAddress`/`WakeByAddress` on
//! for sub-microsecond signalling without syscall overhead when idle.
//!
//! # Module layout
//!
//! * [`ring`]   — the pure-logic SPSC ring. Works on any `&[u8]` with the
//!                right layout; testable in a single process with a `Vec`.
//! * [`shm`]    — Windows `CreateFileMappingW`/`MapViewOfFile` wrappers.
//! * [`signal`] — Windows `WaitOnAddress`/`WakeByAddressSingle` wrappers.
//! * [`channel`]— The end-user abstraction: pairs of rings (`tx`/`rx`) +
//!                a futex, packaged for either the host or the shim side.

pub mod channel;
pub mod ring;
#[cfg(windows)]
pub mod shm;
#[cfg(windows)]
pub mod signal;

pub use channel::{Channel, ChannelLayout, ChannelSide};
pub use ring::{Ring, RingError, RingHeader};
