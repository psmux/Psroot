//! Cross-process futex-style signalling via `WaitOnAddress` /
//! `WakeByAddressSingle`.
//!
//! These APIs operate on any virtual memory address that both parties can
//! observe — so the memory *can* be in a shared mapping. Windows 8+ is the
//! baseline; no admin required.
//!
//! The protocol used by [`crate::channel`]:
//!
//! 1. Consumer sets `futex = FUTEX_SLEEPING` and calls `WaitOnAddress`
//!    with an expected value of `FUTEX_SLEEPING`. If the producer has
//!    already written something (`futex != FUTEX_SLEEPING`) the syscall
//!    returns immediately.
//! 2. Producer writes `FUTEX_WOKEN` and calls `WakeByAddressSingle`.
//! 3. Consumer wakes, resets to `FUTEX_IDLE`, drains whatever is
//!    available on its ring.
//!
//! The futex is only a hint — the ring is the source of truth — so a
//! spurious wake or a missed wake is harmless (the next poll will find
//! either the message or a new sleep token).

use core::sync::atomic::{AtomicU32, Ordering};
use std::io;
use std::time::Duration;

use windows_sys::Win32::System::Threading::{
    WaitOnAddress, WakeByAddressAll, WakeByAddressSingle, INFINITE,
};

/// Futex value meaning "no pending wakeup; consumer may park".
pub const FUTEX_IDLE: u32 = 0;
/// Futex value meaning "consumer has parked — producer should wake on post".
pub const FUTEX_SLEEPING: u32 = 1;
/// Futex value meaning "producer posted; consumer should re-check ring".
pub const FUTEX_WOKEN: u32 = 2;

/// Park on `word` until someone wakes us or `timeout` elapses.
///
/// Returns `Ok(true)` if woken, `Ok(false)` on timeout.
pub fn wait(word: &AtomicU32, expected: u32, timeout: Option<Duration>) -> io::Result<bool> {
    let addr = word as *const AtomicU32 as *const core::ffi::c_void;
    let expected_ref = &expected as *const u32 as *const core::ffi::c_void;
    let ms = timeout.map(|d| d.as_millis().min(u32::MAX as u128) as u32).unwrap_or(INFINITE);
    // SAFETY: `addr` is a live reference; expected_ref outlives the call.
    let ok = unsafe { WaitOnAddress(addr, expected_ref, core::mem::size_of::<u32>(), ms) };
    if ok == 0 {
        let err = io::Error::last_os_error();
        // ERROR_TIMEOUT == 1460
        if err.raw_os_error() == Some(1460) {
            Ok(false)
        } else {
            Err(err)
        }
    } else {
        Ok(true)
    }
}

/// Wake one waiter on `word`. No-op if no one is parked.
pub fn wake_one(word: &AtomicU32) {
    let addr = word as *const AtomicU32 as *const core::ffi::c_void;
    unsafe { WakeByAddressSingle(addr) };
}

/// Wake every waiter on `word`.
pub fn wake_all(word: &AtomicU32) {
    let addr = word as *const AtomicU32 as *const core::ffi::c_void;
    unsafe { WakeByAddressAll(addr) };
}

/// Producer-side: mark the word as "woken" and wake a parked consumer.
pub fn post(word: &AtomicU32) {
    // Only wake if the consumer actually parked; this avoids the syscall
    // in the steady-state busy case where we're streaming packets faster
    // than the consumer can sleep.
    let prev = word.swap(FUTEX_WOKEN, Ordering::Release);
    if prev == FUTEX_SLEEPING {
        wake_one(word);
    }
}

/// Consumer-side: park on the word unless a post has already arrived.
/// Returns `true` if a post was seen (either before or during the wait).
pub fn park(word: &AtomicU32, timeout: Option<Duration>) -> io::Result<bool> {
    // Claim the sleep slot. If a post raced us, we'll observe it here.
    let prev = word.swap(FUTEX_SLEEPING, Ordering::AcqRel);
    if prev == FUTEX_WOKEN {
        // Producer already posted; consume the token.
        word.store(FUTEX_IDLE, Ordering::Release);
        return Ok(true);
    }
    let woken = wait(word, FUTEX_SLEEPING, timeout)?;
    // Consume the token whether we timed out or were explicitly woken;
    // the ring is the source of truth.
    word.store(FUTEX_IDLE, Ordering::Release);
    Ok(woken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn post_wakes_park() {
        let word = Arc::new(AtomicU32::new(FUTEX_IDLE));
        let w2 = Arc::clone(&word);
        let t = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            post(&w2);
        });
        let woken = park(&word, Some(Duration::from_secs(2))).unwrap();
        assert!(woken);
        t.join().unwrap();
    }

    #[test]
    fn post_before_park_does_not_block() {
        let word = AtomicU32::new(FUTEX_IDLE);
        post(&word);
        let woken = park(&word, Some(Duration::from_millis(100))).unwrap();
        assert!(woken);
    }

    #[test]
    fn park_times_out() {
        let word = AtomicU32::new(FUTEX_IDLE);
        let woken = park(&word, Some(Duration::from_millis(30))).unwrap();
        assert!(!woken);
    }
}
