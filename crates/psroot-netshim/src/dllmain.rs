//! DllMain for the `cdylib` build.
//!
//! When `psroot-netshim` is loaded into a target process (e.g. via
//! `CreateRemoteThread(LoadLibraryW)` from `psroot-netinject`), Windows
//! calls this `DllMain` on `DLL_PROCESS_ATTACH`. We keep the work inside
//! `DllMain` itself to the absolute minimum — just `DisableThreadLibrary
//! Calls` and spawning a dedicated init thread — to avoid deadlocks
//! with the loader lock.
//!
//! The init thread reads two environment variables:
//!
//! * `PSROOT_NS_NAME` — the named shared memory object exposed by the
//!   host daemon (e.g. `Local\psroot-ns-42`). Required.
//! * `PSROOT_NS_SIZE` — the mapping size in bytes, as a decimal string.
//!   Required.
//!
//! If either variable is absent or the attach fails, the DLL silently
//! becomes a no-op and the process's Winsock calls keep going to the
//! real OS stack. This is intentional: loading this DLL into a process
//! that is not under psroot's control must not crash the process.
//!
//! # Safety of `DllMain`
//!
//! The Windows loader holds a process-wide lock when executing `DllMain`.
//! Doing too much work here — especially anything that could cause
//! another DLL to load — is the classic loader-lock deadlock bug. We
//! touch only:
//!
//! * `DisableThreadLibraryCalls` (safe per MSDN)
//! * `std::thread::spawn` (creates a thread; CRT may internally load
//!   `ntdll` APIs, but that module is always already loaded)
//!
//! The heavy lifting (opening the named SHM, building the [`Client`],
//! patching the IAT) happens on the init thread, AFTER `DllMain`
//! returns.

#![cfg(windows)]

use core::ffi::c_void;

use windows_sys::Win32::Foundation::{BOOL, HINSTANCE, TRUE};
use windows_sys::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

/// The Windows entry point for this DLL.
///
/// Exported with `#[no_mangle]` so the loader can find it by its
/// canonical name. The signature matches `BOOL WINAPI DllMain(HINSTANCE,
/// DWORD, LPVOID)` as required by the SDK.
///
/// # Safety
/// Called by the OS loader on its own schedule. Must not block or
/// acquire locks that could deadlock with the loader.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    inst: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        unsafe {
            // We don't care about thread attach/detach notifications and
            // avoiding them reduces loader pressure in heavily-threaded
            // targets (Chromium, Node, etc).
            DisableThreadLibraryCalls(inst);
        }
        // Move the real work off the loader-locked path.
        //
        // `std::thread::spawn` itself is loader-safe on Windows — thread
        // creation goes through `NtCreateThreadEx` which is provided by
        // `ntdll` (always loaded). The new thread's first Rust code runs
        // after DllMain has returned and the loader lock has been
        // released, so it's safe to do whatever we want there.
        let _ = std::thread::Builder::new()
            .name("psroot-netshim-init".to_string())
            .spawn(|| {
                let _ = try_init();
            });
    }
    TRUE
}

/// Attempt to attach to the host daemon's SHM and install IAT hooks on
/// the main executable. Returns `None` on any failure — we never panic,
/// because panicking inside an injected DLL would take the host process
/// down with us.
fn try_init() -> Option<()> {
    use psroot_netstack_ipc::{shm::SharedMemory, Channel, ChannelLayout, ChannelSide};

    let name = std::env::var("PSROOT_NS_NAME").ok()?;
    let size: usize = std::env::var("PSROOT_NS_SIZE").ok()?.parse().ok()?;

    // The default ring layout must match exactly what the host created.
    let layout = ChannelLayout::new(psroot_netstack_proto::DEFAULT_RING_SLOTS);
    if layout.total_size != size {
        // Host and shim disagree on the mapping layout; refuse rather
        // than silently producing garbage traffic.
        return None;
    }

    let shm = SharedMemory::open(&name, size).ok()?;
    let channel = Channel::attach(shm, layout, ChannelSide::Shim);
    let client = crate::Client::new(channel);

    // IAT-patch the main executable image. Any module loaded later that
    // imports ws2_32 directly (e.g. a plugin DLL) will escape us — but
    // Phase 3 scope explicitly excludes `LdrLoadDll` trapping.
    let guard = unsafe { crate::install_main_exe(client) }.ok()?;
    // Leak the guard: we want hooks installed for the lifetime of the
    // process. Dropping would restore the IAT and route syscalls back
    // to the kernel stack.
    core::mem::forget(guard);
    Some(())
}
