//! Hook implementations for process-visibility isolation.
//!
//! We intercept two ntdll exports:
//!
//! 1. `NtQuerySystemInformation` — the single chokepoint for ALL
//!    process enumeration on Windows. Every tool (tasklist, Get-Process,
//!    WMI, Toolhelp32, .NET Process class) ends up here. We call the
//!    real function, then walk the returned linked list of
//!    `SYSTEM_PROCESS_INFORMATION` structs and unlink entries whose PID
//!    is not the container root or a descendant.
//!
//! 2. `NtOpenProcess` — defense-in-depth. Even if a PID leaks through
//!    some path we didn't hook, opening a handle to a host process is
//!    denied with STATUS_ACCESS_DENIED.

#![cfg(windows)]

use core::ffi::c_void;
use core::sync::atomic::Ordering;
use std::collections::HashSet;

use crate::state::{is_bypassed, BypassGuard, STATE};

// ─────────────── NT status codes ───────────────────────

const STATUS_SUCCESS: i32 = 0;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004_u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC0000022_u32 as i32;

// ─────────────── System information classes ─────────────

const SYSTEM_PROCESS_INFORMATION: u32 = 5;
const SYSTEM_EXTENDED_PROCESS_INFORMATION: u32 = 57;
const SYSTEM_FULL_PROCESS_INFORMATION: u32 = 148;

// ─────────────── SYSTEM_PROCESS_INFORMATION layout ──────
//
// We only access the fields we need. The struct is variable-length
// (threads array follows), linked via NextEntryOffset.
//
// Offsets (x64):
//   0x00: NextEntryOffset (u32)
//   0x04: NumberOfThreads (u32)
//   ...
//   0x50: UniqueProcessId (HANDLE = usize on x64)
//   0x58: InheritedFromUniqueProcessId (HANDLE = usize on x64)
//
// These offsets are stable across Win10/11 (verified against
// ntdll headers and ReactOS).

const OFFSET_NEXT_ENTRY: usize = 0x00;
const OFFSET_UNIQUE_PID: usize = 0x50;
const OFFSET_INHERITED_PID: usize = 0x58;

// ─────────────── NtOpenProcess CLIENT_ID layout ─────────
//
// NtOpenProcess takes a pointer to OBJECT_ATTRIBUTES and CLIENT_ID.
//   CLIENT_ID { UniqueProcess: HANDLE, UniqueThread: HANDLE }

const OFFSET_CLIENT_ID_PROCESS: usize = 0x00;

// ─────────────── ABI-exact function pointer types ───────

type FnNtQuerySystemInformation = unsafe extern "system" fn(
    system_information_class: u32,
    system_information: *mut c_void,
    system_information_length: u32,
    return_length: *mut u32,
) -> i32;

type FnNtOpenProcess = unsafe extern "system" fn(
    process_handle: *mut isize, // PHANDLE
    desired_access: u32,
    object_attributes: *const c_void,
    client_id: *const c_void,
) -> i32;

// ─────────────── Hook: NtQuerySystemInformation ─────────

pub unsafe extern "system" fn hook_nt_query_system_information(
    class: u32,
    info: *mut c_void,
    length: u32,
    return_length: *mut u32,
) -> i32 {
    // Always call the real function first.
    let real = get_real_query();
    let status = real(class, info, length, return_length);

    // Only filter process-enumeration classes.
    if status != STATUS_SUCCESS {
        return status;
    }

    // If we're in a bypass context (our own code calling internally),
    // or this isn't a process-enumeration class, pass through.
    if is_bypassed()
        || (class != SYSTEM_PROCESS_INFORMATION
            && class != SYSTEM_EXTENDED_PROCESS_INFORMATION
            && class != SYSTEM_FULL_PROCESS_INFORMATION)
    {
        return status;
    }

    let _guard = BypassGuard::enter();

    let Some(state) = STATE.get() else {
        return status;
    };

    // The result is a linked list of variable-size structs. Walk it
    // twice: first to build the set of allowed PIDs (container root +
    // descendants), then to unlink disallowed entries.
    let base = info as *mut u8;
    if base.is_null() {
        return status;
    }

    let allowed = build_allowed_pids(base, state.container_root_pid);
    filter_process_list(base, &allowed);

    status
}

/// Walk the linked list and build a set of PIDs that belong to the
/// container's process tree (root + all descendants).
unsafe fn build_allowed_pids(base: *mut u8, root_pid: u32) -> HashSet<u32> {
    // First pass: collect all (PID, ParentPID) pairs.
    let mut entries: Vec<(u32, u32)> = Vec::new();
    let mut offset = 0usize;
    loop {
        let entry = base.add(offset);
        let pid = read_usize(entry, OFFSET_UNIQUE_PID) as u32;
        let ppid = read_usize(entry, OFFSET_INHERITED_PID) as u32;
        entries.push((pid, ppid));

        let next = read_u32(entry, OFFSET_NEXT_ENTRY);
        if next == 0 {
            break;
        }
        offset += next as usize;
    }

    // Build the allowed set: start with root, then iteratively add
    // any PID whose parent is already in the set. Repeat until stable.
    let mut allowed = HashSet::new();
    allowed.insert(root_pid);

    // Iterative closure: keep adding children until no new PIDs found.
    loop {
        let prev_len = allowed.len();
        for &(pid, ppid) in &entries {
            if allowed.contains(&ppid) && !allowed.contains(&pid) {
                allowed.insert(pid);
            }
        }
        if allowed.len() == prev_len {
            break;
        }
    }

    // Always allow PID 0 (Idle) in the final display set — some tools
    // crash if it's missing. But do NOT add it before the loop above,
    // otherwise PID 4 (System, parent=0) and its entire subtree leak.
    allowed.insert(0u32);

    allowed
}

/// Second pass: unlink entries not in `allowed` by adjusting
/// NextEntryOffset pointers.
unsafe fn filter_process_list(base: *mut u8, allowed: &HashSet<u32>) {
    let mut offset = 0usize;
    let mut prev_offset: Option<usize> = None;

    loop {
        let entry = base.add(offset);
        let pid = read_usize(entry, OFFSET_UNIQUE_PID) as u32;
        let next = read_u32(entry, OFFSET_NEXT_ENTRY);

        if !allowed.contains(&pid) {
            // Unlink this entry.
            if let Some(prev) = prev_offset {
                let prev_entry = base.add(prev);
                let prev_next = read_u32(prev_entry, OFFSET_NEXT_ENTRY);
                if next == 0 {
                    // This was the last entry; make prev the new last.
                    write_u32(prev_entry, OFFSET_NEXT_ENTRY, 0);
                } else {
                    // Skip over this entry: prev's next jumps to our next.
                    write_u32(
                        prev_entry,
                        OFFSET_NEXT_ENTRY,
                        prev_next + next,
                    );
                }
                // Don't update prev_offset — we removed this entry.
            } else {
                // First entry is not allowed. This is the Idle process
                // (PID 0) scenario; we always allow PID 0, so this
                // branch is unlikely. If it happens, we can't unlink
                // the first entry (no prev pointer), so just zero out
                // its PID field to make it look like a dead entry.
                write_usize(entry, OFFSET_UNIQUE_PID, 0);
            }
        } else {
            prev_offset = Some(offset);
        }

        if next == 0 {
            break;
        }
        offset += next as usize;
    }
}

// ─────────────── Hook: NtOpenProcess ────────────────────

pub unsafe extern "system" fn hook_nt_open_process(
    process_handle: *mut isize,
    desired_access: u32,
    object_attributes: *const c_void,
    client_id: *const c_void,
) -> i32 {
    if is_bypassed() || client_id.is_null() {
        return call_real_open_process(process_handle, desired_access, object_attributes, client_id);
    }

    let _guard = BypassGuard::enter();

    let Some(state) = STATE.get() else {
        return call_real_open_process(process_handle, desired_access, object_attributes, client_id);
    };

    // Read the target PID from CLIENT_ID.UniqueProcess.
    let target_pid = *((client_id as *const u8).add(OFFSET_CLIENT_ID_PROCESS) as *const usize) as u32;

    // Allow opening our own process and PID 0 (Idle) / PID 4 (System)
    // unconditionally — some system internals need these.
    if target_pid == 0 || target_pid == 4 || target_pid == state.container_root_pid {
        return call_real_open_process(process_handle, desired_access, object_attributes, client_id);
    }

    // For any other PID, we need to check if it's a descendant of our
    // container root. We do this by querying the real process list
    // (bypassed) and checking ancestry.
    if is_descendant_of_root(target_pid, state.container_root_pid) {
        return call_real_open_process(process_handle, desired_access, object_attributes, client_id);
    }

    // Host process — deny access.
    STATUS_ACCESS_DENIED
}

/// Check if `target_pid` is a descendant of `root_pid` by querying the
/// real (unfiltered) process list.
unsafe fn is_descendant_of_root(target_pid: u32, root_pid: u32) -> bool {
    // Use the real NtQuerySystemInformation (bypassed) to enumerate
    // all processes and walk the parent chain.
    let real = get_real_query();

    // Allocate a buffer. Start at 256 KB, retry with larger if needed.
    let mut buf_size: u32 = 256 * 1024;
    let mut buf: Vec<u8>;

    loop {
        buf = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;
        let status = real(
            SYSTEM_PROCESS_INFORMATION,
            buf.as_mut_ptr() as *mut c_void,
            buf_size,
            &mut returned,
        );
        if status == STATUS_SUCCESS {
            break;
        }
        if status == STATUS_INFO_LENGTH_MISMATCH {
            buf_size = returned.max(buf_size * 2);
            if buf_size > 16 * 1024 * 1024 {
                // Safety cap — don't allocate more than 16 MB.
                return false;
            }
            continue;
        }
        // Other error — can't determine ancestry, default deny.
        return false;
    }

    // Build pid→ppid map.
    let base = buf.as_ptr();
    let mut pid_to_ppid = std::collections::HashMap::new();
    let mut off = 0usize;
    loop {
        let entry = base.add(off);
        let pid = read_usize_const(entry, OFFSET_UNIQUE_PID) as u32;
        let ppid = read_usize_const(entry, OFFSET_INHERITED_PID) as u32;
        pid_to_ppid.insert(pid, ppid);
        let next = read_u32_const(entry, OFFSET_NEXT_ENTRY);
        if next == 0 {
            break;
        }
        off += next as usize;
    }

    // Walk the parent chain from target_pid toward root_pid.
    let mut current = target_pid;
    let mut visited = HashSet::new();
    loop {
        if current == root_pid {
            return true;
        }
        if current == 0 || !visited.insert(current) {
            // Hit PID 0 or a cycle — not a descendant.
            return false;
        }
        match pid_to_ppid.get(&current) {
            Some(&ppid) => current = ppid,
            None => return false,
        }
    }
}

// ─────────────── Helpers ────────────────────────────────

unsafe fn read_u32(ptr: *mut u8, offset: usize) -> u32 {
    (ptr.add(offset) as *const u32).read_unaligned()
}

unsafe fn write_u32(ptr: *mut u8, offset: usize, val: u32) {
    (ptr.add(offset) as *mut u32).write_unaligned(val);
}

unsafe fn read_usize(ptr: *mut u8, offset: usize) -> usize {
    (ptr.add(offset) as *const usize).read_unaligned()
}

unsafe fn write_usize(ptr: *mut u8, offset: usize, val: usize) {
    (ptr.add(offset) as *mut usize).write_unaligned(val);
}

unsafe fn read_u32_const(ptr: *const u8, offset: usize) -> u32 {
    (ptr.add(offset) as *const u32).read_unaligned()
}

unsafe fn read_usize_const(ptr: *const u8, offset: usize) -> usize {
    (ptr.add(offset) as *const usize).read_unaligned()
}

fn get_real_query() -> FnNtQuerySystemInformation {
    let state = STATE.get().expect("procshim not initialized");
    let ptr = state
        .originals
        .nt_query_system_information
        .load(Ordering::Acquire);
    assert!(ptr != 0, "original NtQuerySystemInformation not captured");
    unsafe { core::mem::transmute::<usize, FnNtQuerySystemInformation>(ptr) }
}

unsafe fn call_real_open_process(
    process_handle: *mut isize,
    desired_access: u32,
    object_attributes: *const c_void,
    client_id: *const c_void,
) -> i32 {
    let state = STATE.get().expect("procshim not initialized");
    let ptr = state.originals.nt_open_process.load(Ordering::Acquire);
    assert!(ptr != 0, "original NtOpenProcess not captured");
    let real: FnNtOpenProcess = core::mem::transmute(ptr);
    real(process_handle, desired_access, object_attributes, client_id)
}
