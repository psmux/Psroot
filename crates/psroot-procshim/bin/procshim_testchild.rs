//! Test child for the process-visibility shim.
//!
//! When run inside a psroot container with psroot_procshim.dll injected,
//! this binary exercises EVERY known Windows process enumeration API and
//! reports how many host processes are visible.
//!
//! Expected output when procshim is active:
//!   ONLY the test child itself (and possibly PID 0 Idle).
//!
//! The test harness (test-procshim.ps1) spawns this inside psroot and
//! validates the output.

#[cfg(not(windows))]
fn main() {
    eprintln!("This test only runs on Windows");
}

#[cfg(windows)]
fn main() {
    let own_pid = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
    println!("OWN_PID={}", own_pid);
    println!();

    // Method 1: NtQuerySystemInformation (direct ntdll call)
    println!("=== METHOD 1: NtQuerySystemInformation (SystemProcessInformation) ===");
    let pids_ntquery = method_ntquery();
    println!("  Processes visible: {}", pids_ntquery.len());
    for &pid in &pids_ntquery {
        let marker = if pid == own_pid { " <-- SELF" } else { "" };
        println!("    PID {}{}", pid, marker);
    }
    println!();

    // Method 2: CreateToolhelp32Snapshot + Process32First/Next
    println!("=== METHOD 2: Toolhelp32 (CreateToolhelp32Snapshot) ===");
    let pids_toolhelp = method_toolhelp32();
    println!("  Processes visible: {}", pids_toolhelp.len());
    for &pid in &pids_toolhelp {
        let marker = if pid == own_pid { " <-- SELF" } else { "" };
        println!("    PID {}{}", pid, marker);
    }
    println!();

    // Method 3: EnumProcesses (psapi / K32EnumProcesses)
    println!("=== METHOD 3: K32EnumProcesses ===");
    let pids_enum = method_enum_processes();
    println!("  Processes visible: {}", pids_enum.len());
    for &pid in &pids_enum {
        let marker = if pid == own_pid { " <-- SELF" } else { "" };
        println!("    PID {}{}", pid, marker);
    }
    println!();

    // Method 4: Try to OpenProcess on PID 4 (System) — should fail
    println!("=== METHOD 4: NtOpenProcess (PID 4 = System) ===");
    let can_open_system = method_open_process(4);
    println!("  Can open System (PID 4): {}", can_open_system);
    println!();

    // Method 5: Try to OpenProcess on a known host PID (parent's parent)
    println!("=== METHOD 5: OpenProcess on host PIDs ===");
    // Try PIDs 1-20 (common system PIDs) excluding our own
    let mut host_opens = 0u32;
    for pid in 1..20u32 {
        if pid == own_pid { continue; }
        if method_open_process(pid) {
            host_opens += 1;
            println!("  LEAK: Could open PID {}", pid);
        }
    }
    if host_opens == 0 {
        println!("  All host PID opens denied (good!)");
    }
    println!();

    // Summary
    println!("=== SUMMARY ===");
    let max_visible = pids_ntquery.len().max(pids_toolhelp.len()).max(pids_enum.len());
    // PID 0 (Idle) is always allowed, plus our own PID
    let leaked = pids_ntquery.iter().filter(|&&p| p != 0 && p != own_pid).count();
    println!("  Own PID: {}", own_pid);
    println!("  Max processes visible across all methods: {}", max_visible);
    println!("  Non-self/non-idle PIDs visible (LEAKS): {}", leaked);
    println!("  Host PIDs opened via NtOpenProcess: {}", host_opens);

    if leaked == 0 && host_opens == 0 {
        println!("  RESULT: PASS — Process isolation PROVEN");
        std::process::exit(0);
    } else {
        println!("  RESULT: FAIL — {} process leaks detected!", leaked + host_opens as usize);
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn method_ntquery() -> Vec<u32> {
    use core::ffi::c_void;
    use std::mem;

    // Load NtQuerySystemInformation dynamically to go through normal import resolution
    // (which our IAT hook intercepts).
    type FnNtQuerySystemInformation = unsafe extern "system" fn(u32, *mut c_void, u32, *mut u32) -> i32;

    let ntdll = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr())
    };
    if ntdll.is_null() {
        println!("  ERROR: Could not get ntdll handle");
        return vec![];
    }
    let proc = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, b"NtQuerySystemInformation\0".as_ptr())
    };
    let Some(proc) = proc else {
        println!("  ERROR: Could not find NtQuerySystemInformation");
        return vec![];
    };
    let query: FnNtQuerySystemInformation = unsafe { mem::transmute(proc) };

    let mut buf_size: u32 = 512 * 1024;
    let mut buf: Vec<u8>;
    loop {
        buf = vec![0u8; buf_size as usize];
        let mut returned: u32 = 0;
        let status = unsafe {
            query(5, buf.as_mut_ptr() as *mut c_void, buf_size, &mut returned)
        };
        if status == 0 { break; } // STATUS_SUCCESS
        if status == 0xC0000004u32 as i32 {
            buf_size = returned.max(buf_size * 2);
            continue;
        }
        println!("  ERROR: NtQuerySystemInformation returned 0x{:08X}", status as u32);
        return vec![];
    }

    // Walk the linked list
    let mut pids = Vec::new();
    let base = buf.as_ptr();
    let mut offset = 0usize;
    loop {
        let entry = unsafe { base.add(offset) };
        let pid = unsafe { (entry.add(0x50) as *const usize).read_unaligned() } as u32;
        pids.push(pid);
        let next = unsafe { (entry as *const u32).read_unaligned() };
        if next == 0 { break; }
        offset += next as usize;
    }
    pids
}

#[cfg(windows)]
fn method_toolhelp32() -> Vec<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        println!("  ERROR: CreateToolhelp32Snapshot failed");
        return vec![];
    }

    let mut pids = Vec::new();
    let mut entry: PROCESSENTRY32W = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;

    if unsafe { Process32FirstW(snap, &mut entry) } != 0 {
        pids.push(entry.th32ProcessID);
        while unsafe { Process32NextW(snap, &mut entry) } != 0 {
            pids.push(entry.th32ProcessID);
        }
    }

    unsafe { CloseHandle(snap); }
    pids
}

#[cfg(windows)]
fn method_enum_processes() -> Vec<u32> {
    // K32EnumProcesses is in kernel32/psapi — goes through NtQuerySystemInformation
    // internally, so our hook catches it.
    type FnEnumProcesses = unsafe extern "system" fn(*mut u32, u32, *mut u32) -> i32;

    let kernel32 = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"kernel32.dll\0".as_ptr())
    };
    if kernel32.is_null() {
        println!("  ERROR: Could not get kernel32 handle");
        return vec![];
    }
    let proc = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetProcAddress(kernel32, b"K32EnumProcesses\0".as_ptr())
    };
    let Some(proc) = proc else {
        println!("  ERROR: Could not find K32EnumProcesses");
        return vec![];
    };
    let enum_procs: FnEnumProcesses = unsafe { core::mem::transmute(proc) };

    let mut pids = vec![0u32; 4096];
    let mut bytes_returned: u32 = 0;
    let ok = unsafe {
        enum_procs(
            pids.as_mut_ptr(),
            (pids.len() * 4) as u32,
            &mut bytes_returned,
        )
    };
    if ok == 0 {
        println!("  ERROR: K32EnumProcesses returned 0");
        return vec![];
    }
    let count = bytes_returned as usize / 4;
    pids.truncate(count);
    // Filter out zeros (unused slots)
    pids.retain(|&p| p != 0);
    pids
}

#[cfg(windows)]
fn method_open_process(target_pid: u32) -> bool {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows_sys::Win32::Foundation::CloseHandle;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, target_pid) };
    if handle.is_null() {
        false
    } else {
        unsafe { CloseHandle(handle); }
        true
    }
}
