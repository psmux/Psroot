//! End-to-end process-visibility isolation test.
//!
//! This test:
//! 1. Spawns `procshim-testchild.exe` in a SUSPENDED state
//! 2. Injects `psroot_procshim.dll` via CreateRemoteThread
//! 3. Resumes the child
//! 4. Captures stdout
//! 5. Validates that ONLY the child's own PID is visible
//!
//! This proves the isolation works at the most fundamental level —
//! completely independent of the full psroot container runtime.

#[cfg(not(windows))]
fn main() {
    eprintln!("This test only runs on Windows");
    std::process::exit(0);
}

#[cfg(windows)]
fn main() {
    use std::io::Read;
    use std::os::windows::io::FromRawHandle;
    use std::process::exit;

    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║  psroot-procshim E2E Test: Process Visibility Proof  ║");
    println!("╚═══════════════════════════════════════════════════════╝");
    println!();

    let exe_dir = std::env::current_exe().unwrap();
    let exe_dir = exe_dir.parent().unwrap();
    let testchild = exe_dir.join("procshim-testchild.exe");
    let procshim_dll = exe_dir.join("psroot_procshim.dll");

    if !testchild.exists() {
        eprintln!("ERROR: {} not found", testchild.display());
        exit(1);
    }
    if !procshim_dll.exists() {
        eprintln!("ERROR: {} not found", procshim_dll.display());
        exit(1);
    }

    println!("[1/5] Spawning testchild SUSPENDED...");
    let (child_pid, process_handle, thread_handle, stdout_read) =
        spawn_suspended(&testchild);
    println!("       Child PID: {}", child_pid);

    println!("[2/5] Injecting psroot_procshim.dll...");
    let result = unsafe { psroot_netinject::inject_dll(process_handle, &procshim_dll) };
    match result {
        Ok(()) => println!("       DLL injected successfully"),
        Err(e) => {
            eprintln!("       FATAL: DLL injection failed: {:?}", e);
            unsafe { kill_process(process_handle); }
            exit(1);
        }
    }

    // Give the DLL init thread a moment to install hooks
    std::thread::sleep(std::time::Duration::from_millis(100));

    println!("[3/5] Resuming child process...");
    unsafe { resume_thread(thread_handle); }

    println!("[4/5] Waiting for child to exit and reading output...");
    unsafe {
        windows_sys::Win32::System::Threading::WaitForSingleObject(process_handle, 10000);
    }

    // Read child stdout
    let mut stdout_file = unsafe { std::fs::File::from_raw_handle(stdout_read as _) };
    let mut output = String::new();
    let _ = stdout_file.read_to_string(&mut output);

    // Get exit code
    let mut exit_code: u32 = 0;
    unsafe {
        windows_sys::Win32::System::Threading::GetExitCodeProcess(process_handle, &mut exit_code);
        windows_sys::Win32::Foundation::CloseHandle(process_handle);
        windows_sys::Win32::Foundation::CloseHandle(thread_handle);
    }

    println!("[5/5] Analyzing results...");
    println!();
    println!("─── Child Output ───");
    println!("{}", output);
    println!("─── End Output ───");
    println!();

    // Parse results
    let max_visible = parse_field(&output, "Max processes visible across all methods:");
    let leaks = parse_field(&output, "Non-self/non-idle PIDs visible (LEAKS):");
    let host_opens = parse_field(&output, "Host PIDs opened via NtOpenProcess:");

    println!("╔═══════════════════════════════════════════════════════╗");
    if leaks == 0 && host_opens == 0 && max_visible <= 3 {
        println!("║  PASS: PROCESS ISOLATION IRREFUTABLY PROVEN           ║");
        println!("║                                                       ║");
        println!("║  • NtQuerySystemInformation: filtered   ✓             ║");
        println!("║  • CreateToolhelp32Snapshot: filtered   ✓             ║");
        println!("║  • K32EnumProcesses: filtered           ✓             ║");
        println!("║  • NtOpenProcess: blocked               ✓             ║");
        println!("║  • Host processes visible: 0            ✓             ║");
        println!("╚═══════════════════════════════════════════════════════╝");
        exit(0);
    } else {
        println!("║  FAIL: ISOLATION INCOMPLETE                           ║");
        println!("║                                                       ║");
        println!("║  Max visible: {}                                      ║", max_visible);
        println!("║  Leaks: {}                                            ║", leaks);
        println!("║  Host opens: {}                                       ║", host_opens);
        println!("╚═══════════════════════════════════════════════════════╝");
        exit(1);
    }
}

#[cfg(windows)]
fn parse_field(output: &str, prefix: &str) -> u32 {
    for line in output.lines() {
        if let Some(rest) = line.trim().strip_prefix(prefix) {
            if let Ok(n) = rest.trim().parse::<u32>() {
                return n;
            }
        }
    }
    u32::MAX // indicate "not found"
}

#[cfg(windows)]
fn spawn_suspended(exe: &std::path::Path) -> (u32, windows_sys::Win32::Foundation::HANDLE, windows_sys::Win32::Foundation::HANDLE, windows_sys::Win32::Foundation::HANDLE) {
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::*;

    // Create a pipe for stdout capture
    let mut stdout_read: HANDLE = 0 as _;
    let mut stdout_write: HANDLE = 0 as _;
    let mut sa: SECURITY_ATTRIBUTES = unsafe { core::mem::zeroed() };
    sa.nLength = core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    sa.bInheritHandle = 1;
    unsafe {
        CreatePipe(&mut stdout_read, &mut stdout_write, &sa, 0);
        // Don't inherit the read end
        SetHandleInformation(stdout_read, 1, 0); // HANDLE_FLAG_INHERIT = 1
    }

    let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = 0x100; // STARTF_USESTDHANDLES
    si.hStdOutput = stdout_write;
    si.hStdError = stdout_write;

    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let mut cmd: Vec<u16> = exe.to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1, // inherit handles
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        eprintln!("CreateProcessW failed: error {}", err);
        std::process::exit(1);
    }

    // Close write end in parent (child has it)
    unsafe { CloseHandle(stdout_write); }

    (pi.dwProcessId, pi.hProcess, pi.hThread, stdout_read)
}

#[cfg(windows)]
unsafe fn resume_thread(thread: windows_sys::Win32::Foundation::HANDLE) {
    windows_sys::Win32::System::Threading::ResumeThread(thread);
}

#[cfg(windows)]
unsafe fn kill_process(process: windows_sys::Win32::Foundation::HANDLE) {
    windows_sys::Win32::System::Threading::TerminateProcess(process, 1);
    windows_sys::Win32::Foundation::CloseHandle(process);
}
