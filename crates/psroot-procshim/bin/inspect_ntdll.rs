//! Inspect the first bytes of NtQuerySystemInformation to understand
//! how many bytes are safe to overwrite for inline hooking.

#[cfg(not(windows))]
fn main() { eprintln!("Windows only"); }

#[cfg(windows)]
fn main() {
    let ntdll = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(b"ntdll.dll\0".as_ptr())
    };
    let nqsi = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, b"NtQuerySystemInformation\0".as_ptr())
    };
    let nop = unsafe {
        windows_sys::Win32::System::LibraryLoader::GetProcAddress(ntdll, b"NtOpenProcess\0".as_ptr())
    };

    println!("NtQuerySystemInformation @ {:p}", nqsi.unwrap() as *const u8);
    let ptr = nqsi.unwrap() as *const u8;
    print!("  First 32 bytes: ");
    for i in 0..32 {
        let b = unsafe { *ptr.add(i) };
        print!("{:02X} ", b);
    }
    println!();

    println!();
    println!("NtOpenProcess @ {:p}", nop.unwrap() as *const u8);
    let ptr = nop.unwrap() as *const u8;
    print!("  First 32 bytes: ");
    for i in 0..32 {
        let b = unsafe { *ptr.add(i) };
        print!("{:02X} ", b);
    }
    println!();
}
