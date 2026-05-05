// Cross-platform entrypoint. The actual implementation lives in
// `main_windows.rs` (Windows) or `main_unix.rs` (Linux + macOS).
//
// On macOS, by default we transparently drive a Lima Linux VM so the
// user gets full per-container IPs / namespaces / parity with Linux.
// Set `PSROOT_BACKEND=native` to use the in-process sandbox-exec +
// chroot backend instead (development-grade isolation, no per-ctr IP).

#[cfg(target_os = "macos")]
mod mac_lima;

#[cfg(windows)]
include!("main_windows.rs");

#[cfg(unix)]
include!("main_unix.rs");

#[cfg(not(any(windows, unix)))]
fn main() {
    eprintln!("psroot: unsupported target OS");
    std::process::exit(1);
}
