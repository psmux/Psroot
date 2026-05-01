//! Example: Launch Chrome headful on an isolated desktop.
//!
//! This demonstrates running a full GUI browser inside psroot's isolation
//! boundary. The browser runs headful (with real GPU rendering) but its
//! windows are invisible to the user's desktop.
//!
//! Usage:
//!   cargo run --example chrome-isolated
//!   cargo run --example chrome-isolated -- --url https://example.com
//!   cargo run --example chrome-isolated -- --timeout 30

use psroot_desktop::{DesktopConfig, IsolatedDesktop};
use std::process::Command;

fn main() {
    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let url = args.iter()
        .position(|a| a == "--url")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("https://example.com");
    let timeout_secs: u64 = args.iter()
        .position(|a| a == "--timeout")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  psroot-desktop: Isolated Headful Chrome Demo       ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  URL:     {:<42}║", url);
    println!("║  Timeout: {} seconds{:<35}║", timeout_secs, "");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    // Find Chrome
    let chrome_path = find_chrome();
    println!("[1/4] Chrome found: {}", chrome_path);

    // Create isolated desktop
    let config = DesktopConfig {
        appcontainer_sid: None, // No AppContainer for this demo (just desktop isolation)
        name: Some("chrome-demo".to_string()),
    };

    println!("[2/4] Creating isolated desktop...");
    let desktop = IsolatedDesktop::create(&config).expect("Failed to create desktop");
    println!("       Desktop: {}", desktop.lpdesktop_name());

    // Launch Chrome on the isolated desktop
    println!("[3/4] Launching Chrome (headful, GPU-enabled, isolated)...");
    let chrome_args = format!(
        "\"{}\" --no-first-run --no-default-browser-check --disable-default-apps \
         --user-data-dir=\"{}\" --new-window \"{}\"",
        chrome_path,
        std::env::temp_dir().join("psroot-chrome-profile").display(),
        url,
    );

    let proc = desktop.spawn_process(
        &chrome_args,
        None,
        false,
        0,
        None,
    ).expect("Failed to spawn Chrome");

    println!("       PID: {}", proc.process_id);
    println!("       Status: Running on isolated desktop (invisible to you)");
    println!();
    println!("  The browser is rendering {} headful.", url);
    println!("  Windows exist but are on a separate desktop — invisible.");
    println!("  GPU acceleration is active. DWM compositing works.");
    println!();

    // Wait for timeout then terminate
    println!("[4/4] Waiting {} seconds then terminating...", timeout_secs);
    std::thread::sleep(std::time::Duration::from_secs(timeout_secs));

    if proc.is_running() {
        println!("       Terminating Chrome...");
        proc.terminate();
        println!("       Done. Chrome was running headful for {} seconds.", timeout_secs);
    } else {
        let exit_code = proc.wait();
        println!("       Chrome exited with code: {}", exit_code);
    }

    // Desktop auto-cleans via Drop
    println!();
    println!("✓ Isolated desktop closed. No windows were visible to you.");
}

fn find_chrome() -> String {
    let candidates = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        &format!(
            r"{}\AppData\Local\Google\Chrome\Application\chrome.exe",
            std::env::var("USERPROFILE").unwrap_or_default()
        ),
        // Edge as fallback (Chromium-based, same rendering engine)
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ];

    for path in &candidates {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }

    // Try PATH
    if Command::new("where").arg("chrome.exe").output().map(|o| o.status.success()).unwrap_or(false) {
        return "chrome.exe".to_string();
    }

    panic!("Chrome not found. Install Chrome or Edge, or pass --chrome-path");
}
