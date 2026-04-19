//! Container root filesystem preparation.
//!
//! Copies essential Windows system files into the container rootfs
//! so processes can actually run inside the silo.

use psroot_types::error::Result;
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

/// Essential System32 files needed for cmd.exe / PowerShell to run.
const ESSENTIAL_BINARIES: &[&str] = &[
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "ucrtbase.dll",
    "msvcrt.dll",
    "cmd.exe",
    "conhost.exe",
    "advapi32.dll",
    "sechost.dll",
    "rpcrt4.dll",
    "bcryptprimitives.dll",
    "user32.dll",
    "win32u.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "msvcp_win.dll",
    "combase.dll",
    "oleaut32.dll",
    "shell32.dll",
    "shlwapi.dll",
    "ole32.dll",
    "imm32.dll",
    "ws2_32.dll",
    "nsi.dll",
    "iphlpapi.dll",
    "powershell.exe",
    "netapi32.dll",
    "winhttp.dll",
    "wininet.dll",
    "crypt32.dll",
    "wintrust.dll",
    "bcrypt.dll",
    "ncrypt.dll",
    "setupapi.dll",
    "cfgmgr32.dll",
    "version.dll",
    "wldp.dll",
    "profapi.dll",
    "userenv.dll",
    "whoami.exe",
    "netutils.dll",
    "samlib.dll",
    "samcli.dll",
    "logoncli.dll",
    "sspicli.dll",
    "cryptbase.dll",
];

/// Prepare a minimal container rootfs.
///
/// Creates the directory structure and copies essential system binaries.
pub fn prepare_rootfs(rootfs_path: &str) -> Result<()> {
    let root = Path::new(rootfs_path);

    // Create directory structure
    let dirs = [
        root.join("Windows").join("System32"),
        root.join("Windows").join("Temp"),
        root.join("Users").join("ContainerUser"),
        root.join("Temp"),
        root.join("ProgramData"),
    ];
    for dir in &dirs {
        fs::create_dir_all(dir)?;
        debug!(dir = %dir.display(), "Created directory");
    }

    // Copy essential binaries from host System32
    let sys32 = Path::new(&std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()))
        .join("System32");
    let dest_sys32 = root.join("Windows").join("System32");

    for file in ESSENTIAL_BINARIES {
        let src = sys32.join(file);
        let dst = dest_sys32.join(file);
        if src.exists() {
            if let Err(e) = fs::copy(&src, &dst) {
                warn!(file, error = %e, "Failed to copy system binary");
            } else {
                debug!(file, "Copied system binary");
            }
        }
    }

    // Set writable directories to Low integrity so sandboxed processes can write
    set_low_integrity_dir(&root.join("Temp"));
    set_low_integrity_dir(&root.join("Windows").join("Temp"));
    set_low_integrity_dir(&root.join("Users").join("ContainerUser"));
    set_low_integrity_dir(&root.join("ProgramData"));

    Ok(())
}

/// Prepare rootfs with additional tools (Node.js, etc.)
pub fn prepare_rootfs_with_tools(rootfs_path: &str, tools: &[&str]) -> Result<()> {
    prepare_rootfs(rootfs_path)?;

    let root = Path::new(rootfs_path);

    for tool in tools {
        match *tool {
            "node" | "nodejs" => install_node(root)?,
            "winget" => install_winget_support(root)?,
            "rust-bin" | "cargo-bin" => install_rust_binaries(root)?,
            _ => {
                warn!(tool, "Unknown tool, skipping");
            }
        }
    }

    Ok(())
}

/// Copy Node.js into the container (from host installation if available).
fn install_node(root: &Path) -> Result<()> {
    // Find node.exe on PATH
    if let Ok(output) = std::process::Command::new("where").arg("node.exe").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(node_path) = stdout.lines().next() {
            let node_dir = Path::new(node_path.trim()).parent().unwrap();
            let dest = root.join("nodejs");
            fs::create_dir_all(&dest)?;

            // Copy node.exe + npm + npx
            for entry in fs::read_dir(node_dir)? {
                let entry = entry?;
                let src = entry.path();
                let dst = dest.join(entry.file_name());
                if src.is_file() {
                    let _ = fs::copy(&src, &dst);
                }
            }

            // Copy node_modules for npm
            let nm_src = node_dir.join("node_modules");
            if nm_src.exists() {
                copy_dir_recursive(&nm_src, &dest.join("node_modules"))?;
            }

            debug!("Node.js copied to container");
        }
    }
    Ok(())
}

/// Set up winget support paths (the actual winget may need bind-linking).
fn install_winget_support(root: &Path) -> Result<()> {
    let dest = root.join("Program Files").join("WindowsApps");
    fs::create_dir_all(&dest)?;
    debug!("Winget support directories created");
    Ok(())
}

/// Pre-built Rust binaries to copy from ~/.cargo/bin/ into the container.
/// Only copies .exe files that exist — skips missing ones silently.
const RUST_BIN_ALLOWLIST: &[&str] = &[
    "pstop.exe",
    "psmux.exe",
    "psnet.exe",
    "htop.exe",
    "weathr.exe",
];

/// Copy pre-built Rust binaries from ~/.cargo/bin/ into rootfs/bin/.
///
/// This avoids needing the full 1.4 GB Rust toolchain inside the container.
/// Copies only allowlisted executables (statically linked, no extra DLLs needed).
fn install_rust_binaries(root: &Path) -> Result<()> {
    let cargo_home = std::env::var("CARGO_HOME")
        .unwrap_or_else(|_| {
            let home = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".into());
            format!("{}\\.cargo", home)
        });
    let cargo_bin = Path::new(&cargo_home).join("bin");

    if !cargo_bin.exists() {
        warn!(dir = %cargo_bin.display(), "Cargo bin directory not found, skipping rust-bin tool");
        return Ok(());
    }

    let dest = root.join("bin");
    fs::create_dir_all(&dest)?;

    let mut copied = 0u32;
    for name in RUST_BIN_ALLOWLIST {
        let src = cargo_bin.join(name);
        if src.exists() {
            let dst = dest.join(name);
            match fs::copy(&src, &dst) {
                Ok(_) => {
                    debug!(file = name, "Copied Rust binary");
                    copied += 1;
                }
                Err(e) => warn!(file = name, error = %e, "Failed to copy Rust binary"),
            }
        }
    }

    if copied > 0 {
        // Set low integrity so AppContainer processes can execute from bin/
        set_low_integrity_dir(&dest);
        debug!(count = copied, "Rust binaries installed");
    } else {
        warn!("No Rust binaries found in cargo bin directory");
    }

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            let _ = fs::copy(&src_path, &dst_path);
        }
    }
    Ok(())
}

/// Set a directory (and its children) to Low mandatory integrity level.
/// This allows processes running at Low integrity to write into these directories.
fn set_low_integrity_dir(dir: &Path) {
    if !dir.exists() {
        return;
    }
    // Use icacls to set low integrity: (OI)(CI) = inherit to objects and containers
    let path_str = dir.to_string_lossy().to_string();
    let result = std::process::Command::new("icacls")
        .args([&path_str, "/setintegritylevel", "(OI)(CI)low"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match result {
        Ok(s) if s.success() => debug!(dir = %dir.display(), "Set Low integrity level"),
        Ok(s) => debug!(dir = %dir.display(), code = ?s.code(), "icacls failed — sandbox writes may fail"),
        Err(e) => debug!(dir = %dir.display(), error = %e, "icacls not available"),
    }
}
