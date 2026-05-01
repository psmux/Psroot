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
    // Required by pwsh / .NET runtime
    "secur32.dll",
    "schannel.dll",
    "mswsock.dll",
    "dnsapi.dll",
    "winnsi.dll",
    "fwpuclnt.dll",
    "rasadhlp.dll",
    "msv1_0.dll",
    "kerberos.dll",
    "msasn1.dll",
    "cryptsp.dll",
    "rsaenh.dll",
    "dpapi.dll",
    "icu.dll",
    "icuuc.dll",
    "icuin.dll",
    "powrprof.dll",
    "umpdc.dll",
    "winmm.dll",
    "msacm32.dll",
    "comctl32.dll",
    // Required for HTTPS/TLS (schannel cipher-suite provider)
    "ncryptsslp.dll",
    "ncryptprov.dll",
    "gpapi.dll",
    "msvcp140.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    // Curl (for network probe / package fetches inside container)
    "curl.exe",
    "tar.exe",
];

/// Prepare a minimal container rootfs.
///
/// Creates the directory structure and copies essential system binaries.
pub fn prepare_rootfs(rootfs_path: &str) -> Result<()> {
    prepare_rootfs_with_shares(rootfs_path, &[])
}

/// Prepare a container rootfs, sharing the listed host system directories
/// in instead of mirroring them. Sharing is implemented as volume-GUID
/// junctions inside the rootfs, which survive the per-process device map
/// swap because the Object Manager resolves `\??\Volume{GUID}` globally.
///
/// Recognised share names:
///   * `windows`         — `C:\Windows` (fixes .NET SslStream and provides
///                         every system DLL automatically)
///   * `programfiles`    — `C:\Program Files`
///   * `programfilesx86` — `C:\Program Files (x86)`
///   * `programdata`    — `C:\ProgramData`
///   * `windowsapps`    — `C:\Program Files\WindowsApps` (needed for winget
///                         and other AppX-installed tools)
///
/// Sharing `windows` skips the expensive mirror of `System32`, `.mui`
/// resource dirs, `Globalization`, and `ProgramData\Microsoft\Crypto`.
pub fn prepare_rootfs_with_shares(rootfs_path: &str, shares: &[&str]) -> Result<()> {
    let root = Path::new(rootfs_path);
    let share_windows = shares.iter().any(|s| *s == "windows");
    let share_progdata = shares.iter().any(|s| *s == "programdata");
    let share_progfiles = shares.iter().any(|s| *s == "programfiles");
    let share_progfiles_x86 = shares.iter().any(|s| *s == "programfilesx86");
    let share_windowsapps = shares.iter().any(|s| *s == "windowsapps");

    // Create directory structure (always create writable Users + Temp;
    // create Windows + ProgramData skeletons only if NOT shared, since
    // sharing replaces them with junctions and an existing non-empty
    // directory would block junction creation).
    let mut dirs: Vec<std::path::PathBuf> = vec![
        root.join("Users").join("ContainerUser"),
        root.join("Temp"),
    ];
    if !share_windows {
        dirs.push(root.join("Windows").join("System32"));
        dirs.push(root.join("Windows").join("Temp"));
    }
    if !share_progdata {
        dirs.push(root.join("ProgramData"));
    }
    for dir in &dirs {
        fs::create_dir_all(dir)?;
        debug!(dir = %dir.display(), "Created directory");
    }

    // SHARED-WINDOWS FAST PATH: junction the entire host C:\Windows into
    // the rootfs. Solves missing-DLL issues (cryptnet, webio, …),
    // .NET SslStream SEC_E_DECRYPT_FAILED, and shaves several hundred MB
    // of mirroring. Returns early after handling the other shares.
    if share_windows {
        let host_windows = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        if let Err(e) = crate::sandbox::create_volume_guid_junction(
            &root.join("Windows"),
            &host_windows,
        ) {
            warn!(error = %e, "Failed to junction Windows; falling back to mirror");
        } else {
            debug!(host = %host_windows, "Shared host Windows into rootfs");
        }
    }
    if share_progdata {
        let host_pd =
            std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        if let Err(e) =
            crate::sandbox::create_volume_guid_junction(&root.join("ProgramData"), &host_pd)
        {
            warn!(error = %e, "Failed to junction ProgramData");
        }
    }
    if share_progfiles {
        let host = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
        if let Err(e) =
            crate::sandbox::create_volume_guid_junction(&root.join("Program Files"), &host)
        {
            warn!(error = %e, "Failed to junction Program Files");
        }
    }
    if share_progfiles_x86 {
        let host = std::env::var("ProgramFiles(x86)")
            .unwrap_or_else(|_| "C:\\Program Files (x86)".into());
        if let Err(e) = crate::sandbox::create_volume_guid_junction(
            &root.join("Program Files (x86)"),
            &host,
        ) {
            warn!(error = %e, "Failed to junction Program Files (x86)");
        }
    }
    if share_windowsapps {
        // WindowsApps lives under Program Files. If Program Files itself is
        // shared, the AppX dir is reachable transitively. Otherwise we
        // junction just WindowsApps so winget can find its package files.
        if !share_progfiles {
            let host_pf = std::env::var("ProgramFiles")
                .unwrap_or_else(|_| "C:\\Program Files".into());
            let host_wa =
                std::path::Path::new(&host_pf).join("WindowsApps").to_string_lossy().to_string();
            let dst = root.join("Program Files").join("WindowsApps");
            // Ensure Program Files dir exists (empty) so the WindowsApps
            // junction can be created underneath.
            if let Some(parent) = dst.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Err(e) =
                crate::sandbox::create_volume_guid_junction(&dst, &host_wa)
            {
                warn!(error = %e, "Failed to junction WindowsApps");
            }
        }
    }

    // If Windows is shared, the System32 mirror + locale + Globalization +
    // Crypto blocks below are unnecessary — they all live in real Windows.
    if share_windows {
        // Still set Low integrity on writable per-container dirs.
        set_low_integrity_dir(&root.join("Temp"));
        set_low_integrity_dir(&root.join("Users").join("ContainerUser"));
        if !share_progdata {
            set_low_integrity_dir(&root.join("ProgramData"));
        }
        return Ok(());
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

    // Copy localized resource (.mui) files for each binary that has one.
    // Without these, cmd.exe and others print garbled "DNS server not
    // authoritative" / "0x2350" placeholders for every error and the banner.
    // We mirror the host's UI language directories (typically en-US).
    if let Ok(read_locales) = fs::read_dir(&sys32) {
        for entry in read_locales.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Locale directories look like "en-US", "ja-JP", etc.
            if !name_str.contains('-') || name_str.len() > 8 {
                continue;
            }
            let src_loc = entry.path();
            if !src_loc.is_dir() {
                continue;
            }
            let dst_loc = dest_sys32.join(&name);
            if let Err(e) = fs::create_dir_all(&dst_loc) {
                warn!(loc = %name_str, error = %e, "Failed to create locale dir");
                continue;
            }
            for bin in ESSENTIAL_BINARIES {
                let mui = format!("{}.mui", bin);
                let src_mui = src_loc.join(&mui);
                if src_mui.exists() {
                    let dst_mui = dst_loc.join(&mui);
                    let _ = fs::copy(&src_mui, &dst_mui);
                }
            }
        }
    }

    // Set writable directories to Low integrity so sandboxed processes can write
    set_low_integrity_dir(&root.join("Temp"));
    set_low_integrity_dir(&root.join("Windows").join("Temp"));
    set_low_integrity_dir(&root.join("Users").join("ContainerUser"));
    set_low_integrity_dir(&root.join("ProgramData"));

    // Copy ICU runtime data (required by .NET 6+ / pwsh: icu.dll loads
    // C:\Windows\Globalization\ICU\icudtl.dat at startup; without it the
    // host aborts with "Could not load ICU data. UErrorCode: 2").
    let host_globalization = Path::new(
        &std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()),
    )
    .join("Globalization");
    let dest_globalization = root.join("Windows").join("Globalization");
    if host_globalization.exists() {
        if let Err(e) = copy_dir_recursive(&host_globalization, &dest_globalization) {
            warn!(error = %e, "Failed to mirror Windows\\Globalization (pwsh may fail to start)");
        } else {
            debug!("Mirrored Windows\\Globalization for ICU runtime data");
        }
    }

    // Mirror system crypto key store so schannel can generate ephemeral TLS
    // keys and bcrypt can read the machine certificate store. Without this,
    // HTTPS fails with "Authentication failed" even though the certificate
    // chain validates (the client can't complete the key exchange).
    let host_program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    let host_crypto = Path::new(&host_program_data).join("Microsoft").join("Crypto");
    let dest_crypto = root
        .join("ProgramData")
        .join("Microsoft")
        .join("Crypto");
    if host_crypto.exists() {
        // Best-effort: many files are ACL-locked (SYSTEM-only). Copy what we
        // can — the public machine-key dir is enough for schannel to bootstrap.
        let _ = copy_dir_recursive_besteffort(&host_crypto, &dest_crypto);
        debug!("Mirrored ProgramData\\Microsoft\\Crypto for TLS");
    }

    Ok(())
}

/// Like `copy_dir_recursive` but swallows per-entry errors (used for
/// host-Crypto mirror where many files are SYSTEM-only).
fn copy_dir_recursive_besteffort(src: &Path, dst: &Path) {
    if fs::create_dir_all(dst).is_err() {
        return;
    }
    let entries = match fs::read_dir(src) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let s = entry.path();
        let d = dst.join(entry.file_name());
        if ft.is_dir() {
            copy_dir_recursive_besteffort(&s, &d);
        } else if ft.is_file() {
            if fs::hard_link(&s, &d).is_err() {
                let _ = fs::copy(&s, &d);
            }
        }
    }
}

/// Prepare rootfs with additional tools (Node.js, etc.)
pub fn prepare_rootfs_with_tools(rootfs_path: &str, tools: &[&str]) -> Result<()> {
    prepare_rootfs_with_tools_and_shares(rootfs_path, tools, &[])
}

/// Prepare rootfs with tools and host directory shares. Some tools imply
/// shares automatically: `winget` requires both `windows` and `windowsapps`
/// to function (the AppX activation paths are baked into Windows itself).
pub fn prepare_rootfs_with_tools_and_shares(
    rootfs_path: &str,
    tools: &[&str],
    shares: &[&str],
) -> Result<()> {
    // Auto-imply shares for tools that need them.
    let mut effective_shares: Vec<String> = shares.iter().map(|s| s.to_string()).collect();
    for tool in tools {
        if *tool == "winget" {
            for needed in &["windows", "programfiles", "programdata", "windowsapps"] {
                if !effective_shares.iter().any(|s| s == needed) {
                    effective_shares.push((*needed).to_string());
                }
            }
        }
    }
    let share_refs: Vec<&str> = effective_shares.iter().map(|s| s.as_str()).collect();
    prepare_rootfs_with_shares(rootfs_path, &share_refs)?;

    let root = Path::new(rootfs_path);

    for tool in tools {
        match *tool {
            "node" | "nodejs" => install_node(root)?,
            "winget" => install_winget_shim(root)?,
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

/// Set up winget support paths.
///
/// Note on Win10 (build 19045): winget cannot be run from a portable
/// staged rootfs because it is delivered as an AppX package
/// (`Microsoft.DesktopAppInstaller`) whose files live under
/// `C:\Program Files\WindowsApps`, which is ACLed to `TrustedInstaller`
/// and not readable even by administrators without taking ownership.
/// winget also relies on the Windows AppX state repository and COM
/// activation, which are per-installed-package machine state that
/// cannot be cloned into a private rootfs.
///
/// On Windows 11 you can bind-mount the host's WindowsApps dir with
/// `--bind "C:\Program Files\WindowsApps:C:\Program Files\WindowsApps"`
/// and it will work because registry-based activation is shared. We
/// still create the empty dir so the bind target exists.
///
/// Workarounds on Win10:
///   - Download installers directly with curl.exe (already staged)
///   - Mount your host's C:\Program Files as a bind into the container
///   - Use portable tools (node.zip, python.zip, etc.)
/// Install a winget shim into the rootfs.
///
/// `winget` is the command-line front-end of the AppX-installed package
/// `Microsoft.DesktopAppInstaller`. It cannot run as a plain Win32 binary —
/// `WindowsPackageManager.dll` requires MRT (Modern Resource Technology)
/// activation context to load its embedded `resources.pri`. Without an
/// AppX **package identity** the very first command (even `--version`)
/// fails with `0x8A150001 APPINSTALLER_CLI_ERROR_INTERNAL_ERROR`.
///
/// The host gives processes that identity by routing all `winget`
/// invocations through the AppExecutionAlias reparse point at
/// `%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe` (tag 0x8000001b
/// `IO_REPARSE_TAG_APPEXECLINK`). When `CreateProcess` opens that path
/// it RPCs into `AppXSvc`, which spawns the real binary inside the
/// proper activation context.
///
/// Inside the silo this works iff:
///   1. `--share windows` + `--share windowsapps` are active (already
///      auto-implied by `--tool winget`),
///   2. the host user's profile directory is bind-mounted at the same
///      canonical path (so the alias reparse point at
///      `C:\Users\<HOST_USER>\AppData\Local\Microsoft\WindowsApps\winget.exe`
///      resolves) — this auto-bind is added in
///      `psroot-cli::cmd_shell()` when `winget` is in `tools`,
///   3. `USERPROFILE` / `LOCALAPPDATA` / `APPDATA` env vars are
///      overridden in the wrapper to point at the host profile (the
///      silo synthesises `C:\Users\ContainerUser`), and
///   4. `AppXSvc` is started on the host (it is `Manual` by default).
///
/// All four steps are handled here + in cmd_shell. The wrapper script
/// `<rootfs>\bin\winget.cmd` performs (3) and (4) at every invocation.
fn install_winget_shim(root: &Path) -> Result<()> {
    let host_user = match std::env::var("USERNAME") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            warn!("winget: cannot detect host USERNAME; skipping shim");
            return Ok(());
        }
    };
    let host_profile = format!("C:\\Users\\{}", host_user);
    if !Path::new(&host_profile).exists() {
        warn!(
            profile = %host_profile,
            "winget: host profile directory missing; skipping shim"
        );
        return Ok(());
    }
    let alias = format!(
        "{}\\AppData\\Local\\Microsoft\\WindowsApps\\winget.exe",
        host_profile
    );
    if !Path::new(&alias).exists() {
        warn!(
            alias = %alias,
            "winget: AppExecutionAlias not found on host. Install winget \
             first via the Microsoft Store, then retry."
        );
        return Ok(());
    }

    let bin = root.join("bin");
    fs::create_dir_all(&bin)?;
    // Write BOTH a `.ps1` (for pwsh in-process invocation) and a `.cmd`
    // (so cmd.exe's PATH lookup actually surfaces the shim — `where.exe`
    // and cmd's command resolver only honor .COM/.EXE/.BAT/.CMD even
    // when .PS1 is listed in PATHEXT).
    let alias_path = format!(
        "{}\\AppData\\Local\\Microsoft\\WindowsApps\\winget.exe",
        host_profile
    );
    let ps1 = bin.join("winget.ps1");
    let ps1_body = format!(
        "# psroot winget shim - invokes winget via the host's\r\n\
         # AppExecutionAlias so AppXSvc grants package identity\r\n\
         # (required for MRT/PRI resource loading).\r\n\
         $env:USERPROFILE = '{profile}'\r\n\
         $env:LOCALAPPDATA = $env:USERPROFILE + '\\AppData\\Local'\r\n\
         $env:APPDATA = $env:USERPROFILE + '\\AppData\\Roaming'\r\n\
         $alias = $env:LOCALAPPDATA + '\\Microsoft\\WindowsApps\\winget.exe'\r\n\
         & $alias @args\r\n\
         exit $LASTEXITCODE\r\n",
        profile = host_profile
    );
    fs::write(&ps1, ps1_body)?;
    let cmd_shim = bin.join("winget.cmd");
    let cmd_body = format!(
        "@echo off\r\n\
         REM psroot winget shim - calls host AppExecutionAlias\r\n\
         set \"USERPROFILE={profile}\"\r\n\
         set \"LOCALAPPDATA=%USERPROFILE%\\AppData\\Local\"\r\n\
         set \"APPDATA=%USERPROFILE%\\AppData\\Roaming\"\r\n\
         \"{alias}\" %*\r\n",
        profile = host_profile,
        alias = alias_path
    );
    fs::write(&cmd_shim, cmd_body)?;
    let wrapper = ps1;
    debug!(
        wrapper = %wrapper.display(),
        profile = %host_profile,
        "winget: shim installed (AppExecutionAlias route)"
    );
    Ok(())
}

fn copy_tree_besteffort(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Err(e) = fs::create_dir_all(dst) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    let rd = match fs::read_dir(src) {
        Ok(r) => r,
        Err(_) => return Ok(()), // best-effort: ACL denies, skip
    };
    for entry in rd.flatten() {
        let ft = match entry.file_type() {
            Ok(ft) => ft,
            Err(_) => continue,
        };
        let s = entry.path();
        let d = dst.join(entry.file_name());
        if ft.is_dir() {
            let _ = copy_tree_besteffort(&s, &d);
        } else if ft.is_file() {
            let _ = fs::copy(&s, &d);
        }
    }
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
