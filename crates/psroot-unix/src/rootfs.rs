//! Populate a minimal Unix rootfs.
//!
//! On both macOS and Linux we don't try to be a full Debian; we just create
//! a reasonable directory skeleton with `/home/container`, `/tmp`, and
//! placeholder etc files. The sandbox profile (macOS) or bind-mount
//! plan (Linux) is what actually scopes which host files are visible.

use std::path::Path;
use crate::Result;

pub fn populate(rootfs: &Path) -> Result<()> {
    // If this looks like a real distro rootfs (has /usr/bin), don't touch
    // its /etc skeleton — the distro already has correct files. We still
    // ensure /home/container, /tmp, /proc, /sys, /dev exist as mountpoints.
    let self_contained = rootfs.join("usr/bin/env").exists()
        || rootfs.join("bin/sh").is_symlink()
        || rootfs.join("bin/sh").exists();
    for sub in &[
        "home/container",
        "tmp",
        "etc",
        "var",
        "run",
        "dev",
        "proc",
        "sys",
        "usr",
        "bin",
    ] {
        let p = rootfs.join(sub);
        if !p.exists() {
            std::fs::create_dir_all(&p)?;
        }
    }
    let etc = rootfs.join("etc");
    // Write a usable resolv.conf. We deliberately do NOT copy the host's
    // /etc/resolv.conf because on systemd hosts it points at 127.0.0.53
    // (systemd-resolved), which is unreachable from the container's netns.
    let resolv = etc.join("resolv.conf");
    let _ = std::fs::remove_file(&resolv);
    std::fs::write(&resolv, b"nameserver 1.1.1.1\nnameserver 8.8.8.8\n")?;
    if self_contained {
        return Ok(());
    }
    let hosts = etc.join("hosts");
    if !hosts.exists() {
        std::fs::write(&hosts, b"127.0.0.1 localhost psroot\n::1 localhost psroot\n")?;
    }
    Ok(())
}
