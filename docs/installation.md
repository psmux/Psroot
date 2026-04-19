# Installation

## Download the Binary

Grab the latest `psroot.exe` from the [Releases](https://github.com/psmux/Psroot/releases) page and put it somewhere on your PATH.

```powershell
# Example: copy to a folder on your PATH
mkdir "$env:USERPROFILE\.psroot\bin" -Force
# Copy psroot.exe there, then add to PATH:
[Environment]::SetEnvironmentVariable("Path", "$env:Path;$env:USERPROFILE\.psroot\bin", "User")
```

## Build from Source

Requirements:
- **Rust 1.75+** (stable) — [install Rust](https://rustup.rs)
- **Windows 10 build 17763+** (runtime only — cross-compiles from anywhere)

```powershell
git clone https://github.com/psmux/Psroot.git
cd Psroot
cargo build --release
```

The binary is at `target\release\psroot.exe` (~2 MB).

### Verify

```powershell
.\target\release\psroot.exe info
.\target\release\psroot.exe test all
# Expected: 66/66 passed
```

## System Requirements

| Requirement | Minimum |
|---|---|
| OS | Windows 10 version 1809 (build 17763) |
| Architecture | x86_64 |
| Admin | **Not required** for Standard tier |
| VT-x / Hyper-V | **Not required** |
| Disk space | ~2 MB (binary) + ~50 MB per container rootfs |
| RAM | Whatever you allocate to containers + ~10 MB overhead |

## Verify Your Setup

```powershell
psroot info
```

This shows your Windows build, admin status, and available isolation features. If you see `Isolation Level: Standard (AppContainer + Env)` or higher, you're good to go.
