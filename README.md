<p align="center">
  <h1 align="center">Psroot</h1>
  <p align="center">
    <strong>Docker-style containers for Windows, Linux, and macOS — no VTx, no Hyper-V, no Docker, no WSL.</strong>
  </p>
  <p align="center">
    A single ~2 MB binary. Pure OS kernel primitives (AppContainer on Windows, namespaces+cgroups on Linux, sandbox-exec on macOS).<br>
    Works on VMs, bare metal, and cloud instances where nested virtualization is unavailable.
  </p>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#why-psroot">Why Psroot?</a> •
  <a href="#features">Features</a> •
  <a href="#commands">Commands</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#isolation-tiers">Isolation Tiers</a> •
  <a href="#building-from-source">Building</a> •
  <a href="#documentation">Docs</a>
</p>

---

## Quick Start

```powershell
# Drop into an isolated container shell — one command, zero setup
psroot shell

# That's it. You're inside an AppContainer sandbox:
psroot> echo %USERNAME%
ContainerUser

psroot> echo %COMPUTERNAME%
PSROOT

psroot> echo %PATH%
C:\...\rootfs\Windows\System32

psroot> exit
```

### With tools and network

```powershell
# Container with Node.js and outbound internet
psroot shell --tool node --network outbound

# Container with Rust CLI tools
psroot shell --tool rust-bin

# Run a specific command and exit
psroot run -- cmd /c "echo Hello from the sandbox"
```

### Full container lifecycle (Docker-style)

```powershell
# Create → Start → Exec → Stop → Remove
psroot create --name myapp --memory 512M --cpu 5000 --tool node
psroot start myapp
psroot exec myapp "node -e \"console.log('hi')\""
psroot stats myapp
psroot stop myapp
psroot rm myapp

# Or list everything
psroot ls
```

---

## Why Psroot?

**The problem is real.** If you've ever tried to run containers on:

- ☁️ A cloud VM without nested virtualization (most AWS/GCP/Azure instances)
- 🖥️ A Windows VM on Proxmox, QEMU, or older ESXi without VT-x passthrough
- 💻 A machine where Docker Desktop / Hyper-V / WSL2 can't be installed
- 🏢 A corporate environment where admin rights are restricted

...you know the frustration. Docker on Windows requires Hyper-V or WSL2. Both require hardware virtualization. No VT-x? No containers. Until now.

**Psroot uses only native Windows kernel primitives** — the same APIs that Chrome, Edge, and the Microsoft Store use for sandboxing. No virtualization hardware. No hypervisor. No kernel drivers. No elevated privileges required for the standard tier.

### How is this different from...

| | VTx Required | Admin Required | Startup Time | Binary Size |
|---|:---:|:---:|:---:|:---:|
| **Docker Desktop** | ✅ Yes | ✅ Yes | ~2-10s | ~1 GB |
| **WSL2** | ✅ Yes | ✅ Yes | ~1-3s | ~300 MB |
| **Hyper-V Containers** | ✅ Yes | ✅ Yes | ~5-20s | N/A |
| **Sandboxie** | ❌ No | ✅ Yes (driver) | ~1s | ~15 MB |
| **Psroot** | ❌ **No** | ❌ **No** | **<1s** | **~2 MB** |

---

## Features

### 🔒 Kernel-Level Filesystem Isolation (AppContainer)

Psroot uses Windows **AppContainer** — the same sandbox technology that isolates Chrome tabs, Edge processes, and Microsoft Store apps. This is a *kernel-enforced* boundary, not a userspace hack.

```
AppContainer process CANNOT:
  ✗ Read C:\Users\*          (your files are invisible)
  ✗ Read C:\Program Files\*  (host software is invisible)
  ✗ Write anywhere outside the container rootfs
  ✗ Access the Windows registry (AppContainer-scoped hive only)
  ✗ See other processes' named objects (mutexes, events, sections)

AppContainer process CAN:
  ✓ Read C:\Windows\System32  (shared OS libraries, same as Docker)
  ✓ Read/write the container rootfs
  ✓ Run cmd.exe, PowerShell, Node.js, Rust binaries
```

### 👁️ Process Visibility Isolation (ProcShim)

Inside a psroot container, processes can only see their own process tree — not the host's processes. This is implemented via `psroot-procshim`, a DLL injected at container start that intercepts process enumeration at the OS level.

All process listing APIs are covered from a single chokepoint — `NtQuerySystemInformation` in ntdll — so tools like `tasklist`, `Get-Process`, `CreateToolhelp32Snapshot`, and .NET's `Process.GetProcesses()` all return the filtered view automatically. `OpenProcess` on host PIDs is blocked with `ACCESS_DENIED`.

This achieves PID-namespace-equivalent isolation on the Standard tier, without admin privileges or Server Silos.

### 🌐 Network Access Control

```powershell
psroot shell --network none      # Default: no network at all
psroot shell --network outbound  # Can reach the internet, can't listen
psroot shell --network full      # Full network + loopback (for servers)
```

### 🧹 Environment Sanitization

Host environment variables are **completely replaced** inside the container. No path leaks, no username leaks, no tool path leaks:

| Variable | Host Value | Container Value |
|---|---|---|
| `PATH` | `C:\Users\you\...;C:\Program Files\...` | `<rootfs>\Windows\System32` |
| `USERNAME` | `you` | `ContainerUser` |
| `COMPUTERNAME` | `YOUR-PC` | `PSROOT` |
| `USERPROFILE` | `C:\Users\you` | `<rootfs>\Users\ContainerUser` |
| `PROMPT` | `C:\Users\you>` | `psroot>` |

35+ environment variables are sanitized, including VS Code paths, tool paths, and any variable containing host directory references.

### 📊 Resource Limits (Job Objects)

```powershell
psroot shell --memory 512M --cpu 5000 --max-procs 50
```

- **Memory limits** — hard cap, process killed on exceed (like Docker `--memory`)
- **CPU throttling** — 1–10000 scale (5000 = 50% of all cores)
- **Process count limits** — prevent fork bombs
- **Full accounting** — `psroot stats <id>` shows memory/CPU/process usage

### 🛠️ Tool Provisioning

Containers auto-provision with tools from your host:

```powershell
psroot shell --tool node       # Copies Node.js + npm into rootfs
psroot shell --tool rust-bin   # Copies Rust CLI tools from ~/.cargo/bin
psroot shell --tool winget     # Sets up winget support directories
```

### 📋 66 Isolation Tests

```powershell
psroot test all
```

Runs a comprehensive test suite covering:
- Job object limits (memory, CPU, process count)
- Filesystem isolation (host paths inaccessible)
- Process visibility (host processes not enumerable)
- Network isolation (connectivity control)
- Environment sanitization (no host leaks)
- AppContainer enforcement (registry, named objects)
- Stress tests (100 processes, rapid spawn/kill)

---

## Commands

| Command | Description |
|---|---|
| `psroot info` | Show system capabilities and isolation level |
| `psroot shell` | Interactive sandboxed shell (create + enter + auto-cleanup) |
| `psroot create` | Create a container (returns ID) |
| `psroot start <id>` | Start a created container |
| `psroot run [cmd]` | Create + start in one step |
| `psroot exec <id> <cmd>` | Execute command in running container |
| `psroot stop <id>` | Stop a running container |
| `psroot rm <id>` | Remove a container |
| `psroot ls` | List all containers |
| `psroot stats <id>` | Show resource usage |
| `psroot test [category]` | Run isolation tests |

See the full [CLI Reference](docs/cli-reference.md) for all flags and options.

---

## Isolation Tiers

Psroot is **admin-aware** — it automatically detects what's available and uses the strongest isolation possible:

| Tier | Requirements | What You Get |
|---|---|---|
| **Standard** | No admin, Windows 10+ | AppContainer + Job Objects + process visibility isolation + env sanitization + network control |
| **Enhanced** | Admin, Windows 11 24H2+ | Standard + BindFilter path remapping |
| **Full** | Admin, Windows 10 1809+ | Enhanced + Server Silo namespace isolation |

```powershell
PS> psroot info

Psroot System Capabilities
─────────────────────────────────────
Windows Build:    19045
Administrator:    NO
Job Objects:      ✓
Process Shim:     ✓
Server Silos:     ✗ (needs admin + build >= 17763)
Bind Filter:      ✗ (needs admin + build >= 26100)
VTx Required:     NO (pure kernel primitives)

Isolation Level:  Standard (AppContainer + ProcShim + Env)
  ⚠ Non-admin: server silos and bind filter unavailable
    Run as Administrator for full namespace isolation
```

> **Standard tier is strong.** It's the same kernel sandbox that Chrome uses for renderer processes, plus process visibility isolation and resource limits on top. Admin tiers add mount-level path remapping and full PID/IPC/UTS namespace separation via Server Silos.

---

## Architecture

Psroot is a Cargo workspace with focused crates:

```
psroot (workspace)
├── psroot-types         # Config, errors, state types
├── psroot-job           # Job Objects (memory/CPU/process limits + accounting)
├── psroot-bindlink      # Bind Filter filesystem remapping (admin, Win 11 24H2+)
├── psroot-namespace     # Object namespace isolation via NT APIs
├── psroot-silo          # Server Silo creation and management (admin)
├── psroot-container     # Container lifecycle + AppContainer sandbox + rootfs
├── psroot-procshim      # Process visibility isolation (ntdll inline hooking)
├── psroot-netinject     # DLL injection (CreateRemoteThread + LoadLibraryW)
├── psroot-netshim       # Network interception layer
├── psroot-netstack-*    # Virtual network stack (host/ipc/proto)
├── psroot-portmap       # Port forwarding for containerized servers
├── psroot-rootfs-stager # Rootfs provisioning and tool staging
├── psroot-shell-resolver# Interactive shell resolution
├── psroot-desktop       # Desktop integration
├── psroot-unix          # Linux/macOS backend (namespaces+cgroups / sandbox-exec)
└── psroot-cli           # CLI interface (clap)
```

### Kernel Primitives Used (Windows)

| Windows API | Linux Equivalent | Purpose |
|---|---|---|
| **AppContainer** | `pivot_root` + mount namespace | Filesystem isolation |
| **Job Objects** | `cgroups v2` | Resource limits |
| **Restricted Tokens** | Capability drop | Privilege reduction |
| **ntdll inline hooking** | PID namespace | Process visibility isolation |
| **BindFilter** | Bind mount | Path remapping (admin) |
| **Server Silos** | PID/IPC/UTS namespaces | Full namespace isolation (admin) |

No kernel drivers. No virtualization. Just the Windows kernel doing what it already knows how to do.

---

## Cross-Platform Support

Psroot's Windows backend is the unique value-add. On Linux and macOS it provides a consistent CLI over the platform's native primitives:

| Platform | Backend | Notes |
|---|---|---|
| **Windows 10+** | AppContainer + Job Objects + ProcShim | Primary target |
| **Linux** | clone(2) namespaces + cgroups v2 + pivot_root | Same primitives as bubblewrap |
| **macOS** | sandbox-exec SBPL profiles + PTY + rlimits | Wraps Seatbelt |

---

## Building from Source

### Requirements

- **Rust 1.75+** (stable)
- **Windows 10 build 17763+** (for runtime — compiles anywhere)

### Build

```powershell
git clone https://github.com/psmux/Psroot.git
cd Psroot
cargo build --release
```

The binary lands at `target\release\psroot.exe` (~2 MB with LTO).

### Run Tests

```powershell
.\target\release\psroot.exe test all
# RESULTS: 66/66 passed, 0 failed
```

---

## Documentation

| Guide | What you'll learn |
|---|---|
| [Installation](docs/installation.md) | Download, build from source, system requirements |
| [Quick Start](docs/quick-start.md) | First container in 10 seconds, tools, networking |
| [Container Lifecycle](docs/container-lifecycle.md) | Create, start, exec, stop, remove — Docker-style workflow |
| [Isolation Guide](docs/isolation.md) | How AppContainer + procshim works, what's blocked |
| [Network & Tools](docs/network-and-tools.md) | Network modes, Node.js/Rust/winget provisioning |
| [Resource Limits](docs/resource-limits.md) | Memory, CPU, process limits and monitoring |
| [CLI Reference](docs/cli-reference.md) | Every command and flag |

---

## FAQ

**Q: Is this as secure as Docker?**
A: Different trade-offs. Docker uses a hypervisor (hardware boundary). Psroot uses AppContainer + process visibility isolation (kernel boundary). AppContainer is battle-tested — Chrome trusts it for billions of users. For dev/CI/tooling workloads, it's excellent. For multi-tenant hostile workloads, use a VM.

**Q: Can I run Linux binaries?**
A: No. Psroot runs native Windows executables. For Linux binaries, you need WSL2 (which needs VT-x). Psroot is for Windows-native workloads.

**Q: Does it work on Windows Server?**
A: Yes. Windows Server 2019+ supports all the APIs. Server editions also unlock Server Silos for the Full isolation tier.

**Q: Can I use this in CI/CD?**
A: Absolutely — that's a primary use case. Isolate build steps, run untrusted scripts, limit resource usage. Works on any Windows CI runner, even those without nested virtualization.

**Q: How does process visibility isolation work?**
A: The `psroot-procshim` DLL is injected before the container's first process starts. It patches ntdll's `NtQuerySystemInformation` and `NtOpenProcess` at the function entry point, so every process enumeration API (tasklist, PowerShell Get-Process, WMI, .NET, Toolhelp32) returns only the container's own processes. This is a single kernel-level chokepoint that catches all callers.

**Q: Why Rust?**
A: Zero-overhead FFI to Win32 APIs. Single static binary. No runtime dependencies. Memory safety for security-critical sandbox code. Compiles to a 2 MB binary that starts in under a second.

---

## License

MIT

---

<p align="center">
  <strong>Built by <a href="https://github.com/psmux">psmux</a></strong>
</p>
