<p align="center">
  <h1 align="center">Psroot</h1>
  <p align="center">
    <strong>Container-grade process isolation for Windows — no VTx, no Hyper-V, no Docker, no WSL.</strong>
  </p>
  <p align="center">
    A single ~2 MB binary. Pure OS kernel primitives.<br>
    Works on VMs, bare metal, and cloud instances where nested virtualization is unavailable.
  </p>
</p>

---

## Windows Isolation Features (First-Class)

Psroot is the **first-class sandboxing solution for Windows**. It delivers container-grade isolation on the Standard tier without admin privileges:

| Isolation Layer | Mechanism | Admin Required | Proven |
|---|---|---|---|
| **Filesystem isolation** | AppContainer kernel-enforced ACL gating | No | ✓ |
| **Process visibility isolation** | Inline hooking of `ntdll!NtQuerySystemInformation` + `NtOpenProcess` | No | ✓ Zero leaks |
| **Registry isolation** | AppContainer-scoped registry hive | No | ✓ |
| **Named-object isolation** | AppContainer scopes mutexes, events, sections | No | ✓ |
| **Resource limits** | Job Objects: memory cap, CPU rate (1–10000), max-procs, kill-on-close | No | ✓ |
| **Network access control** | `--network none/outbound/full` | No | ✓ |
| **Capabilities drop** | Restricted Token strips most privileges | No | ✓ |
| **Environment sanitization** | 35+ host vars replaced with synthetic values | No | ✓ |
| **Path remapping** | BindFilter filesystem redirection | Yes (Win 11 24H2+) | ✓ |
| **Full namespace isolation** | Server Silos (PID/IPC/UTS/Registry/FS) | Yes (Win 10 1809+) | ✓ |

### Process Visibility Isolation — Proven Zero Leaks

The `psroot-procshim` crate injects a DLL that patches ntdll syscall stubs at the function entry point. This intercepts **every** process enumeration call regardless of how the caller reaches the function:

```
╔═══════════════════════════════════════════════════════╗
║  PASS: PROCESS ISOLATION IRREFUTABLY PROVEN           ║
║                                                       ║
║  • NtQuerySystemInformation: filtered   ✓             ║
║  • CreateToolhelp32Snapshot: filtered   ✓             ║
║  • K32EnumProcesses: filtered           ✓             ║
║  • NtOpenProcess: blocked               ✓             ║
║  • Host processes visible: 0            ✓             ║
╚═══════════════════════════════════════════════════════╝
```

**Technique:** 16-byte inline patch (`jmp [rip+0]` + absolute address) overwrites the ntdll syscall stub prologue. The original 24-byte stub is preserved as an executable trampoline. The hook filters the `SYSTEM_PROCESS_INFORMATION` linked list, removing all entries not in the container's process tree.

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

psroot> exit
```

### With tools and network

```powershell
# Container with Node.js and outbound internet
psroot shell --tool node --network outbound

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
```

---

## Why Psroot?

| | VTx Required | Admin Required | Startup Time | Binary Size |
|---|:---:|:---:|:---:|:---:|
| **Docker Desktop** | ✅ Yes | ✅ Yes | ~2-10s | ~1 GB |
| **WSL2** | ✅ Yes | ✅ Yes | ~1-3s | ~300 MB |
| **Hyper-V Containers** | ✅ Yes | ✅ Yes | ~5-20s | N/A |
| **Sandboxie** | ❌ No | ✅ Yes (driver) | ~1s | ~15 MB |
| **Psroot** | ❌ **No** | ❌ **No** | **<1s** | **~2 MB** |

---

## Architecture

Cargo workspace with focused crates:

```
psroot (workspace)
├── psroot-types        # Config, errors, state types
├── psroot-job          # Job Objects (memory/CPU/process limits + accounting)
├── psroot-bindlink     # Bind Filter filesystem remapping (admin, Win 11 24H2+)
├── psroot-namespace    # Object namespace isolation via NT APIs
├── psroot-silo         # Server Silo creation and management (admin)
├── psroot-container    # Container lifecycle + AppContainer sandbox + rootfs
├── psroot-procshim     # Process visibility isolation (inline hooking)
├── psroot-netinject    # DLL injection via CreateRemoteThread(LoadLibraryW)
├── psroot-netshim      # Network interception layer
├── psroot-netstack-*   # Virtual network stack (host/ipc/proto)
├── psroot-portmap      # Port forwarding for containerized servers
├── psroot-rootfs-stager# Rootfs provisioning and tool staging
├── psroot-shell-resolver# Interactive shell resolution
├── psroot-desktop      # Desktop integration
├── psroot-unix         # Linux/macOS backend (namespaces + cgroups / sandbox-exec)
└── psroot-cli          # CLI interface (clap)
```

### Kernel Primitives Used (Windows)

| Windows API | Linux Equivalent | Purpose |
|---|---|---|
| **AppContainer** | `pivot_root` + mount namespace | Filesystem isolation |
| **Job Objects** | `cgroups v2` | Resource limits |
| **Restricted Tokens** | Capability drop | Privilege reduction |
| **BindFilter** | `bind mount` | Path remapping |
| **Server Silos** | PID/IPC/UTS namespace | Full namespace isolation |
| **Inline ntdll hooking** | PID namespace (`unshare -p`) | Process visibility isolation |

---

## Isolation Tiers

Psroot auto-detects available primitives and uses the strongest isolation possible:

| Tier | Requirements | Isolation |
|---|---|---|
| **Standard** | No admin, Windows 10+ | AppContainer + Job Objects + procshim + env sanitization + network control |
| **Enhanced** | Admin, Windows 11 24H2+ | Standard + BindFilter path remapping |
| **Full** | Admin, Windows 10 1809+ | Enhanced + Server Silo namespace isolation |

```powershell
PS> psroot info

Psroot System Capabilities
─────────────────────────────────────
Windows Build:    19045
Administrator:    NO
Job Objects:      ✓
Process Shim:     ✓ (inline hook, zero leaks)
Server Silos:     ✗ (needs admin + build >= 17763)
Bind Filter:      ✗ (needs admin + build >= 26100)
VTx Required:     NO (pure kernel primitives)

Isolation Level:  Standard (AppContainer + ProcShim + Env)
```

> **Standard tier is container-grade.** With procshim providing proven PID isolation, the Standard tier now covers: filesystem, process visibility, registry, named objects, resource limits, network, environment, and capabilities. Admin tiers add defense-in-depth.

---

## Commands

| Command | Description |
|---|---|
| `psroot info` | Show system capabilities and isolation level |
| `psroot shell` | Interactive sandboxed shell |
| `psroot create` | Create a container (returns ID) |
| `psroot start <id>` | Start a created container |
| `psroot run [cmd]` | Create + start in one step |
| `psroot exec <id> <cmd>` | Execute command in running container |
| `psroot stop <id>` | Stop a running container |
| `psroot rm <id>` | Remove a container |
| `psroot ls` | List all containers |
| `psroot stats <id>` | Show resource usage |
| `psroot test [category]` | Run isolation tests |

---

## Cross-Platform Support

| Platform | Backend | Status |
|---|---|---|
| **Windows 10+** | AppContainer + Job Objects + procshim | **Primary target, proven** |
| **Linux** | clone(2) namespaces + cgroups v2 + pivot_root | Working |
| **macOS** | sandbox-exec SBPL profiles + PTY + rlimits | Working |

The Windows backend is Psroot's unique value-add. On Linux and macOS, the primitives are shared with bubblewrap and sandbox-exec respectively.

---

## Building from Source

```powershell
git clone https://github.com/psmux/Psroot.git
cd Psroot
cargo build --release
```

Binary: `target/release/psroot.exe` (~2 MB).

### Run Isolation Tests

```powershell
# Full test suite (66 tests)
.\target\release\psroot.exe test all

# Process isolation proof (E2E)
.\target\release\procshim-e2e-test.exe
```

---

## Documentation

| Guide | Topic |
|---|---|
| [Installation](docs/installation.md) | System requirements, build from source |
| [Quick Start](docs/quick-start.md) | First container in 10 seconds |
| [Container Lifecycle](docs/container-lifecycle.md) | Create, start, exec, stop, remove |
| [Isolation Guide](docs/isolation.md) | How AppContainer + procshim works |
| [Network & Tools](docs/network-and-tools.md) | Network modes, tool provisioning |
| [Resource Limits](docs/resource-limits.md) | Memory, CPU, process limits |
| [CLI Reference](docs/cli-reference.md) | Every command and flag |

---

## FAQ

**Q: Is this as secure as Docker?**
A: Different trade-offs. Docker uses a hypervisor (hardware boundary). Psroot uses AppContainer + inline hooking (kernel boundary). AppContainer is battle-tested — Chrome trusts it for billions of users. With procshim providing proven PID isolation, the Standard tier delivers comparable containment for dev/CI/tooling workloads without any admin privileges.

**Q: Can I run Linux binaries?**
A: No. Psroot runs native Windows executables. For Linux binaries, you need WSL2 (which needs VT-x).

**Q: Does it work on Windows Server?**
A: Yes. Windows Server 2019+ supports all APIs. Server editions also unlock Server Silos.

**Q: Can I use this in CI/CD?**
A: Absolutely — that's a primary use case. Isolate build steps, run untrusted scripts, limit resource usage. Works on any Windows CI runner, even without nested virtualization.

**Q: How does process isolation work without a real PID namespace?**
A: The `psroot-procshim` DLL is injected into the target process before it starts. It patches the first 16 bytes of `ntdll!NtQuerySystemInformation` and `ntdll!NtOpenProcess` with a jump to our hook. The hook filters the process list to show only the container's own process tree. Since every Windows process enumeration API (tasklist, Get-Process, WMI, .NET, Toolhelp32) ultimately calls NtQuerySystemInformation, this is a single chokepoint that catches all callers.

---

## License

MIT

---

<p align="center">
  <strong>Built by <a href="https://github.com/psmux">psmux</a></strong>
</p>
