# Isolation Guide

How Psroot isolates containers from the host — and what each layer does.

## Isolation Layers

Psroot applies multiple layers of isolation. Each layer works independently, so even if one is bypassed, the others still protect you.

### 1. AppContainer (Filesystem + Registry)

The primary isolation boundary. AppContainer is a **kernel-enforced** sandbox — the same technology used by Chrome, Edge, and Microsoft Store apps.

**What it blocks:**
- Reading any file not explicitly granted (your entire home directory, Program Files, etc.)
- Writing anywhere outside the container rootfs
- Accessing the Windows registry
- Seeing other processes' named objects (mutexes, pipes, shared memory)

**What it allows:**
- Reading `C:\Windows\System32` (shared OS libraries — same as Docker reading `/usr/lib`)
- Reading and writing the container rootfs
- Running executables copied into the rootfs

This is not a userspace filter. It's enforced by the Windows kernel's Security Reference Monitor. A process cannot bypass it without a kernel exploit.

### 2. Environment Sanitization

Even though AppContainer blocks *access* to host paths, environment variables could still *reveal* them. Psroot replaces 35+ host environment variables with sandbox values:

- `PATH` → only rootfs directories
- `USERNAME` → `ContainerUser`
- `COMPUTERNAME` → `PSROOT`
- `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` → rootfs paths
- `PROMPT` → `psroot>`
- VS Code paths, tool paths, temp dirs → all cleaned

Dynamic variables containing host path fragments are also detected and removed.

### 3. Job Objects (Resource Limits)

Every container runs inside a Windows Job Object that enforces:
- Hard memory ceiling (process killed on exceed)
- CPU throttling (rate-limited across all cores)
- Process count limit (prevents fork bombs)
- Child process containment (all descendants inherit the job)

### 4. Restricted Token (Fallback)

If AppContainer APIs are unavailable, Psroot falls back to a restricted token that strips administrative SIDs and privileges. This is weaker than AppContainer but still reduces the attack surface.

## Isolation Tiers

Psroot detects available features and uses the strongest isolation possible:

| Tier | Requirements | Layers |
|---|---|---|
| **Standard** | Windows 10+, no admin | AppContainer + Env + Job Objects |
| **Enhanced** | Windows 11 24H2+, admin | Standard + BindFilter path remapping |
| **Full** | Windows 10 1809+, admin | Enhanced + Server Silo namespaces |

Check your tier:
```powershell
psroot info
```

### Standard Tier (Recommended)

The default. No admin required. Uses:
- AppContainer for kernel-level filesystem isolation
- Environment sanitization to hide host paths
- Job Objects for resource limits

This is sufficient for dev environments, CI/CD, and running untrusted scripts. It's the same boundary Chrome uses to isolate every tab.

### Enhanced Tier (Admin)

Adds BindFilter — Windows' equivalent of `bind mount`. This lets Psroot remap filesystem paths so the container sees a clean `C:\` instead of its actual rootfs path. Requires admin and Windows 11 24H2+ (build 26100).

### Full Tier (Admin)

Adds Server Silos — full process/registry/object namespace isolation (like Docker's Linux namespaces). Each container gets its own PID space and registry hive. Requires admin and Windows 10 1809+ (build 17763).

> **Security note:** Admin tiers require running Psroot elevated. If a sandbox escape occurs in admin mode, the attacker gains admin privileges. Standard tier is safer for most use cases — a sandbox escape only yields an unprivileged user.

## What's NOT Isolated

Be aware of these limitations:

- **Clipboard** — container processes can read/write the clipboard
- **Display/GUI** — container processes can create windows (if they have the DLLs)
- **System time** — container sees the host's clock
- **CPU architecture info** — container can detect the host CPU model
- **Network metadata** — with `--network outbound/full`, the container shares the host's IP

These are inherent to userspace containerization without a hypervisor. For workloads where these matter, use a VM.
