# Network & Tools

## Network Modes

Control what network access the container has.

### None (Default)

```powershell
psroot shell
# or explicitly:
psroot shell --network none
```

The container has **no network access** at all. DNS, HTTP, TCP — all blocked. This is the safest option for running untrusted code.

### Outbound

```powershell
psroot shell --network outbound
```

The container can **make outgoing connections** (HTTP requests, DNS lookups, etc.) but **cannot listen** on ports. Good for:
- Installing npm packages
- Fetching data from APIs
- Running scripts that need internet access

Uses the Windows `internetClient` capability.

### Full

```powershell
psroot shell --network full
```

Full network access including **listening on ports** and **loopback** (localhost). Good for:
- Running dev servers (Express, Next.js, etc.)
- Services that need to accept connections
- Inter-process communication via localhost

Uses `internetClient` + `internetClientServer` capabilities, plus loopback exemption.

> **Note:** The container shares the host's network stack and IP address. There's no network namespace isolation. If the container listens on port 3000, that port is occupied on the host too.

## Tool Provisioning

Psroot can copy tools from your host into the container rootfs so they're available inside the sandbox.

### Node.js

```powershell
psroot shell --tool node
```

Copies your host's Node.js installation into the container:
- `node.exe`, `npm`, `npx`
- `node_modules` directory (for npm)

Inside the container:
```
psroot> node --version
v22.0.0

psroot> npm --version
10.8.0
```

**Requires:** Node.js installed on the host and on PATH.

### Rust Binaries

```powershell
psroot shell --tool rust-bin
```

Copies pre-built executables from `~/.cargo/bin/` into the container's `bin/` directory. Only copies from an allowlist:
- `pstop.exe` — system monitor
- `psmux.exe` — terminal multiplexer
- `psnet.exe` — network tool
- `htop.exe` — process viewer
- `weathr.exe` — weather CLI

This avoids copying the full 1.4 GB Rust toolchain. The copied binaries are statically linked and need no extra DLLs.

**Requires:** The binaries installed via `cargo install`.

### Winget

```powershell
psroot shell --tool winget
```

Creates the directory structure for winget support. The actual winget binary may need bind-linking (admin) to work inside the container.

### Multiple Tools

```powershell
psroot shell --tool node --tool rust-bin
```

All tools are installed into the container rootfs before the shell starts. PATH is automatically set to include tool directories.

## Custom Environment Variables

Pass environment variables into the container:

```powershell
psroot create --env "API_KEY=secret123" --env "NODE_ENV=production" --tool node
```

Custom env vars are applied *after* sanitization, so they override sandbox defaults.

## Volume Mounts

Mount host directories into the container:

```powershell
# Read-write mount
psroot create --volume "C:\myproject:C:\app"

# Read-only mount
psroot create --volume "C:\myproject:C:\app:ro"
```

> **Note:** Volume mounts require granting the AppContainer SID access to the host directory. The container can read (and write, unless `:ro`) the mounted path.
