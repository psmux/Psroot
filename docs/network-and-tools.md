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

> **Note:** The container shares the host's network stack and IP address. There's no network namespace isolation — `bind(3000)` from inside is a `bind(3000)` on the host. Use **port publishing** (below) to map container ports to different, non-colliding host ports.

## Port Publishing

Psroot supports Docker-style `-p` / `--publish` to expose container services
without hard-coded host-port conflicts.

```powershell
# Run a Node dev server that thinks it listens on 3000,
# reachable on the host at http://127.0.0.1:8080
psroot run --network full -p 8080:3000 --tool node -- node server.js

# Two containers both "listening on 3000" — no collision
psroot run --network full -p 8080:3000 --tool node -- node app.js
psroot run --network full -p 8081:3000 --tool node -- node app.js

# Expose on all interfaces
psroot run --network full -p 0.0.0.0:8080:3000 -- node app.js

# Multiple ports
psroot run --network full -p 8080:3000 -p 9090:4000 -- node app.js
```

### How it works

Because Windows has no user-mode network namespaces without Hyper-V, psroot
cannot truly give the container its own TCP port space. Instead, each `-p`
mapping:

1. **Allocates a random ephemeral loopback port** on `127.0.0.1` (e.g.
   `54321`) at container start.
2. **Injects it as environment variables** into the container:
   - `PORT=54321` (set to the first mapping — picked up automatically by
     Next.js, Express, FastAPI, Flask, Rails, etc.)
   - `PSROOT_PORT_3000=54321` (per-mapping, for programs that need to know
     their public-facing logical port).
   - `HOST=127.0.0.1`.
3. **Starts a host-side TCP reverse proxy** on `host_bind:host_port`
   (default bind `127.0.0.1`) that forwards every connection to
   `127.0.0.1:54321`.
4. **Tears the proxy down** cleanly when the container stops.

End result: two containers can each say "I serve on port 3000" and the user
picks distinct `-p` host ports for them. The ephemeral ports are not
chosen by the user and don't conflict with well-known developer ports.

### Publish spec formats

| Form                       | Meaning                                      |
| -------------------------- | -------------------------------------------- |
| `PORT`                     | bind `127.0.0.1:PORT`, logical container=PORT|
| `HOST:CONTAINER`           | bind `127.0.0.1:HOST`, logical=CONTAINER     |
| `BIND:HOST:CONTAINER`      | bind `BIND:HOST`, logical=CONTAINER          |

### Limitations

- **Requires `--network full`.** Outbound-only and none-networking containers
  cannot accept inbound connections.
- **The program must honor `$PORT`** (or read `PSROOT_PORT_*`). Programs
  that hard-code `listen(3000)` will try to bind port 3000 on the host and
  conflict with any other process already using it. A future Detours-based
  `bind()` interception shim will transparently rewrite these; until then
  prefer frameworks that respect `$PORT`.
- **TCP only.** UDP, ICMP, SCTP, and protocol-aware features (PROXY
  protocol, TLS SNI) are not implemented.
- **Small TOCTOU window.** The ephemeral port is reserved by briefly
  binding `127.0.0.1:0` at start — another process could snatch it before
  the container rebinds. In practice the window is microseconds.

### Inspecting mappings

```powershell
psroot ls
# ID                       STATUS     CREATED              PORTS
# ──────────────────────────────────────────────────────────────────
# psroot-a1b2c3d4          running    2026-04-21 10:15:03  127.0.0.1:8080->3000
```

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
