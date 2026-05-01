# Quick Start Guide

Get a sandboxed Windows shell in 10 seconds.

## Your First Container

```powershell
psroot shell
```

That's it. You're inside an isolated container:

```
╔══════════════════════════════════════════════════╗
║  Psroot Interactive Shell                        ║
║  Container: psroot-a1b2c3d4                      ║
║  Network: None      Sandbox: AppContainer        ║
║  Isolation: Standard (AppContainer + Env)        ║
║  Type 'exit' to leave the sandbox                ║
╚══════════════════════════════════════════════════╝

psroot>
```

### What's different inside?

```
psroot> echo %USERNAME%
ContainerUser

psroot> echo %COMPUTERNAME%
PSROOT

psroot> echo %PATH%
C:\...\rootfs\Windows\System32

psroot> whoami
psroot-a1b2c3d4\containeruser
```

Your real username, paths, and environment are hidden. The container can only see its own rootfs.

### Try accessing host files

```
psroot> dir C:\Users
Access is denied.

psroot> dir C:\Program Files
Access is denied.
```

AppContainer blocks access at the kernel level — your files are invisible, not just hidden.

### Exit

```
psroot> exit
Shell exited (code 0). Cleaning up...
Container psroot-a1b2c3d4 removed.
```

The container and its rootfs are automatically cleaned up.

## Add Tools

```powershell
# Node.js (copies from your host installation)
psroot shell --tool node

# Rust CLI tools (pstop, psmux, etc. from ~/.cargo/bin)
psroot shell --tool rust-bin

# Multiple tools
psroot shell --tool node --tool rust-bin
```

## Enable Networking

```powershell
# No network (default — most secure)
psroot shell

# Outbound only (can reach internet, can't listen on ports)
psroot shell --network outbound

# Full network + loopback (for running servers)
psroot shell --network full
```

## Set Resource Limits

```powershell
# 512 MB RAM, 50% CPU, max 50 processes
psroot shell --memory 512M --cpu 5000 --max-procs 50
```

## Run a One-Off Command

```powershell
# Run a command and exit (no interactive shell)
psroot run -- cmd /c "echo Hello from the sandbox"

# Run Node.js script in a container
psroot run --tool node -- node -e "console.log(process.env.USERNAME)"
```

## Next Steps

- [Interactive Shells](./interactive-shells.md) — shell selection, environment, caching
- [Networking Inside Sandboxes](./sandbox-networking.md) — ping, DNS, SSH, IP discovery
- [Container Lifecycle](./container-lifecycle.md) — create, start, exec, stop, remove
- [Isolation Guide](./isolation.md) — how the sandbox works, what's blocked
- [Network & Tools](./network-and-tools.md) — networking modes, tool provisioning
- [Resource Limits](./resource-limits.md) — memory, CPU, process caps
- [CLI Reference](./cli-reference.md) — every command and flag
