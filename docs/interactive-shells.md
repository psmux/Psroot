# Interactive Shells

Psroot can launch interactive shells inside isolated AppContainer sandboxes.
The shell process runs with a restricted token, sanitized environment, and
its own rootfs — while you interact with it just like a normal terminal.

## Available Shells

| Shell | Command | Notes |
| ----- | ------- | ----- |
| **cmd** | `psroot shell` | Default. Windows Command Prompt. |
| **pwsh** | `psroot shell --shell pwsh` | PowerShell 7+. Staged from host install via hardlinks. |
| **powershell** | `psroot shell --shell powershell` | Windows PowerShell 5.1. Uses System32 (no staging needed). |

Check what's available on your system:

```powershell
psroot shell-list
```

```
NAME           DISPLAY
────────────────────────────────────────────────────────────
cmd            Windows Command Prompt
pwsh           PowerShell 7
powershell     Windows PowerShell 5.1
```

Inspect what the resolver will do for a specific shell:

```powershell
psroot shell-info pwsh
```

```
Catalog entry : pwsh (PowerShell 7)
Aliases       : powershell-core, pwsh7
Probe rules   : 4
Host install  : C:\Program Files\PowerShell\7\pwsh.exe (v7.6.0)
Cache dir     : C:\Users\you\.psroot\cache\shells\pwsh-7.6.0 (exists: true)
Stage ops     : 7
ACE grants    : 1
Caps (outbound): [InternetClient]
```

## Launching a Shell

### Basic (no network)

```powershell
psroot shell --shell pwsh
```

```
╔══════════════════════════════════════════════════╗
║  Psroot Interactive Shell                        ║
║  Container: psroot-da2f9462                      ║
║  Network  : none      Sandbox: AppContainer      ║
║  Isolation: Standard (AppContainer + Env)        ║
║  Type 'exit' to leave the sandbox                ║
╚══════════════════════════════════════════════════╝

Shell      : pwsh (v7.6.0)
Cache      : C:\Users\you\.psroot\cache\shells\pwsh-7.6.0
Isolation  : AppContainer (access restricted, host FS visible)

PS C:\>
```

### With Outbound Networking

```powershell
psroot shell --shell pwsh --network outbound
```

Grants the `internetClient` capability — the container can make outgoing TCP
connections, resolve DNS, and fetch URLs. Cannot listen on ports.

### With Full Networking

```powershell
psroot shell --shell pwsh --network full
```

Grants `internetClient` + `internetClientServer` + loopback exemption.
The container can both connect outward and listen on ports.

## What's Different Inside

```powershell
PS C:\> $env:USERNAME
ContainerUser

PS C:\> $env:COMPUTERNAME
PSROOT

PS C:\> $PSVersionTable.PSVersion
Major  Minor  Patch
-----  -----  -----
7      6      0
```

The sandbox environment is isolated:

| Variable | Host Value | Sandbox Value |
| -------- | ---------- | ------------- |
| `USERNAME` | Your real username | `ContainerUser` |
| `COMPUTERNAME` | Your PC name | `PSROOT` |
| `USERPROFILE` | `C:\Users\you` | `{rootfs}\Users\ContainerUser` |
| `PATH` | Full host PATH | Minimal: System32 + shell binary |
| `PSModulePath` | Host module paths | Shell modules + user modules dir |

## Exiting

Type `exit` or press `Ctrl+D`. The container and rootfs are automatically
cleaned up, ACE grants are revoked, and the cache refcount is decremented.

```
PS C:\> exit
Shell exited (code 0). Cleaning up...
Container psroot-da2f9462 removed.
```

## Shell Caching

The first time you launch a shell, psroot hardlinks the host installation
into a per-user cache (`~/.psroot/cache/shells/pwsh-7.6.0/`). Subsequent
containers reuse the cache — startup drops from ~2 seconds to ~200 ms.

The cache is shared across containers but each container gets its own rootfs
with a junction pointing to the cache. ACE grants are per-container (each
AppContainer SID is unique) and revoked on exit.

## Run a One-Off Command

```powershell
# Run a command and exit (no interactive shell)
psroot run --shell pwsh -- Get-ChildItem C:\

# Run a script
psroot run --shell pwsh -- pwsh -File script.ps1
```

## Next Steps

- [Network & Tools](./network-and-tools.md) — networking modes, tool provisioning, port publishing
- [Networking Inside Sandboxes](./sandbox-networking.md) — ping, DNS, SSH, IP discovery
- [CLI Reference](./cli-reference.md) — every command and flag
