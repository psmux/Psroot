# CLI Reference

Complete reference for all `psroot` commands and flags.

## Global Flags

| Flag | Description |
|---|---|
| `--verbose` | Enable debug logging (`RUST_LOG=debug`) |
| `--version` | Show version |
| `--help` | Show help |

---

## `psroot info`

Show system capabilities and current isolation level.

```powershell
psroot info
```

```
Psroot System Capabilities
─────────────────────────────────────
Windows Build:    19045
Administrator:    NO
Job Objects:      ✓
Server Silos:     ✗ (needs admin + build >= 17763)
Bind Filter:      ✗ (needs admin + build >= 26100)
VTx Required:     NO (pure kernel primitives)

Isolation Level:  Standard (AppContainer + Env)
  ⚠ Non-admin: some isolation features unavailable
    Run as Administrator for: bind filter, server silos
```

---

## `psroot shell`

Create a container and drop into an interactive shell. Auto-cleans up on exit.

```powershell
psroot shell [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--tool <name>` | none | Tool to install: `node`, `rust-bin`, `winget` (repeatable) |
| `--network <mode>` | `none` | Network access: `none`, `outbound`, `full` |
| `--memory <size>` | `1G` | Memory limit (e.g., `512M`, `2G`) |
| `--cpu <rate>` | `10000` | CPU rate 1–10000 |
| `--max-procs <n>` | `100` | Max processes |

---

## `psroot create`

Create a container without starting it.

```powershell
psroot create [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `--name <name>` | auto | Human-readable container name |
| `--rootfs <path>` | auto | Root filesystem path |
| `--command <cmd>` | `cmd.exe` | Command to run on start |
| `--memory <size>` | `1G` | Memory limit |
| `--cpu <rate>` | `10000` | CPU rate 1–10000 |
| `--max-procs <n>` | `100` | Max processes |
| `--tool <name>` | none | Tool to install (repeatable) |
| `--network <mode>` | `none` | Network access |
| `-v, --volume <spec>` | none | Volume mount `host:container[:ro]` (repeatable) |
| `-e, --env <VAR=VAL>` | none | Environment variable (repeatable) |
| `--workdir <path>` | `C:\` | Working directory |
| `--silo` | false | Enable server silo (requires admin) |

Returns the container ID.

---

## `psroot start <id>`

Start a created container.

```powershell
psroot start psroot-a1b2c3d4
```

---

## `psroot run [OPTIONS] [-- command...]`

Create and start a container in one step.

```powershell
psroot run -- cmd /c "echo hello"
psroot run --tool node -- node -e "console.log('hi')"
```

Same flags as `create`. Trailing arguments after `--` are the command.

---

## `psroot exec <id> <command>`

Execute a command inside a running container.

```powershell
psroot exec psroot-a1b2c3d4 "dir C:\\"
```

Returns the PID of the spawned process.

---

## `psroot stop <id>`

Stop a running container (terminates all processes).

```powershell
psroot stop psroot-a1b2c3d4
```

---

## `psroot rm <id>`

Remove a container and delete its rootfs.

```powershell
psroot rm psroot-a1b2c3d4

# Force (stop first if running)
psroot rm -f psroot-a1b2c3d4
```

---

## `psroot ls`

List all containers.

```powershell
psroot ls
psroot ls --status running
```

---

## `psroot stats <id>`

Show resource usage for a container.

```powershell
psroot stats psroot-a1b2c3d4
```

---

## `psroot test [category]`

Run the built-in isolation test suite.

```powershell
psroot test all        # All 66 tests
psroot test job        # Job object tests only
psroot test fs         # Filesystem isolation tests
psroot test process    # Process containment tests
psroot test network    # Network isolation tests
psroot test silo       # Server silo tests (skipped without admin)
psroot test bindlink   # Bind filter tests (skipped without admin)
```
