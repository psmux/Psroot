# Container Lifecycle

Psroot containers follow a Docker-like lifecycle: **create → start → exec → stop → remove**.

For quick usage, `psroot shell` does all of this in one command. For more control, use the individual commands below.

## Create

```powershell
psroot create --name myapp --memory 512M --cpu 5000 --tool node
# Output: psroot-a1b2c3d4
```

This creates the container (provisions rootfs, copies tools) but doesn't start it.

| Flag | Default | Description |
|---|---|---|
| `--name` | auto-generated | Human-readable name |
| `--rootfs` | auto-created | Path to root filesystem (empty = auto) |
| `--command` | `cmd.exe` | Command to run on start |
| `--memory` | `1G` | Memory limit (e.g., `512M`, `2G`) |
| `--cpu` | `10000` | CPU rate 1–10000 (10000 = 100%) |
| `--max-procs` | `100` | Max concurrent processes |
| `--tool` | none | Tools to install: `node`, `rust-bin`, `winget` |
| `--network` | `none` | Network mode: `none`, `outbound`, `full` |
| `--volume` | none | Mount host path: `C:\src:C:\app` or `C:\src:C:\app:ro` |
| `--env` | none | Set env var: `KEY=VALUE` |
| `--workdir` | `C:\` | Working directory inside container |
| `--silo` | false | Enable server silo (requires admin) |

## Start

```powershell
psroot start psroot-a1b2c3d4
# Output: Started psroot-a1b2c3d4
```

Runs the container's configured command inside the sandbox.

## Exec

```powershell
psroot exec psroot-a1b2c3d4 "node -e \"console.log('hello')\""
# Output: PID: 12345
```

Runs an additional command inside an existing container.

## Stats

```powershell
psroot stats psroot-a1b2c3d4
```

Shows live resource usage:
```
Container: psroot-a1b2c3d4
Memory Usage:   42 MB
Peak Memory:    67 MB
CPU (kernel):   156 ms
CPU (user):     892 ms
Active Procs:   3
Total Procs:    7
```

## Stop

```powershell
psroot stop psroot-a1b2c3d4
# Output: Stopped psroot-a1b2c3d4
```

Terminates all processes in the container's job object.

## Remove

```powershell
psroot rm psroot-a1b2c3d4
# Output: Removed psroot-a1b2c3d4

# Force remove (stops first if running)
psroot rm -f psroot-a1b2c3d4
```

Deletes the container's rootfs and metadata.

## List

```powershell
psroot ls
```

```
ID                       STATUS     CREATED
psroot-a1b2c3d4          running    2026-04-19 10:30:00
psroot-e5f6g7h8          stopped    2026-04-19 09:15:00
```

Filter by status:
```powershell
psroot ls --status running
```

## Shell (All-in-One)

```powershell
psroot shell --tool node --network outbound
```

This is equivalent to:
1. `psroot create --tool node --network outbound --command cmd.exe`
2. Attach interactive stdin/stdout
3. Wait for `exit`
4. `psroot rm <id>` (auto-cleanup)

The container is automatically removed when you exit the shell.
