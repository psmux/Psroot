# Resource Limits

Psroot uses Windows **Job Objects** to enforce hard resource limits on containers — the Windows equivalent of Linux cgroups.

## Memory

```powershell
psroot shell --memory 512M
psroot shell --memory 2G
```

Sets a hard memory ceiling for the entire container (all processes combined). If the container exceeds the limit, Windows terminates the process that triggered the violation.

**Default:** 1 GB

Suffixes: `M` (megabytes), `G` (gigabytes)

## CPU

```powershell
psroot shell --cpu 5000   # 50% of all cores
psroot shell --cpu 2500   # 25%
psroot shell --cpu 10000  # 100% (default, no throttle)
```

CPU rate is on a 1–10000 scale where 10000 = 100% of all CPU cores. The kernel scheduler enforces this — the container physically cannot use more.

**Default:** 10000 (no limit)

## Process Count

```powershell
psroot shell --max-procs 50
```

Maximum number of active processes in the container. Prevents fork bombs and runaway process spawning. When the limit is hit, new process creation fails.

**Default:** 100

## Combining Limits

```powershell
psroot shell --memory 256M --cpu 2500 --max-procs 20
```

All limits are enforced simultaneously and independently.

## Monitoring Usage

Check a running container's resource consumption:

```powershell
psroot stats <container-id>
```

```
Container: psroot-a1b2c3d4
Memory Usage:   42 MB
Peak Memory:    67 MB
CPU (kernel):   156 ms
CPU (user):     892 ms
Active Procs:   3
Total Procs:    7
```

| Metric | Description |
|---|---|
| Memory Usage | Current committed memory across all processes |
| Peak Memory | Highest memory usage since container start |
| CPU (kernel) | Time spent in kernel mode (syscalls, I/O) |
| CPU (user) | Time spent in user mode (your code) |
| Active Procs | Currently running processes |
| Total Procs | All processes ever created (including exited) |

## How It Works

Under the hood, Psroot creates a Windows Job Object and assigns the container's process to it. All child processes automatically inherit the job — there's no escape via `CreateProcess`.

```
Job Object (psroot-a1b2c3d4)
├── Memory limit: 512 MB
├── CPU rate: 5000 (50%)
├── Max processes: 50
├── cmd.exe (PID 1234)
│   ├── node.exe (PID 1235)
│   └── npm.exe (PID 1236)
│       └── node.exe (PID 1237)
```

Every descendant process is subject to the same limits. The job's memory limit is shared — if `cmd.exe` uses 200 MB and `node.exe` uses 300 MB, that's 500 MB total against a 512 MB limit.
