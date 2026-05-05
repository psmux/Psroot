# Platform Networking Comparison: Windows vs Linux vs macOS

`psroot` provides container networking on three host operating systems, but
the underlying mechanisms — and therefore the available isolation
primitives — differ substantially. This document spells out what works
where, so you do not assume per-container IPs on a platform that cannot
provide them.

## Linux: full per-container netns + bridge + DNAT

* **Per-container IP** ✅ — every container is placed in its own
  `CLONE_NEWNET` namespace and connected to host bridge `psroot0`
  (10.88.0.0/16) via a `veth` pair. `eth0` inside the container gets a
  stable IP like `10.88.0.2`.
* **Outbound NAT** ✅ — `iptables -t nat POSTROUTING -s 10.88.0.0/16 ! -o
  psroot0 -j MASQUERADE` plus IP forwarding allow any container to reach
  the internet.
* **Loopback DNAT** ✅ — `route_localnet=1` plus a SNAT rule
  (`POSTROUTING -s 127.0.0.0/8 -d 10.88.0.0/16 -j MASQUERADE`) means
  `curl http://127.0.0.1:<published>` on the host actually reaches the
  container.
* **External published ports** ✅ — `--publish 80:80` (default
  `--publish-addr 127.0.0.1`, can be `0.0.0.0`) installs DNAT rules in
  both PREROUTING and OUTPUT.
* **Demonstrated** end-to-end (ssh into container, apt install,
  Node/Flask/Django services, host-file invisibility) in
  [PRD/10-linux-end-to-end-proof.md](../PRD/10-linux-end-to-end-proof.md).

## Windows: AppContainer + WFP + winsock filtering

* **Per-container IP** ❌ — AppContainers share the host network stack;
  there is no native equivalent of a netns. Each container shares the
  host's IPs but is isolated by Windows Firewall (WFP) capability rules
  scoped to the AppContainer SID.
* **Outbound NAT** N/A — outbound traffic uses the host stack directly
  with WFP filtering applied per AppContainer SID.
* **Published ports** ✅ via the Windows-specific `psroot-portmap` and
  `psroot-netshim` shim DLL. Inbound rules are added to WFP for the
  AppContainer SID.
* **Custom networking shim** — see `crates/psroot-netshim/` for the IAT
  hook layer that intercepts winsock calls and routes them through the
  netstack daemon.

## macOS: same `psroot` binary, full Linux semantics via Lima VM (default)

**The user sees no difference between macOS, Linux, and Windows.** The
same `psroot` binary, same subcommands, same flags, same behaviour. On
macOS the binary transparently drives a [Lima](https://lima-vm.io)
Linux VM under the hood and proxies published ports back to the Mac via
`ssh -L`. There is no separate `psroot-mac` command for users to learn.

```bash
psroot run --rootfs /opt/psroot/rootfs --network outbound \
    --publish 12345:22 --name dev -- /usr/sbin/sshd -D -e
# nc 127.0.0.1 12345 → SSH-2.0-OpenSSH_…   (real container 10.88.0.2)
```

First invocation auto-creates the `psroot` Lima VM (Apple
Virtualization framework, arm64 Ubuntu 24.04, 1 CPU / 512 MiB / 10 GiB)
from an embedded template — no manual setup. Subsequent invocations
reuse it.

### Backend selection

* **Default** — Lima-backed Linux: full per-container IP / netns /
  cgroups / pivot_root parity with Linux.
* **`PSROOT_BACKEND=native`** — escape hatch to use the in-process
  sandbox-exec + chroot backend. Development-grade isolation, no
  per-container IP, no namespaces. Limitations documented below.

### Native macOS backend (`PSROOT_BACKEND=native`, sandbox-exec + chroot)

* **Per-container IP** ❌ — Darwin has no concept of network namespaces.
  Every container shares the host's network stack.
  - The kernel's network policy can be reduced via `sandbox-exec`'s
    `network*` selectors, but containers cannot be given their own
    independent address.
* **Outbound NAT** N/A — outbound traffic uses the host stack directly
  with the sandbox profile's `network-outbound` rules controlling allow
  patterns.
* **Published ports** ⚠️ via the **userspace TCP proxy** in
  `crates/psroot-unix/src/ports.rs::spawn_forwarder`. The `--publish
  H:C` flag spawns a parent-process accept loop on `H` that proxies each
  accepted connection to `127.0.0.1:C` inside the chroot. Sufficient
  for development workflows; not as fast or transparent as the Linux
  DNAT path.
* **PID/UTS/IPC namespaces** ❌ — Darwin lacks namespacing. Process
  isolation is enforced by:
  - sandbox profile (file/network/Mach restrictions)
  - chroot for filesystem
  - resource limits via `setrlimit`

### Why macOS cannot match Linux/Windows feature parity natively

macOS does not expose primitives equivalent to:

* `CLONE_NEWNET` / `CLONE_NEWPID` / `CLONE_NEWUTS`
* `pivot_root` (chroot is shallower; no mount-namespace replacement)
* cgroups v2 (replaced by Apple's private process limits, not
  programmatically pluggable)
* `iptables` / `nftables` (PF is the closest, but not per-process)

Sandbox-exec + chroot + userspace proxying gives a **development-grade**
isolation comparable to Linux user-namespace-only mode, but real
**per-container IPs and network namespaces require a Linux kernel**.

Per-container IPs on a Mac development host therefore require a Linux
kernel. **The default `psroot` macOS binary handles this for you**: it
drives Lima transparently and proxies published ports via `ssh -L`. The
Lima integration:

* Auto-creates a Lima VM (vz backend, native arm64, **1 CPU / 512 MiB
  RAM / 10 GiB disk** — measured floor) on first use from an embedded
  copy of `tools/mac/lima.psroot.yaml`.
* Re-execs `psroot <args>` inside the VM for every subcommand.
* For `run` / `create` / `start` with `--publish H:C`, looks up the
  container's IP from the in-VM state JSON and brings up
  `ssh -L H:CTR_IP:C lima-psroot` so the port is reachable on
  `127.0.0.1:H` of the Mac.
* Tears down tunnels and stops the in-VM container on exit (Drop guard).

Prerequisite (one-time): `brew install lima`.

Deprecated bash wrapper `tools/mac/psroot-mac` is now a thin shim that
just execs the `psroot` binary, kept for backward compat with old
scripts. End-to-end proof: see
[PRD/11-mac-lima-end-to-end-proof.md](../PRD/11-mac-lima-end-to-end-proof.md).

Other VM choices (OrbStack, Colima, Docker Desktop) work too with
manual setup, but Lima is what we test and ship for.

## Summary table

Users run the same `psroot` binary with the same flags on every OS. The
columns reflect what is implemented under the hood; on macOS the default
backend is Lima (use `PSROOT_BACKEND=native` to opt into the in-process
sandbox-exec backend).

| Capability                     | Linux | Windows | macOS (default = Lima) | macOS (`PSROOT_BACKEND=native`) |
|--------------------------------|:-----:|:-------:|:----------------------:|:-------------------------------:|
| Per-container IP / netns       |  ✅   |   ❌    |          ✅            |               ❌                |
| Bridge + veth                  |  ✅   |   ❌    |          ✅            |               ❌                |
| DNAT-published port            |  ✅   |   N/A   |     ✅ (ssh -L)        |          ⚠️ (proxy)              |
| Outbound NAT                   |  ✅   |   N/A   |          ✅            |              N/A                |
| PID namespace                  |  ✅   |   N/A   |          ✅            |               ❌                |
| UTS namespace (own hostname)   |  ✅   |   N/A   |          ✅            |               ❌                |
| Mount namespace + pivot_root   |  ✅   |   N/A   |          ✅            |          ⚠️ (chroot)             |
| cgroups v2 (mem/cpu/pids)      |  ✅   |   N/A   |          ✅            |          ⚠️ (rlimit)             |
| Filesystem isolation           |  ✅   |   ✅    |          ✅            |               ✅                 |
| Outbound network               |  ✅   |   ✅    |          ✅            |               ✅                 |
