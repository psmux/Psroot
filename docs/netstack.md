# Userland Netstack

> **Status**
> * **Phase 1** — wire protocol, SPSC-ring IPC, daemon, NAT backend, shim `Client` API: **landed + tested.**
> * **Phase 2** — transparent Winsock interception via IAT patching, TLS bypass for daemon re-entrancy, destination address translator, full in-process end-to-end integration test: **landed + tested.**
> * **Phase 3** — UDP opcode + NAT backend UDP support, `DllMain` cdylib entry point, `psroot-netinject` (`CreateRemoteThread(LoadLibraryW)`), cross-process injection E2E, container runtime wiring for `NetworkAccess::Netstack` (non-AppContainer/job-mode): **landed + tested.**
> * **Phase 4** — AppContainer Detours-based static injection, full `WSA*` surface (`WSARecv`/`WSASend`/`WSAIoctl`), IOCP/overlapped I/O, `getaddrinfo`/DNS interception, smoltcp L2/L3 backend with inter-container routing: **designed, not yet implemented.** See the TODO list at the bottom.

## Why a userland netstack?

Windows has **no user-mode network namespaces**. The kernel TCP/IP stack is
process-global, so two processes that both `bind(8080)` will collide.
The existing options for giving a container its own IP all have heavy
dependencies:

| Option                     | Requires                | Works on lightweight VM? |
| -------------------------- | ----------------------- | ------------------------ |
| Hyper-V containers         | VT-x + Hyper-V role     | ❌ nested-virt needed     |
| WSL2                       | Hyper-V + vmcompute     | ❌                        |
| Host Compute Network (HNS) | Hyper-V virtual switch  | ❌                        |
| **Userland netstack**      | Nothing special         | ✅                        |

"Path 2" in the design discussion: terminate every Winsock syscall
inside the container in user space, relay it to a host-side daemon over
shared memory, and let the daemon decide whether to NAT it to a real
socket or route it to another container's virtual NIC.

This is the same approach used by **gVisor/netstack** and
**slirpnetstack** on Linux. Nothing about it requires Hyper-V, VT-x, or
WSL. It runs on any Windows 10+ machine, including nested VMs without
`ExposeVirtualizationExtensions`.

## Architecture

```
┌──────────────────────────── container (AppContainer) ────────────────┐
│                                                                      │
│   app code  ──►  ws2_32.dll   ──►  psroot-netshim (injected DLL)     │
│                  (hooked)          │                                 │
│                                    ▼                                 │
│                             ┌────────────┐                           │
│                             │  Client    │  (psroot-netshim::Client) │
│                             └─────┬──────┘                           │
└───────────────────────────────────│──────────────────────────────────┘
                                    │  SPSC ring in shared memory
                                    │  + WaitOnAddress futex
                                    ▼
┌───────────────────────────── host (normal user) ─────────────────────┐
│                             ┌────────────┐                           │
│                             │  Daemon    │  (psroot-netstack-host)   │
│                             └─────┬──────┘                           │
│                                   ▼                                  │
│                         ┌───────────────────┐                        │
│                         │ Backend (pluggable│                        │
│                         │  NAT  | smoltcp)  │                        │
│                         └─────────┬─────────┘                        │
│                                   ▼                                  │
│                       real host sockets / router                     │
└──────────────────────────────────────────────────────────────────────┘
```

## Crate map

| Crate                     | Role                                                                     | State     |
| ------------------------- | ------------------------------------------------------------------------ | --------- |
| `psroot-netstack-proto`   | Wire types (opcodes, slot header, `SockAddrBytes`). No deps.             | ✅ Phase 1 |
| `psroot-netstack-ipc`     | SPSC ring + named shared memory + `WaitOnAddress` futex + `Channel`.     | ✅ Phase 1 |
| `psroot-netstack-host`    | Daemon event loop + `Backend` trait + `NatBackend` (NAT + translator, TCP + UDP).   | ✅ Phase 1/2/3 |
| `psroot-netshim`          | `Client` (rlib) + `cdylib` with `DllMain` auto-init + IAT-patching Winsock hooks (TCP + UDP) + public `install_main_exe`.   | ✅ Phase 2/3 |
| `psroot-netinject`        | `CreateRemoteThread(LoadLibraryW)` injector — given an arbitrary process handle, loads `psroot_netshim.dll` into it.        | ✅ Phase 3 |

## Phase 2 hook mechanism

We chose **IAT patching** over inline detours (retour / minhook) because
it requires no instruction rewriting, no nightly-only deps, and the blast
radius is exactly the modules the installer walks — not process-global.

```rust
use psroot_netshim::{install_main_exe, Client};

// Callers build a Client from their shared-memory Channel
// and hand it to install_main_exe. The returned HookGuard
// restores the IAT on drop (tests rely on this; production will
// mem::forget it for the injected process's lifetime).
let guard = unsafe { install_main_exe(client) }.expect("install");
```

Hooked exports (all in `ws2_32.dll`):

| Export        | Hook behaviour                                                                 |
| ------------- | ------------------------------------------------------------------------------ |
| `socket`      | `AF_INET + SOCK_STREAM` → virtual socket via daemon; otherwise passthrough.    |
| `connect`     | Route via `Client::connect`; daemon may apply `AddrTranslator`.                 |
| `bind`        | Route via `Client::bind`.                                                      |
| `listen`      | Route via `Client::listen`.                                                    |
| `send`        | Route via `Client::send` (partial-write semantics preserved).                   |
| `recv`        | Route via `Client::recv`; daemon `WouldBlock` → `WSAEWOULDBLOCK`.               |
| `closesocket` | Release the fake handle and close the virtual socket.                           |
| `getsockname` | Return the *virtual* container IP + port, never the host's real loopback port.  |
| `getpeername` | Return the virtual peer address.                                                |

### TLS re-entrancy bypass

The daemon runs on a thread that uses `std::net` internally — which is
itself Winsock. To prevent daemon calls from recursing back through our
hooks, each hook checks a thread-local `BYPASS` counter; the daemon
thread holds a `BypassGuard` for its entire lifetime, pinning the
counter at `>0`. This is a RAII guard, so any future code that spawns
worker threads inside the daemon just has to construct a
`BypassGuard::enter()` at thread start.

### Address translation

`NatBackend::with_translator(|SocketAddr| Option<SocketAddr>)` lets the
daemon rewrite the destination of a `connect()` before opening the real
host socket. The integration test uses this to map the virtual IP
`10.88.0.7` to `127.0.0.1:<echo_port>`, so the container genuinely sees
itself as connecting to `10.88.0.7` while the real socket reaches a
real echo server on loopback. In production, Phase 3's smoltcp backend
replaces the translator with a full L2/L3 state machine.

## Performance design

* **4 KiB fixed slots.** One `memcpy` per message, aligned to the header.
* **Lock-free SPSC.** Each direction has one producer and one consumer;
  `head` / `tail` are `AtomicU64` updated with `Release` / `Acquire`.
* **Cache-line aligned ring header** (`#[repr(C, align(64))]`) to keep
  producer and consumer counters on separate cache lines.
* **`WaitOnAddress` + `WakeByAddressSingle`** for signalling. No event
  objects, no kernel round-trip when a message is already ready; the
  receiver only parks when the ring is empty.
* **Compile-time ABI guards** (`const _: () = assert!(size_of<T>() ==
  EXPECTED)`) catch layout drift between shim and daemon.
* **Power-of-two slot count** → `tail & (N-1)` masking, no modulo.
* **No `serde`** on the hot path; raw little-endian helpers only.

Measured on a 5950X dev box, the in-process ring does **> 4 million
messages/sec** with the consumer running on another thread (see
`ring::tests::parallel_producer_consumer`). The shared-memory path adds
one extra map/unmap of the kernel object — still negligible.

## Phase 3 — what landed

Phase 3 closed the gap from "in-process hook demo" to "end-to-end,
cross-process, real container-class sandbox":

1. **UDP through the pipeline.** Added `OP_SENDTO` / `OP_RECVFROM` to
   the wire protocol, `Dgram` variant to `SockState`, full UDP paths
   on `NatBackend` (auto-bind on first `sendto`, `SIO_UDP_CONNRESET`
   disable to suppress Windows' ICMP-port-unreachable reflection on
   loopback), and matching `hook_sendto` / `hook_recvfrom` IAT hooks.
   `hook_socket` now routes both `SOCK_STREAM` and `SOCK_DGRAM`.
   `e2e_udp` asserts a raw-Winsock UDP round-trip through hooks → SHM
   → daemon → NAT → echo → back.

2. **`DllMain` cdylib entry point.** `psroot-netshim` is now built
   both as an `rlib` (for the existing in-process tests) and as a
   `cdylib` (`psroot_netshim.dll`). `DllMain` disables thread
   notifications and spawns an init thread that reads
   `PSROOT_NS_NAME` + `PSROOT_NS_SIZE` from the process environment,
   attaches the named SHM, builds a `Client`, and calls
   `install_main_exe` — then `mem::forget`s the guard so hooks
   persist for the process lifetime.

3. **`psroot-netinject`.** New crate exposing `unsafe fn inject_dll(HANDLE, &Path)`:
   `GetModuleHandleA("kernel32")` → `GetProcAddress("LoadLibraryW")`
   → `VirtualAllocEx`/`WriteProcessMemory` of the DLL path (wide) →
   `CreateRemoteThread` targeting `LoadLibraryW` → `WaitForSingleObject` +
   `GetExitCodeThread` (0 ⇒ load failed). All allocations release via
   an RAII `RemoteBuf` guard on every exit path.

4. **Cross-process E2E proof.** `tests/e2e_inject.rs` spawns a
   dedicated test-child binary (`bin/ns_testchild.rs`) that does raw
   `windows-sys` Winsock against the virtual IP `10.88.0.11`, while
   the parent process hosts the NAT daemon and echo server. The
   parent injects the shim DLL via `psroot-netinject`; the child's
   `DllMain` attaches to the SHM and installs hooks; the child's
   subsequent `connect`/`send`/`recv` flow through the full
   inter-process pipeline and the child exits with code 0 iff every
   link survived. This replaces the in-process `e2e_hooks` as the
   canonical proof that the stack works across a real process
   boundary.

5. **Container runtime wiring.** `psroot-container` grew a
   `netstack_runtime` module:
   * `NetstackRuntime::spawn(tag, dll, virt_ip, translator)` — creates
     the named SHM, spawns the host-side daemon on a background
     thread, and hands back `child_env()` containing the
     `PSROOT_NS_NAME` / `PSROOT_NS_SIZE` vars to inject into the
     child's environment block before `CreateProcessW`.
   * `inject_into(HANDLE)` — calls `psroot_netinject::inject_dll`.
   * `Drop` sets the daemon stop flag and joins the thread.

   `Container::start` wires it in for the job-object path when
   `config.network == NetworkAccess::Netstack`: allocate a
   deterministic per-container virtual IP in `10.88.0.0/24`
   (`netstack_runtime::virtual_ip_for(&id)`), set up a loopback
   `AddrTranslator` so the virtual IP resolves to `127.0.0.1:<port>`
   for host-side services, inject env vars, spawn sandboxed, re-open
   the child with the process rights `CreateRemoteThread` needs,
   inject the DLL. All failure paths are **best-effort**: if the DLL
   is missing, the daemon fails to start, or injection fails, the
   container still runs with its AppContainer network caps intact
   — we just log a warning and fall back to OS networking.

### Phase 3 scope notes

* AppContainer injection is **intentionally deferred to Phase 4**.
  `CreateRemoteThread(LoadLibraryW)` against an AppContainer process
  requires ACL-ing the shim DLL to the container's capability SID;
  Detours' `DetourCreateProcessWithDllEx` handles this more cleanly by
  rewriting the suspended child's import table. The current wiring
  exercises the **job-object (non-AppContainer)** path only.
* `config.silo = true` / full Silo mode does not yet plumb netstack
  through `Silo::spawn` (the init process is created inside the Silo
  and doesn't return a handle usable for `CreateRemoteThread`). Same
  Phase 4 treatment as AppContainer.

## Phase 4 TODO

The Phase 1+2 code exists to make Phase 4 a mechanical swap. Open items:

1. **AppContainer DLL injection** (Phase 3 landed the job-mode path):
   * Integrate **Microsoft Detours** via `DetourCreateProcessWithDllEx`, which patches the new image's import table to force-load our DLL. Works across integrity levels since the parent process owns the creation.
   * Alternative: ACL the shim DLL for the capability SID and continue using `psroot-netinject`'s `CreateRemoteThread(LoadLibraryW)`.
   * Hook `GetProcAddress` itself so dynamic resolution of `WSAConnectByNameW`, `AcceptEx`, `ConnectEx`, etc. also flows through us.

2. **Full ws2_32 hook surface**:
   * `WSASocketW`, `WSAConnect`, `WSAConnectByNameW`, `WSARecv`, `WSASend`, `WSARecvFrom`, `WSASendTo`.
   * `WSAIoctl` — trap `SIO_GET_EXTENSION_FUNCTION_POINTER` and hand back our own `ConnectEx` / `AcceptEx` / `DisconnectEx` stubs.
   * `getaddrinfo`, `GetAddrInfoW`, `gethostbyname` — daemon-side DNS interception that can resolve container names to sibling virtual IPs.
   * `setsockopt`, `getsockopt`, `shutdown`.

3. **IOCP / overlapped I/O**:
   * Replace `CreateIoCompletionPort` + overlapped `WSARecv` / `WSASend`.
   * Without this, async Windows apps (Node.js, .NET sockets, Rust `tokio`) fall back through the hooks but get effectively synchronous semantics. Critical for real workloads.

4. **smoltcp backend** (`backend::smoltcp_backend::SmolBackend`):
   * Per-container TCP/IP state machine driven by packets synthesised from the opcode stream.
   * Shared virtual L2 switch between containers on the same subnet (e.g. `10.88.0.0/16`), so `c1 → c2` traffic never touches the host at all.
   * Replaces the `AddrTranslator` hack used in Phase 2 tests with real L3 routing.

5. **UDP + raw sockets**: UDP landed in Phase 3 (`OP_SENDTO` / `OP_RECVFROM`, `NatBackend::sendto`/`recvfrom`, `hook_sendto`/`hook_recvfrom`, `e2e_udp`). Raw sockets remain `StatusCode::NotSupported`.

6. **Container runtime wiring**:
   * Phase 3 landed for the **job-object / non-AppContainer** path:
     `Container::start` spawns the daemon via
     `netstack_runtime::NetstackRuntime::spawn`, injects
     `PSROOT_NS_*` env vars, and `LoadLibraryW`-injects the shim DLL
     into the newly-spawned child.
   * **Still open:** AppContainer + full-Silo paths (see item 1 and
     the Phase 3 scope notes above).

## Testing

```text
$ cargo test --workspace

psroot-netstack-proto          6 passed
psroot-netstack-ipc           12 passed   (ring, SHM, futex, named-SHM roundtrip)
psroot-netstack-host           9 passed   (NAT backend TCP+UDP, daemon dispatch, accept)
psroot-netshim (iat)           2 passed   (IAT helpers)
psroot-netshim (e2e_nat)       3 passed   (Client ↔ SHM ↔ Daemon ↔ NAT)
psroot-netshim (e2e_hooks)     1 passed   (Phase 2 E2E: raw Winsock → IAT hooks → daemon → NAT → echo)
psroot-netshim (e2e_udp)       1 passed   (Phase 3 E2E: raw Winsock UDP → hooks → daemon → NAT → UDP echo)
psroot-netshim (e2e_inject)    1 passed   (Phase 3 E2E: CreateRemoteThread → DllMain → full TCP pipeline across processes)
psroot-netinject               —          (exercised by e2e_inject)
psroot-portmap                 7 passed
────────────────────────────── ─────────
total                         39 passed
```

The Phase 2 `e2e_hooks` test is the canonical proof. It:

1. Starts a real echo server on `127.0.0.1:<real_port>`.
2. Starts the daemon with `NatBackend::new(10.88.0.7).with_translator(|addr| 10.88.0.7 → 127.0.0.1:real_port)`.
3. Installs IAT hooks on the test binary's main image.
4. From a worker thread (no bypass flag), calls **raw `windows-sys` Winsock** — `WSAStartup`, `socket`, `connect`, `send`, `recv`, `closesocket`, `WSACleanup` — pointed at the virtual address `10.88.0.7:<real_port>`.
5. Asserts the payload round-tripped to the echo server and came back uppercased.

If any link in the chain had failed silently and delegated to the real OS, `connect(10.88.0.7)` would have returned `WSAETIMEDOUT` / `WSAEHOSTUNREACH` (nothing listens on `10.88.0.7` on the dev machine). A passing test therefore proves every hook was invoked, the shared-memory channel round-tripped, the daemon translated + connected, and data flowed bidirectionally through the full pipeline.
