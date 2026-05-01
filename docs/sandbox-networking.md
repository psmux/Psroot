# Networking Inside Sandboxes

AppContainer sandboxes block many traditional networking tools at the kernel
level. Psroot ships a built-in **PsrootNet** PowerShell module that provides
working replacements for `ping`, `nslookup`/`dig`, and port scanning.

> **Prerequisite:** All networking features require `--network outbound` or
> `--network full`. Without a network flag, all connectivity is blocked.

## Quick Reference

| You type | What happens | Works in AppContainer? |
| -------- | ------------ | ---------------------- |
| `ping google.com` | TCP-based ping (port 443) | ✅ Yes |
| `ping 8.8.8.8 -Port 53` | TCP ping on custom port | ✅ Yes |
| `nslookup github.com` | DNS resolution via .NET | ✅ Yes |
| `dig cloudflare.com` | Same as nslookup (alias) | ✅ Yes |
| `nslookup 8.8.8.8 -Type PTR` | Reverse DNS lookup | ✅ Yes |
| `Test-Port host 443` | Check if a port is open | ✅ Yes |
| `C:\Windows\System32\ping.exe` | Native ICMP ping | ❌ Blocked |
| `Test-Connection` | PowerShell ICMP ping | ❌ Blocked |
| `C:\Windows\System32\nslookup.exe` | Native DNS tool | ❌ Blocked |
| `Resolve-DnsName` | DnsClient CIM module | ❌ Not available |

## The PsrootNet Module

PsrootNet is automatically staged into every pwsh container. It provides
three commands with familiar aliases:

### `ping` (Invoke-Ping)

TCP-based connectivity test. Since AppContainer blocks ICMP (raw sockets),
this uses TCP connections to test reachability.

```powershell
PS C:\> ping google.com

TCP-PING google.com (142.250.67.46) port 443
--- AppContainer mode: using TCP instead of ICMP ---

Connected to google.com:443 — time=24.5ms
Connected to google.com:443 — time=8.9ms
Connected to google.com:443 — time=7.9ms
Connected to google.com:443 — time=9.2ms

--- TCP-PING statistics for google.com ---
    4 probes sent, 4 succeeded, 0 failed
    min/avg/max = 7.9/12.6/24.5 ms
```

#### Parameters

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-Target` | (required) | Hostname or IP address |
| `-Port` | `443` | TCP port to probe |
| `-Count` | `4` | Number of probes |
| `-TimeoutMs` | `3000` | Connection timeout (ms) |

#### Examples

```powershell
# Ping a DNS server on port 53
ping 8.8.8.8 -Port 53 -Count 2

# Ping an SSH server
ping myserver.com -Port 22

# Quick single-probe check
ping 10.0.0.1 -Count 1 -TimeoutMs 1000
```

### `nslookup` / `dig` (Resolve-Dns)

DNS resolution using .NET `System.Net.Dns` (which works through Winsock
inside AppContainer) with optional DNS-over-HTTPS enrichment via Cloudflare.

```powershell
PS C:\> nslookup github.com

Resolving: github.com
--- AppContainer mode: using .NET DNS API ---

  A     20.207.73.82

  DNS-over-HTTPS (Cloudflare):
    A   20.207.73.82    TTL=37
```

#### Reverse Lookups

```powershell
PS C:\> nslookup 8.8.8.8 -Type PTR

Resolving: 8.8.8.8
--- AppContainer mode: using .NET DNS API ---

Reverse DNS:
  8.8.8.8 -> dns.google
```

#### Multiple Records

```powershell
PS C:\> dig cloudflare.com

Resolving: cloudflare.com
--- AppContainer mode: using .NET DNS API ---

  A     104.16.133.229
  A     104.16.132.229

  DNS-over-HTTPS (Cloudflare):
    A   104.16.133.229  TTL=243
    A   104.16.132.229  TTL=243
```

#### Parameters

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-Name` | (required) | Hostname or IP to resolve |
| `-Type` | `All` | Record type: `A`, `AAAA`, `PTR`, or `All` |
| `-Server` | system + Cloudflare DoH | Custom DNS-over-HTTPS endpoint |

### `Test-Port`

Check if a TCP port is open on a remote host.

```powershell
PS C:\> Test-Port google.com 80

Target     Port Open LatencyMs
------     ---- ---- ---------
google.com   80 True OK

PS C:\> Test-Port 192.168.1.1 22

Target        Port Open  LatencyMs
------        ---- ----  ---------
192.168.1.1     22 False timeout
```

## Finding Your IP Address

The container shares the host's network stack — it has the same IP addresses.

### Local / Private IPs

```powershell
# List all IPv4 addresses
[System.Net.Dns]::GetHostAddresses(
    [System.Net.Dns]::GetHostName()
) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
    ForEach-Object { $_.IPAddressToString }
```

```
192.168.77.126
10.8.0.12
```

### Public IP

```powershell
(Invoke-RestMethod -Uri "https://api.ipify.org?format=json").ip
```

```
124.123.68.230
```

### All Addresses (IPv4 + IPv6)

```powershell
[System.Net.Dns]::GetHostAddresses(
    [System.Net.Dns]::GetHostName()
) | ForEach-Object {
    "$($_.AddressFamily): $($_.IPAddressToString)"
}
```

```
InterNetworkV6: fe80::a3c8:a90c:de4f:278c%7
InterNetworkV6: fe80::b720:3188:3f32:c88%4
InterNetwork: 192.168.77.126
InterNetwork: 10.8.0.12
```

> **Note:** `ipconfig.exe` and `Get-NetIPAddress` are not available inside
> the sandbox. Use the .NET APIs shown above.

## SSH from Inside the Sandbox

The Windows OpenSSH client (`ssh.exe`) is available inside the sandbox at
its standard System32 location. Combined with `--network outbound`, you can
SSH into remote servers from within a container.

### Verify SSH is Available

```powershell
Test-Path C:\Windows\System32\OpenSSH\ssh.exe
# True
```

### Test SSH Connectivity

```powershell
# Check if SSH port is open
Test-Port myserver.com 22

# Grab the SSH banner (confirms protocol-level connectivity)
$tcp = [System.Net.Sockets.TcpClient]::new()
$tcp.Connect("github.com", 22)
$reader = [System.IO.StreamReader]::new($tcp.GetStream())
$reader.ReadLine()
$tcp.Close()
# Output: SSH-2.0-babeld-...
```

### Connect via SSH

```powershell
# Interactive SSH session
C:\Windows\System32\OpenSSH\ssh.exe user@myserver.com

# With a specific key (key must be accessible from the sandbox)
C:\Windows\System32\OpenSSH\ssh.exe -i C:\path\to\key user@myserver.com

# Non-interactive command execution
C:\Windows\System32\OpenSSH\ssh.exe user@myserver.com "uname -a"
```

### SSH Key Considerations

Since the sandbox runs under an AppContainer token, it can access files on
the host filesystem that have the `ALL APPLICATION PACKAGES` ACE. By default:

- **System32 files** (including `ssh.exe`) — accessible
- **Your user profile** (`~/.ssh/`) — may be restricted depending on ACLs

To use SSH keys inside the sandbox, either:

1. **Copy the key into the rootfs** before launching:
   ```powershell
   # From outside the sandbox
   psroot run --shell pwsh --network outbound -- `
     C:\Windows\System32\OpenSSH\ssh.exe -i C:\Users\you\.ssh\id_ed25519 user@host
   ```

2. **Use `--network full`** with ssh-agent forwarding (if the host's ssh-agent
   is running and the key is loaded).

3. **Pass the key via environment** for scripts that generate ephemeral keys.

## HTTP Requests

Standard PowerShell HTTP cmdlets work inside the sandbox:

```powershell
# GET request
Invoke-RestMethod -Uri "https://api.github.com/zen"

# POST request
Invoke-RestMethod -Uri "https://httpbin.org/post" -Method POST -Body '{"key":"value"}'

# Download a file
Invoke-WebRequest -Uri "https://example.com/file.zip" -OutFile "$env:TEMP\file.zip"
```

## TCP Connections

Raw TCP connections work through .NET Sockets:

```powershell
# Connect to a TCP service
$tcp = [System.Net.Sockets.TcpClient]::new()
$tcp.Connect("google.com", 443)
"Connected: $($tcp.Connected)"
$tcp.Close()
```

## Listening on Ports

Requires `--network full`:

```powershell
# Start a TCP listener
$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Loopback, 9999
)
$listener.Start()
"Listening on 127.0.0.1:9999"
$listener.Stop()
```

With `--network outbound`, listening will fail (no `internetClientServer`
capability).

## What Doesn't Work (and Why)

| Tool | Error | Reason |
| ---- | ----- | ------ |
| `ping.exe` | "Unable to contact IP driver" | ICMP requires raw sockets; AppContainer blocks raw socket access |
| `Test-Connection` | "Ping request failed" | Uses ICMP internally (same issue) |
| `nslookup.exe` | "DNS request timed out" | Bypasses Winsock, talks directly to DNS driver (blocked) |
| `Resolve-DnsName` | "Not recognized" | DnsClient CIM module not staged into sandbox |
| `ipconfig.exe` | No useful output | Reads adapter info via WMI (restricted in AppContainer) |
| `tracert.exe` | Fails | Uses ICMP TTL manipulation (raw sockets blocked) |
| `netstat.exe` | Access denied | Reads TCP table from kernel (restricted) |

All of these are fundamental Windows/AppContainer restrictions, not psroot
limitations. The PsrootNet module provides working alternatives for the most
important ones (ping and DNS).

## Network Architecture

```
┌─────────────────────────────────┐
│  Psroot Container (AppContainer)│
│  ┌───────────────────────────┐  │
│  │  pwsh.exe                 │  │
│  │  ├─ Invoke-WebRequest ────┼──┼──► Winsock ──► Internet  ✅
│  │  ├─ TcpClient.Connect ───┼──┼──► Winsock ──► Internet  ✅
│  │  ├─ [Dns]::GetHostAddrs ─┼──┼──► Winsock ──► DNS       ✅
│  │  ├─ ssh.exe ──────────────┼──┼──► Winsock ──► SSH       ✅
│  │  ├─ ping.exe ─────────────┼──┼──► Raw ICMP ──► BLOCKED  ❌
│  │  └─ nslookup.exe ────────┼──┼──► DNS Driver ► BLOCKED  ❌
│  └───────────────────────────┘  │
│  Capabilities: internetClient   │
└─────────────────────────────────┘
```

The key insight: anything that goes through **Winsock** (the standard Windows
socket API) works. Tools that bypass Winsock and talk directly to kernel
drivers (ICMP, raw DNS) are blocked by AppContainer's security boundary.

## Next Steps

- [Interactive Shells](./interactive-shells.md) — launching shells, shell selection
- [Network & Tools](./network-and-tools.md) — network modes, port publishing, tool provisioning
- [Isolation Guide](./isolation.md) — what the sandbox blocks and why
