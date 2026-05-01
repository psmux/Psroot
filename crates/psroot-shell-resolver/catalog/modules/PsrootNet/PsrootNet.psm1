# PsrootNet — Networking tools for Psroot sandboxes
# Works inside AppContainer where ICMP (ping.exe) and nslookup.exe are blocked.
# Uses TCP/HTTP probes and .NET DNS APIs which ARE allowed through Winsock.

using namespace System.Net
using namespace System.Net.Sockets
using namespace System.Diagnostics

function Invoke-Ping {
    <#
    .SYNOPSIS
        TCP-based ping for Psroot sandboxes (ICMP is blocked in AppContainer).
    .DESCRIPTION
        Tests connectivity to a host by attempting a TCP connection to a specified
        port. Returns round-trip time in milliseconds. Works inside AppContainer
        where ping.exe and Test-Connection fail.
    .PARAMETER Target
        Hostname or IP address to ping.
    .PARAMETER Port
        TCP port to connect to. Default: 443 (HTTPS). Common alternatives: 80, 22.
    .PARAMETER Count
        Number of pings to send. Default: 4.
    .PARAMETER TimeoutMs
        Connection timeout in milliseconds. Default: 3000.
    .EXAMPLE
        ping google.com
    .EXAMPLE
        Invoke-Ping -Target 8.8.8.8 -Port 53 -Count 2
    #>
    [CmdletBinding()]
    [Alias('ping')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Target,

        [Parameter(Position = 1)]
        [int]$Port = 443,

        [int]$Count = 4,

        [int]$TimeoutMs = 3000
    )

    # Resolve hostname first
    $resolved = $null
    try {
        $addresses = [Dns]::GetHostAddresses($Target)
        $resolved = $addresses | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if (-not $resolved) { $resolved = $addresses[0] }
    }
    catch {
        Write-Error "Cannot resolve hostname '$Target': $_"
        return
    }

    Write-Host ""
    Write-Host "TCP-PING $Target ($resolved) port $Port" -ForegroundColor Cyan
    Write-Host "--- AppContainer mode: using TCP instead of ICMP ---" -ForegroundColor DarkGray
    Write-Host ""

    $successes = 0
    $failures = 0
    $times = [System.Collections.Generic.List[double]]::new()

    for ($i = 1; $i -le $Count; $i++) {
        $tcp = [TcpClient]::new()
        $sw = [Stopwatch]::StartNew()
        try {
            $task = $tcp.ConnectAsync($resolved, $Port)
            if ($task.Wait($TimeoutMs)) {
                $sw.Stop()
                $ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)
                $times.Add($ms)
                $successes++
                Write-Host "Connected to ${Target}:${Port} — time=${ms}ms" -ForegroundColor Green
            }
            else {
                $sw.Stop()
                $failures++
                Write-Host "Connection to ${Target}:${Port} — timed out (${TimeoutMs}ms)" -ForegroundColor Red
            }
        }
        catch {
            $sw.Stop()
            $failures++
            $msg = $_.Exception.InnerException.Message ?? $_.Exception.Message
            Write-Host "Connection to ${Target}:${Port} — failed: $msg" -ForegroundColor Red
        }
        finally {
            $tcp.Dispose()
        }

        if ($i -lt $Count) {
            Start-Sleep -Milliseconds 800
        }
    }

    Write-Host ""
    Write-Host "--- TCP-PING statistics for $Target ---" -ForegroundColor Cyan
    Write-Host "    $Count probes sent, $successes succeeded, $failures failed"

    if ($times.Count -gt 0) {
        $min = [math]::Round(($times | Measure-Object -Minimum).Minimum, 1)
        $max = [math]::Round(($times | Measure-Object -Maximum).Maximum, 1)
        $avg = [math]::Round(($times | Measure-Object -Average).Average, 1)
        Write-Host "    min/avg/max = ${min}/${avg}/${max} ms"
    }
    Write-Host ""
}


function Resolve-Dns {
    <#
    .SYNOPSIS
        DNS resolution for Psroot sandboxes (Resolve-DnsName and nslookup are blocked in AppContainer).
    .DESCRIPTION
        Resolves a hostname to IP addresses using .NET System.Net.Dns which works
        through Winsock inside AppContainer. Supports forward (A/AAAA) and reverse
        (PTR) lookups.
    .PARAMETER Name
        Hostname or IP address to resolve.
    .PARAMETER Type
        Record type to query: A, AAAA, PTR, or All. Default: All.
    .PARAMETER Server
        DNS-over-HTTPS server to use for extended lookups (optional).
        Default: uses system resolver via .NET.
    .EXAMPLE
        nslookup google.com
    .EXAMPLE
        Resolve-Dns -Name 8.8.8.8 -Type PTR
    .EXAMPLE
        dig github.com
    #>
    [CmdletBinding()]
    [Alias('nslookup', 'dig')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Position = 1)]
        [ValidateSet('A', 'AAAA', 'PTR', 'All')]
        [string]$Type = 'All',

        [string]$Server
    )

    Write-Host ""
    Write-Host "Resolving: $Name" -ForegroundColor Cyan
    Write-Host "--- AppContainer mode: using .NET DNS API ---" -ForegroundColor DarkGray
    Write-Host ""

    # Detect if input is an IP (reverse lookup)
    $isIP = [IPAddress]::TryParse($Name, [ref]$null)

    if ($isIP -and ($Type -eq 'PTR' -or $Type -eq 'All')) {
        # Reverse lookup
        try {
            $entry = [Dns]::GetHostEntry($Name)
            Write-Host "Reverse DNS:" -ForegroundColor Yellow
            Write-Host "  $Name -> $($entry.HostName)" -ForegroundColor Green

            if ($entry.Aliases.Count -gt 0) {
                Write-Host "  Aliases:" -ForegroundColor Yellow
                foreach ($alias in $entry.Aliases) {
                    Write-Host "    $alias"
                }
            }
        }
        catch {
            Write-Host "  Reverse lookup failed: $($_.Exception.Message)" -ForegroundColor Red
        }
        Write-Host ""
        return
    }

    # Forward lookup
    try {
        $entry = [Dns]::GetHostEntry($Name)

        # Show results
        $results = @()
        foreach ($addr in $entry.AddressList) {
            $family = if ($addr.AddressFamily -eq 'InterNetwork') { 'A' } else { 'AAAA' }

            if ($Type -eq 'All' -or $Type -eq $family) {
                $results += [PSCustomObject]@{
                    Name    = $Name
                    Type    = $family
                    Address = $addr.ToString()
                    TTL     = '(system-cached)'
                }
                Write-Host "  $family`t$($addr.ToString())" -ForegroundColor Green
            }
        }

        if ($entry.HostName -ne $Name) {
            Write-Host "  CNAME`t$($entry.HostName)" -ForegroundColor Green
        }

        if ($entry.Aliases.Count -gt 0) {
            Write-Host "  Aliases:" -ForegroundColor Yellow
            foreach ($alias in $entry.Aliases) {
                Write-Host "    $alias"
            }
        }

        if ($results.Count -eq 0) {
            Write-Host "  No records of type '$Type' found." -ForegroundColor Yellow
        }

        # Also try DNS-over-HTTPS for richer results if network is available
        if ($Server -or $Type -eq 'All') {
            try {
                $dohServer = if ($Server) { $Server } else { 'https://cloudflare-dns.com/dns-query' }
                $uri = "${dohServer}?name=${Name}&type=A"
                $resp = Invoke-RestMethod -Uri $uri -Headers @{ 'Accept' = 'application/dns-json' } -TimeoutSec 3 -ErrorAction Stop
                if ($resp.Answer) {
                    Write-Host ""
                    Write-Host "  DNS-over-HTTPS (Cloudflare):" -ForegroundColor Yellow
                    foreach ($ans in $resp.Answer) {
                        $rtype = switch ($ans.type) { 1 { 'A' } 5 { 'CNAME' } 28 { 'AAAA' } default { $ans.type } }
                        Write-Host "    ${rtype}`t$($ans.data)`tTTL=$($ans.TTL)" -ForegroundColor DarkGreen
                    }
                }
            }
            catch {
                # DoH is best-effort — system resolver already gave us the answer
            }
        }
    }
    catch {
        Write-Host "  DNS resolution failed: $($_.Exception.Message)" -ForegroundColor Red

        # Fall back to DNS-over-HTTPS
        Write-Host "  Trying DNS-over-HTTPS fallback..." -ForegroundColor Yellow
        try {
            $dohServer = if ($Server) { $Server } else { 'https://cloudflare-dns.com/dns-query' }
            $dohType = if ($Type -eq 'All' -or $Type -eq 'A') { 'A' } else { $Type }
            $uri = "${dohServer}?name=${Name}&type=${dohType}"
            $resp = Invoke-RestMethod -Uri $uri -Headers @{ 'Accept' = 'application/dns-json' } -TimeoutSec 5
            if ($resp.Answer) {
                foreach ($ans in $resp.Answer) {
                    $rtype = switch ($ans.type) { 1 { 'A' } 5 { 'CNAME' } 28 { 'AAAA' } default { $ans.type } }
                    Write-Host "    ${rtype}`t$($ans.data)`tTTL=$($ans.TTL)" -ForegroundColor Green
                }
            }
            else {
                Write-Host "    No results from DoH either." -ForegroundColor Red
            }
        }
        catch {
            Write-Host "    DoH fallback failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    Write-Host ""
}


function Test-Port {
    <#
    .SYNOPSIS
        Test if a TCP port is open on a remote host.
    .PARAMETER Target
        Hostname or IP address.
    .PARAMETER Port
        TCP port number to test.
    .PARAMETER TimeoutMs
        Timeout in milliseconds. Default: 3000.
    .EXAMPLE
        Test-Port google.com 443
    .EXAMPLE
        Test-Port 192.168.1.1 22
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Target,

        [Parameter(Mandatory, Position = 1)]
        [int]$Port,

        [int]$TimeoutMs = 3000
    )

    $tcp = [TcpClient]::new()
    try {
        $task = $tcp.ConnectAsync($Target, $Port)
        $connected = $task.Wait($TimeoutMs)
        [PSCustomObject]@{
            Target    = $Target
            Port      = $Port
            Open      = $connected
            LatencyMs = if ($connected) { 'OK' } else { 'timeout' }
        }
    }
    catch {
        [PSCustomObject]@{
            Target    = $Target
            Port      = $Port
            Open      = $false
            LatencyMs = 'error'
        }
    }
    finally {
        $tcp.Dispose()
    }
}

# Export
Export-ModuleMember -Function Invoke-Ping, Resolve-Dns, Test-Port -Alias ping, nslookup, dig
