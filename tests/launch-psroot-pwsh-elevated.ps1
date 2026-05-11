#!/usr/bin/env pwsh
# launch-psroot-shell-elevated.ps1
#
#   Start-Process pwsh -Verb RunAs -ArgumentList '-NoExit','-File','<repo>\tests\launch-psroot-pwsh-elevated.ps1'
#
# Opens an elevated console, runs `psroot shell` with cmd.exe as the
# entry shell (proven-working under AppContainer), and from that prompt
# you can attempt to launch pwsh.exe with its full host path.
#
# Why cmd.exe and not pwsh directly?
#   AppContainer + restricted token + low integrity gives the child a
#   sandboxed PATH that contains only <rootfs>\Windows\System32 (which
#   is bind-linked to the host's System32 mirror — that's where cmd.exe
#   lives). pwsh.exe lives in C:\Program Files\PowerShell\7 which the
#   AppContainer SID doesn't have read+execute on, AND pwsh requires
#   the .NET 8 runtime that ships beside it. Both require additional
#   grant_appcontainer_access work that's out of scope for the Phase-3
#   netstack milestone — see docs/netstack.md.

$ErrorActionPreference = 'Continue'
$Host.UI.RawUI.WindowTitle = 'PSROOT (elevated) -- interactive shell inside AppContainer'
$RepoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $RepoRoot

$logPath = Join-Path $RepoRoot 'launch-psroot-pwsh.log'
# Write a heartbeat BEFORE Start-Transcript in case the transcript itself fails.
"[heartbeat $(Get-Date -Format o)] launcher entered, PID=$PID" | Out-File -FilePath $logPath -Encoding utf8 -Force
Start-Transcript -Path $logPath -Append | Out-Null

$psroot = Join-Path $RepoRoot 'target\release\psroot.exe'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
$adminColor = if ($isAdmin) { 'Green' } else { 'Red' }

Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '  PSROOT  --  interactive shell inside AppContainer' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host ("Host user      : " + $id.Name)
Write-Host ("Host elevated  : $isAdmin") -ForegroundColor $adminColor
Write-Host ("psroot binary  : $psroot")
Write-Host ("log file       : $logPath")
Write-Host ''

if (-not $isAdmin) {
    Write-Host 'ERROR: run elevated.' -ForegroundColor Red
    Stop-Transcript | Out-Null
    Read-Host 'Press Enter to close'
    exit 1
}
if (-not (Test-Path $psroot)) {
    Write-Host "ERROR: psroot binary not found at $psroot" -ForegroundColor Red
    Stop-Transcript | Out-Null
    Read-Host 'Press Enter to close'
    exit 1
}

Write-Host '-- psroot info --' -ForegroundColor Yellow
& $psroot info
Write-Host ''

# One-time machine setup (idempotent). Grants ALL APPLICATION PACKAGES
# the minimum ACEs on C:\ root + cache root that AppContainer needs so
# DriveInfo.IsReady=true and pwsh can register a C: PSDrive.
Write-Host '-- psroot setup (one-time, idempotent) --' -ForegroundColor Yellow
& $psroot setup
$setupRc = $LASTEXITCODE
if ($setupRc -ne 0) {
    Write-Host "WARNING: psroot setup exited $setupRc; continuing anyway." -ForegroundColor Red
}
Write-Host ''

Write-Host 'Launching:  psroot shell --shell pwsh --network outbound --isolate full' -ForegroundColor Yellow
Write-Host '(use --shell cmd or --shell powershell for other shells)' -ForegroundColor DarkYellow
Write-Host '(--isolate full = Server Silo: Docker-like virtual filesystem)' -ForegroundColor DarkYellow
Write-Host ''
Write-Host 'Inside the sandbox, useful demo commands:' -ForegroundColor Yellow
Write-Host '   whoami                           (host principal — silo does not create new user)'
Write-Host '   dir C:\                          (shows ONLY rootfs contents — not host filesystem)'
Write-Host '   dir P:\                          (shell cache drive — staged binaries live here)'
Write-Host '   $env:PATH                        (sandboxed PATH, points to C: and P: inside silo)'
Write-Host '   $env:USERNAME                    (USERNAME=ContainerUser)'
Write-Host '   exit                             (leave the sandbox, silo is destroyed)'
Write-Host ''

& $psroot shell --shell pwsh --network outbound --isolate full
$rc = $LASTEXITCODE

Write-Host ''
Write-Host ("psroot shell exit code: $rc") -ForegroundColor Yellow
Write-Host '-- containers after exit --' -ForegroundColor Yellow
& $psroot ls
Write-Host ''
Stop-Transcript | Out-Null
Write-Host 'Press Enter to close this window.' -ForegroundColor Yellow
Read-Host | Out-Null
