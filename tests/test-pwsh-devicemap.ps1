#!/usr/bin/env pwsh
# Headless test of pwsh interactive launch under devicemap mode.
$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $RepoRoot
$psroot = Join-Path $RepoRoot 'target\release\psroot.exe'
$logPath = Join-Path $RepoRoot 'pwsh-devicemap.log'
Remove-Item $logPath -ErrorAction SilentlyContinue

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
"Admin: $isAdmin" | Tee-Object -FilePath $logPath -Append

$env:RUST_LOG = 'debug'

# Pipe a tiny pwsh script into the spawned shell so it produces visible output and exits.
$payload = "`$PSVersionTable.PSVersion.ToString(); 'CWD=' + (Get-Location).Path; Get-ChildItem C:\ | Select-Object -First 5 Name; 'EXIT_OK'; exit"
$payload | & $psroot shell --shell pwsh --isolate full 2>&1 | Tee-Object -FilePath $logPath -Append

"--- exit code: $LASTEXITCODE" | Tee-Object -FilePath $logPath -Append
