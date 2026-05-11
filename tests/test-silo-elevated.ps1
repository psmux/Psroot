#!/usr/bin/env pwsh
# Quick elevated test of Server Silo isolation.
# Run: Start-Process pwsh -Verb RunAs -ArgumentList '-File','<repo>\tests\test-silo-elevated.ps1'

$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $RepoRoot
$psroot = Join-Path $RepoRoot 'target\release\psroot.exe'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Admin: $isAdmin" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'Red' })

if (-not $isAdmin) {
    Write-Host "ERROR: Must run elevated!" -ForegroundColor Red
    Read-Host "Press Enter"
    exit 1
}

Write-Host "`n--- psroot info ---" -ForegroundColor Yellow
& $psroot info

Write-Host "`n--- psroot setup ---" -ForegroundColor Yellow
& $psroot setup

Write-Host "`n--- Launching: psroot shell --shell cmd --isolate full ---" -ForegroundColor Yellow
Write-Host "Inside the silo, run: dir C:\ and dir P:\" -ForegroundColor Cyan
Write-Host "Then type 'exit' to leave." -ForegroundColor Cyan
Write-Host ""

$env:RUST_LOG = 'debug'
$logPath = 'C:\Users\gj\Documents\workspace\Psroot\silo-test.log'
# Capture stderr (tracing logs go to stderr) to the log file AND to the console.
# Pipe "dir C:\ & dir P:\ & exit" into cmd so it auto-terminates for headless tests.
if ($env:PSROOT_TEST_AUTOEXIT -eq '1') {
    "dir C:\ & echo --- & dir P:\ & exit" | & $psroot shell --shell cmd --isolate full 2>&1 | Tee-Object -FilePath $logPath
} else {
    & $psroot shell --shell cmd --isolate full 2>&1 | Tee-Object -FilePath $logPath
}

Write-Host "`nDone. Exit code: $LASTEXITCODE" -ForegroundColor Yellow
# Auto-exit so parent agent can read the log
if ($env:PSROOT_TEST_AUTOEXIT -ne '1') {
    Read-Host "Press Enter to close"
}
