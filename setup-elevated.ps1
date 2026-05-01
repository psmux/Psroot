# Run this script in an ELEVATED pwsh to apply psroot's one-time ACE grants.
# Right-click pwsh -> Run as Administrator, then:
#   cd C:\Users\gj\Documents\workspace\Psroot
#   .\setup-elevated.ps1

$ErrorActionPreference = 'Continue'  # don't bail on first error — log everything
$LogPath = Join-Path $env:TEMP 'psroot-setup.log'
"=== psroot setup-elevated.ps1 started $(Get-Date) ===" | Out-File $LogPath -Encoding utf8

function Log($msg) {
    Write-Host $msg
    $msg | Out-File $LogPath -Append -Encoding utf8
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
Log "IsAdmin: $IsAdmin"
if (-not $IsAdmin) {
    Log "ERROR: This script must run as Administrator."
    Log "Right-click pwsh and choose 'Run as Administrator', then re-run."
    exit 1
}

$Repo = $PSScriptRoot
$Psroot = Join-Path $Repo 'target\release\psroot.exe'
Log "Psroot binary: $Psroot"
if (-not (Test-Path $Psroot)) {
    Log "ERROR: psroot.exe not found at $Psroot. Build it first: cargo build --release -p psroot-cli"
    if ($Host.Name -eq 'ConsoleHost') { Read-Host "Press Enter to close" }
    

Log ""
Log "Running psroot setup..."
$out = & $Psroot setup 2>&1
$out | ForEach-Object { Log $_ }
Log "psroot exit code: $LASTEXITCODE"

Log ""
Log "Verifying via icacls..."
$cRoot = (& icacls C:\ 2>&1) -join "`n"
Log "icacls C:\ contains 'APPLICATION PACKAGES': $($cRoot -match 'APPLICATION PACKAGES')"
$cache = (& icacls C:\Users\gj\.psroot\cache\shells 2>&1) -join "`n"
Log "icacls cache contains 'APPLICATION PACKAGES': $($cache -match 'APPLICATION PACKAGES')"

Log ""
Log "Re-running dry-run check..."
& $Psroot setup --dry-run 2>&1 | ForEach-Object { Log $_ }

Log ""
Log "=== Done. Log saved to $LogPath ==="
