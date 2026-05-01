# Launches a psmux session with one window per psroot interactive shell.
# Attach with:  psmux attach -t psroot-shells
# Switch windows: Ctrl-B then 0/1/2/3 (or n/p)
# Detach:       Ctrl-B then d

$ErrorActionPreference = 'Stop'

$Repo   = $PSScriptRoot
$Psroot = Join-Path $Repo 'target\release\psroot.exe'
if (-not (Test-Path $Psroot)) {
    throw "psroot.exe not found at $Psroot. Run: cargo build --release -p psroot-cli"
}

$Session = 'psroot-shells'

# 1) Pre-flight: make sure psroot setup has been run. If not, request elevation.
$check = & $Psroot setup --dry-run 2>&1 | Out-String
if ($check -match 'MISSING') {
    Write-Host "psroot AppContainer prerequisites are missing. Requesting admin elevation..." -ForegroundColor Yellow
    Write-Host $check
    $p = Start-Process -FilePath $Psroot -ArgumentList 'setup' -Verb RunAs -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        throw "psroot setup failed (exit $($p.ExitCode)). Re-run this script after fixing."
    }
    Write-Host "Setup complete." -ForegroundColor Green
}

# Kill any prior session of the same name so this script is idempotent.
& psmux has-session -t $Session 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Killing existing psmux session '$Session'..." -ForegroundColor Yellow
    & psmux kill-session -t $Session | Out-Null
}

Write-Host "Creating psmux session '$Session'..." -ForegroundColor Cyan

# Window 0: pwsh 7 inside psroot — the main attraction (full silo isolation).
& psmux new-session -d -s $Session -n 'pwsh' -- $Psroot shell --shell pwsh --network outbound --isolate full

# Window 1: cmd inside psroot (full silo isolation).
& psmux new-window -t $Session -n 'cmd' -- $Psroot shell --shell cmd --network outbound --isolate full

# Window 2: Windows PowerShell 5.1 inside psroot (full silo isolation).
& psmux new-window -t $Session -n 'powershell' -- $Psroot shell --shell powershell --network outbound --isolate full

# Window 3: host shell for inspection / cleanup commands.
& psmux new-window -t $Session -n 'host' -c $Repo -- pwsh -NoLogo -NoExit

Write-Host ""
Write-Host "Session '$Session' is ready. Windows:" -ForegroundColor Green
Write-Host "  0: pwsh       - psroot shell --shell pwsh  (INTERACTIVE)"
Write-Host "  1: cmd        - psroot shell --shell cmd"
Write-Host "  2: powershell - psroot shell --shell powershell"
Write-Host "  3: host       - regular host pwsh in $Repo"
Write-Host ""
Write-Host "Attach with:  psmux attach -t $Session" -ForegroundColor Cyan
Write-Host "Inside:       Ctrl-B then 0/1/2/3 to switch, Ctrl-B then d to detach."
Write-Host ""
& psmux ls
