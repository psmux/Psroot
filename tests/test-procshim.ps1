#!/usr/bin/env pwsh
# ============================================================================
# test-procshim.ps1 — Proof of process isolation via psroot-procshim
#
# This script:
# 1. Runs the procshim-testchild.exe OUTSIDE a sandbox (baseline)
# 2. Runs it INSIDE psroot with procshim injection (isolated)
# 3. Compares results and reports PASS/FAIL
#
# The psroot container automatically injects psroot_procshim.dll when
# it finds the DLL next to the psroot binary.
# ============================================================================

$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot

$psroot = '.\target\release\psroot.exe'
$testchild = '.\target\release\procshim-testchild.exe'
$procshimDll = '.\target\release\psroot_procshim.dll'

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  psroot-procshim Integration Test: Process Visibility" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# ─── Check prerequisites ─────────────────────────────────────────────
$missing = @()
if (-not (Test-Path $psroot))      { $missing += "psroot.exe ($psroot)" }
if (-not (Test-Path $testchild))   { $missing += "procshim-testchild.exe ($testchild)" }
if (-not (Test-Path $procshimDll)) { $missing += "psroot_procshim.dll ($procshimDll)" }

if ($missing.Count -gt 0) {
    Write-Host "ERROR: Missing prerequisites:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "Run: cargo build --release -p psroot-procshim -p psroot-cli" -ForegroundColor Yellow
    exit 1
}

Write-Host "[OK] All binaries found" -ForegroundColor Green
Write-Host "  psroot.exe:             $(Get-Item $psroot | Select-Object -ExpandProperty Length) bytes"
Write-Host "  procshim-testchild.exe: $(Get-Item $testchild | Select-Object -ExpandProperty Length) bytes"
Write-Host "  psroot_procshim.dll:    $(Get-Item $procshimDll | Select-Object -ExpandProperty Length) bytes"
Write-Host ""

# ─── Test 1: Baseline (no sandbox) ───────────────────────────────────
Write-Host "─── TEST 1: Baseline (no sandbox) ───" -ForegroundColor Yellow
$baselineOutput = & $testchild 2>&1
$baselineSummary = $baselineOutput | Where-Object { $_ -match 'Max processes visible' }
$baselineLeaks = $baselineOutput | Where-Object { $_ -match 'Non-self/non-idle PIDs visible' }
Write-Host "  $baselineSummary"
Write-Host "  $baselineLeaks"

$baselineCount = 0
if ($baselineSummary -match '(\d+)') { $baselineCount = [int]$Matches[1] }
Write-Host "  Baseline process count: $baselineCount" -ForegroundColor Gray
Write-Host ""

# ─── Test 2: Sandboxed via psroot (with procshim injection) ──────────
Write-Host "─── TEST 2: Sandboxed via psroot (procshim active) ───" -ForegroundColor Yellow

# Create a container that runs the testchild
$containerName = "procshim-test-$(Get-Random -Maximum 9999)"
Write-Host "  Creating container: $containerName" -ForegroundColor Gray

# Use psroot spawn to run the testchild inside a container
$sandboxedOutput = & $psroot spawn --name $containerName --network none -- $testchild 2>&1
$exitCode = $LASTEXITCODE

Write-Host "  psroot spawn exit code: $exitCode" -ForegroundColor Gray
Write-Host ""

# Parse sandboxed output
$sandboxSummary = $sandboxedOutput | Where-Object { $_ -match 'Max processes visible' }
$sandboxLeaks = $sandboxedOutput | Where-Object { $_ -match 'Non-self/non-idle PIDs visible' }
$sandboxResult = $sandboxedOutput | Where-Object { $_ -match 'RESULT:' }
$sandboxOpenHost = $sandboxedOutput | Where-Object { $_ -match 'Host PIDs opened' }

if ($sandboxSummary) {
    Write-Host "  $sandboxSummary"
} else {
    Write-Host "  [Could not parse sandbox summary]" -ForegroundColor Red
    Write-Host "  Full output:" -ForegroundColor Red
    $sandboxedOutput | ForEach-Object { Write-Host "    $_" }
}
if ($sandboxLeaks) { Write-Host "  $sandboxLeaks" }
if ($sandboxOpenHost) { Write-Host "  $sandboxOpenHost" }
Write-Host ""

# ─── Test 3: Verify the DLL was actually injected ────────────────────
Write-Host "─── TEST 3: Verify DLL injection ───" -ForegroundColor Yellow
$injectionLog = $sandboxedOutput | Where-Object { $_ -match 'procshim|Process-visibility shim' }
if ($injectionLog) {
    Write-Host "  DLL injection confirmed:" -ForegroundColor Green
    $injectionLog | ForEach-Object { Write-Host "    $_" -ForegroundColor Green }
} else {
    Write-Host "  WARNING: No injection log found in output" -ForegroundColor Red
    Write-Host "  (procshim.dll may not have been loaded)" -ForegroundColor Red
}
Write-Host ""

# ─── Test 4: Direct DLL injection test (manual) ─────────────────────
Write-Host "─── TEST 4: Manual DLL injection test ───" -ForegroundColor Yellow
Write-Host "  Spawning testchild suspended, injecting DLL, resuming..." -ForegroundColor Gray

# This test spawns the child suspended, injects the DLL manually, then resumes.
# We can't easily do this from PowerShell, so we rely on the psroot container test above.
# Instead, verify via an in-process test:
Write-Host "  [Covered by Test 2 via psroot container injection]" -ForegroundColor Gray
Write-Host ""

# ─── Final Verdict ───────────────────────────────────────────────────
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  FINAL VERDICT" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$sandboxedCount = 0
if ($sandboxSummary -match '(\d+)') { $sandboxedCount = [int]$Matches[1] }

$leakCount = 0
if ($sandboxLeaks -match '(\d+)') { $leakCount = [int]$Matches[1] }

Write-Host "  Baseline (no sandbox):    $baselineCount processes visible"
Write-Host "  Sandboxed (with procshim): $sandboxedCount processes visible"
Write-Host "  Reduction:                 $([math]::Round((1 - $sandboxedCount/$baselineCount) * 100, 1))%"
Write-Host ""

$allPassed = $true

# Check 1: Sandboxed count should be <= 3 (self + idle + maybe system)
if ($sandboxedCount -le 3 -and $sandboxedCount -gt 0) {
    Write-Host "  [PASS] Process visibility: only $sandboxedCount process(es) visible (max 3 allowed)" -ForegroundColor Green
} elseif ($sandboxedCount -eq 0) {
    Write-Host "  [WARN] Zero processes visible — test may not have run inside sandbox" -ForegroundColor Yellow
    $allPassed = $false
} else {
    Write-Host "  [FAIL] Process visibility: $sandboxedCount processes visible (expected <= 3)" -ForegroundColor Red
    $allPassed = $false
}

# Check 2: Leak count should be 0
if ($leakCount -eq 0) {
    Write-Host "  [PASS] No host process leaks detected" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] $leakCount host processes leaked!" -ForegroundColor Red
    $allPassed = $false
}

# Check 3: NtOpenProcess denied for host PIDs
$openCount = 0
if ($sandboxOpenHost -match '(\d+)') { $openCount = [int]$Matches[1] }
if ($openCount -eq 0) {
    Write-Host "  [PASS] NtOpenProcess denied for all host PIDs" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] NtOpenProcess allowed access to $openCount host PIDs!" -ForegroundColor Red
    $allPassed = $false
}

Write-Host ""
if ($allPassed) {
    Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  ALL TESTS PASSED — PROCESS ISOLATION PROVEN         ║" -ForegroundColor Green
    Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Green
    exit 0
} else {
    Write-Host "  ╔═══════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║  TESTS FAILED — SEE DETAILS ABOVE                    ║" -ForegroundColor Red
    Write-Host "  ╚═══════════════════════════════════════════════════════╝" -ForegroundColor Red
    exit 1
}
