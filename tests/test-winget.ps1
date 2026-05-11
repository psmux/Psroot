#!/usr/bin/env pwsh
# Test winget tool provisioning inside a psroot container.
$ErrorActionPreference = 'Continue'
$RepoRoot = Split-Path $PSScriptRoot -Parent
$psroot = Join-Path $RepoRoot 'target\release\psroot.exe'

$env:RUST_LOG = "warn"
& $psroot shell --tool winget --network outbound
