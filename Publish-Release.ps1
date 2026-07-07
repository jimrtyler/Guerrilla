#requires -version 7.0
<#
.SYNOPSIS
    The ONLY supported way to publish PSGuerrilla to PSGallery. Mechanically couples
    a release to green: runs the golden-fixture detection suite AND the collector
    query-contract tests, and refuses to publish if either is red (or the tree is dirty).

.DESCRIPTION
    Gate -> validate -> stage-clean -> publish. A release cannot leave this script while
    a test is failing, which closes the "human ignores the Actions tab" gap for the
    documented path. Publishing is rare, so it runs both the verdict-logic suite and the
    endpoint-drift (contract) suite — a release is exactly when you want drift checked.

    Do NOT publish with a bare `Publish-PSResource` — that bypasses the gate. This script
    is the documented path in the repo and the release runbook.

.PARAMETER ApiKey
    PSGallery key. Defaults to $env:PSGALLERY_KEY. Never hardcode; never commit.

.PARAMETER DryRun
    Run every gate + stage + manifest validation and report what WOULD publish, without
    publishing. Use this to prove the guard end-to-end without a key.

.EXAMPLE
    pwsh ./Publish-Release.ps1 -DryRun
.EXAMPLE
    $env:PSGALLERY_KEY = '<key>'; pwsh ./Publish-Release.ps1
#>
[CmdletBinding()]
param(
    [string]$ApiKey = $env:PSGALLERY_KEY,
    [string]$Repository = 'PSGallery',
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
function Fail($m) { Write-Host "ABORT: $m" -ForegroundColor Red; exit 1 }
function Ok($m)   { Write-Host "  [ok] $m" -ForegroundColor Green }

$version = (Import-PowerShellDataFile (Join-Path $root 'PSGuerrilla.psd1')).ModuleVersion
Write-Host "== Publish-Release: PSGuerrilla $version ($([string](& git -C $root rev-parse --short HEAD))) ==" -ForegroundColor Cyan

# 0) Clean, committed tree — a release ships a known SHA, not a working copy.
if (& git -C $root status --porcelain) { Fail 'working tree is dirty. Commit or stash before releasing.' }
Ok 'working tree clean'

# 1) GATE A — golden-fixture detection suite (verdict logic). Child process so its exit() can't kill us.
Write-Host "-- gate A: golden-fixture detection suite --"
& pwsh -NoProfile -File (Join-Path $root 'Tests' 'Invoke-FixtureTests.ps1') | Select-Object -Last 3 | Out-Host
if ($LASTEXITCODE -ne 0) { Fail "golden-fixture suite RED (exit $LASTEXITCODE) — release blocked." }
Ok 'golden-fixture suite green'

# 2) GATE B — collector query-contract tests (endpoint/param drift).
Write-Host "-- gate B: collector query-contract tests --"
$contract = Join-Path $root 'Tests' 'Unit' 'Private' 'Entra' 'CollectorQueryContract.Tests.ps1'
if (Test-Path $contract) {
    & pwsh -NoProfile -c "`$r = Invoke-Pester -Path '$contract' -Output None -PassThru; 'contract: '+`$r.PassedCount+' passed, '+`$r.FailedCount+' failed'; exit `$r.FailedCount" | Out-Host
    if ($LASTEXITCODE -ne 0) { Fail "collector contract tests RED (exit $LASTEXITCODE) — release blocked." }
    Ok 'collector contract tests green'
} else { Write-Host "  [warn] contract tests not found at $contract — skipping gate B" -ForegroundColor Yellow }

# 3) Manifest validity + ReleaseNotes length.
$null = Test-ModuleManifest (Join-Path $root 'PSGuerrilla.psd1')
$rn = (Import-PowerShellDataFile (Join-Path $root 'PSGuerrilla.psd1')).PrivateData.PSData.ReleaseNotes
if ($rn.Length -ge 10000) { Fail "ReleaseNotes is $($rn.Length) chars (PSGallery limit 10000)." }
Ok "manifest valid; ReleaseNotes $($rn.Length) chars"

# 4) Stage a clean copy from HEAD (NOT the working tree). Exclude dev/test/CI + the analyzer
#    dot-file (PSResourceGet grabs the first .psd1 alphabetically — the leading-dot file has no
#    Author and dies with a misleading 'No author' error) + this release script itself.
$stage = Join-Path ([System.IO.Path]::GetTempPath()) "psg-release-$version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
$pkg = Join-Path $stage 'PSGuerrilla'
New-Item -ItemType Directory -Path $pkg -Force | Out-Null
# Write the archive to a file first — piping `git archive | tar` through the PowerShell
# pipeline corrupts the binary tar stream. -o avoids the pipe entirely.
$tar = Join-Path $stage 'head.tar'
& git -C $root archive --format=tar -o $tar HEAD
& tar -xf $tar -C $pkg
Remove-Item $tar -Force -ErrorAction SilentlyContinue
foreach ($ex in 'Tests', '.github', '.PSScriptAnalyzerSettings.psd1', 'Publish-Release.ps1', '.gitignore', '.gitattributes') {
    Remove-Item (Join-Path $pkg $ex) -Recurse -Force -ErrorAction SilentlyContinue
}
$null = Test-ModuleManifest (Join-Path $pkg 'PSGuerrilla.psd1')
Ok "staged clean package at $pkg"

# 5) Publish (or report, in dry run).
if ($DryRun) {
    Write-Host "DRY RUN — all gates green. WOULD publish PSGuerrilla $version to $Repository." -ForegroundColor Cyan
    exit 0
}
if ([string]::IsNullOrWhiteSpace($ApiKey)) { Fail 'no ApiKey. Pass -ApiKey or set $env:PSGALLERY_KEY (never commit it).' }
Import-Module Microsoft.PowerShell.PSResourceGet -MinimumVersion 1.1.0 -Force
Publish-PSResource -Path $pkg -Repository $Repository -ApiKey $ApiKey -ErrorAction Stop
Write-Host "PUBLISHED PSGuerrilla $version to $Repository." -ForegroundColor Green
