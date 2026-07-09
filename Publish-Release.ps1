#requires -version 7.0
<#
.SYNOPSIS
    The ONLY supported way to publish Guerrilla to PSGallery. Mechanically couples
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

$version = (Import-PowerShellDataFile (Join-Path $root 'Guerrilla.psd1')).ModuleVersion
Write-Host "== Publish-Release: Guerrilla $version ($([string](& git -C $root rev-parse --short HEAD))) ==" -ForegroundColor Cyan

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

# 2c) GATE C — Zero Trust schema (every check must declare pillar + weight).
Write-Host "-- gate C: Zero Trust check-definition schema --"
$ztSchema = Join-Path $root 'Tests' 'Unit' 'ZeroTrustSchema.Tests.ps1'
& pwsh -NoProfile -c "`$r = Invoke-Pester -Path '$ztSchema' -Output None -PassThru; exit `$r.FailedCount" | Out-Host
if ($LASTEXITCODE -ne 0) { Fail "Zero Trust schema RED — a check is missing pillar/weight. Release blocked." }
Ok 'Zero Trust schema green (all checks declare pillar + weight)'

# 3) Manifest validity + ReleaseNotes length.
$null = Test-ModuleManifest (Join-Path $root 'Guerrilla.psd1')
$rn = (Import-PowerShellDataFile (Join-Path $root 'Guerrilla.psd1')).PrivateData.PSData.ReleaseNotes
if ($rn.Length -ge 10000) { Fail "ReleaseNotes is $($rn.Length) chars (PSGallery limit 10000)." }
Ok "manifest valid; ReleaseNotes $($rn.Length) chars"

# 4) Stage a clean copy from HEAD (NOT the working tree). Exclude dev/test/CI + the analyzer
#    dot-file (PSResourceGet grabs the first .psd1 alphabetically — the leading-dot file has no
#    Author and dies with a misleading 'No author' error) + this release script itself.
$stage = Join-Path ([System.IO.Path]::GetTempPath()) "psg-release-$version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
$pkg = Join-Path $stage 'Guerrilla'
New-Item -ItemType Directory -Path $pkg -Force | Out-Null
# Write the archive to a file first — piping `git archive | tar` through the PowerShell
# pipeline corrupts the binary tar stream. -o avoids the pipe entirely.
$tar = Join-Path $stage 'head.tar'
& git -C $root archive --format=tar -o $tar HEAD
& tar -xf $tar -C $pkg
Remove-Item $tar -Force -ErrorAction SilentlyContinue
foreach ($ex in 'Tests', '.github', '.PSScriptAnalyzerSettings.psd1', 'Publish-Release.ps1', '.gitignore', '.gitattributes', 'Samples') {
    Remove-Item (Join-Path $pkg $ex) -Recurse -Force -ErrorAction SilentlyContinue
}
$null = Test-ModuleManifest (Join-Path $pkg 'Guerrilla.psd1')
Ok "staged clean package at $pkg"

# 5) Publish (or report, in dry run).
if ($DryRun) {
    Write-Host "DRY RUN — all gates green. WOULD publish Guerrilla $version to $Repository." -ForegroundColor Cyan
    exit 0
}
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    # No key in $env:PSGALLERY_KEY / -ApiKey. Prompt for it HERE, in your terminal.
    # -AsSecureString means it's hidden on screen and never written to shell history,
    # a file, or any transcript — it lives only in this process until publish, then is gone.
    if ([Environment]::UserInteractive -or $Host.UI.RawUI) {
        $sec = Read-Host 'PSGallery API key (hidden; paste here, not into chat)' -AsSecureString
        $ApiKey = [System.Net.NetworkCredential]::new('', $sec).Password
    }
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { Fail 'no ApiKey. Set $env:PSGALLERY_KEY or paste at the prompt — never commit it or put it in chat.' }
}
$ProgressPreference = 'SilentlyContinue'
# Publish in two reliable steps instead of Publish-PSResource's push, which stalls
# indefinitely on macOS ("Removed N of M files … 0.0 MB/s") when the API key's glob
# scope doesn't cover the package name (it never surfaces the 403). Step 1 PACKS the
# module into a local .nupkg (the part PSResourceGet does fine). Step 2 PUSHES that
# .nupkg with `dotnet nuget push`, which is fast and returns a clear 403 on a bad key.
$packDir = Join-Path $stage 'nupkg'
New-Item -ItemType Directory -Path $packDir -Force | Out-Null
Import-Module Microsoft.PowerShell.PSResourceGet -MinimumVersion 1.1.0 -Force
Register-PSResourceRepository -Name 'guerrilla-pack' -Uri $packDir -Trusted -Force -ErrorAction SilentlyContinue
try   { Publish-PSResource -Path $pkg -Repository 'guerrilla-pack' -SkipDependenciesCheck -ErrorAction Stop }
finally { Unregister-PSResourceRepository -Name 'guerrilla-pack' -ErrorAction SilentlyContinue }
$nupkg = Get-ChildItem $packDir -Filter '*.nupkg' | Select-Object -First 1
if (-not $nupkg) { Fail 'packing produced no .nupkg.' }
Ok "packed $($nupkg.Name)"

$dotnet = if (Get-Command dotnet -ErrorAction SilentlyContinue) { 'dotnet' }
          elseif (Test-Path "$HOME/.dotnet/dotnet") { "$HOME/.dotnet/dotnet" }
          else { $null }
if (-not $dotnet) { Fail 'dotnet SDK not found (needed to push). Install it, or add ~/.dotnet to PATH.' }

$pushUri = 'https://www.powershellgallery.com/api/v2/package'
& $dotnet nuget push $nupkg.FullName --api-key $ApiKey --source $pushUri --skip-duplicate
if ($LASTEXITCODE -ne 0) {
    Fail ("push failed (exit $LASTEXITCODE). A 403 means the API key's glob scope does not cover 'Guerrilla' — " +
          "mint a key at https://www.powershellgallery.com/account/apikeys with 'Push new packages and package versions' and glob '*'.")
}
Write-Host "PUBLISHED Guerrilla $version to $Repository." -ForegroundColor Green

# ── Tag + GitHub release so the repo and the Gallery don't diverge ──────────
# Historical gap flagged by the validation host: the Gallery advanced to 2.4x while
# git tags froze at v2.9.x. Every published version now gets a matching tag + release.
$tag = "v$version"
& git -C $root rev-parse -q --verify "refs/tags/$tag" *> $null
if ($LASTEXITCODE -eq 0) {
    Write-Host "tag $tag already exists — skipping tag/release." -ForegroundColor Yellow
} else {
    & git -C $root tag -a $tag -m "Guerrilla $version"
    & git -C $root push origin $tag
    Write-Host "tagged $tag and pushed" -ForegroundColor Green
    if (Get-Command gh -ErrorAction SilentlyContinue) {
        # This version's release-notes paragraph becomes the GitHub release body.
        $notes = (Import-PowerShellDataFile (Join-Path $root 'Guerrilla.psd1')).PrivateData.PSData.ReleaseNotes
        $body = ($notes -split '(?=v\d+\.\d+\.\d+:)' | Where-Object { $_ -like "v$version*" } | Select-Object -First 1)
        if ([string]::IsNullOrWhiteSpace($body)) { $body = "Guerrilla $version — see CHANGELOG.md." }
        Push-Location $root
        try { $body | & gh release create $tag --title "Guerrilla $version" --notes-file - ; Write-Host "created GitHub release $tag" -ForegroundColor Green }
        catch { Write-Host "gh release create failed ($_). Tag is pushed; create the release manually." -ForegroundColor Yellow }
        finally { Pop-Location }
    } else {
        Write-Host "gh CLI not found — tag pushed, but create the GitHub release manually." -ForegroundColor Yellow
    }
}
