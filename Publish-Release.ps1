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

$version = (Import-PowerShellDataFile (Join-Path $root 'source' 'Guerrilla.psd1')).ModuleVersion
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
$null = Test-ModuleManifest (Join-Path $root 'source' 'Guerrilla.psd1')
$rn = (Import-PowerShellDataFile (Join-Path $root 'source' 'Guerrilla.psd1')).PrivateData.PSData.ReleaseNotes
if ($rn.Length -ge 10000) { Fail "ReleaseNotes is $($rn.Length) chars (PSGallery limit 10000)." }
Ok "manifest valid; ReleaseNotes $($rn.Length) chars"

# 4) Stage a clean copy from HEAD (NOT the working tree). Exclude dev/test/CI + the analyzer
#    dot-file (PSResourceGet grabs the first .psd1 alphabetically — the leading-dot file has no
#    Author and dies with a misleading 'No author' error) + this release script itself.
$stage = Join-Path ([System.IO.Path]::GetTempPath()) "psg-release-$version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
$pkg = Join-Path $stage 'Guerrilla'
New-Item -ItemType Directory -Path $pkg -Force | Out-Null
# The distributable module IS the source/ subtree: manifest, public/, internal/,
# checks/, Data/, format file. Archive that subtree as the package root, so repo-only
# artifacts (Tests/, Samples/, Config/, docs/, .github/, action.yml) never ship.
# Write the archive to a file first — piping `git archive | tar` through the PowerShell
# pipeline corrupts the binary tar stream. -o avoids the pipe entirely.
$tar = Join-Path $stage 'head.tar'
& git -C $root archive --format=tar -o $tar HEAD:source
& tar -xf $tar -C $pkg
Remove-Item $tar -Force -ErrorAction SilentlyContinue
# The standard docs live at the repo root, not in source/; copy them into the package.
foreach ($doc in 'README.md', 'LICENSE', 'CHANGELOG.md') {
    $src = Join-Path $root $doc
    if (Test-Path $src) { Copy-Item $src (Join-Path $pkg $doc) -Force }
}
$null = Test-ModuleManifest (Join-Path $pkg 'Guerrilla.psd1')
Ok "staged clean package at $pkg"

# 5) Pack the .nupkg (runs under -DryRun too, so packing is validated without a key).
$ProgressPreference = 'SilentlyContinue'
# Pack the .nupkg with .NET's OPC packager (System.IO.Packaging, the same
# container format NuGet uses) instead of Publish-PSResource, whose pack/cleanup
# stalls indefinitely on macOS at "Removed N of M files … 0.0 MB/s". This path
# has no progress/cleanup stage to hang on. Then PUSH with `dotnet nuget push`,
# which is fast and returns a clear 403 on a bad key.
Add-Type -AssemblyName System.IO.Packaging
$man  = Import-PowerShellDataFile (Join-Path $root 'source' 'Guerrilla.psd1')
$ps   = $man.PrivateData.PSData
$tags = (@('PSModule', 'PSEdition_Core') + @($ps.Tags)) -join ' '
$xe   = { param($s) [System.Security.SecurityElement]::Escape([string]$s) }
$nuspec = @"
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Guerrilla</id>
    <version>$version</version>
    <authors>$(& $xe $man.Author)</authors>
    <owners>$(& $xe $man.CompanyName)</owners>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <licenseUrl>$(& $xe $ps.LicenseUri)</licenseUrl>
    <projectUrl>$(& $xe $ps.ProjectUri)</projectUrl>
    <description>$(& $xe $man.Description)</description>
    <releaseNotes>$(& $xe $ps.ReleaseNotes)</releaseNotes>
    <copyright>$(& $xe $man.Copyright)</copyright>
    <tags>$(& $xe $tags)</tags>
  </metadata>
</package>
"@
Set-Content -Path (Join-Path $pkg 'Guerrilla.nuspec') -Value $nuspec -Encoding utf8
$packDir = Join-Path $stage 'out'
New-Item -ItemType Directory -Path $packDir -Force | Out-Null
$nupkgPath = Join-Path $packDir "Guerrilla.$version.nupkg"
if (Test-Path $nupkgPath) { Remove-Item $nupkgPath -Force }
$opc = [System.IO.Packaging.Package]::Open($nupkgPath, [System.IO.FileMode]::Create)
try {
    foreach ($f in Get-ChildItem -Path $pkg -Recurse -File) {
        $rel = ($f.FullName.Substring($pkg.Length).TrimStart('/', '\')) -replace '\\', '/'
        $partPath = '/' + ((($rel -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/')
        $uri  = [System.IO.Packaging.PackUriHelper]::CreatePartUri([Uri]::new($partPath, [UriKind]::Relative))
        $part = $opc.CreatePart($uri, 'application/octet', [System.IO.Packaging.CompressionOption]::Normal)
        $dst = $part.GetStream(); $src = [System.IO.File]::OpenRead($f.FullName)
        try { $src.CopyTo($dst) } finally { $src.Dispose(); $dst.Dispose() }
        if ($rel -eq 'Guerrilla.nuspec') {
            $null = $opc.CreateRelationship($uri, [System.IO.Packaging.TargetMode]::Internal, 'http://schemas.microsoft.com/packaging/2010/07/manifest')
        }
    }
    $opc.PackageProperties.Creator     = $man.Author
    $opc.PackageProperties.Identifier  = 'Guerrilla'
    $opc.PackageProperties.Version     = $version
    $opc.PackageProperties.Keywords    = $tags
    $opc.PackageProperties.Description = $man.Description
} finally { $opc.Close() }
$nupkg = Get-Item $nupkgPath
if (-not $nupkg) { Fail 'packing produced no .nupkg.' }
Ok "packed $($nupkg.Name) ($([math]::Round($nupkg.Length/1MB,2)) MB)"

# 6) Dry run stops here: packed, gates green, nothing pushed. Otherwise get the key and push.
if ($DryRun) {
    Write-Host "DRY RUN — all gates green, packed $($nupkg.Name). WOULD push Guerrilla $version to $Repository." -ForegroundColor Cyan
    exit 0
}
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    # Prompt HERE, in your terminal. -AsSecureString keeps it off screen and out of
    # history/transcripts; it lives only in this process until the push, then is gone.
    if ([Environment]::UserInteractive -or $Host.UI.RawUI) {
        $sec = Read-Host 'PSGallery API key (hidden; paste here, not into chat)' -AsSecureString
        $ApiKey = [System.Net.NetworkCredential]::new('', $sec).Password
    }
    if ([string]::IsNullOrWhiteSpace($ApiKey)) { Fail 'no ApiKey. Set $env:PSGALLERY_KEY or paste at the prompt — never commit it or put it in chat.' }
}

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
        $notes = (Import-PowerShellDataFile (Join-Path $root 'source' 'Guerrilla.psd1')).PrivateData.PSData.ReleaseNotes
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
