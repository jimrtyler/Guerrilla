# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Device & Endpoint Management).
#
# OUTCOME: 0 convertible placeholders. None of the device-category manual-verify
# placeholders (DEVICE-002/003/004/005/006/010) map to a Cloud Identity policy
# schema binding available to this category (drive_and_docs.drive_for_desktop,
# data_regions.data_at_rest_region, <service>.service_status). Those settings are
# mobile/endpoint MDM controls with no corresponding policy type, so they remain
# manual "verify in Admin Console" checks. The real device-inventory and Chrome-
# policy checks (DEVICE-001/007/008/009/011) were already implemented and are
# left untouched. No conversions were made, so the check count is unchanged.
#
# This test therefore: (1) imports the module, (2) asserts the assigned file parses,
# (3) asserts every Test-FortificationDEVICE0NN function still loads, and
# (4) sanity-checks that the device category still returns the same number of checks.
# Run: pwsh -File Tests/verify-gws1-device-checks.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

# (1) Module imported.
Add-R 'Guerrilla module imported' ($null -ne $mod) ''

# (2) Assigned file parses (PowerShell tokenizer/parser — no syntax errors).
$deviceFile = Join-Path $root 'Private/Audit/Invoke-DeviceManagementChecks.ps1'
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($deviceFile, [ref]$null, [ref]$parseErrors)
Add-R 'Invoke-DeviceManagementChecks.ps1 parses' (@($parseErrors).Count -eq 0) ("errors=$(@($parseErrors).Count)")

$out = & $mod {
    $r = @{}
    # (3) Every device check function still loads.
    $missing = @()
    foreach ($n in 1..11) {
        $fn = "Test-FortificationDEVICE{0:D3}" -f $n
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) { $missing += $fn }
    }
    $r.MissingFns = $missing

    # (4) Device category definition still resolves and still has 11 checks (count unchanged).
    $def = Get-AuditCategoryDefinitions -Category 'DeviceManagementChecks'
    $r.CheckCount = @($def.checks).Count
    $r
}

Add-R 'All 11 device check functions present' (@($out.MissingFns).Count -eq 0) ("missing=$(@($out.MissingFns) -join ',')")
Add-R 'Device check count unchanged (11)'    ($out.CheckCount -eq 11) ("got=$($out.CheckCount)")

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($r in $results) {
    $mark = if ($r.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($r.Name)"; if ($r.Detail) { $line += "  ($($r.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host '  NOTE: 0 convertible placeholders in this category (see header).'
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
