# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# CISA SCuBA + EIDSCA compliance crosswalk: scuba/eidsca tags on check definitions flow through
# New-AuditFinding into Get-ComplianceCrosswalk as Framework='SCUBA'/'EIDSCA' rows, filter correctly,
# and don't appear for untagged checks — with no regression to CIS/NIST. Run:
#   pwsh -File Tests/verify-scuba-crosswalk.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla
$dataDir = Join-Path $root 'Data/AuditChecks'

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

function Get-CheckDef($file, $id) {
    $d = Get-Content (Join-Path $dataDir $file) -Raw | ConvertFrom-Json -AsHashtable
    $c = $d.checks | Where-Object { $_.id -eq $id }
    if ($c) { $c['_categoryName'] = $d.categoryName }
    $c
}

$defs = @(
    (Get-CheckDef 'EntraAuthChecks.json' 'EIDAUTH-015')   # scuba MS.AAD.1.1v1
    (Get-CheckDef 'EidscaChecks.json'    'EIDSCA-AT01')   # eidsca AT01 (dedicated EIDSCA catalog), no scuba
    (Get-CheckDef 'EntraAuthChecks.json' 'EIDAUTH-001')   # scuba + cisM365 (regression anchor)
    (Get-CheckDef 'EntraFedChecks.json'  'EIDFED-001')    # untagged (no scuba/eidsca)
)
Add-R 'all check defs loaded' (@($defs | Where-Object { $_ }).Count -eq 4) ''

# Build findings via the real New-AuditFinding path (proves scuba/eidsca survive finding construction).
$findings = & $mod {
    param($defs)
    foreach ($d in $defs) { New-AuditFinding -CheckDefinition $d -Status 'FAIL' -CurrentValue 'test' }
} $defs

# Sanity: the finding's Compliance carries Scuba (the engine change in New-AuditFinding).
$f015 = $findings | Where-Object CheckId -eq 'EIDAUTH-015'
Add-R 'finding.Compliance.Scuba carried' (@($f015.Compliance.Scuba) -contains 'MS.AAD.1.1v1') ''

$cw = @(Get-ComplianceCrosswalk -Findings $findings)
$scuba = @($cw | Where-Object Framework -eq 'SCUBA')

Add-R 'SCUBA rows produced'              ($scuba.Count -gt 0) "n=$($scuba.Count)"
Add-R 'EIDAUTH-015 -> MS.AAD.1.1v1'      (@($scuba | Where-Object { $_.CheckId -eq 'EIDAUTH-015' -and $_.Requirement -match 'MS\.AAD\.1\.1v1' }).Count -eq 1) ''
Add-R 'SCUBA framework name set'         (@($scuba | Where-Object { $_.FrameworkName -match 'SCuBA' }).Count -gt 0) ''
Add-R 'untagged check has no SCUBA row'  (@($scuba | Where-Object CheckId -eq 'EIDFED-001').Count -eq 0) ''

# -Framework SCUBA filters to only SCUBA
$only = @(Get-ComplianceCrosswalk -Findings $findings -Framework SCUBA)
Add-R '-Framework SCUBA filters'         (($only.Count -gt 0) -and (@($only | Where-Object Framework -ne 'SCUBA').Count -eq 0)) "n=$($only.Count)"

# EIDSCA works via the dedicated EIDSCA catalog (EIDSCA-AT01 tagged AT01, no scuba)
$eid = @(Get-ComplianceCrosswalk -Findings $findings -Framework EIDSCA)
Add-R 'EIDSCA rows produced'             ($eid.Count -gt 0) "n=$($eid.Count)"
Add-R 'EIDSCA-AT01 -> AT01 (eidsca)'     (@($eid | Where-Object { $_.CheckId -eq 'EIDSCA-AT01' -and $_.Requirement -match 'AT01' }).Count -eq 1) ''
Add-R 'EIDSCA-AT01 has no SCUBA row'     (@($scuba | Where-Object CheckId -eq 'EIDSCA-AT01').Count -eq 0) ''

# No regression: CIS + NIST still produced from the same findings
$cis  = @(Get-ComplianceCrosswalk -Findings $findings -Framework CIS)
$nist = @(Get-ComplianceCrosswalk -Findings $findings -Framework 'NIST-800-53')
Add-R 'CIS still works (EIDAUTH-001 5.2.1)' (@($cis | Where-Object { $_.CheckId -eq 'EIDAUTH-001' -and $_.Requirement -match '5\.2\.1' }).Count -eq 1) ''
Add-R 'NIST still works'                     ($nist.Count -gt 0) "n=$($nist.Count)"

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($x in $results) {
    $mark = if ($x.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($x.Name)"; if ($x.Detail) { $line += "  ($($x.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
