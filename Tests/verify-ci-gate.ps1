# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Get-GuerrillaCIGate — the severity-threshold gate behind the GitHub Action / CI templates. FAIL gates
# (plus WARN with -WarningsAsFailures); SKIP/"Not Assessed" never gates. Run: pwsh -File Tests/verify-ci-gate.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }
function F($status, $sev) { [PSCustomObject]@{ CheckId = "$sev-$status"; Severity = $sev; Status = $status } }

$mix = @(
    F 'FAIL' 'Critical'
    F 'FAIL' 'High'
    F 'FAIL' 'Medium'
    F 'FAIL' 'Low'
    F 'WARN' 'High'
    F 'PASS' 'Critical'
    F 'SKIP' 'Critical'
)

$high  = Get-GuerrillaCIGate -Findings $mix -FailOn High
$crit  = Get-GuerrillaCIGate -Findings $mix -FailOn Critical
$any   = Get-GuerrillaCIGate -Findings $mix -FailOn Any
$none  = Get-GuerrillaCIGate -Findings $mix -FailOn None
$med   = Get-GuerrillaCIGate -Findings $mix -FailOn Medium
$waf   = Get-GuerrillaCIGate -Findings $mix -FailOn High -WarningsAsFailures
$clean = Get-GuerrillaCIGate -Findings @((F 'PASS' 'High'), (F 'SKIP' 'Critical')) -FailOn Any

Add-R 'High: gates Critical+High FAIL (2)'   ($high.ShouldFail -and $high.GatingCount -eq 2) "n=$($high.GatingCount)"
Add-R 'Critical: gates only Critical (1)'    ($crit.ShouldFail -and $crit.GatingCount -eq 1) "n=$($crit.GatingCount)"
Add-R 'Medium: gates Crit+High+Med (3)'      ($med.GatingCount -eq 3) "n=$($med.GatingCount)"
Add-R 'Any: gates all 4 FAIL'                ($any.GatingCount -eq 4) "n=$($any.GatingCount)"
Add-R 'None: never gates'                     (-not $none.ShouldFail -and $none.GatingCount -eq 0) ''
Add-R 'WARN not gated by default'            ($high.GatingCount -eq 2) ''
Add-R 'WarningsAsFailures adds the WARN (3)' ($waf.GatingCount -eq 3) "n=$($waf.GatingCount)"
Add-R 'SKIP never gates'                      (@($any.GatingCheckIds | Where-Object { $_ -match 'SKIP' }).Count -eq 0) ''
Add-R 'PASS never gates'                      (@($any.GatingCheckIds | Where-Object { $_ -match 'PASS' }).Count -eq 0) ''
Add-R 'all-clean estate -> no gate'          (-not $clean.ShouldFail) ''
Add-R 'gate exposes triggering check ids'    ($crit.GatingCheckIds -contains 'Critical-FAIL') ''

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
