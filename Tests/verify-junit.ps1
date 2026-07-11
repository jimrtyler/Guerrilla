# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Export-GuerrillaJUnit (Maester parity M4 — CI/CD): findings -> valid JUnit XML that GitHub/Azure
# DevOps/GitLab render natively. Verifies structure, counts, FAIL->failure / SKIP->skipped mapping,
# WarningsAsFailures, XML escaping, and the gating counts. Run: pwsh -File Tests/verify-junit.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

function F($id, $cat, $status, $sev, $cv = 'val', $rem = 'fix') {
    [PSCustomObject]@{ CheckId = $id; CheckName = "name-$id"; Category = $cat; Severity = $sev; Status = $status; CurrentValue = $cv; RemediationSteps = $rem }
}

$findings = @(
    F 'A1' 'Authentication' 'FAIL' 'Critical'
    F 'A2' 'Authentication' 'PASS' 'High'
    F 'A3' 'Authentication' 'WARN' 'Medium'
    F 'B1' 'Email' 'SKIP' 'High' 'Not Assessed — not connected'
    F 'B2' 'Email' 'FAIL' 'High' 'bad <value> & "quotes"' 'do & fix <it>'   # escaping
)

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("psg-junit-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".xml")
$tmp2 = Join-Path ([IO.Path]::GetTempPath()) ("psg-junit2-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".xml")
try {
    $r = Export-GuerrillaJUnit -Findings $findings -OutputPath $tmp
    Add-R 'returns counts'         ($r.Tests -eq 5 -and $r.Failures -eq 2 -and $r.Skipped -eq 1 -and $r.Passed -eq 2) "t=$($r.Tests) f=$($r.Failures) s=$($r.Skipped) p=$($r.Passed)"
    Add-R 'file written'           (Test-Path $tmp) ''

    # Parses as valid XML
    [xml]$xml = Get-Content $tmp -Raw
    Add-R 'valid XML parses'       ($null -ne $xml.testsuites) ''
    Add-R 'root counts correct'    ($xml.testsuites.tests -eq '5' -and $xml.testsuites.failures -eq '2' -and $xml.testsuites.skipped -eq '1') ''
    $suites = @($xml.testsuites.testsuite)
    Add-R 'one suite per category'  ($suites.Count -eq 2) "n=$($suites.Count)"

    $auth = $suites | Where-Object name -eq 'Authentication'
    $cases = @($auth.testcase)
    Add-R 'testcase per check'      ($cases.Count -eq 3) "n=$($cases.Count)"
    $failCase = $cases | Where-Object { $_.name -match 'A1' }
    Add-R 'FAIL -> failure element' ($null -ne $failCase.failure) ''
    Add-R 'failure carries severity type' ($failCase.failure.type -eq 'Critical') "got=$($failCase.failure.type)"

    $email = $suites | Where-Object name -eq 'Email'
    $skipCase = @($email.testcase) | Where-Object { $_.name -match 'B1' }
    Add-R 'SKIP -> skipped element' ($null -ne $skipCase.skipped) ''

    # WARN is NOT a failure by default
    $warnCase = $cases | Where-Object { $_.name -match 'A3' }
    Add-R 'WARN not a failure (default)' ($null -eq $warnCase.failure) ''

    # XML escaping survived (the [xml] parse itself proves well-formedness; check decoded text)
    $b2 = @($email.testcase) | Where-Object { $_.name -match 'B2' }
    Add-R 'special chars escaped + decoded' ($b2.failure.'#text' -match 'bad <value> & "quotes"') "got=$($b2.failure.'#text')"

    # WarningsAsFailures promotes WARN
    $r2 = Export-GuerrillaJUnit -Findings $findings -OutputPath $tmp2 -WarningsAsFailures
    Add-R '-WarningsAsFailures counts WARN' ($r2.Failures -eq 3) "f=$($r2.Failures)"
    [xml]$xml2 = Get-Content $tmp2 -Raw
    $warn2 = @($xml2.testsuites.testsuite | Where-Object name -eq 'Authentication').testcase | Where-Object { $_.name -match 'A3' }
    Add-R 'WARN -> failure when promoted' ($null -ne $warn2.failure) ''

    # Gating pattern works
    Add-R 'gating: Failures>0 actionable' ($r.Failures -gt 0) ''
}
finally { Remove-Item $tmp, $tmp2 -ErrorAction SilentlyContinue }

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
