# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Get-GuerrillaMaturity (CMMI 1-5): worst-anchors-the-score, per-category levels, anchors,
# and that PASS/SKIP/ERROR never cap. Run: pwsh -File Tests/verify-maturity.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

function F($id, $status, $sev = 'High', $cat = 'CatA') {
    [PSCustomObject]@{ CheckId = $id; CheckName = "name-$id"; Category = $cat; Severity = $sev; Status = $status }
}

# 1. All PASS -> Level 5 Optimized
$m = Get-GuerrillaMaturity -Findings @((F 'A' 'PASS'), (F 'B' 'PASS' 'Critical'))
Add-R 'All PASS -> Level 5 (Optimized)' ($m.OverallLevel -eq 5 -and $m.OverallLabel -eq 'Optimized') ("L=$($m.OverallLevel)")
Add-R 'Level 5 -> no blockers'          (@($m.NextLevelBlockers).Count -eq 0) ""
Add-R 'Level 5 -> NextLevel null'       ($null -eq $m.NextLevel) ""

# 2. One Critical FAIL -> Level 1 Initial, anchored on it
$m = Get-GuerrillaMaturity -Findings @((F 'A' 'PASS'), (F 'CRIT' 'FAIL' 'Critical'))
Add-R 'Critical FAIL -> Level 1 (Initial)' ($m.OverallLevel -eq 1 -and $m.OverallLabel -eq 'Initial') ("L=$($m.OverallLevel)")
Add-R 'Critical FAIL anchored'             ($m.AnchorCheckIds -contains 'CRIT') ("$($m.AnchorCheckIds -join ',')")
Add-R 'Level 1 -> NextLevel 2'             ($m.NextLevel -eq 2) ("got=$($m.NextLevel)")

# 3. High FAIL (no crit) -> Level 2
$m = Get-GuerrillaMaturity -Findings @((F 'H' 'FAIL' 'High'), (F 'P' 'PASS'))
Add-R 'High FAIL -> Level 2 (Managed)' ($m.OverallLevel -eq 2 -and $m.OverallLabel -eq 'Managed') ("L=$($m.OverallLevel)")

# 4. Medium FAIL -> Level 3
$m = Get-GuerrillaMaturity -Findings @((F 'M' 'FAIL' 'Medium'))
Add-R 'Medium FAIL -> Level 3 (Defined)' ($m.OverallLevel -eq 3) ("L=$($m.OverallLevel)")

# 5. WARN only -> Level 4
$m = Get-GuerrillaMaturity -Findings @((F 'W' 'WARN' 'High'), (F 'P' 'PASS'))
Add-R 'WARN only -> Level 4 (Quant. Managed)' ($m.OverallLevel -eq 4 -and $m.OverallLabel -eq 'Quantitatively Managed') ("L=$($m.OverallLevel)")

# 6. Mixed categories: Critical in A, High in B -> overall 1; A=1, B=2
$m = Get-GuerrillaMaturity -Findings @((F 'a1' 'FAIL' 'Critical' 'CatA'), (F 'b1' 'FAIL' 'High' 'CatB'), (F 'b2' 'PASS' 'High' 'CatB'))
Add-R 'Mixed -> overall Level 1'        ($m.OverallLevel -eq 1) ("L=$($m.OverallLevel)")
Add-R 'Per-category: CatA Level 1'      ($m.CategoryLevels['CatA'].Level -eq 1) ("A=$($m.CategoryLevels['CatA'].Level)")
Add-R 'Per-category: CatB Level 2'      ($m.CategoryLevels['CatB'].Level -eq 2) ("B=$($m.CategoryLevels['CatB'].Level)")
Add-R 'Overall anchor is the Critical'  ($m.AnchorCheckIds -contains 'a1' -and -not ($m.AnchorCheckIds -contains 'b1')) ("$($m.AnchorCheckIds -join ',')")

# 7. SKIP/ERROR never cap -> Level 5
$m = Get-GuerrillaMaturity -Findings @((F 's' 'SKIP' 'Critical'), (F 'e' 'ERROR' 'Critical'), (F 'p' 'PASS'))
Add-R 'SKIP/ERROR never cap -> Level 5' ($m.OverallLevel -eq 5) ("L=$($m.OverallLevel)")

# 8. Pipeline input works
$m = @((F 'H' 'FAIL' 'High'), (F 'P' 'PASS')) | Get-GuerrillaMaturity -Theater AD
Add-R 'Pipeline input -> Level 2'       ($m.OverallLevel -eq 2) ("L=$($m.OverallLevel)")
Add-R 'Theater carried through'         ($m.Theater -eq 'AD') ("got=$($m.Theater)")

# 9. Summary counts
$m = Get-GuerrillaMaturity -Findings @((F 'c' 'FAIL' 'Critical'), (F 'h' 'FAIL' 'High'), (F 'w' 'WARN'), (F 'p' 'PASS'))
Add-R 'Summary counts correct' ($m.Summary.CriticalFail -eq 1 -and $m.Summary.HighFail -eq 1 -and $m.Summary.Warn -eq 1 -and $m.Summary.Pass -eq 1) `
    ("c=$($m.Summary.CriticalFail) h=$($m.Summary.HighFail) w=$($m.Summary.Warn) p=$($m.Summary.Pass)")

# 10. All-SKIP estate -> Level 0 Not Assessed (absence of evidence is NOT Optimized)
$m = Get-GuerrillaMaturity -Findings @((F 'S1' 'SKIP'), (F 'S2' 'SKIP' 'Critical'))
Add-R 'All-SKIP -> Level 0 (Not Assessed)' ($m.OverallLevel -eq 0 -and $m.OverallLabel -eq 'Not Assessed') ("L=$($m.OverallLevel)")
Add-R 'All-SKIP -> NextLevel null'         ($null -eq $m.NextLevel) ""

# 11. Mixed: assessed CatA + all-SKIP CatB -> CatB Level 0, overall driven by CatA only
$m = Get-GuerrillaMaturity -Findings @((F 'A1' 'FAIL' 'High' 'CatA'), (F 'B1' 'SKIP' 'Critical' 'CatB'), (F 'B2' 'SKIP' 'High' 'CatB'))
Add-R 'all-SKIP category -> Level 0'       ($m.CategoryLevels['CatB'].Level -eq 0) ("got=$($m.CategoryLevels['CatB'].Level)")
Add-R 'assessed category keeps its level'  ($m.CategoryLevels['CatA'].Level -eq 2) ("got=$($m.CategoryLevels['CatA'].Level)")
Add-R 'overall ignores all-SKIP category'  ($m.OverallLevel -eq 2) ("L=$($m.OverallLevel)")

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($r in $results) {
    $mark = if ($r.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($r.Name)"; if ($r.Detail) { $line += "  ($($r.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
