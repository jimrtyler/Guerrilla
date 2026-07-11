# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Invoke-Lookout (Google Workspace configuration-drift monitor): verifies baseline establishment,
# drift detection (new failures), resolved detection, the no-findings guard, and that it drives
# Invoke-Fortification read-only (NoReports + Quiet). Uses an in-memory fake state store so two
# sequential runs simulate baseline -> drift. Run: pwsh -File Tests/verify-lookout.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$out = & $mod {
    # In-memory fake theater-state store + mockable Fortification output.
    $script:fakeState = $null
    $script:fakeFindings = @()
    $script:fakeScore = 0
    $script:lastFort = $null

    function Get-TheaterState  { param($Theater, $ConfigPath) $script:fakeState }
    function Save-TheaterState { param($Theater, $State, $ConfigPath) $script:fakeState = $State }
    function Invoke-Fortification {
        param($ServiceAccountKeyPath, $AdminEmail, $TargetOU, $IncludeChildOUs, $OutputDirectory,
              $NoReports, $NoDelta, $Quiet, $ConfigPath, $ConfigFile, $VaultName, $ReportStyle, $TestMode, $Quick)
        $script:lastFort = @{ NoReports = [bool]$NoReports; Quiet = [bool]$Quiet; Quick = [bool]$Quick }
        # Score from the real engine so the stored baseline and the recomputed current score
        # (which Compare-FortificationState derives from findings) are on the same scale.
        $sc = if (@($script:fakeFindings).Count -gt 0) { (Get-AuditPostureScore -Findings $script:fakeFindings).OverallScore } else { 0 }
        [PSCustomObject]@{ PSTypeName = 'Guerrilla.AuditResult'; Findings = $script:fakeFindings; OverallScore = $sc }
    }
    function F($id, $status, $sev = 'High') {
        [PSCustomObject]@{ CheckId = $id; CheckName = "name-$id"; Category = 'cat'; Severity = $sev; Status = $status; CurrentValue = "val-$id-$status"; OrgUnitPath = '/' }
    }

    $r = @{}

    # ── Run 1: baseline (A=PASS, B=FAIL, C=PASS) ──
    $script:fakeFindings = @((F 'A' 'PASS'), (F 'B' 'FAIL'), (F 'C' 'PASS')); $script:fakeScore = 80
    $b = Invoke-Lookout -Quiet
    $r.BaselineEstablished = $b.BaselineEstablished
    $r.BaselineThreats     = @($b.NewThreats).Count
    $r.FortNoReports       = $script:lastFort.NoReports
    $r.FortQuiet           = $script:lastFort.Quiet
    $r.FastUsesQuick       = $script:lastFort.Quick   # default ScanMode Fast -> Quick

    # ── Run 2: drift — A flips PASS->FAIL (new), B stays FAIL (not new), C stays PASS ──
    $script:fakeFindings = @((F 'A' 'FAIL' 'Critical'), (F 'B' 'FAIL'), (F 'C' 'PASS')); $script:fakeScore = 70
    $d = Invoke-Lookout -Quiet
    $r.DriftBaseline   = $d.BaselineEstablished           # should be $false now
    $r.NewFailCount    = @($d.NewFailures).Count          # only A
    $r.NewFailIsA      = (@($d.NewFailures).CheckId -contains 'A') -and -not (@($d.NewFailures).CheckId -contains 'B')
    $r.ThreatCount     = @($d.NewThreats).Count
    $r.ThreatDetId     = @($d.NewThreats)[0].DetectionId
    $r.CritCount       = $d.CriticalCount                 # A is Critical
    $r.ScoreChange     = $d.ScoreChange                   # drift worsens posture -> negative

    # ── Run 3: resolved — B flips FAIL->PASS (A still FAIL, not new) ──
    $script:fakeFindings = @((F 'A' 'FAIL' 'Critical'), (F 'B' 'PASS'), (F 'C' 'PASS')); $script:fakeScore = 85
    $e = Invoke-Lookout -Quiet
    $r.ResolvedCount   = @($e.Resolved).Count             # B
    $r.ResolvedIsB     = (@($e.Resolved).CheckId -contains 'B')
    $r.NewFailAfter    = @($e.NewFailures).Count          # 0 (A already failing)
    $r.ScoreChange3    = $e.ScoreChange                   # resolving B improves posture -> positive
    $r.ScoreChange3    = $e.ScoreChange                   # resolving B improves posture -> positive

    # ── No findings: fresh state, empty findings -> graceful, no baseline ──
    $script:fakeState = $null; $script:fakeFindings = @(); $script:fakeScore = 0
    $n = Invoke-Lookout -Quiet
    $r.NoFindBaseline  = $n.BaselineEstablished           # $false
    $r.NoFindThreats   = @($n.NewThreats).Count

    # ── Full mode does NOT pass -Quick ──
    $script:fakeState = $null; $script:fakeFindings = @((F 'A' 'PASS')); $script:fakeScore = 90
    Invoke-Lookout -Quiet -ScanMode Full | Out-Null
    $r.FullSkipsQuick  = (-not $script:lastFort.Quick)

    $r
}

Add-R 'Run1 establishes baseline'              ($out.BaselineEstablished -eq $true) ""
Add-R 'Baseline reports no threats'            ($out.BaselineThreats -eq 0) ("got=$($out.BaselineThreats)")
Add-R 'Fortification driven read-only (NoReports)' ($out.FortNoReports) ""
Add-R 'Fortification driven quiet'             ($out.FortQuiet) ""
Add-R 'Fast mode uses Fortification -Quick'    ($out.FastUsesQuick) ""
Add-R 'Run2 is a diff (not baseline)'          ($out.DriftBaseline -eq $false) ""
Add-R 'Drift: exactly 1 new failure'           ($out.NewFailCount -eq 1) ("got=$($out.NewFailCount)")
Add-R 'Drift: new failure is A (B not re-flagged)' ($out.NewFailIsA) ""
Add-R 'Drift: surfaced on NewThreats'          ($out.ThreatCount -eq 1 -and $out.ThreatDetId -eq 'A') ("c=$($out.ThreatCount) id=$($out.ThreatDetId)")
Add-R 'Drift: critical severity counted'       ($out.CritCount -eq 1) ("got=$($out.CritCount)")
Add-R 'Drift: score change negative (worsened)' ($out.ScoreChange -lt 0) ("got=$($out.ScoreChange)")
Add-R 'Resolved: 1 control resolved'           ($out.ResolvedCount -eq 1 -and $out.ResolvedIsB) ("got=$($out.ResolvedCount)")
Add-R 'Resolved run: no new failures'          ($out.NewFailAfter -eq 0) ("got=$($out.NewFailAfter)")
Add-R 'Resolved: score change positive'        ($out.ScoreChange3 -gt 0) ("got=$($out.ScoreChange3)")
Add-R 'No-findings: no baseline, no throw'     ($out.NoFindBaseline -eq $false -and $out.NoFindThreats -eq 0) ""
Add-R 'Full mode omits -Quick'                 ($out.FullSkipsQuick) ""

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
