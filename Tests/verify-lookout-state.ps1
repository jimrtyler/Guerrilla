# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Invoke-Lookout REAL-state persistence (regression for the v2.12.0 ValidateSet bug where
# theater 'workspace' was rejected by Get/Save-TheaterState, so the baseline never persisted
# and every run re-baselined). Uses the REAL state helpers (only Invoke-Fortification is mocked)
# with an isolated temp ConfigPath so state writes go to a throwaway dir. Mirrors the MON-4
# "survives repeated runs" check. Run: pwsh -File Tests/verify-lookout-state.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("psg-lookout-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$cfg = Join-Path $tmp 'config.json'
$stateFile = Join-Path $tmp 'workspace-state.json'

try {
    $out = & $mod {
        param($cfg, $stateFile)
        # Mock ONLY Fortification — use the REAL Get/Save-TheaterState so the ValidateSet is exercised.
        $script:ff = @()
        function Invoke-Fortification {
            param($ServiceAccountKeyPath, $AdminEmail, $TargetOU, $IncludeChildOUs, $OutputDirectory,
                  $NoReports, $NoDelta, $Quiet, $ConfigPath, $ConfigFile, $VaultName, $ReportStyle, $TestMode, $Quick)
            $sc = if (@($script:ff).Count -gt 0) { (Get-AuditPostureScore -Findings $script:ff).OverallScore } else { 0 }
            [PSCustomObject]@{ PSTypeName = 'Guerrilla.AuditResult'; Findings = $script:ff; OverallScore = $sc }
        }
        function F($id, $st, $sev = 'High') { [PSCustomObject]@{ CheckId = $id; CheckName = "n-$id"; Category = 'c'; Severity = $sev; Status = $st; CurrentValue = "v"; OrgUnitPath = '/' } }

        $r = @{}

        # Direct ValidateSet exercise — these threw before the fix.
        $r.SaveOk = $true
        try { Save-TheaterState -Theater 'workspace' -State @{ schemaVersion = 1; theater = 'workspace'; findings = @(); scanHistory = @() } -ConfigPath $cfg } catch { $r.SaveOk = $false; $r.SaveErr = "$_" }
        $r.GetOk = $true
        try { Get-TheaterState -Theater 'workspace' -ConfigPath $cfg | Out-Null } catch { $r.GetOk = $false }

        # Reset for the two-run scenario.
        Remove-Item $stateFile -ErrorAction SilentlyContinue

        $script:ff = @((F 'A' 'PASS'), (F 'B' 'FAIL'))
        $run1 = Invoke-Lookout -ConfigPath $cfg -Quiet
        $r.Run1Baseline    = $run1.BaselineEstablished
        $r.StatePersisted  = Test-Path $stateFile

        # Second run with identical posture: must LOAD the baseline (not re-establish it) and see no drift.
        $run2 = Invoke-Lookout -ConfigPath $cfg -Quiet
        $r.Run2Baseline    = $run2.BaselineEstablished
        $r.Run2Changes     = $run2.TotalChangesDetected
        $r
    } $cfg $stateFile

    Add-R 'Save-TheaterState accepts ''workspace''' ($out.SaveOk) ($out.SaveErr)
    Add-R 'Get-TheaterState accepts ''workspace''' ($out.GetOk) ''
    Add-R 'Run1 establishes baseline'              ($out.Run1Baseline -eq $true) ''
    Add-R 'Baseline persisted to workspace-state.json' ($out.StatePersisted) ''
    Add-R 'Run2 LOADS baseline (not re-baselined)' ($out.Run2Baseline -eq $false) ("got=$($out.Run2Baseline)")
    Add-R 'Run2 identical posture -> 0 drift'      ($out.Run2Changes -eq 0) ("got=$($out.Run2Changes)")
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

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
