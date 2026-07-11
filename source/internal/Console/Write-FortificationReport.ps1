# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-FortificationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$OverallScore,

        [Parameter(Mandatory)]
        [string]$ScoreLabel,

        [Parameter(Mandatory)]
        [hashtable]$CategoryScores,

        [Parameter(Mandatory)]
        [int]$TotalChecks,

        [int]$PassCount = 0,
        [int]$FailCount = 0,
        [int]$WarnCount = 0,
        [int]$SkipCount = 0,
        [int]$CriticalCount = 0,
        [int]$HighCount = 0,
        [int]$MediumCount = 0,
        [int]$LowCount = 0,

        [PSCustomObject[]]$TopFindings = @()
    )

    Write-Host ''

    # Header
    Write-SpectrePanel -Content @('F O R T I F I C A T I O N   R E P O R T') `
        -BorderColor 'Olive' -ContentColor 'Olive' -Width 64
    Write-Host ''

    # Overall score
    $scoreColor = if ($OverallScore -ge 90) { 'Sage' }
                  elseif ($OverallScore -ge 75) { 'Olive' }
                  elseif ($OverallScore -ge 60) { 'Gold' }
                  elseif ($OverallScore -ge 40) { 'Amber' }
                  else { 'DeepOrange' }

    Write-GuerrillaText '  Fortification Score: ' -Color Dim -NoNewline
    Write-GuerrillaText "$OverallScore / 100" -Color $scoreColor -NoNewline
    Write-GuerrillaText "  [ $ScoreLabel ]" -Color $scoreColor
    Write-Host ''

    # Summary stats
    Write-SpectreBarChart -Items @(
        @{ Label = 'Passed'; Value = $PassCount; Color = 'Sage' }
        @{ Label = 'Failed'; Value = $FailCount; Color = 'DeepOrange' }
        @{ Label = 'Warnings'; Value = $WarnCount; Color = 'Gold' }
        @{ Label = 'Skipped'; Value = $SkipCount; Color = 'Dim' }
    ) -Title "Summary ($TotalChecks checks evaluated):"
    Write-Host ''

    # Severity breakdown
    if ($CriticalCount -gt 0 -or $HighCount -gt 0 -or $MediumCount -gt 0 -or $LowCount -gt 0) {
        $severityItems = @()
        if ($CriticalCount -gt 0) { $severityItems += @{ Label = 'CRITICAL'; Value = $CriticalCount; Color = 'DeepOrange' } }
        if ($HighCount -gt 0)     { $severityItems += @{ Label = 'HIGH'; Value = $HighCount; Color = 'Amber' } }
        if ($MediumCount -gt 0)   { $severityItems += @{ Label = 'MEDIUM'; Value = $MediumCount; Color = 'Gold' } }
        if ($LowCount -gt 0)      { $severityItems += @{ Label = 'LOW'; Value = $LowCount; Color = 'Sage' } }

        Write-SpectreBarChart -Items $severityItems -Title 'Findings by severity:'
        Write-Host ''
    }

    # Category scores
    $catItems = @()
    foreach ($cat in ($CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
        $catColor = if ($cat.Value.Score -ge 90) { 'Sage' }
                    elseif ($cat.Value.Score -ge 75) { 'Olive' }
                    elseif ($cat.Value.Score -ge 60) { 'Gold' }
                    elseif ($cat.Value.Score -ge 40) { 'Amber' }
                    else { 'DeepOrange' }
        $catItems += @{ Label = "$($cat.Key) (P:$($cat.Value.Pass) F:$($cat.Value.Fail) W:$($cat.Value.Warn))"; Value = $cat.Value.Score; Color = $catColor }
    }
    if ($catItems.Count -gt 0) {
        Write-SpectreBarChart -Items $catItems -Title 'Category scores:'
        Write-Host ''
    }

    # Top critical/high findings
    $critical = @($TopFindings | Where-Object { $_.Status -eq 'FAIL' -and $_.Severity -in @('Critical', 'High') } | Select-Object -First 10)
    if ($critical.Count -gt 0) {
        $findingRows = @()
        $findingColors = @()
        foreach ($f in $critical) {
            $sevColor = if ($f.Severity -eq 'Critical') { 'DeepOrange' } else { 'Amber' }
            $findingRows += , @($f.Severity.ToUpper(), $f.CheckId, $f.CheckName)
            $findingColors += $sevColor
        }
        Write-SpectreTable -Title 'Priority findings' `
            -Columns @(
                @{ Name = 'Severity'; Color = 'DeepOrange' }
                @{ Name = 'Check ID'; Color = 'Dim' }
                @{ Name = 'Finding'; Color = 'Olive' }
            ) -Rows $findingRows -RowColors $findingColors
        Write-Host ''
    }
}
