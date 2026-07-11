# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-CampaignReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$OverallScore,

        [Parameter(Mandatory)]
        [string]$ScoreLabel,

        [Parameter(Mandatory)]
        [hashtable]$TheaterScores,

        [Parameter(Mandatory)]
        [hashtable]$CategoryScores,

        [PSCustomObject[]]$Findings = @()
    )

    Write-Host ''

    # Header
    Write-SpectrePanel -Content @(
        'C A M P A I G N   R E P O R T'
        'Unified Security Posture Assessment'
    ) -BorderColor 'Olive' -ContentColor 'Olive' -Width 64
    Write-Host ''

    # Overall score
    $scoreColor = if ($OverallScore -ge 90) { 'Sage' }
                  elseif ($OverallScore -ge 75) { 'Olive' }
                  elseif ($OverallScore -ge 60) { 'Gold' }
                  elseif ($OverallScore -ge 40) { 'Amber' }
                  else { 'DeepOrange' }

    Write-GuerrillaText '  Combined Score: ' -Color Dim -NoNewline
    Write-GuerrillaText "$OverallScore / 100" -Color $scoreColor -NoNewline
    Write-GuerrillaText "  [ $ScoreLabel ]" -Color $scoreColor
    Write-Host ''

    # Theater breakdown as table
    $theaterRows = @()
    $theaterColors = @()
    foreach ($theater in ($TheaterScores.GetEnumerator() | Sort-Object Key)) {
        $ts = $theater.Value
        $tColor = if ($ts.Score -ge 90) { 'Sage' }
                  elseif ($ts.Score -ge 75) { 'Olive' }
                  elseif ($ts.Score -ge 60) { 'Gold' }
                  elseif ($ts.Score -ge 40) { 'Amber' }
                  else { 'DeepOrange' }

        $theaterRows += , @($theater.Key, [string]$ts.Score, [string]$ts.PassCount, [string]$ts.FailCount, [string]$ts.WarnCount, [string]$ts.SkipCount)
        $theaterColors += $tColor
    }

    Write-SpectreTable -Columns @(
        @{ Name = 'Theater'; Color = 'Olive' }
        @{ Name = 'Score'; Color = 'Parchment'; Alignment = 'Right' }
        @{ Name = 'Pass'; Color = 'Sage'; Alignment = 'Right' }
        @{ Name = 'Fail'; Color = 'DeepOrange'; Alignment = 'Right' }
        @{ Name = 'Warn'; Color = 'Gold'; Alignment = 'Right' }
        @{ Name = 'Skip'; Color = 'Dim'; Alignment = 'Right' }
    ) -Rows $theaterRows -RowColors $theaterColors
    Write-Host ''

    # Summary stats
    $totalChecks = $Findings.Count
    $passCount   = @($Findings | Where-Object Status -eq 'PASS').Count
    $failCount   = @($Findings | Where-Object Status -eq 'FAIL').Count
    $warnCount   = @($Findings | Where-Object Status -eq 'WARN').Count
    $skipCount   = @($Findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    Write-SpectreBarChart -Items @(
        @{ Label = 'Passed'; Value = $passCount; Color = 'Sage' }
        @{ Label = 'Failed'; Value = $failCount; Color = 'DeepOrange' }
        @{ Label = 'Warnings'; Value = $warnCount; Color = 'Gold' }
        @{ Label = 'Skipped'; Value = $skipCount; Color = 'Dim' }
    ) -Title "Summary ($totalChecks checks evaluated):"
    Write-Host ''

    # Severity breakdown
    $failFindings = @($Findings | Where-Object Status -eq 'FAIL')
    $critCount = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount = @($failFindings | Where-Object Severity -eq 'High').Count
    $medCount  = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount  = @($failFindings | Where-Object Severity -eq 'Low').Count

    if ($critCount -gt 0 -or $highCount -gt 0 -or $medCount -gt 0 -or $lowCount -gt 0) {
        $severityItems = @()
        if ($critCount -gt 0) { $severityItems += @{ Label = 'CRITICAL'; Value = $critCount; Color = 'DeepOrange' } }
        if ($highCount -gt 0) { $severityItems += @{ Label = 'HIGH'; Value = $highCount; Color = 'Amber' } }
        if ($medCount -gt 0)  { $severityItems += @{ Label = 'MEDIUM'; Value = $medCount; Color = 'Gold' } }
        if ($lowCount -gt 0)  { $severityItems += @{ Label = 'LOW'; Value = $lowCount; Color = 'Sage' } }
        Write-SpectreBarChart -Items $severityItems -Title 'Findings by severity:'
        Write-Host ''
    }

    # Category scores grouped by theater — use tree view
    $treeChildren = @()
    foreach ($theater in ($TheaterScores.GetEnumerator() | Sort-Object Key)) {
        $ts = $theater.Value
        if (-not $ts.CategoryScores) { continue }

        $catChildren = @()
        foreach ($cat in ($ts.CategoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
            $catColor = if ($cat.Value.Score -ge 90) { 'Sage' }
                        elseif ($cat.Value.Score -ge 75) { 'Olive' }
                        elseif ($cat.Value.Score -ge 60) { 'Gold' }
                        elseif ($cat.Value.Score -ge 40) { 'Amber' }
                        else { 'DeepOrange' }
            $catChildren += @{
                Label = "$($cat.Key): $($cat.Value.Score)/100 (P:$($cat.Value.Pass) F:$($cat.Value.Fail) W:$($cat.Value.Warn))"
                Color = $catColor
            }
        }

        $treeChildren += @{
            Label = "$($theater.Key) ($($ts.Score)/100)"
            Color = 'Olive'
            Children = $catChildren
        }
    }

    if ($treeChildren.Count -gt 0) {
        Write-SpectreTree -RootLabel 'Category Scores by Theater' -RootColor 'Parchment' `
            -Children $treeChildren -GuideColor 'Dim'
        Write-Host ''
    }

    # Priority findings across all theaters
    $critical = @($Findings | Where-Object {
        $_.Status -eq 'FAIL' -and $_.Severity -in @('Critical', 'High')
    } | Select-Object -First 15)

    if ($critical.Count -gt 0) {
        $findingRows = @()
        $findingColors = @()
        foreach ($f in $critical) {
            $sevColor = if ($f.Severity -eq 'Critical') { 'DeepOrange' } else { 'Amber' }
            $theaterTag = switch ($f.Theater) {
                'Google Workspace' { 'GWS' }
                'Active Directory' { 'AD' }
                'Microsoft Cloud'  { 'CLD' }
                default            { '???' }
            }
            $findingRows += , @($f.Severity.ToUpper(), $theaterTag, $f.CheckId, $f.CheckName)
            $findingColors += $sevColor
        }
        Write-SpectreTable -Title 'Priority findings' `
            -Columns @(
                @{ Name = 'Severity'; Color = 'DeepOrange' }
                @{ Name = 'Theater'; Color = 'Dim' }
                @{ Name = 'Check ID'; Color = 'Dim' }
                @{ Name = 'Finding'; Color = 'Olive' }
            ) -Rows $findingRows -RowColors $findingColors
        Write-Host ''
    }
}
