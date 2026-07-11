# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-InfiltrationReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result
    )

    $score = $Result.Score
    $findings = $Result.Findings
    $overallScore = $score.OverallScore
    $categoryScores = $score.CategoryScores

    $totalChecks = $findings.Count
    $passCount = @($findings | Where-Object Status -eq 'PASS').Count
    $failCount = @($findings | Where-Object Status -eq 'FAIL').Count
    $warnCount = @($findings | Where-Object Status -eq 'WARN').Count
    $skipCount = @($findings | Where-Object Status -in @('SKIP', 'ERROR')).Count

    $failFindings = @($findings | Where-Object Status -eq 'FAIL')
    $criticalCount = @($failFindings | Where-Object Severity -eq 'Critical').Count
    $highCount = @($failFindings | Where-Object Severity -eq 'High').Count
    $mediumCount = @($failFindings | Where-Object Severity -eq 'Medium').Count
    $lowCount = @($failFindings | Where-Object Severity -eq 'Low').Count

    $scoreLabel = Get-FortificationScoreLabel -Score $overallScore

    Write-Host ''

    # Header
    Write-SpectrePanel -Content @(
        'I N F I L T R A T I O N   R E P O R T'
        'Entra ID / Azure / M365 Security Audit'
    ) -BorderColor 'Olive' -ContentColor 'Olive' -Width 64
    Write-Host ''

    # Tenant info
    if ($Result.TenantId) {
        Write-GuerrillaText '  Tenant: ' -Color Dim -NoNewline
        Write-GuerrillaText $Result.TenantId -Color Parchment
        Write-Host ''
    }

    # Overall score
    $scoreColor = if ($overallScore -ge 90) { 'Sage' }
                  elseif ($overallScore -ge 75) { 'Olive' }
                  elseif ($overallScore -ge 60) { 'Gold' }
                  elseif ($overallScore -ge 40) { 'Amber' }
                  else { 'DeepOrange' }

    Write-GuerrillaText '  Cloud Security Score: ' -Color Dim -NoNewline
    Write-GuerrillaText "$overallScore / 100" -Color $scoreColor -NoNewline
    Write-GuerrillaText "  [ $scoreLabel ]" -Color $scoreColor
    Write-Host ''

    # Summary stats
    Write-SpectreBarChart -Items @(
        @{ Label = 'Passed'; Value = $passCount; Color = 'Sage' }
        @{ Label = 'Failed'; Value = $failCount; Color = 'DeepOrange' }
        @{ Label = 'Warnings'; Value = $warnCount; Color = 'Gold' }
        @{ Label = 'Skipped'; Value = $skipCount; Color = 'Dim' }
    ) -Title "Summary ($totalChecks checks evaluated):"
    Write-Host ''

    # Severity breakdown
    if ($criticalCount -gt 0 -or $highCount -gt 0 -or $mediumCount -gt 0 -or $lowCount -gt 0) {
        $severityItems = @()
        if ($criticalCount -gt 0) { $severityItems += @{ Label = 'CRITICAL'; Value = $criticalCount; Color = 'DeepOrange' } }
        if ($highCount -gt 0)     { $severityItems += @{ Label = 'HIGH'; Value = $highCount; Color = 'Amber' } }
        if ($mediumCount -gt 0)   { $severityItems += @{ Label = 'MEDIUM'; Value = $mediumCount; Color = 'Gold' } }
        if ($lowCount -gt 0)      { $severityItems += @{ Label = 'LOW'; Value = $lowCount; Color = 'Sage' } }
        Write-SpectreBarChart -Items $severityItems -Title 'Findings by severity:'
        Write-Host ''
    }

    # Category scores
    $catItems = @()
    foreach ($cat in ($categoryScores.GetEnumerator() | Sort-Object { $_.Value.Score })) {
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

    # Priority findings
    $critical = @($failFindings | Where-Object { $_.Severity -in @('Critical', 'High') } | Select-Object -First 15)
    if ($critical.Count -gt 0) {
        $findingRows = @()
        $findingColors = @()
        foreach ($f in $critical) {
            $sevColor = if ($f.Severity -eq 'Critical') { 'DeepOrange' } else { 'Amber' }
            $currentVal = if ($f.CurrentValue) { $f.CurrentValue } else { '' }
            $findingRows += , @($f.Severity.ToUpper(), $f.CheckId, $f.CheckName, $currentVal)
            $findingColors += $sevColor
        }
        Write-SpectreTable -Title 'Priority findings' `
            -Columns @(
                @{ Name = 'Severity'; Color = 'DeepOrange' }
                @{ Name = 'Check ID'; Color = 'Dim' }
                @{ Name = 'Finding'; Color = 'Olive' }
                @{ Name = 'Current Value'; Color = 'Dim' }
            ) -Rows $findingRows -RowColors $findingColors
        Write-Host ''
    }

    # Data errors
    if ($Result.DataErrors -and $Result.DataErrors.Count -gt 0) {
        Write-GuerrillaText '  Data collection notes:' -Color Dim
        foreach ($err in $Result.DataErrors.GetEnumerator()) {
            Write-GuerrillaText "    $($err.Key): " -Color Dim -NoNewline
            Write-GuerrillaText $err.Value -Color Amber
        }
        Write-Host ''
    }

    Write-GuerrillaText '  ─────────────────────────────────────────────────────────────' -Color Dim
    Write-GuerrillaText '  Guerrilla Infiltration Audit complete.' -Color Olive
    Write-Host ''
}
