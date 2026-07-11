# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-FieldReport {
    [CmdletBinding()]
    param(
        [int]$TotalUsers,
        [int]$FlaggedCount,
        [int]$CleanCount,
        [int]$CriticalCount,
        [int]$HighCount,
        [int]$MediumCount,
        [int]$LowCount,
        [int]$NewThreats,
        [int]$TotalEvents,
        [PSCustomObject[]]$FlaggedUsers
    )

    # Calculate Guerrilla Score
    $guerrillaScore = 100.0
    $guerrillaScore -= ($CriticalCount * 25)
    $guerrillaScore -= ($HighCount * 15)
    $guerrillaScore -= ($MediumCount * 8)
    $guerrillaScore -= ($LowCount * 3)
    $guerrillaScore = [Math]::Max(0, [Math]::Min(100, $guerrillaScore))
    $scoreInfo = Get-GuerrillaScoreLabel -Score $guerrillaScore

    Write-Host ''
    Write-SpectrePanel -Content @('FIELD REPORT') -BorderColor 'Dim' -ContentColor 'Parchment' -Width 64
    Write-Host ''

    # Guerrilla Score
    Write-GuerrillaText "  Guerrilla Score: " -Color Dim -NoNewline
    Write-GuerrillaText ('{0,3:N0}' -f $guerrillaScore) -Color $scoreInfo.Color -Bold -NoNewline
    Write-GuerrillaText " / 100  " -Color Dim -NoNewline
    Write-GuerrillaText $scoreInfo.Label -Color $scoreInfo.Color -Bold
    Write-Host ''

    # Stats
    Write-GuerrillaText "  Users scanned:     " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $TotalUsers) -Color White
    Write-GuerrillaText "  Events analyzed:   " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $TotalEvents) -Color White
    Write-GuerrillaText "  Clean:             " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $CleanCount) -Color Sage
    Write-Host ''

    # Threat breakdown with bar charts
    $threatItems = @()
    if ($CriticalCount -gt 0) { $threatItems += @{ Label = 'CRITICAL'; Value = $CriticalCount; Color = 'DarkRed' } }
    if ($HighCount -gt 0)     { $threatItems += @{ Label = 'HIGH'; Value = $HighCount; Color = 'DeepOrange' } }
    if ($MediumCount -gt 0)   { $threatItems += @{ Label = 'MEDIUM'; Value = $MediumCount; Color = 'Amber' } }
    if ($LowCount -gt 0)      { $threatItems += @{ Label = 'LOW'; Value = $LowCount; Color = 'Gold' } }

    if ($threatItems.Count -gt 0) {
        Write-SpectreBarChart -Items $threatItems
    }

    if ($FlaggedCount -eq 0) {
        Write-Host ''
        Write-GuerrillaText '  All clear. No threats detected.' -Color Sage
    }

    # Flagged users detail
    if ($FlaggedUsers -and $FlaggedUsers.Count -gt 0) {
        Write-Host ''
        $userRows = @()
        $userColors = @()
        foreach ($p in $FlaggedUsers) {
            $levelColor = switch ($p.ThreatLevel) {
                'CRITICAL' { 'DarkRed' }
                'HIGH'     { 'DeepOrange' }
                'MEDIUM'   { 'Amber' }
                'LOW'      { 'Gold' }
                default    { 'Dim' }
            }
            $tags = ''
            if ($p.IsKnownCompromised) { $tags += ' [CONFIRMED]' }
            if ($p.WasRemediated) { $tags += ' [REMEDIATED]' }
            elseif ($p.ThreatScore -ge 60 -and -not $p.IsKnownCompromised) { $tags += ' [NOT REMEDIATED!]' }

            $indicators = if ($p.Indicators.Count -gt 0) {
                ($p.Indicators | Select-Object -First 3) -join '; '
            } else { '' }

            $userRows += , @(('{0:N0}' -f $p.ThreatScore), $p.ThreatLevel, "$($p.Email)$tags", $indicators)
            $userColors += $levelColor
        }

        Write-SpectreTable -Title 'Flagged Users' `
            -Columns @(
                @{ Name = 'Score'; Color = 'Parchment'; Alignment = 'Right' }
                @{ Name = 'Level'; Color = 'DeepOrange' }
                @{ Name = 'User'; Color = 'Olive' }
                @{ Name = 'Top Indicators'; Color = 'Dim' }
            ) -Rows $userRows -RowColors $userColors
    }

    Write-Host ''
    Write-GuerrillaText ('=' * 62) -Color Dim
}
