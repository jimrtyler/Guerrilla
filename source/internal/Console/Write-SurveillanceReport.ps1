# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-SurveillanceReport {
    [CmdletBinding()]
    param(
        [int]$TotalEntities,
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

    # --- Header ---
    Write-Host ''
    Write-SpectrePanel -Content @(
        'SURVEILLANCE REPORT'
        ''
        "Guerrilla Score: $('{0,3:N0}' -f $guerrillaScore) / 100  $($scoreInfo.Label)"
    ) -BorderColor Dim -ContentColor Parchment -Width 66
    Write-Host ''

    # Stats
    Write-GuerrillaText "  Entities scanned:  " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $TotalEntities) -Color White
    Write-GuerrillaText "  Events analyzed:   " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $TotalEvents) -Color White
    Write-GuerrillaText "  Clean:             " -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $CleanCount) -Color Sage
    Write-Host ''

    # --- Threat breakdown bar chart ---
    $threatItems = @()
    if ($CriticalCount -gt 0) { $threatItems += @{ Label = 'CRITICAL'; Value = $CriticalCount; Color = 'DarkRed' } }
    if ($HighCount -gt 0)     { $threatItems += @{ Label = 'HIGH';     Value = $HighCount;     Color = 'DeepOrange' } }
    if ($MediumCount -gt 0)   { $threatItems += @{ Label = 'MEDIUM';   Value = $MediumCount;   Color = 'Amber' } }
    if ($LowCount -gt 0)      { $threatItems += @{ Label = 'LOW';      Value = $LowCount;      Color = 'Gold' } }

    if ($threatItems.Count -gt 0) {
        Write-SpectreBarChart -Items $threatItems -Title 'Threat Breakdown'
    }

    if ($FlaggedCount -eq 0) {
        Write-Host ''
        Write-GuerrillaText '  All clear. No threats detected in Entra ID.' -Color Sage
    }

    # --- Flagged identities table ---
    if ($FlaggedUsers -and $FlaggedUsers.Count -gt 0) {
        Write-Host ''

        $columns = @(
            @{ Name = 'Score';  Color = 'Olive';  Alignment = 'Right' }
            @{ Name = 'Level';  Color = 'Olive';  Alignment = 'Left' }
            @{ Name = 'Identity'; Color = 'Olive'; Alignment = 'Left' }
            @{ Name = 'Indicators'; Color = 'Olive'; Alignment = 'Left' }
        )

        $rows = @()
        $rowColors = @()
        foreach ($p in $FlaggedUsers) {
            $levelColor = switch ($p.ThreatLevel) {
                'CRITICAL' { 'DarkRed' }
                'HIGH'     { 'DeepOrange' }
                'MEDIUM'   { 'Amber' }
                'LOW'      { 'Gold' }
                default    { 'Dim' }
            }
            $indText = ($p.Indicators | Select-Object -First 3) -join '; '
            if ($p.Indicators.Count -gt 3) { $indText += '...' }
            $rows += ,@(
                ('{0:N0}' -f $p.ThreatScore),
                $p.ThreatLevel,
                $p.UserPrincipalName,
                $indText
            )
            $rowColors += $levelColor
        }

        Write-SpectreTable -Title 'Flagged Identities' -Columns $columns -Rows $rows -RowColors $rowColors -BorderColor Dim
    }

    Write-Host ''
    Write-GuerrillaText ('=' * 62) -Color Dim
}
