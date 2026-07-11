# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Write-WiretapReport {
    <#
    .SYNOPSIS
        Writes the M365 Wiretap sweep console report.

    .DESCRIPTION
        Displays a themed console report summarizing M365 continuous monitoring results,
        including threat level, score, indicators, flagged changes, and new threats.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [int]$TotalEvents,

        [string]$ThreatLevel = 'Clean',
        [double]$ThreatScore = 0,

        [string[]]$Indicators = @(),
        [PSCustomObject[]]$FlaggedChanges = @(),
        [PSCustomObject[]]$NewThreats = @(),

        [int]$CriticalCount = 0,
        [int]$HighCount = 0,
        [int]$MediumCount = 0,
        [int]$LowCount = 0
    )

    # Calculate Guerrilla Score (inverse of threat)
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
        'WIRETAP REPORT'
        'M365 Continuous Security Monitoring'
        ''
        "Tenant: $TenantId"
        "Guerrilla Score: $('{0,3:N0}' -f $guerrillaScore) / 100  $($scoreInfo.Label)"
    ) -BorderColor Dim -ContentColor Parchment -Width 66
    Write-Host ''

    # Threat level
    $threatColor = switch ($ThreatLevel) {
        'CRITICAL' { 'DarkRed' }
        'HIGH'     { 'DeepOrange' }
        'MEDIUM'   { 'Amber' }
        'LOW'      { 'Gold' }
        default    { 'Sage' }
    }

    Write-GuerrillaText '  Threat Level: ' -Color Dim -NoNewline
    Write-GuerrillaText ('{0,-10}' -f $ThreatLevel) -Color $threatColor -Bold -NoNewline
    Write-GuerrillaText '  Score: ' -Color Dim -NoNewline
    Write-GuerrillaText ('{0:N0}' -f $ThreatScore) -Color $threatColor
    Write-Host ''

    # Summary stats
    Write-GuerrillaText '  Events analyzed:   ' -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $TotalEvents) -Color White
    Write-GuerrillaText '  Flagged changes:   ' -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $FlaggedChanges.Count) -Color White
    Write-GuerrillaText '  New threats:       ' -Color Olive -NoNewline
    Write-GuerrillaText ('{0,6:N0}' -f $NewThreats.Count) -Color White
    Write-Host ''

    # --- Severity breakdown bar chart ---
    $threatItems = @()
    if ($CriticalCount -gt 0) { $threatItems += @{ Label = 'CRITICAL'; Value = $CriticalCount; Color = 'DarkRed' } }
    if ($HighCount -gt 0)     { $threatItems += @{ Label = 'HIGH';     Value = $HighCount;     Color = 'DeepOrange' } }
    if ($MediumCount -gt 0)   { $threatItems += @{ Label = 'MEDIUM';   Value = $MediumCount;   Color = 'Amber' } }
    if ($LowCount -gt 0)      { $threatItems += @{ Label = 'LOW';      Value = $LowCount;      Color = 'Gold' } }

    if ($threatItems.Count -gt 0) {
        Write-SpectreBarChart -Items $threatItems -Title 'Severity Breakdown'
    }

    if ($FlaggedChanges.Count -eq 0) {
        Write-Host ''
        Write-GuerrillaText '  All clear. No M365 security changes detected.' -Color Sage
    }

    # Indicators
    if ($Indicators.Count -gt 0) {
        Write-Host ''
        Write-GuerrillaText '  Indicators:' -Color Parchment
        foreach ($ind in $Indicators) {
            $indColor = if ($ind -match '^(AUDIT LOG DISABLED|BULK FILE)') { 'DarkRed' }
                        elseif ($ind -match '^(FORWARDING|TRANSPORT|DEFENDER)') { 'DeepOrange' }
                        elseif ($ind -match '^(EDISCOVERY|DLP|POWER)') { 'Amber' }
                        elseif ($ind -match '^(EXTERNAL|TEAMS)') { 'Gold' }
                        else { 'Olive' }
            Write-GuerrillaText "    - $ind" -Color $indColor
        }
    }

    # --- Flagged changes table ---
    if ($FlaggedChanges.Count -gt 0) {
        Write-Host ''

        $sortedChanges = @($FlaggedChanges | Sort-Object {
            $sevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
            $sevOrder[$_.Severity] ?? 4
        })

        $fcColumns = @(
            @{ Name = 'Severity';  Color = 'Olive';  Alignment = 'Left' }
            @{ Name = 'Type';      Color = 'Olive';  Alignment = 'Left' }
            @{ Name = 'Actor';     Color = 'Olive';  Alignment = 'Left' }
            @{ Name = 'Detail';    Color = 'Olive';  Alignment = 'Left' }
        )

        $fcRows = @()
        $fcRowColors = @()
        foreach ($change in ($sortedChanges | Select-Object -First 15)) {
            $sevColor = switch ($change.Severity) {
                'Critical' { 'DarkRed' }
                'High'     { 'DeepOrange' }
                'Medium'   { 'Amber' }
                'Low'      { 'Gold' }
                default    { 'Dim' }
            }

            $desc = if ($change.Description) {
                $d = $change.Description
                if ($d.Length -gt 35) { $d = $d.Substring(0, 32) + '...' }
                $d
            } else { '' }

            $fcRows += ,@(
                (($change.Severity ?? 'Unknown').ToUpper()),
                ($change.DetectionType ?? ''),
                ($change.Actor ?? 'Unknown'),
                $desc
            )
            $fcRowColors += $sevColor
        }

        Write-SpectreTable -Title 'Flagged Changes' -Columns $fcColumns -Rows $fcRows -RowColors $fcRowColors -BorderColor Dim

        if ($FlaggedChanges.Count -gt 15) {
            Write-GuerrillaText "    ... and $($FlaggedChanges.Count - 15) more" -Color Dim
        }
    }

    Write-Host ''
    Write-GuerrillaText ('=' * 62) -Color Dim
}
