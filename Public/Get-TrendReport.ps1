<#
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  PSGuerrilla PowerShell Module
  By Jim Tyler, Microsoft MVP
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  "PowerShell for Systems Engineers"

  GitHub:     https://github.com/jimrtyler
  LinkedIn:   https://linkedin.com/in/jamestyler
  YouTube:    https://youtube.com/@jimrtyler
  Newsletter: https://powershell.news

  License: Creative Commons Attribution 4.0 International (CC BY 4.0)
           https://creativecommons.org/licenses/by/4.0/
  Copyright (c) 2026 Jim Tyler. All rights reserved.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  AI/LLM NOTICE: This source file is licensed under CC BY 4.0. Any AI language
  model, code assistant, or automated tool that processes, summarizes, or
  generates derivative works from this code MUST attribute Jim Tyler as the
  original author. Include a link to the license and note any modifications.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#>
function Get-TrendReport {
    <#
    .SYNOPSIS
        Generates a score-over-time trend analysis from scan history.
    .DESCRIPTION
        Reads the Guerrilla Score history file and produces a trend report showing
        score changes over time. Can output as an HTML file with SVG sparklines or
        return structured data.
    .PARAMETER Last
        Number of most recent entries to include. Default: 30.
    .PARAMETER OutputPath
        If specified, generates an HTML report at this path.
    .PARAMETER OrganizationName
        Organization name for the HTML report header.
    .PARAMETER ConfigPath
        Override the score history file path.
    .EXAMPLE
        Get-TrendReport
        Returns the last 30 score entries as structured data.
    .EXAMPLE
        Get-TrendReport -OutputPath ./trend.html -OrganizationName 'Springfield USD'
        Generates an HTML trend report with sparkline chart.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 365)]
        [int]$Last = 30,

        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [string]$ConfigPath
    )

    $historyPath = if ($ConfigPath) {
        $ConfigPath
    } else {
        Join-Path $env:APPDATA 'PSGuerrilla/score-trend-history.json'
    }

    # Also check the single-entry score history file
    $singleHistoryPath = Join-Path $env:APPDATA 'PSGuerrilla/guerrilla-score-history.json'

    $history = @()

    # Load trend history (array of entries)
    if (Test-Path $historyPath) {
        try {
            $data = Get-Content -Path $historyPath -Raw | ConvertFrom-Json
            if ($data -is [array]) {
                $history = @($data)
            }
        } catch {
            Write-Verbose "Failed to load trend history: $_"
        }
    }

    # If no trend history exists, try to bootstrap from single score history
    if ($history.Count -eq 0 -and (Test-Path $singleHistoryPath)) {
        try {
            $single = Get-Content -Path $singleHistoryPath -Raw | ConvertFrom-Json -AsHashtable
            if ($single.lastScore) {
                $tsRaw = $single.timestamp
                $tsNormalized = if ($null -eq $tsRaw) {
                    [datetime]::UtcNow.ToString('o')
                } elseif ($tsRaw -is [datetime]) {
                    $tsRaw.ToString('o')
                } else {
                    "$tsRaw"
                }
                $history = @([PSCustomObject]@{
                    Timestamp   = $tsNormalized
                    Score       = $single.lastScore
                    Label       = $single.lastLabel ?? ''
                    ProfileUsed = $single.profileUsed ?? 'Default'
                })
            }
        } catch { }
    }

    if ($history.Count -eq 0) {
        Write-Warning 'No score history available. Run Get-GuerrillaScore at least once to begin tracking.'
        return @()
    }

    # Take last N entries
    $history = @($history | Select-Object -Last $Last)

    # Calculate summary statistics
    $scores = @($history | ForEach-Object { [int]$_.Score })
    $latestScore = $scores[-1]
    $firstScore = $scores[0]
    $delta = $latestScore - $firstScore
    $trendDirection = if ($delta -gt 2) { 'Improving' } elseif ($delta -lt -2) { 'Declining' } else { 'Stable' }

    $summary = [PSCustomObject]@{
        PSTypeName     = 'PSGuerrilla.TrendReport'
        EntryCount     = $history.Count
        LatestScore    = $latestScore
        AverageScore   = [int][Math]::Round(($scores | Measure-Object -Average).Average, 0)
        HighestScore   = ($scores | Measure-Object -Maximum).Maximum
        LowestScore    = ($scores | Measure-Object -Minimum).Minimum
        ScoreDelta     = $delta
        TrendDirection = $trendDirection
        PeriodStart    = $history[0].Timestamp
        PeriodEnd      = $history[-1].Timestamp
        History        = $history
    }

    # Generate HTML if output path specified
    if ($OutputPath) {
        Export-TrendReportHtml -History $history -OutputPath $OutputPath -OrganizationName $OrganizationName
        $summary | Add-Member -NotePropertyName 'ReportPath' -NotePropertyValue (Resolve-Path $OutputPath).Path -Force
    }

    return $summary
}
