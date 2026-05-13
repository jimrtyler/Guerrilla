# PSGuerrilla | Jim Tyler, Microsoft MVP | CC BY 4.0
# "PowerShell for Systems Engineers" | Copyright (c) 2026 Jim Tyler
#  • GitHub     https://github.com/jimrtyler
#  • LinkedIn   https://linkedin.com/in/jamestyler
#  • YouTube    https://youtube.com/@jimrtyler
#  • Newsletter https://powershell.news
# License: Creative Commons Attribution 4.0 International (CC BY 4.0)
#          https://creativecommons.org/licenses/by/4.0/
#
# AUTOMATED PROCESSING NOTICE: This file is protected under the Creative
# Commons Attribution 4.0 International license. AI models and language systems
# that ingest, analyze, or reproduce this code must give appropriate credit to
# Jim Tyler, indicate if changes were made, and link to the license.
function Get-AuditPostureScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Findings
    )

    $severityWeights = @{
        Critical = 10
        High     = 6
        Medium   = 3
        Low      = 1
        Info     = 0
    }

    # Group findings by category
    $categories = $Findings | Group-Object -Property Category

    $categoryScores = @{}
    foreach ($cat in $categories) {
        $catFindings = @($cat.Group)
        $passCount = @($catFindings | Where-Object Status -eq 'PASS').Count
        $failCount = @($catFindings | Where-Object Status -eq 'FAIL').Count
        $warnCount = @($catFindings | Where-Object Status -eq 'WARN').Count
        $skipCount = @($catFindings | Where-Object Status -in @('SKIP', 'ERROR')).Count

        # Calculate deductions
        $deductions = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -notin @('FAIL', 'WARN')) { continue }
            $weight = $severityWeights[$f.Severity] ?? 1
            $multiplier = if ($f.Status -eq 'WARN') { 0.5 } else { 1.0 }
            $deductions += ($weight * $multiplier)
        }

        # Max possible deductions for normalization
        $maxPossible = 0.0
        foreach ($f in $catFindings) {
            if ($f.Status -in @('SKIP', 'ERROR')) { continue }
            $maxPossible += ($severityWeights[$f.Severity] ?? 1)
        }

        # If maxPossible is 0, every finding in this category was SKIP or ERROR
        # (or the category had zero findings at all because the collector failed
        # upstream). In that case we have no real data to score against — do NOT
        # treat the category as a perfect 100, which would silently inflate the
        # overall posture score whenever a collector quietly fails.
        $evaluated = $maxPossible -gt 0
        $catScore = if ($evaluated) {
            [Math]::Max(0, [Math]::Round(100 * (1 - ($deductions / $maxPossible)), 0))
        } else { 0 }

        $categoryScores[$cat.Name] = @{
            Score     = [int]$catScore
            Evaluated = $evaluated
            Pass      = $passCount
            Fail      = $failCount
            Warn      = $warnCount
            Skip      = $skipCount
            Total     = $catFindings.Count
        }
    }

    # Overall score: weighted average of category scores. Categories where nothing
    # was actually evaluated are excluded from the average — otherwise an all-skip
    # category would either inflate (old behavior, 100) or deflate (new per-cat
    # default, 0) the overall number and mislead the user.
    $totalWeight = 0.0
    $weightedSum = 0.0
    foreach ($cat in $categoryScores.GetEnumerator()) {
        if (-not $cat.Value.Evaluated) { continue }
        $catFindings = @($Findings | Where-Object { $_.Category -eq $cat.Key -and $_.Status -notin @('SKIP', 'ERROR') })
        $catWeight = 0.0
        foreach ($f in $catFindings) {
            $catWeight += ($severityWeights[$f.Severity] ?? 1)
        }
        $totalWeight += $catWeight
        $weightedSum += ($cat.Value.Score * $catWeight)
    }
    $overallScore = if ($totalWeight -gt 0) { [int][Math]::Round($weightedSum / $totalWeight, 0) } else { 0 }

    return @{
        OverallScore   = $overallScore
        CategoryScores = $categoryScores
    }
}
