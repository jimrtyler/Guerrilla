# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaScoreCalculation {
    <#
    .SYNOPSIS
        Computes the composite Guerrilla Security Score (0-100).
    .DESCRIPTION
        Calculates a weighted composite score from four components:
          - Posture (40%): Audit posture scores from AD + Cloud findings
          - Threats (30%): Inverse normalized threat count, weighted by severity
          - Coverage (15%): Percentage of theaters actively monitored
          - Trend (15%): Score delta from previous scan (improving = bonus)
    .PARAMETER AuditFindings
        Array of audit finding objects (from Fortification/Reconnaissance theaters).
    .PARAMETER ScanResults
        Array of scan result objects from all theaters.
    .PARAMETER PreviousScore
        Previous Guerrilla Score for trend calculation. If not provided, trend is neutral.
    .PARAMETER Profile
        Baseline profile hashtable with component weights. Uses default weights if not provided.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$AuditFindings,
        [PSCustomObject[]]$ScanResults,
        [double]$PreviousScore = -1,
        [hashtable]$Profile
    )

    # Component weights from profile or defaults
    $weights = if ($Profile.guerrillaScore.componentWeights) {
        $Profile.guerrillaScore.componentWeights
    } else {
        @{ posture = 0.40; threats = 0.30; coverage = 0.15; trend = 0.15 }
    }

    # --- Component 1: Posture Score (0-100) ---
    $postureScore = 100
    if ($AuditFindings -and $AuditFindings.Count -gt 0) {
        $postureResult = Get-AuditPostureScore -Findings $AuditFindings
        $postureScore = [Math]::Max(0, [Math]::Min(100, $postureResult.OverallScore))
    }

    # --- Component 2: Threat Score (0-100, inverse normalized) ---
    $threatScore = 100
    $threatSeverityWeights = @{
        'CRITICAL' = 20
        'HIGH'     = 10
        'MEDIUM'   = 4
        'LOW'      = 1
    }
    $maxThreatBudget = 200  # Weighted threat count that maps to score 0

    if ($ScanResults -and $ScanResults.Count -gt 0) {
        $weightedThreatCount = 0.0
        foreach ($result in $ScanResults) {
            $weightedThreatCount += ($result.CriticalCount ?? 0) * $threatSeverityWeights['CRITICAL']
            $weightedThreatCount += ($result.HighCount ?? 0) * $threatSeverityWeights['HIGH']
            $weightedThreatCount += ($result.MediumCount ?? 0) * $threatSeverityWeights['MEDIUM']
            $weightedThreatCount += ($result.LowCount ?? 0) * $threatSeverityWeights['LOW']
        }
        $threatScore = [Math]::Max(0, [Math]::Round(100 * (1 - ($weightedThreatCount / $maxThreatBudget)), 0))
    }

    # --- Component 3: Coverage Score (0-100) ---
    $allTheaters = @('Fortification', 'Reconnaissance', 'Surveillance', 'Watchtower')
    $activeTheaters = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($AuditFindings -and $AuditFindings.Count -gt 0) {
        # Fortification = AD checks, Reconnaissance = Cloud checks
        $hasAD = @($AuditFindings | Where-Object { $_.CheckId -match '^AD' }).Count -gt 0
        $hasCloud = @($AuditFindings | Where-Object { $_.CheckId -match '^(AUTH|ADMIN|EMAIL|COLLAB|DRIVE|OAUTH|DEVICE|LOG|EID|M365|AZIAM|INTUNE)' }).Count -gt 0
        if ($hasAD) { $activeTheaters.Add('Fortification') | Out-Null }
        if ($hasCloud) { $activeTheaters.Add('Reconnaissance') | Out-Null }
    }

    if ($ScanResults -and $ScanResults.Count -gt 0) {
        foreach ($result in $ScanResults) {
            $theater = $result.Theater ?? $result.PSObject.TypeNames[0]
            if ($theater -match 'Surveillance') { $activeTheaters.Add('Surveillance') | Out-Null }
            if ($theater -match 'Watchtower') { $activeTheaters.Add('Watchtower') | Out-Null }
            if ($theater -match 'Wiretap') { $activeTheaters.Add('Wiretap') | Out-Null }
        }
    }

    $coverageScore = if ($allTheaters.Count -gt 0) {
        [int][Math]::Round(100 * ($activeTheaters.Count / $allTheaters.Count), 0)
    } else { 0 }

    # --- Component 4: Trend Score (0-100) ---
    $trendScore = 50  # Neutral default
    if ($PreviousScore -ge 0) {
        $currentRaw = [Math]::Round(
            ($postureScore * $weights.posture + $threatScore * $weights.threats + $coverageScore * $weights.coverage) /
            ($weights.posture + $weights.threats + $weights.coverage), 0
        )
        $delta = $currentRaw - $PreviousScore
        # Map delta to 0-100: +20 or more = 100, -20 or less = 0, linear between
        $trendScore = [Math]::Max(0, [Math]::Min(100, [int][Math]::Round(50 + ($delta * 2.5), 0)))
    }

    # --- Composite Score ---
    $compositeScore = [int][Math]::Round(
        ($postureScore * $weights.posture) +
        ($threatScore * $weights.threats) +
        ($coverageScore * $weights.coverage) +
        ($trendScore * $weights.trend),
        0
    )
    $compositeScore = [Math]::Max(0, [Math]::Min(100, $compositeScore))

    $label = Get-GuerrillaScoreLabel -Score $compositeScore

    return [PSCustomObject]@{
        PSTypeName    = 'Guerrilla.GuerrillaScore'
        Score         = $compositeScore
        Label         = $label.Label
        LabelColor    = $label.Color
        Components    = [PSCustomObject]@{
            Posture  = [PSCustomObject]@{ Score = $postureScore;  Weight = $weights.posture;  Weighted = [int][Math]::Round($postureScore * $weights.posture, 0) }
            Threats  = [PSCustomObject]@{ Score = $threatScore;   Weight = $weights.threats;  Weighted = [int][Math]::Round($threatScore * $weights.threats, 0) }
            Coverage = [PSCustomObject]@{ Score = $coverageScore; Weight = $weights.coverage; Weighted = [int][Math]::Round($coverageScore * $weights.coverage, 0) }
            Trend    = [PSCustomObject]@{ Score = $trendScore;    Weight = $weights.trend;    Weighted = [int][Math]::Round($trendScore * $weights.trend, 0) }
        }
        ActiveTheaters = @($activeTheaters)
        PreviousScore  = if ($PreviousScore -ge 0) { $PreviousScore } else { $null }
        Timestamp      = [datetime]::UtcNow
    }
}
