# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaScoreCalculation {
    <#
    .SYNOPSIS
        Computes the composite Guerrilla Security Score (0-100).
    .DESCRIPTION
        Calculates a weighted composite score from three components:
          - Posture (70%): Audit posture scores from AD, Entra, and GWS findings
          - Coverage (15%): Percentage of the three assessment platforms with findings
          - Trend (15%): Score delta from previous run (improving = bonus)

        The retired Threats component scored monitoring detections; with the
        monitoring subsystem removed, keeping it would have silently awarded
        full credit for threats never assessed. Nothing in this score reflects
        data that was not collected.
    .PARAMETER AuditFindings
        Array of audit finding objects (from the AD, Entra, and GWS audits).
    .PARAMETER PreviousScore
        Previous Guerrilla Score for trend calculation. If not provided, trend is neutral.
    .PARAMETER Profile
        Baseline profile hashtable with component weights. Uses default weights if not provided.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$AuditFindings,
        [double]$PreviousScore = -1,
        [hashtable]$Profile
    )

    # Component weights from profile or defaults. Ignore any profile that still
    # carries the retired threats weight so old config cannot dilute the score.
    $weights = @{ posture = 0.70; coverage = 0.15; trend = 0.15 }
    $pw = $Profile.guerrillaScore.componentWeights
    if ($pw -and $pw.posture -and $pw.coverage -and $pw.trend -and -not $pw.threats) {
        $weights = $pw
    }

    # --- Component 1: Posture Score (0-100) ---
    # Default 0, not 100: an empty finding set means nothing was assessed, and
    # "not assessed" must never render as a perfect posture.
    $postureScore = 0
    if ($AuditFindings -and $AuditFindings.Count -gt 0) {
        $postureResult = Get-AuditPostureScore -Findings $AuditFindings
        $postureScore = [Math]::Max(0, [Math]::Min(100, $postureResult.OverallScore))
    }

    # --- Component 2: Coverage Score (0-100) over the three assessment platforms ---
    # Prefix note: GWS's ADMIN-* collides with a bare ^AD match, so the AD
    # pattern enumerates the real AD families instead.
    # A platform counts as active only if at least one of its findings was actually
    # ASSESSED (PASS/FAIL/WARN). An all-SKIP platform contributed no evidence and
    # must not earn Coverage credit — absence of evidence is not coverage.
    $assessedStatuses = @('PASS', 'FAIL', 'WARN')
    $activePlatforms = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($AuditFindings -and $AuditFindings.Count -gt 0) {
        $platformPatterns = @{
            'Active Directory' = '^AD(ACL|CS|DOM|GPO|KERB|LOG|NET|PATH|PRIV|PWD|SCRIPT|STALE|TIER|TRADE|TRUST)-'
            'Entra ID / M365'  = '^(EID|EIDSCA|M365|AZIAM|INTUNE|AIAGENT)'
            'Google Workspace' = '^(AUTH|ADMIN|COLLAB|DEVICE|DRIVE|EMAIL|GROUP|GTRADE|GWS|LOG|OAUTH)-'
        }
        foreach ($name in $platformPatterns.Keys) {
            $assessed = @($AuditFindings | Where-Object {
                $_.CheckId -match $platformPatterns[$name] -and $_.Status -in $assessedStatuses
            })
            if ($assessed.Count -gt 0) {
                $activePlatforms.Add($name) | Out-Null
            }
        }
    }
    $coverageScore = [int][Math]::Round(100 * ($activePlatforms.Count / 3), 0)

    # --- Component 3: Trend Score (0-100) ---
    $trendScore = 50  # Neutral default
    if ($PreviousScore -ge 0) {
        $currentRaw = [Math]::Round(
            ($postureScore * $weights.posture + $coverageScore * $weights.coverage) /
            ($weights.posture + $weights.coverage), 0
        )
        $delta = $currentRaw - $PreviousScore
        # Map delta to 0-100: +20 or more = 100, -20 or less = 0, linear between
        $trendScore = [Math]::Max(0, [Math]::Min(100, [int][Math]::Round(50 + ($delta * 2.5), 0)))
    }

    # --- Composite Score ---
    $compositeScore = [int][Math]::Round(
        ($postureScore * $weights.posture) +
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
            Coverage = [PSCustomObject]@{ Score = $coverageScore; Weight = $weights.coverage; Weighted = [int][Math]::Round($coverageScore * $weights.coverage, 0) }
            Trend    = [PSCustomObject]@{ Score = $trendScore;    Weight = $weights.trend;    Weighted = [int][Math]::Round($trendScore * $weights.trend, 0) }
        }
        ActivePlatforms = @($activePlatforms)
        PreviousScore  = if ($PreviousScore -ge 0) { $PreviousScore } else { $null }
        Timestamp      = [datetime]::UtcNow
    }
}
