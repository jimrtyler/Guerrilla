function Get-ZeroTrustScore {
    <#
    .SYNOPSIS
        Compute a Zero Trust posture score per CISA ZTMM pillar from audit findings — and
        disclose how much coverage backs each score.

    .DESCRIPTION
        Rolls Guerrilla findings up by their ZeroTrustPillar / ZeroTrustWeight into a
        weighted posture score per pillar:

            score% = 100 * Σ(weight × credit) / Σ(weight)   over ASSESSED checks
            credit: PASS = 1.0, WARN = 0.5, FAIL = 0.0

        Only checks that produced a real verdict (PASS/FAIL/WARN) count toward a score;
        Not-Assessed (SKIP) checks are excluded from both numerator and denominator, so an
        uncollected control never quietly inflates or deflates the number.

        Every pillar also reports CoverageConfidence — Solid / Moderate / Directional — based
        on how many checks define that pillar. A pillar computed from few checks (e.g. Data)
        is flagged Directional so its score is read as indicative, not authoritative. The
        score that discloses its own density is the whole point: it cannot 200 confidently
        over a thin basis without saying so.

    .PARAMETER Finding
        Guerrilla.AuditFinding objects (pipeline). Typically the .Findings of an
        Invoke-Campaign / Invoke-Infiltration / Invoke-Reconnaissance / Invoke-Fortification
        result, e.g.  (Invoke-Infiltration ...).Findings | Get-ZeroTrustScore

    .PARAMETER DirectionalThreshold
        Pillars with fewer than this many checks are marked Directional (default 25).

    .PARAMETER SolidThreshold
        Pillars with at least this many checks are marked Solid (default 60); between the two
        thresholds is Moderate.

    .EXAMPLE
        (Invoke-Infiltration -TenantId $t).Findings | Get-ZeroTrustScore | Format-Table

    .EXAMPLE
        $r.Findings | Get-ZeroTrustScore | Where-Object CoverageConfidence -ne 'Directional'
    #>
    [CmdletBinding()]
    [OutputType('Guerrilla.ZeroTrustPillarScore')]
    param(
        [Parameter(ValueFromPipeline)]
        [object[]]$Finding,
        [int]$DirectionalThreshold = 25,
        [int]$SolidThreshold = 60
    )
    begin {
        $all = [System.Collections.Generic.List[object]]::new()
        $credit = @{ PASS = 1.0; WARN = 0.5; FAIL = 0.0 }
    }
    process {
        foreach ($f in $Finding) { if ($null -ne $f) { $all.Add($f) } }
    }
    end {
        $withPillar = @($all | Where-Object { $_.ZeroTrustPillar })
        foreach ($g in ($withPillar | Group-Object ZeroTrustPillar | Sort-Object Name)) {
            $items    = @($g.Group)
            $assessed = @($items | Where-Object { $_.Status -in 'PASS', 'FAIL', 'WARN' })
            $maxW     = [double](@($assessed | Measure-Object ZeroTrustWeight -Sum).Sum)
            $earnedW  = 0.0
            foreach ($i in $assessed) {
                $earnedW += ([double]$i.ZeroTrustWeight) * ([double]($credit["$($i.Status)"] ?? 0))
            }
            $score = if ($maxW -gt 0) { [int][math]::Round(100 * $earnedW / $maxW, 0) } else { $null }
            $conf  = if ($items.Count -lt $DirectionalThreshold) { 'Directional' }
                     elseif ($items.Count -lt $SolidThreshold)   { 'Moderate' }
                     else                                        { 'Solid' }
            [PSCustomObject]@{
                PSTypeName         = 'Guerrilla.ZeroTrustPillarScore'
                Pillar             = $g.Name
                ScorePercent       = $score
                CoverageConfidence = $conf
                AssessedChecks     = $assessed.Count
                TotalChecks        = $items.Count
                MaxWeight          = [int]$maxW
                EarnedWeight       = [math]::Round($earnedW, 1)
            }
        }
    }
}
