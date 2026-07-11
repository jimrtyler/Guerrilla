# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaMaturity {
    <#
    .SYNOPSIS
        Computes a CMMI-style 1-5 security-maturity level from audit findings.

    .DESCRIPTION
        Turns a set of Guerrilla audit findings into an executive-grade maturity rating
        (Active Directory, Google Workspace, or Entra/M365 — anything that produces findings).

        Like a maturity model should, the WORST unmet control anchors the score: a single
        open Critical caps the whole environment at Level 1 no matter how much else passes.
        This is deliberately stricter than an averaged 0-100 score — it answers "how mature
        is this estate" the way an auditor or a board reads it, and it tells you exactly which
        findings are holding you at the current level (the anchors) so advancement is concrete.

        Level model (CMMI-aligned):
          1 Initial                  - an open Critical exposure exists
          2 Managed                  - no Criticals, but open High findings
          3 Defined                  - no High, but open Medium findings
          4 Quantitatively Managed   - only Low findings / warnings remain
          5 Optimized                - no open failures or warnings

        Anchoring: FAIL caps by severity (Critical->1, High->2, Medium->3, Low->4); any WARN
        caps at 4; PASS / SKIP / ERROR never cap. The overall level is the lowest cap across
        all findings; per-category levels are computed the same way.

    .PARAMETER Findings
        Audit findings (e.g. (Invoke-Reconnaissance).Findings). Accepts pipeline input.

    .PARAMETER Theater
        Optional label carried onto the result (e.g. 'ActiveDirectory').

    .EXAMPLE
        (Invoke-Reconnaissance).Findings | Get-GuerrillaMaturity -Theater ActiveDirectory

    .EXAMPLE
        $m = Get-GuerrillaMaturity -Findings $result.Findings
        "AD maturity: Level $($m.OverallLevel) ($($m.OverallLabel))"
    #>
    [CmdletBinding()]
    [OutputType('Guerrilla.Maturity')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [object[]]$Findings,

        [string]$Theater = ''
    )

    begin { $all = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($f in $Findings) { if ($null -ne $f) { $all.Add($f) } } }
    end {
        $findings = @($all)
        # Level 0 is a sentinel: the scope produced no PASS/FAIL/WARN (everything SKIP/ERROR), so it
        # was never actually assessed — absence of evidence must NOT read as Level 5 Optimized.
        $levelLabels = @{ 0 = 'Not Assessed'; 1 = 'Initial'; 2 = 'Managed'; 3 = 'Defined'; 4 = 'Quantitatively Managed'; 5 = 'Optimized' }
        $assessedStatuses = @('PASS', 'FAIL', 'WARN')

        # The maturity ceiling a single finding imposes (lower = worse). 5 == imposes no cap.
        $capFor = {
            param($f)
            $status = "$($f.Status)"
            if ($status -notin @('FAIL', 'WARN')) { return 5 }
            if ($status -eq 'WARN') { return 4 }
            switch -regex ("$($f.Severity)") {
                '(?i)^crit' { return 1 }
                '(?i)^high' { return 2 }
                '(?i)^med'  { return 3 }
                '(?i)^low'  { return 4 }
                default     { return 3 }   # a FAIL with no/unknown severity -> Defined cap
            }
        }

        $capped = foreach ($f in $findings) { [PSCustomObject]@{ Finding = $f; Cap = (& $capFor $f) } }
        $capped = @($capped)

        $capping = @($capped | Where-Object { $_.Cap -lt 5 })
        $assessedCount = @($findings | Where-Object { "$($_.Status)" -in $assessedStatuses }).Count
        # Cast to [int] — Measure-Object -Minimum returns a double, which misses the int hashtable keys.
        # Nothing assessed -> Level 0 (Not Assessed), never 5.
        $overallLevel = if ($assessedCount -eq 0) { 0 }
                        elseif ($capping.Count -gt 0) { [int]($capping.Cap | Measure-Object -Minimum).Minimum }
                        else { 5 }
        $anchors = @($capped | Where-Object { $_.Cap -eq $overallLevel -and $_.Cap -lt 5 } | ForEach-Object { $_.Finding })

        # Per-category maturity (same worst-anchors logic within each category)
        $categoryLevels = [ordered]@{}
        $cats = @($findings | ForEach-Object { "$($_.Category)" } | Where-Object { $_ } | Select-Object -Unique | Sort-Object)
        foreach ($cat in $cats) {
            $catCapped = @($capped | Where-Object { "$($_.Finding.Category)" -eq $cat })
            $catCap = @($catCapped | Where-Object { $_.Cap -lt 5 })
            $catAssessed = @($catCapped | Where-Object { "$($_.Finding.Status)" -in $assessedStatuses }).Count
            $lvl = if ($catAssessed -eq 0) { 0 }
                   elseif ($catCap.Count -gt 0) { [int]($catCap.Cap | Measure-Object -Minimum).Minimum }
                   else { 5 }
            $categoryLevels[$cat] = [PSCustomObject]@{
                Category = $cat
                Level    = $lvl
                Label    = $levelLabels[$lvl]
                Anchors  = @($catCapped | Where-Object { $_.Cap -eq $lvl -and $_.Cap -lt 5 } | ForEach-Object { $_.Finding.CheckId })
            }
        }

        # What to fix to climb one level (the current anchors)
        $blockers = if ($overallLevel -lt 5) {
            @($anchors | ForEach-Object { "$($_.CheckId): $($_.CheckName)" } | Select-Object -Unique)
        } else { @() }

        [PSCustomObject]@{
            PSTypeName        = 'Guerrilla.Maturity'
            Theater           = $Theater
            OverallLevel      = $overallLevel
            OverallLabel      = $levelLabels[$overallLevel]
            NextLevel         = if ($overallLevel -ge 1 -and $overallLevel -lt 5) { $overallLevel + 1 } else { $null }
            NextLevelBlockers = $blockers
            Anchors           = $anchors
            AnchorCheckIds    = @($anchors | ForEach-Object { $_.CheckId } | Select-Object -Unique)
            CategoryLevels    = $categoryLevels
            Summary           = [PSCustomObject]@{
                CriticalFail = @($findings | Where-Object { $_.Status -eq 'FAIL' -and "$($_.Severity)" -match '(?i)^crit' }).Count
                HighFail     = @($findings | Where-Object { $_.Status -eq 'FAIL' -and "$($_.Severity)" -match '(?i)^high' }).Count
                MediumFail   = @($findings | Where-Object { $_.Status -eq 'FAIL' -and "$($_.Severity)" -match '(?i)^med' }).Count
                LowFail      = @($findings | Where-Object { $_.Status -eq 'FAIL' -and "$($_.Severity)" -match '(?i)^low' }).Count
                Warn         = @($findings | Where-Object { $_.Status -eq 'WARN' }).Count
                Pass         = @($findings | Where-Object { $_.Status -eq 'PASS' }).Count
            }
        }
    }
}
