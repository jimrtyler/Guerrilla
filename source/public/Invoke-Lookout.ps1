# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-Lookout {
    <#
    .SYNOPSIS
        Continuous Google Workspace security-posture (configuration-drift) monitoring.

    .DESCRIPTION
        Invoke-Lookout is the Google Workspace theater of Guerrilla's continuous-monitoring
        suite (alongside Invoke-Surveillance for Entra sign-in risk, Invoke-Watchtower for
        Active Directory baseline change, and Invoke-Wiretap for M365 audit logs).

        It runs the read-only Fortification posture audit, stores the result as a baseline,
        and on each subsequent run diffs the current posture against that baseline — surfacing
        newly-FAILing controls (drift) and controls that have been resolved, plus the change in
        the overall posture score. It complements Invoke-Recon (which watches user *behaviour*
        for compromise) by watching the tenant's *configuration* for regressions.

        The first run establishes the baseline (no drift reported). Subsequent runs report the
        delta. This makes NO changes to Google Workspace — it only reads policy/config (the
        same read-only collection Invoke-Fortification performs) and writes local state.

        Pair with Register-Patrol to run it on a schedule with alert dispatch; new failures are
        surfaced on the result's .NewThreats so the patrol alert wiring picks them up.

    .PARAMETER ServiceAccountKeyPath
        Path to the Google service-account JSON key. Falls back to config/vault if omitted.

    .PARAMETER AdminEmail
        Delegated super-admin to impersonate. Falls back to config/vault if omitted.

    .PARAMETER TargetOU
        Org-unit path to audit. Default: '/'.

    .PARAMETER ScanMode
        Fast (skips the slow per-user Gmail crawl, via Fortification -Quick) or Full. Default: Fast.

    .PARAMETER Force
        Re-establish the baseline from the current posture instead of diffing against the stored one.

    .EXAMPLE
        Invoke-Lookout
        # First run establishes the Google Workspace posture baseline.

    .EXAMPLE
        Invoke-Lookout -ScanMode Full
        # Subsequent run; reports controls that newly FAIL (drift) and ones that were resolved.

    .NOTES
        Baseline state is stored under the per-user Guerrilla data root (theater 'workspace').
        Read-only against Google Workspace.
    #>
    [CmdletBinding()]
    param(
        [string]$ServiceAccountKeyPath,
        [string]$AdminEmail,
        [string]$TargetOU = '/',
        [switch]$IncludeChildOUs,

        [ValidateSet('Fast', 'Full')]
        [string]$ScanMode = 'Fast',

        [string]$OutputDirectory,
        [switch]$Force,
        [switch]$NoReports,
        [switch]$Quiet,

        [Alias('RuntimeConfig')]
        [string]$ConfigPath,

        [Alias('MissionConfig')]
        [string]$ConfigFile,

        [string]$VaultName = 'Guerrilla'
    )

    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $scanId = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $timestamp = [datetime]::UtcNow
    $timestampStr = $timestamp.ToString('yyyy-MM-dd_HHmmss')

    if (-not $Quiet) {
        $target = if ($AdminEmail) { $AdminEmail } else { '(config/vault)' }
        try { Write-OperationHeader -Operation 'LOOKOUT SWEEP' -Mode $ScanMode -Target $target } catch { }
    }

    # ── 1. Collect current Google Workspace posture (read-only) ────────────────
    if (-not $Quiet) { try { Write-ProgressLine -Phase SCANNING -Message 'Collecting Google Workspace posture snapshot' -Detail "($ScanMode mode)" } catch { } }

    $fortParams = @{ Quiet = $true; NoReports = $true; TargetOU = $TargetOU; VaultName = $VaultName }
    if ($PSBoundParameters.ContainsKey('ServiceAccountKeyPath')) { $fortParams.ServiceAccountKeyPath = $ServiceAccountKeyPath }
    if ($PSBoundParameters.ContainsKey('AdminEmail'))            { $fortParams.AdminEmail = $AdminEmail }
    if ($ConfigPath)     { $fortParams.ConfigPath = $ConfigPath }
    if ($ConfigFile)     { $fortParams.ConfigFile = $ConfigFile }
    if ($IncludeChildOUs) { $fortParams.IncludeChildOUs = $true }
    if ($ScanMode -eq 'Fast') { $fortParams.Quick = $true }

    $fort = Invoke-Fortification @fortParams
    $findings = @($fort.Findings)
    $currentScore = if ($null -ne $fort.OverallScore) { $fort.OverallScore } else { 0 }

    if ($findings.Count -eq 0) {
        if (-not $Quiet) { Write-Warning 'LOOKOUT: Fortification returned no findings (no Workspace connection / credentials?). Nothing to baseline.' }
        return [PSCustomObject]@{
            PSTypeName           = 'Guerrilla.LookoutResult'
            ScanId               = $scanId
            Timestamp            = $timestamp
            Theater              = 'GoogleWorkspace'
            ScanMode             = $ScanMode
            BaselineEstablished  = $false
            TotalChangesDetected = 0
            CriticalCount = 0; HighCount = 0; MediumCount = 0; LowCount = 0
            NewThreats = @(); NewFailures = @(); Resolved = @()
            ScoreChange = 0; CurrentScore = 0; PreviousScore = 0
            ReportPaths = @{}
        }
    }

    # Lowercase-keyed projection for storage — Compare-FortificationState reads the previous
    # side via .checkId/.status/.orgUnitPath (the JSON-round-tripped shape).
    $storeFindings = @($findings | ForEach-Object {
        @{
            checkId      = $_.CheckId
            checkName    = $_.CheckName
            category     = $_.Category
            severity     = $_.Severity
            status       = $_.Status
            currentValue = $_.CurrentValue
            orgUnitPath  = $_.OrgUnitPath
        }
    })

    # ── 2. Load theater state ──────────────────────────────────────────────────
    $theaterState = Get-TheaterState -Theater 'workspace' -ConfigPath $cfgPath
    $isFirstRun = $null -eq $theaterState

    # ── 3. First run / Force: establish baseline and return ────────────────────
    if ($isFirstRun -or $Force) {
        $newState = @{
            schemaVersion    = 1
            theater          = 'workspace'
            findings         = $storeFindings
            overallScore     = $currentScore
            lastScanId       = $scanId
            lastScanTimestamp = $timestamp.ToString('o')
            scanHistory      = @(@{
                scanId = $scanId; timestamp = $timestamp.ToString('o'); mode = $ScanMode
                result = 'baseline_established'; changes = 0
            })
        }
        Save-TheaterState -Theater 'workspace' -State $newState -ConfigPath $cfgPath

        if (-not $Quiet) {
            $reason = if ($Force) { 'Force flag set' } else { 'First run' }
            try {
                Write-ProgressLine -Phase SCANNING -Message "Baseline established ($reason)" -Detail "score: $currentScore"
                Write-Host ''
                Write-GuerrillaText ('=' * 62) -Color Dim
                Write-GuerrillaText '  LOOKOUT: Workspace baseline saved. No comparison performed.' -Color Sage
                Write-GuerrillaText '  Run again to detect configuration drift against this baseline.' -Color Dim
                Write-GuerrillaText ('=' * 62) -Color Dim
            } catch { Write-Host "LOOKOUT: Workspace baseline established ($reason); score $currentScore." }
        }

        return [PSCustomObject]@{
            PSTypeName           = 'Guerrilla.LookoutResult'
            ScanId               = $scanId
            Timestamp            = $timestamp
            Theater              = 'GoogleWorkspace'
            ScanMode             = $ScanMode
            BaselineEstablished  = $true
            TotalChangesDetected = 0
            CriticalCount = 0; HighCount = 0; MediumCount = 0; LowCount = 0
            NewThreats = @(); NewFailures = @(); Resolved = @()
            ScoreChange = 0; CurrentScore = $currentScore; PreviousScore = $currentScore
            ReportPaths = @{}
        }
    }

    # ── 4. Diff current posture against baseline ───────────────────────────────
    if (-not $Quiet) { try { Write-ProgressLine -Phase ANALYZING -Message 'Comparing posture against baseline' } catch { } }

    $drift = Compare-FortificationState -CurrentFindings $findings -PreviousState $theaterState
    $newFailures = @($drift.NewFailures)
    $resolved    = @($drift.Resolved)

    # New failures become .NewThreats so Register-Patrol's alert wiring picks them up.
    $newThreats = @($newFailures | ForEach-Object {
        [PSCustomObject]@{
            DetectionId    = $_.CheckId
            DetectionName  = $_.CheckName
            Severity       = $_.Severity
            Description    = $_.CurrentValue
            OrgUnitPath    = $_.OrgUnitPath
            PreviousStatus = $_.PreviousStatus
            IsNew          = $true
        }
    })

    $criticalCount = @($newFailures | Where-Object { "$($_.Severity)" -match '(?i)^crit' }).Count
    $highCount     = @($newFailures | Where-Object { "$($_.Severity)" -match '(?i)^high' }).Count
    $mediumCount   = @($newFailures | Where-Object { "$($_.Severity)" -match '(?i)^med'  }).Count
    $lowCount      = @($newFailures | Where-Object { "$($_.Severity)" -match '(?i)^low'  }).Count

    # ── 5. Save updated baseline ───────────────────────────────────────────────
    $theaterState['findings']         = $storeFindings
    $theaterState['overallScore']     = $currentScore
    $theaterState['lastScanId']       = $scanId
    $theaterState['lastScanTimestamp'] = $timestamp.ToString('o')
    $theaterState['scanHistory']      = @($theaterState.scanHistory) + @(@{
        scanId = $scanId; timestamp = $timestamp.ToString('o'); mode = $ScanMode
        result = if ($newFailures.Count -gt 0) { 'drift_detected' } else { 'clean' }
        changes = $newFailures.Count
    })
    Save-TheaterState -Theater 'workspace' -State $theaterState -ConfigPath $cfgPath

    # ── 6. Console summary ─────────────────────────────────────────────────────
    if (-not $Quiet) {
        try {
            $arrow = if ($drift.ScoreChange -gt 0) { "+$($drift.ScoreChange)" } else { "$($drift.ScoreChange)" }
            Write-ProgressLine -Phase REPORTING -Message "Drift: $($newFailures.Count) new failure(s), $($resolved.Count) resolved" -Detail "score $($drift.PreviousScore) -> $($drift.CurrentScore) ($arrow)"
        } catch {
            Write-Host "LOOKOUT: $($newFailures.Count) new failure(s), $($resolved.Count) resolved; score $($drift.PreviousScore) -> $($drift.CurrentScore)."
        }
    }

    # ── 7. Optional JSON drift report ──────────────────────────────────────────
    $reportPaths = @{}
    if (-not $NoReports -and $newFailures.Count -gt 0) {
        $outDir = if ($OutputDirectory) { $OutputDirectory } else { Join-Path (Get-GuerrillaDataRoot) 'Reports' }
        if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
        $jsonPath = Join-Path $outDir "lookout_workspace_${timestampStr}.json"
        @{
            scanId        = $scanId
            timestamp     = $timestamp.ToString('o')
            theater       = 'GoogleWorkspace'
            scanMode      = $ScanMode
            previousScore = $drift.PreviousScore
            currentScore  = $drift.CurrentScore
            scoreChange   = $drift.ScoreChange
            newFailures   = @($newFailures)
            resolved      = @($resolved)
        } | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonPath -Encoding utf8
        $reportPaths['json'] = $jsonPath
        if (-not $Quiet) { try { Write-ProgressLine -Phase REPORTING -Message 'Drift report exported' -Detail $jsonPath } catch { } }
    }

    # ── 8. Return result ───────────────────────────────────────────────────────
    return [PSCustomObject]@{
        PSTypeName           = 'Guerrilla.LookoutResult'
        ScanId               = $scanId
        Timestamp            = $timestamp
        Theater              = 'GoogleWorkspace'
        ScanMode             = $ScanMode
        BaselineEstablished  = $false
        TotalChangesDetected = $newFailures.Count
        CriticalCount = $criticalCount; HighCount = $highCount; MediumCount = $mediumCount; LowCount = $lowCount
        NewThreats   = @($newThreats)
        NewFailures  = @($newFailures)
        Resolved     = @($resolved)
        ScoreChange  = $drift.ScoreChange
        CurrentScore = $drift.CurrentScore
        PreviousScore = $drift.PreviousScore
        ReportPaths  = $reportPaths
    }
}
