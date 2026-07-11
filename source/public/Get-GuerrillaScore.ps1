# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaScore {
    <#
    .SYNOPSIS
        Returns the composite Guerrilla Security Score (0-100) with breakdown.
    .DESCRIPTION
        Computes a single 0-100 security score from audit findings, threat scan results,
        theater coverage, and trend data. Uses the active baseline profile (Default or K12)
        for component weights and thresholds.

        Score tiers:
          FORTRESS (90+)  |  DEFENDED POSITION (75-89)  |  CONTESTED GROUND (60-74)
          EXPOSED FLANK (40-59)  |  UNDER SIEGE (20-39)  |  OVERRUN (0-19)

    .PARAMETER AuditFindings
        Array of audit finding objects from Fortification/Reconnaissance theaters.
        If not provided, reads the latest state file.
    .PARAMETER ScanResults
        Array of scan result objects from Surveillance/Watchtower theaters.
        If not provided, reads the latest state files.
    .PARAMETER ProfileName
        Baseline profile to use: Default or K12. If not specified, uses the profile
        configured in Set-Safehouse, falling back to Default.
    .PARAMETER ConfigPath
        Override config file path.
    .EXAMPLE
        Get-GuerrillaScore
        Returns the composite score using latest scan data and configured profile.
    .EXAMPLE
        Get-GuerrillaScore -ProfileName K12
        Returns the score using K-12 education baseline weights.
    .EXAMPLE
        $findings = Invoke-Fortification -PassThru; Get-GuerrillaScore -AuditFindings $findings
        Computes score from specific audit findings.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$AuditFindings,
        [PSCustomObject[]]$ScanResults,

        [ValidateSet('Default', 'K12')]
        [string]$ProfileName,

        [Alias('RuntimeConfig')]
        [string]$ConfigPath
    )

    # Load config
    $cfgPath = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }
    $config = $null
    if ($cfgPath -and (Test-Path $cfgPath)) {
        $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
    }

    # Determine profile
    if (-not $ProfileName) {
        $ProfileName = $config.profile ?? 'Default'
    }

    $profileFile = switch ($ProfileName) {
        'K12'     { 'K12-Baseline.json' }
        default   { 'Default-Baseline.json' }
    }

    $profilePath = Join-Path $script:ModuleRoot 'Data/Profiles' $profileFile
    $profile = $null
    if (Test-Path $profilePath) {
        $profile = Get-Content -Path $profilePath -Raw | ConvertFrom-Json -AsHashtable
    }

    # Load state data if not provided
    $dataDir = Get-GuerrillaDataRoot

    if (-not $AuditFindings) {
        # Try to load from latest state files
        $auditStateFiles = @()
        if (Test-Path $dataDir) {
            $auditStateFiles = @(Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)
        }
        if ($auditStateFiles.Count -gt 0) {
            $AuditFindings = @()
            foreach ($f in $auditStateFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $AuditFindings += @($data)
                } catch {
                    Write-Verbose "Failed to load findings from $($f.Name): $_"
                }
            }
        }
    }

    if (-not $ScanResults) {
        $stateFiles = @()
        if (Test-Path $dataDir) {
            $stateFiles = @(Get-ChildItem -Path $dataDir -Filter '*.state.json' -ErrorAction SilentlyContinue)
        }
        if ($stateFiles.Count -gt 0) {
            $ScanResults = @()
            foreach ($f in $stateFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $ScanResults += $data
                } catch {
                    Write-Verbose "Failed to load state from $($f.Name): $_"
                }
            }
        }
    }

    # Load previous score for trend
    $previousScore = -1
    $scoreHistoryPath = Join-Path $dataDir 'guerrilla-score-history.json'
    if (Test-Path $scoreHistoryPath) {
        try {
            $history = Get-Content -Path $scoreHistoryPath -Raw | ConvertFrom-Json -AsHashtable
            if ($history.lastScore -is [double] -or $history.lastScore -is [int]) {
                $previousScore = [double]$history.lastScore
            }
        } catch { }
    }

    # Calculate composite score
    $scoreResult = Get-GuerrillaScoreCalculation `
        -AuditFindings $AuditFindings `
        -ScanResults $ScanResults `
        -PreviousScore $previousScore `
        -Profile $profile

    # Save score history
    if (-not (Test-Path $dataDir)) { New-Item -Path $dataDir -ItemType Directory -Force | Out-Null }
    @{
        lastScore    = $scoreResult.Score
        lastLabel    = $scoreResult.Label
        timestamp    = [datetime]::UtcNow.ToString('o')
        profileUsed  = $ProfileName
    } | ConvertTo-Json -Depth 3 | Set-Content -Path $scoreHistoryPath -Encoding UTF8

    return $scoreResult
}
