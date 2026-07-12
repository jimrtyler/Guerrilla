# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

function Get-GuerrillaEvidenceHash {
    <#
    .SYNOPSIS
        Deterministic SHA256 over a finding's evidence (CurrentValue + Details).
    .DESCRIPTION
        The run history stores verdicts and evidence hashes, never raw evidence
        values, so the history file cannot leak what the report contains. The
        hash is deterministic: Details keys are sorted before serialization so
        the same evidence always produces the same hash across runs.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][string]$CurrentValue,
        [AllowNull()]$Details
    )
    $detailText = ''
    if ($null -ne $Details) {
        try {
            if ($Details -is [System.Collections.IDictionary]) {
                $ordered = [ordered]@{}
                foreach ($k in ($Details.Keys | Sort-Object { "$_" })) { $ordered["$k"] = $Details[$k] }
                $detailText = $ordered | ConvertTo-Json -Depth 6 -Compress
            } else {
                $detailText = $Details | ConvertTo-Json -Depth 6 -Compress
            }
        } catch {
            $detailText = "$Details"
        }
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("$CurrentValue`n$detailText")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-GuerrillaTargetHash {
    <#
    .SYNOPSIS
        Privacy-preserving identity for the assessed target(s).
    .DESCRIPTION
        A SHA256 over the normalized (lowercased, sorted) target identifiers so
        run history can refuse to compare different tenants/domains without
        storing the tenant or domain name itself.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$TargetId)
    $normalized = ($TargetId | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Sort-Object) -join '|'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function ConvertTo-GuerrillaRunVerdict {
    <#
    .SYNOPSIS
        Normalize a finding Status to the four run-record verdicts.
    .DESCRIPTION
        PASS/FAIL/WARN pass through; SKIP and ERROR are both "Not Assessed"
        (absence of evidence is never a best case). Anything else throws:
        an unknown status silently mapped is a silent diff waiting to happen.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Status)
    switch ($Status.ToUpperInvariant()) {
        'PASS'  { return 'PASS' }
        'FAIL'  { return 'FAIL' }
        'WARN'  { return 'WARN' }
        'SKIP'  { return 'Not Assessed' }
        'ERROR' { return 'Not Assessed' }
        default { throw "Unknown finding status '$Status': refusing to guess a run-record verdict." }
    }
}

function New-GuerrillaRunRecord {
    <#
    .SYNOPSIS
        Build the run record persisted after a completed assessment.
    .DESCRIPTION
        Pure builder: findings in, record out; writes nothing. The record is
        small enough to keep forever (verdicts, hashes, and scores; no raw
        evidence) and carries everything Compare-GuerrillaRun needs: per-check
        verdict + evidence hash, module version, platforms, overall and
        per-Zero-Trust-pillar scores, and the Not Assessed count.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][PSCustomObject[]]$Findings,
        [Parameter(Mandatory)][string[]]$Platforms,
        [Parameter(Mandatory)][string[]]$TargetId,
        [Parameter(Mandatory)][string]$ScanId,
        [AllowNull()][Nullable[int]]$OverallScore,

        # OU scope is part of the run's comparison-series identity: a run scoped
        # to an OU (collection scope) or carrying a student-OU designation is
        # never comparable to a whole-tenant run — the differences would surface
        # as false drift. Defaults mirror what pre-scope records implied.
        [string]$TargetOu = '/',
        [AllowNull()][AllowEmptyCollection()][string[]]$StudentOu = @()
    )

    $moduleVersion = "$($ExecutionContext.SessionState.Module.Version)"
    if (-not $moduleVersion -or $moduleVersion -eq '') {
        $moduleVersion = "$((Import-PowerShellDataFile (Join-Path $script:ModuleRoot 'Guerrilla.psd1')).ModuleVersion)"
    }

    $checks = foreach ($f in $Findings) {
        [ordered]@{
            checkId          = "$($f.CheckId)"
            orgUnitPath      = "$($f.OrgUnitPath)"
            verdict          = ConvertTo-GuerrillaRunVerdict -Status "$($f.Status)"
            rawStatus        = "$($f.Status)"
            severity         = "$($f.Severity)"
            category         = "$($f.Category)"
            zeroTrustPillar  = "$($f.ZeroTrustPillar)"
            zeroTrustWeight  = $f.ZeroTrustWeight
            evidenceHash     = Get-GuerrillaEvidenceHash -CurrentValue "$($f.CurrentValue)" -Details $f.Details
        }
    }
    $checks = @($checks)

    # Per-pillar scores from the same engine the report uses.
    $pillarScores = [ordered]@{}
    if ($Findings.Count -gt 0) {
        foreach ($p in ($Findings | Get-ZeroTrustScore)) {
            $pillarScores["$($p.Pillar)"] = $p.ScorePercent
        }
    }

    $verdictGroups = @{}
    foreach ($c in $checks) { $verdictGroups[$c.verdict] = 1 + ($verdictGroups[$c.verdict] ?? 0) }

    [ordered]@{
        schemaVersion    = 1
        tool             = 'Guerrilla'
        moduleVersion    = $moduleVersion
        generatedAt      = [datetime]::UtcNow.ToString('o')
        runId            = "$ScanId"
        scope            = [ordered]@{
            platforms  = @($Platforms | Sort-Object)
            targetHash = Get-GuerrillaTargetHash -TargetId $TargetId
            targetOu   = ("$TargetOu".Trim() ? "$TargetOu".Trim() : '/')
            studentOus = @(ConvertTo-GuerrillaStudentOuList -StudentOu $StudentOu)
        }
        overallScore     = $OverallScore
        pillarScores     = $pillarScores
        summary          = [ordered]@{
            total       = $checks.Count
            pass        = [int]($verdictGroups['PASS'] ?? 0)
            fail        = [int]($verdictGroups['FAIL'] ?? 0)
            warn        = [int]($verdictGroups['WARN'] ?? 0)
            notAssessed = [int]($verdictGroups['Not Assessed'] ?? 0)
        }
        checks           = $checks
    }
}
