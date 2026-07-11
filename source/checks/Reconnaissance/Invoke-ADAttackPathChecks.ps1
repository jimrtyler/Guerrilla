# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADAttackPathChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADAttackPathChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Recon$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# ── ADPATH-001: Escalation Paths to Tier-0 ─────────────────────────────────
function Test-ReconADPATH001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('PrivilegedMembers','ObjectACLs') -Subject 'attack-path inputs'
    if ($na) { return $na }

    $analysis = Get-ADAttackPath -AuditData $AuditData

    if (-not $analysis.DataAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available — run with the ACLDelegation (or All) category enabled to compute attack paths'
    }

    $paths = @($analysis.Paths)
    # Expected paths are by-design Tier-0 service accounts (Azure AD Connect MSOL_*),
    # already tracked by ADTIER-001 — they don't constitute a finding on their own.
    $genuine  = @($paths | Where-Object { -not $_.Expected })
    $expected = @($paths | Where-Object { $_.Expected })

    if ($genuine.Count -eq 0) {
        $cv = 'No non-default principals have control over Tier-0 objects — no one-hop escalation paths found'
        if ($expected.Count -gt 0) {
            $cv += " ($($expected.Count) expected service-account path(s) — e.g. Azure AD Connect — are tracked by ADTIER-001)"
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue $cv `
            -Details @{ PathCount = 0; ExpectedCount = $expected.Count; Paths = @($paths) }
    }

    $nonPriv = @($genuine | Where-Object { -not $_.SourceIsPrivileged })
    $preview = @($genuine | Select-Object -First 6 | ForEach-Object { $_.Path }) -join ' | '

    $currentValue = "$($genuine.Count) escalation path(s) to Tier-0"
    if ($nonPriv.Count -gt 0) {
        $currentValue += " — $($nonPriv.Count) from NON-privileged principals (highest risk)"
    }
    if ($expected.Count -gt 0) {
        $currentValue += "; plus $($expected.Count) expected service-account path(s) (see ADTIER-001)"
    }
    $currentValue += ": $preview"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            PathCount          = $genuine.Count
            NonPrivilegedCount = $nonPriv.Count
            ExpectedCount      = $expected.Count
            AffectedLabel      = 'Escalation paths to Tier-0'
            AffectedItems      = @($genuine | ForEach-Object { $_.Path })
            Paths              = @($paths)
        }
}

# ── ADPATH-002: Transitive Escalation Chains to Tier-0 ─────────────────────
function Test-ReconADPATH002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('PrivilegedMembers','ObjectACLs') -Subject 'attack-path inputs'
    if ($na) { return $na }

    $analysis = Get-ADTransitiveAttackPath -AuditData $AuditData

    if (-not $analysis.DataAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL / privileged-group data not available — run with the ACLDelegation + PrivilegedAccounts (or All) categories enabled to compute transitive chains'
    }

    # ADPATH-002 reports MULTI-HOP chains (Length > 1); single-hop control is ADPATH-001's job.
    $paths = @($analysis.Paths)
    $multi = @($paths | Where-Object { $_.Length -gt 1 })
    $multiNonPriv = @($multi | Where-Object { -not $_.SourceIsPrivileged })

    if ($multi.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No multi-hop transitive escalation chains found in the collected ACL scope (deep transitive coverage requires full-domain ACL collection — see ADPATH-002 notes)' `
            -Details @{ ChainCount = 0; SinglehopPathCount = @($paths).Count }
    }

    $preview = @($multi | Select-Object -First 5 | ForEach-Object { $_.Path }) -join ' | '
    $currentValue = "$($multi.Count) transitive escalation chain(s) to Tier-0"
    if ($multiNonPriv.Count -gt 0) {
        $currentValue += " — $($multiNonPriv.Count) from NON-privileged principals (highest risk)"
    }
    $currentValue += ": $preview"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            ChainCount         = $multi.Count
            NonPrivilegedCount = $multiNonPriv.Count
            AffectedLabel      = 'Transitive escalation chains to Tier-0'
            AffectedItems      = @($multi | ForEach-Object { $_.Path })
            Chains             = @($multi)
        }
}
