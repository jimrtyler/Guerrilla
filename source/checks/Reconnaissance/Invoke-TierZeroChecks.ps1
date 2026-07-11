# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-TierZeroChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'TierZeroChecks'
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

# Substring-match helper. Compares against sAMAccountName, displayName, and description.
# Keywords are intentionally distinctive brand names (veeam, vcenter, sccm) so simple
# substring match is safe — no need for word-boundary regex gymnastics that fail on
# things like "veeamsvc" or "VeeamAdmin".
function Get-TierBleedMatchedKeyword {
    param(
        [Parameter(Mandatory)]$Member,
        [Parameter(Mandatory)][string[]]$Keywords
    )
    $haystack = "$($Member.SamAccountName) $($Member.DisplayName) $($Member.Description)".ToLower()
    foreach ($kw in $Keywords) {
        if ($haystack.Contains($kw.ToLower())) { return $kw }
    }
    return $null
}

# Get the union of members from the highest-impact privileged groups (DA/EA/SA/BO).
# The data model from Get-ADPrivilegedMembers stores per-group member lists in
# $AuditData.PrivilegedAccounts.PrivilegedGroups, keyed by friendly group label —
# each value is the flat array of normalized member hashtables (NOT wrapped in
# @{ Members = ... }).
function Get-Tier0HighPrivMembers {
    param([Parameter(Mandatory)][hashtable]$AuditData)

    $priv = $AuditData.PrivilegedAccounts
    if (-not $priv -or -not $priv.PrivilegedGroups) {
        return @()
    }

    # Group labels to scan — order matters for human-readable output (DA first).
    $targetGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Backup Operators')

    $members = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($g in $targetGroups) {
        if ($priv.PrivilegedGroups.ContainsKey($g)) {
            foreach ($m in @($priv.PrivilegedGroups[$g])) {
                $members.Add(@{
                    Group              = $g
                    SamAccountName     = $m.SamAccountName ?? ''
                    DistinguishedName  = $m.DistinguishedName ?? ''
                    DisplayName        = $m.DisplayName ?? ''
                    Description        = $m.Description ?? ''
                    ObjectClass        = $m.ObjectClass ?? ''
                    UserAccountControl = [int]($m.UserAccountControl ?? 0)
                })
            }
        }
    }
    return @($members)
}

function New-TierBleedFinding {
    param(
        [Parameter(Mandatory)][hashtable]$CheckDefinition,
        # AllowEmptyCollection so the secure/clean state (zero hits) reaches the PASS
        # branch — a Mandatory [array] rejects @() at bind time and would ERROR instead.
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Hits,
        [string]$ProductLabel
    )
    if ($Hits.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "No $ProductLabel-pattern service accounts found in highly privileged groups (DA/EA/SA/BO)" `
            -Details @{ MatchCount = 0 }
    }
    $summary = @($Hits | ForEach-Object { "$($_.Group)\$($_.SamAccountName) (matched: $($_.MatchedKeyword))" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Found $($Hits.Count) $ProductLabel-pattern account(s) in privileged groups: $summary" `
        -Details @{ MatchCount = $Hits.Count; Hits = $Hits }
}

# ── ADTIER-001: Azure AD Connect MSOL_ Account Audit ───────────────────────
function Test-ReconADTIER001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TierZeroSignals' -Subject 'Tier-Zero signals'
    if ($na) { return $na }
    $tz = $AuditData.TierZero
    if (-not $tz) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tier-Zero signal data not collected.'
    }
    $accounts = @($tz.MsolAccounts)
    if ($accounts.Count -eq 0) {
        # Genuinely "no AAD Connect" is a PASS. Could also indicate the customer renamed
        # the account (which the docs explicitly permit). Make the language reflect that.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No MSOL_ accounts found. Either AAD Connect is not deployed in this domain, or the sync account has been renamed away from the default MSOL_ pattern (verify out-of-band).' `
            -Details @{ Count = 0 }
    }

    $stalePwdDays = 365
    $issues = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $accounts) {
        if ($a.DistinguishedName -match 'CN=Users,DC=') {
            $issues.Add("$($a.SamAccountName) lives in the default CN=Users container (should be in a Tier-0 OU with logon restrictions)")
        }
        if ($null -ne $a.PasswordAgeDays -and $a.PasswordAgeDays -gt $stalePwdDays) {
            $issues.Add("$($a.SamAccountName) password is $($a.PasswordAgeDays) days old (default expiry is 10 years; rotate periodically)")
        }
    }

    if ($issues.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue ("MSOL_ account(s) found ($($accounts.Count)): " + ($issues -join '; ')) `
            -Details @{ Count = $accounts.Count; Issues = @($issues); Accounts = @($accounts) }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "MSOL_ account(s) found ($($accounts.Count)) — placement and password age are within recommended bounds. Confirm separately that the AAD Connect server itself is hardened as Tier-0." `
        -Details @{ Count = $accounts.Count; Accounts = @($accounts) }
}

# ── ADTIER-002: Backup Software Service Accounts ───────────────────────────
function Test-ReconADTIER002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }
    $keywords = @('veeam', 'commvault', 'rubrik', 'cohesity', 'nakivo', 'backupexec', 'vembu', 'acronis', 'unitrends', 'arcserve')
    $members = Get-Tier0HighPrivMembers -AuditData $AuditData
    if ($members.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged-group member data not available; ADTIER-002 needs PrivilegedAccounts category to have run.'
    }
    $hits = foreach ($m in $members) {
        $kw = Get-TierBleedMatchedKeyword -Member $m -Keywords $keywords
        if ($kw) { $m + @{ MatchedKeyword = $kw } }
    }
    return New-TierBleedFinding -CheckDefinition $CheckDefinition -Hits @($hits) -ProductLabel 'backup-software'
}

# ── ADTIER-003: Hypervisor Service Accounts ────────────────────────────────
function Test-ReconADTIER003 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }
    $keywords = @('vmware', 'vcenter', 'esxi', 'vsphere', 'hyperv', 'hyper-v', 'scvmm', 'citrix', 'xenserver', 'xenapp', 'proxmox', 'nutanix')
    $members = Get-Tier0HighPrivMembers -AuditData $AuditData
    if ($members.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged-group member data not available.'
    }
    $hits = foreach ($m in $members) {
        $kw = Get-TierBleedMatchedKeyword -Member $m -Keywords $keywords
        if ($kw) { $m + @{ MatchedKeyword = $kw } }
    }
    return New-TierBleedFinding -CheckDefinition $CheckDefinition -Hits @($hits) -ProductLabel 'hypervisor / virtualization'
}

# ── ADTIER-004: Configuration Management Service Accounts ──────────────────
function Test-ReconADTIER004 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }
    $keywords = @('sccm', 'mecm', 'configmgr', 'intune', 'jamf', 'kace', 'lansweeper', 'manageengine', 'ivanti', 'bigfix', 'tanium')
    $members = Get-Tier0HighPrivMembers -AuditData $AuditData
    if ($members.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged-group member data not available.'
    }
    $hits = foreach ($m in $members) {
        $kw = Get-TierBleedMatchedKeyword -Member $m -Keywords $keywords
        if ($kw) { $m + @{ MatchedKeyword = $kw } }
    }
    return New-TierBleedFinding -CheckDefinition $CheckDefinition -Hits @($hits) -ProductLabel 'configuration-management'
}

# ── ADTIER-005: SQL / Database Service Accounts ────────────────────────────
function Test-ReconADTIER005 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }
    $keywords = @('sqlsvc', 'sqlserver', 'mssql', 'sqlagent', 'sqlbrowser', 'mysql', 'postgres', 'oracledb')
    $members = Get-Tier0HighPrivMembers -AuditData $AuditData
    if ($members.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged-group member data not available.'
    }
    $hits = foreach ($m in $members) {
        $kw = Get-TierBleedMatchedKeyword -Member $m -Keywords $keywords
        if ($kw) { $m + @{ MatchedKeyword = $kw } }
    }
    return New-TierBleedFinding -CheckDefinition $CheckDefinition -Hits @($hits) -ProductLabel 'database / SQL'
}

# ── ADTIER-006: Tier-0 Admins Outside Dedicated Admin OU ───────────────────
function Test-ReconADTIER006 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }
    $members = Get-Tier0HighPrivMembers -AuditData $AuditData
    # Strip BO from this check — backup operators are not technically tier-0 admins.
    $members = @($members | Where-Object { $_.Group -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins') })
    # De-duplicate by DN (a user can be in multiple groups)
    $unique = @($members | Group-Object DistinguishedName | ForEach-Object { $_.Group[0] })

    if ($unique.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No DA/EA/SA member data available.'
    }

    # Heuristic: a "Tier-0 OU" path contains the literal "tier" or "tier-0" or "tier 0" or "admin" early in the DN.
    # Computer/builtin accounts are excluded (those live elsewhere by design).
    $offenders = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($m in $unique) {
        if ($m.ObjectClass -eq 'computer') { continue }
        if ($m.SamAccountName -eq 'Administrator') { continue }  # built-in lives in Users by default
        $dn = $m.DistinguishedName.ToLower()
        $inAdminOu = $dn -match 'ou=(tier-?0|admin|t0|secure)'
        if (-not $inAdminOu) {
            $offenders.Add($m)
        }
    }

    if ($offenders.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'All Tier-0 admins live under an OU that names itself "Tier-0" or "Admin" (or similar)' `
            -Details @{ Count = $unique.Count }
    }

    $summary = @($offenders | Select-Object -First 10 | ForEach-Object { "$($_.SamAccountName) at $($_.DistinguishedName)" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($offenders.Count) Tier-0 admin(s) not in a dedicated admin OU: $summary" `
        -Details @{ Count = $offenders.Count; Offenders = @($offenders) }
}

# ── ADTIER-007: Service-named accounts in privileged groups ────────────────
function Test-ReconADTIER007 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }
    $members = Get-Tier0HighPrivMembers -AuditData $AuditData
    if ($members.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged-group member data not available.'
    }

    # Service-account heuristics: sAMAccountName prefix or suffix conventions.
    $isServiceish = {
        param($Name)
        $n = $Name.ToLower()
        return ($n -match '^(svc|sa|service|srv)[-_.]') -or `
               ($n -match '[-_.](svc|sa|service|srv)$') -or `
               ($n -match '^s_') -or `
               ($n -match '_svc$')
    }

    $hits = @($members | Where-Object {
        $_.ObjectClass -ne 'computer' -and (& $isServiceish $_.SamAccountName)
    })

    if ($hits.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No service-named accounts (svc-*, *-svc, s_*, *_svc) in DA/EA/SA/BO' `
            -Details @{ MatchCount = 0 }
    }
    $summary = @($hits | ForEach-Object { "$($_.Group)\$($_.SamAccountName)" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($hits.Count) service-named account(s) in highly privileged groups: $summary. Service accounts should never be interactive-logon-capable principals." `
        -Details @{ MatchCount = $hits.Count; Hits = @($hits) }
}
