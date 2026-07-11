# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADPrivilegedAccountChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADPrivilegedAccountChecks'
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

# ═════════════════════════════════════════════════════════════════════════════
# Helper: Get the privileged groups hashtable safely
# ═════════════════════════════════════════════════════════════════════════════

function Get-PrivilegedGroupMembers {
    [CmdletBinding()]
    param(
        [hashtable]$AuditData,
        [string]$GroupName
    )

    if (-not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        return @()
    }

    $groups = $AuditData.PrivilegedAccounts.PrivilegedGroups
    if ($groups.Contains($GroupName)) {
        return @($groups[$GroupName])
    }

    return @()
}

# ═════════════════════════════════════════════════════════════════════════════
# Helper: Get all privileged members deduplicated across all groups
# ═════════════════════════════════════════════════════════════════════════════

function Get-AllPrivilegedMembers {
    [CmdletBinding()]
    param([hashtable]$AuditData)

    # Use the pre-computed AllPrivilegedUsers list if available
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.AllPrivilegedUsers) {
        return @($AuditData.PrivilegedAccounts.AllPrivilegedUsers)
    }

    # Fallback: manually deduplicate across all groups
    if (-not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        return @()
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $members = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($groupName in $AuditData.PrivilegedAccounts.PrivilegedGroups.Keys) {
        foreach ($member in @($AuditData.PrivilegedAccounts.PrivilegedGroups[$groupName])) {
            if (-not $member) { continue }
            $dn = $member.DistinguishedName
            if (-not $dn -or $seen.Contains($dn)) { continue }
            if ($member.ObjectClass -eq 'group' -or $member.IsGroup) { continue }
            [void]$seen.Add($dn)
            $members.Add($member)
        }
    }

    return @($members)
}

# ═════════════════════════════════════════════════════════════════════════════
# Helper: Format member list for details output
# ═════════════════════════════════════════════════════════════════════════════

function Format-MemberDetail {
    [CmdletBinding()]
    param([array]$Members)

    return @($Members | ForEach-Object {
        @{
            SamAccountName = $_.SamAccountName
            Enabled        = $_.Enabled
            ObjectClass    = $_.ObjectClass
        }
    })
}

# ── ADPRIV-001: Domain Admins Enumeration ─────────────────────────────────
function Test-ReconADPRIV001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'Domain Admins'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('Domain Admins'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain Admins group data not available'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $groupMembers = @($members | Where-Object { $_.ObjectClass -eq 'group' -or $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    $status = if ($totalCount -le 3) { 'PASS' }
              elseif ($totalCount -le 5) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "Domain Admins has $totalCount effective member(s)"
    if ($groupMembers.Count -gt 0) {
        $currentValue += " (plus $($groupMembers.Count) nested group(s))"
    }

    $memberNames = @($effectiveMembers | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MemberCount      = $totalCount
            NestedGroupCount = $groupMembers.Count
            Members          = Format-MemberDetail -Members $effectiveMembers
            MemberNames      = $memberNames
        }
}

# ── ADPRIV-002: Enterprise Admins Enumeration ─────────────────────────────
function Test-ReconADPRIV002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'Enterprise Admins'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('Enterprise Admins'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Enterprise Admins group data not available'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    $status = if ($totalCount -eq 0) { 'PASS' }
              elseif ($totalCount -le 2) { 'WARN' }
              else { 'FAIL' }

    $currentValue = if ($totalCount -eq 0) {
        'Enterprise Admins group is empty (recommended state)'
    } else {
        "Enterprise Admins has $totalCount member(s). This group should be empty during normal operations"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MemberCount = $totalCount
            Members     = Format-MemberDetail -Members $effectiveMembers
        }
}

# ── ADPRIV-003: Schema Admins Enumeration ─────────────────────────────────
function Test-ReconADPRIV003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'Schema Admins'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('Schema Admins'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Schema Admins group data not available'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    $status = if ($totalCount -eq 0) { 'PASS' }
              elseif ($totalCount -eq 1) { 'WARN' }
              else { 'FAIL' }

    $currentValue = if ($totalCount -eq 0) {
        'Schema Admins group is empty (recommended state)'
    } else {
        "Schema Admins has $totalCount member(s). This group should be empty during normal operations"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MemberCount = $totalCount
            Members     = Format-MemberDetail -Members $effectiveMembers
        }
}

# ── ADPRIV-004: Account Operators Enumeration ─────────────────────────────
function Test-ReconADPRIV004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'Account Operators'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('Account Operators'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Account Operators group data not available'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    $status = if ($totalCount -eq 0) { 'PASS' } else { 'FAIL' }

    $currentValue = if ($totalCount -eq 0) {
        'Account Operators group is empty (recommended)'
    } else {
        "Account Operators has $totalCount member(s). This group should be empty; use delegated OU-level permissions instead"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MemberCount = $totalCount
            Members     = Format-MemberDetail -Members $effectiveMembers
        }
}

# ── ADPRIV-005: Server Operators Enumeration ──────────────────────────────
function Test-ReconADPRIV005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'Server Operators'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('Server Operators'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Server Operators group data not available'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    $status = if ($totalCount -eq 0) { 'PASS' } else { 'FAIL' }

    $currentValue = if ($totalCount -eq 0) {
        'Server Operators group is empty (recommended)'
    } else {
        "Server Operators has $totalCount member(s). This group should be empty; members can escalate privileges on DCs"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MemberCount = $totalCount
            Members     = Format-MemberDetail -Members $effectiveMembers
        }
}

# ── ADPRIV-006: Backup Operators Enumeration ──────────────────────────────
function Test-ReconADPRIV006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'Backup Operators'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('Backup Operators'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Backup Operators group data not available'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    $status = if ($totalCount -eq 0) { 'PASS' } else { 'FAIL' }

    $currentValue = if ($totalCount -eq 0) {
        'Backup Operators group is empty (recommended)'
    } else {
        "Backup Operators has $totalCount member(s). Members can extract the AD database (ntds.dit) containing all password hashes"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MemberCount = $totalCount
            Members     = Format-MemberDetail -Members $effectiveMembers
        }
}

# ── ADPRIV-007: Print Operators Enumeration ───────────────────────────────
function Test-ReconADPRIV007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'Print Operators'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('Print Operators'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Print Operators group data not available'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    $status = if ($totalCount -eq 0) { 'PASS' } else { 'WARN' }

    $currentValue = if ($totalCount -eq 0) {
        'Print Operators group is empty (recommended)'
    } else {
        "Print Operators has $totalCount member(s). Members can load printer drivers on DCs which can execute as SYSTEM"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MemberCount = $totalCount
            Members     = Format-MemberDetail -Members $effectiveMembers
        }
}

# ── ADPRIV-008: DnsAdmins Group Membership ────────────────────────────────
function Test-ReconADPRIV008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $members = Get-PrivilegedGroupMembers -AuditData $AuditData -GroupName 'DnsAdmins'
    if ($members.Count -eq 0 -and (
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups.Contains('DnsAdmins'))) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DnsAdmins group data not available (group may not exist in this domain)'
    }

    $effectiveMembers = @($members | Where-Object { $_.ObjectClass -ne 'group' -and -not $_.IsGroup })
    $totalCount = $effectiveMembers.Count

    if ($totalCount -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'DnsAdmins group is empty (recommended)' `
            -Details @{ MemberCount = 0 }
    }

    # Any members in DnsAdmins is a concern — this group can load arbitrary DLLs on DC DNS service
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "DnsAdmins has $totalCount member(s). Members can configure the DNS service to load an arbitrary DLL as SYSTEM on DCs" `
        -Details @{
            MemberCount = $totalCount
            Members     = Format-MemberDetail -Members $effectiveMembers
        }
}

# ── ADPRIV-009: Nested Group Membership Analysis ──────────────────────────
function Test-ReconADPRIV009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    if (-not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged group data not available'
    }

    $groups = $AuditData.PrivilegedAccounts.PrivilegedGroups
    $nestedGroups = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($groupName in $groups.Keys) {
        $members = @($groups[$groupName])
        $groupObjects = @($members | Where-Object { $_.ObjectClass -eq 'group' -or $_.IsGroup })

        foreach ($nested in $groupObjects) {
            $nestedGroups.Add(@{
                ParentGroup       = $groupName
                NestedGroupName   = $nested.SamAccountName
                DistinguishedName = $nested.DistinguishedName
            })
        }
    }

    if ($nestedGroups.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No nested group memberships found in privileged groups' `
            -Details @{ NestedGroupCount = 0 }
    }

    $summary = @($nestedGroups | ForEach-Object {
        "$($_.NestedGroupName) in $($_.ParentGroup)"
    }) -join '; '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($nestedGroups.Count) nested group(s) found in privileged groups: $summary" `
        -Details @{
            NestedGroupCount = $nestedGroups.Count
            NestedGroups     = @($nestedGroups)
        }
}

# ── ADPRIV-010: Privileged Users Password Never Expires ───────────────────
function Test-ReconADPRIV010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    $flaggedAccounts = @($allPriv | Where-Object {
        $_.UACFlags -and $_.UACFlags.DONT_EXPIRE_PASSWORD -eq $true
    })

    if ($flaggedAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "None of the $($allPriv.Count) privileged account(s) have Password Never Expires set" `
            -Details @{ TotalPrivileged = $allPriv.Count; FlaggedCount = 0 }
    }

    $accountNames = @($flaggedAccounts | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($flaggedAccounts.Count) privileged account(s) have Password Never Expires: $accountNames" `
        -Details @{
            TotalPrivileged = $allPriv.Count
            FlaggedCount    = $flaggedAccounts.Count
            FlaggedAccounts = @($flaggedAccounts | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled }
            })
        }
}

# ── ADPRIV-011: Privileged Users Password Not Required ────────────────────
function Test-ReconADPRIV011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    $flaggedAccounts = @($allPriv | Where-Object {
        $_.UACFlags -and $_.UACFlags.PASSWD_NOTREQD -eq $true
    })

    if ($flaggedAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "None of the $($allPriv.Count) privileged account(s) have PASSWD_NOTREQD set" `
            -Details @{ TotalPrivileged = $allPriv.Count; FlaggedCount = 0 }
    }

    $accountNames = @($flaggedAccounts | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($flaggedAccounts.Count) privileged account(s) have PASSWD_NOTREQD flag (can have blank password): $accountNames" `
        -Details @{
            TotalPrivileged = $allPriv.Count
            FlaggedCount    = $flaggedAccounts.Count
            FlaggedAccounts = @($flaggedAccounts | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled }
            })
        }
}

# ── ADPRIV-012: Privileged Users No Kerberos Pre-Auth ─────────────────────
function Test-ReconADPRIV012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    $flaggedAccounts = @($allPriv | Where-Object {
        $_.UACFlags -and $_.UACFlags.DONT_REQ_PREAUTH -eq $true
    })

    if ($flaggedAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "None of the $($allPriv.Count) privileged account(s) have Kerberos pre-authentication disabled" `
            -Details @{ TotalPrivileged = $allPriv.Count; FlaggedCount = 0 }
    }

    $accountNames = @($flaggedAccounts | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($flaggedAccounts.Count) privileged account(s) are vulnerable to AS-REP Roasting (no pre-auth): $accountNames" `
        -Details @{
            TotalPrivileged = $allPriv.Count
            FlaggedCount    = $flaggedAccounts.Count
            FlaggedAccounts = @($flaggedAccounts | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled }
            })
        }
}

# ── ADPRIV-013: Privileged Users Reversible Encryption ────────────────────
function Test-ReconADPRIV013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    $flaggedAccounts = @($allPriv | Where-Object {
        $_.UACFlags -and $_.UACFlags.ENCRYPTED_TEXT_PWD_ALLOWED -eq $true
    })

    if ($flaggedAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "None of the $($allPriv.Count) privileged account(s) have reversible encryption enabled" `
            -Details @{ TotalPrivileged = $allPriv.Count; FlaggedCount = 0 }
    }

    $accountNames = @($flaggedAccounts | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($flaggedAccounts.Count) privileged account(s) store passwords with reversible encryption (equivalent to cleartext): $accountNames" `
        -Details @{
            TotalPrivileged = $allPriv.Count
            FlaggedCount    = $flaggedAccounts.Count
            FlaggedAccounts = @($flaggedAccounts | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled }
            })
        }
}

# ── ADPRIV-014: Privileged Users DES-Only Kerberos ────────────────────────
function Test-ReconADPRIV014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    $flaggedAccounts = @($allPriv | Where-Object {
        $_.UACFlags -and $_.UACFlags.USE_DES_KEY_ONLY -eq $true
    })

    if ($flaggedAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "None of the $($allPriv.Count) privileged account(s) are restricted to DES-only Kerberos encryption" `
            -Details @{ TotalPrivileged = $allPriv.Count; FlaggedCount = 0 }
    }

    $accountNames = @($flaggedAccounts | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($flaggedAccounts.Count) privileged account(s) use DES-only Kerberos encryption (cryptographically broken): $accountNames" `
        -Details @{
            TotalPrivileged = $allPriv.Count
            FlaggedCount    = $flaggedAccounts.Count
            FlaggedAccounts = @($flaggedAccounts | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled }
            })
        }
}

# ── ADPRIV-015: Privileged Accounts No MFA Indicator ──────────────────────
function Test-ReconADPRIV015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    # Filter to user accounts only (not computers)
    $userAccounts = @($allPriv | Where-Object {
        $_.ObjectClass -eq 'user' -or
        $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' -or
        $_.ObjectClass -eq 'msDS-ManagedServiceAccount'
    })

    if ($userAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged user accounts found to evaluate'
    }

    $smartcardRequired = @($userAccounts | Where-Object {
        $_.UACFlags -and $_.UACFlags.SMARTCARD_REQUIRED -eq $true
    })

    $noSmartcard = @($userAccounts | Where-Object {
        -not $_.UACFlags -or $_.UACFlags.SMARTCARD_REQUIRED -ne $true
    })

    if ($noSmartcard.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($userAccounts.Count) privileged user account(s) require smart card for interactive logon" `
            -Details @{
                TotalPrivilegedUsers = $userAccounts.Count
                SmartcardRequired    = $smartcardRequired.Count
            }
    }

    $status = if ($smartcardRequired.Count -eq 0) { 'FAIL' } else { 'WARN' }
    $accountNames = @($noSmartcard | ForEach-Object { $_.SamAccountName }) -join ', '

    $currentValue = "$($noSmartcard.Count) of $($userAccounts.Count) privileged account(s) do not require smart card logon: $accountNames"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            TotalPrivilegedUsers     = $userAccounts.Count
            SmartcardRequired        = $smartcardRequired.Count
            WithoutSmartcardCount    = $noSmartcard.Count
            AccountsWithoutSmartcard = @($noSmartcard | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled }
            })
        }
}

# ── ADPRIV-016: Privileged Accounts Weak Passwords ────────────────────────
function Test-ReconADPRIV016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordHashQuality' -Subject 'privileged password strength analysis'
    if ($na) { return $na }

    # Check if password analysis data is available (requires DSInternals or similar)
    $privData = $AuditData.PrivilegedAccounts
    $pwdAnalysis = $null

    if ($privData -and $privData.ContainsKey('PasswordAnalysis')) {
        $pwdAnalysis = $privData.PasswordAnalysis
    } elseif ($AuditData.ContainsKey('PasswordAnalysis')) {
        $pwdAnalysis = $AuditData.PasswordAnalysis
    }

    if ($null -eq $pwdAnalysis) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Password strength analysis not available. This check requires DSInternals or offline ntds.dit analysis to compare password hashes against known weak password dictionaries' `
            -Details @{
                Note = 'Run Test-PasswordQuality from DSInternals module against ntds.dit to identify weak passwords among privileged accounts'
            }
    }

    # If password analysis data is available, evaluate it
    $weakAccounts = @()

    if ($pwdAnalysis -is [hashtable] -and $pwdAnalysis.ContainsKey('WeakPasswords')) {
        $weakAccounts = @($pwdAnalysis.WeakPasswords)
    } elseif ($pwdAnalysis -is [array]) {
        $weakAccounts = @($pwdAnalysis)
    }

    if ($weakAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No privileged accounts found with weak passwords' `
            -Details @{ WeakPasswordCount = 0 }
    }

    $accountNames = @($weakAccounts | ForEach-Object {
        if ($_ -is [hashtable] -and $_.ContainsKey('SamAccountName')) { $_.SamAccountName } else { "$_" }
    }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($weakAccounts.Count) privileged account(s) have weak or commonly used passwords: $accountNames" `
        -Details @{
            WeakPasswordCount = $weakAccounts.Count
            WeakAccounts      = @($weakAccounts)
        }
}

# ── ADPRIV-017: Privileged Accounts Old Passwords ─────────────────────────
function Test-ReconADPRIV017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    $now = [datetime]::UtcNow
    $threshold = 365  # days

    $oldPasswordAccounts = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($member in $allPriv) {
        if (-not $member.PwdLastSet) { continue }

        $pwdLastSet = $member.PwdLastSet
        $ageDays = -1

        if ($pwdLastSet -is [datetime]) {
            $ageDays = ($now - $pwdLastSet).TotalDays
        } elseif ($pwdLastSet -is [long] -or $pwdLastSet -is [int64]) {
            if ($pwdLastSet -eq 0 -or $pwdLastSet -eq [int64]::MaxValue) { continue }
            try {
                $pwdDate = [datetime]::FromFileTimeUtc($pwdLastSet)
                $ageDays = ($now - $pwdDate).TotalDays
            } catch { continue }
        } else {
            continue
        }

        if ($ageDays -gt $threshold) {
            $oldPasswordAccounts.Add(@{
                SamAccountName = $member.SamAccountName
                PwdAgeDays     = [math]::Round($ageDays, 0)
                Enabled        = $member.Enabled
            })
        }
    }

    if ($oldPasswordAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($allPriv.Count) privileged account(s) have passwords changed within the last $threshold days" `
            -Details @{ TotalPrivileged = $allPriv.Count; OldPasswordCount = 0 }
    }

    $accountSummary = @($oldPasswordAccounts | ForEach-Object {
        "$($_.SamAccountName) ($($_.PwdAgeDays)d)"
    }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($oldPasswordAccounts.Count) privileged account(s) have passwords older than $threshold days: $accountSummary" `
        -Details @{
            TotalPrivileged     = $allPriv.Count
            OldPasswordCount    = $oldPasswordAccounts.Count
            ThresholdDays       = $threshold
            OldPasswordAccounts = @($oldPasswordAccounts)
        }
}

# ── ADPRIV-018: Privileged Accounts Never Logged In ───────────────────────
function Test-ReconADPRIV018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData
    if ($allPriv.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No privileged member data available'
    }

    $neverLoggedIn = @($allPriv | Where-Object {
        $null -eq $_.LastLogonTimestamp -or
        ($_.LastLogonTimestamp -is [long] -and $_.LastLogonTimestamp -eq 0) -or
        ($_.LastLogonTimestamp -is [string] -and [string]::IsNullOrWhiteSpace($_.LastLogonTimestamp))
    })

    if ($neverLoggedIn.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($allPriv.Count) privileged account(s) have logged in at least once" `
            -Details @{ TotalPrivileged = $allPriv.Count; NeverLoggedInCount = 0 }
    }

    $accountNames = @($neverLoggedIn | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($neverLoggedIn.Count) privileged account(s) have never logged in: $accountNames" `
        -Details @{
            TotalPrivileged    = $allPriv.Count
            NeverLoggedInCount = $neverLoggedIn.Count
            NeverLoggedIn      = @($neverLoggedIn | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled; ObjectClass = $_.ObjectClass }
            })
        }
}

# ── ADPRIV-019: Disabled Accounts in Privileged Groups ────────────────────
function Test-ReconADPRIV019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    if (-not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged group data not available'
    }

    $groups = $AuditData.PrivilegedAccounts.PrivilegedGroups
    $disabledInGroups = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($groupName in $groups.Keys) {
        $members = @($groups[$groupName])
        $disabled = @($members | Where-Object {
            ($_.ObjectClass -ne 'group' -and -not $_.IsGroup) -and
            $_.Enabled -eq $false
        })

        foreach ($d in $disabled) {
            $disabledInGroups.Add(@{
                SamAccountName = $d.SamAccountName
                Group          = $groupName
                ObjectClass    = $d.ObjectClass
            })
        }
    }

    if ($disabledInGroups.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No disabled accounts found in privileged groups' `
            -Details @{ DisabledCount = 0 }
    }

    $summary = @($disabledInGroups | ForEach-Object {
        "$($_.SamAccountName) in $($_.Group)"
    }) -join '; '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($disabledInGroups.Count) disabled account(s) found in privileged groups: $summary" `
        -Details @{
            DisabledCount    = $disabledInGroups.Count
            DisabledAccounts = @($disabledInGroups)
        }
}

# ── ADPRIV-020: AdminSDHolder Protected Object Audit ──────────────────────
function Test-ReconADPRIV020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $adminSDHolder = $null
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.ContainsKey('AdminSDHolderACL')) {
        $adminSDHolder = $AuditData.PrivilegedAccounts.AdminSDHolderACL
    }

    if ($null -eq $adminSDHolder) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'AdminSDHolder ACL data not available'
    }

    # Default well-known SIDs that should have ACEs on AdminSDHolder
    $defaultSids = @(
        'S-1-5-18'      # SYSTEM
        'S-1-5-32-544'  # Administrators
        'S-1-5-9'       # Enterprise Domain Controllers
        'S-1-3-0'       # Creator Owner
        'S-1-5-10'      # Self
    )

    # Well-known domain-relative RIDs that are expected
    $defaultRids = @('500', '512', '516', '518', '519', '498')

    $nonDefaultAces = [System.Collections.Generic.List[string]]::new()
    $totalAces = 0

    try {
        $acl = $null
        if ($adminSDHolder -is [System.DirectoryServices.ActiveDirectorySecurity]) {
            $acl = $adminSDHolder
        }

        if ($acl) {
            $accessRules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

            foreach ($ace in $accessRules) {
                $totalAces++
                $sidString = $ace.IdentityReference.Value

                # Check if this is a known default SID
                $isDefault = $sidString -in $defaultSids

                # Also allow domain SID-relative principals with known RIDs
                if (-not $isDefault -and $sidString -match '-(\d+)$') {
                    $rid = $Matches[1]
                    if ($rid -in $defaultRids) {
                        $isDefault = $true
                    }
                }

                if (-not $isDefault) {
                    $nonDefaultAces.Add("$sidString ($($ace.ActiveDirectoryRights) - $($ace.AccessControlType))")
                }
            }
        } else {
            # Raw bytes or unparseable — report as WARN
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue 'AdminSDHolder ACL was collected but could not be fully parsed. Manual review recommended using Get-ACL on CN=AdminSDHolder,CN=System,<DomainDN>' `
                -Details @{ RawData = $true }
        }
    } catch {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "AdminSDHolder ACL parsing failed: $_. Manual review recommended" `
            -Details @{ Error = "$_" }
    }

    if ($nonDefaultAces.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($nonDefaultAces.Count) non-default ACE(s) found on AdminSDHolder (total $totalAces ACEs). Non-default entries: $($nonDefaultAces -join '; ')" `
            -Details @{
                TotalACEs       = $totalAces
                NonDefaultCount = $nonDefaultAces.Count
                NonDefaultACEs  = @($nonDefaultAces)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "AdminSDHolder ACL contains $totalAces ACE(s), all matching expected defaults" `
        -Details @{
            TotalACEs       = $totalAces
            NonDefaultCount = 0
        }
}

# ── ADPRIV-021: AdminCount Orphans ────────────────────────────────────────
function Test-ReconADPRIV021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $orphans = $null
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.ContainsKey('AdminCountOrphans')) {
        $orphans = @($AuditData.PrivilegedAccounts.AdminCountOrphans)
    }

    if ($null -eq $orphans) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'AdminCount orphan data not available'
    }

    # Filter out null entries
    $validOrphans = @($orphans | Where-Object { $null -ne $_ })

    if ($validOrphans.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No adminCount orphans found. All accounts with adminCount=1 are current members of protected groups' `
            -Details @{ OrphanCount = 0 }
    }

    $orphanNames = @($validOrphans | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($validOrphans.Count) account(s) have adminCount=1 but are not in any protected group: $orphanNames" `
        -Details @{
            OrphanCount = $validOrphans.Count
            Orphans     = @($validOrphans | ForEach-Object {
                @{
                    SamAccountName    = $_.SamAccountName
                    DistinguishedName = $_.DistinguishedName
                    Enabled           = $_.Enabled
                }
            })
        }
}

# ── ADPRIV-022: krbtgt Password Age ──────────────────────────────────────
function Test-ReconADPRIV022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $krbtgt = $null
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.ContainsKey('KrbtgtAccount')) {
        $krbtgt = $AuditData.PrivilegedAccounts.KrbtgtAccount
    }

    if (-not $krbtgt) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'krbtgt account data not available'
    }

    $pwdAgeDays = -1
    if ($krbtgt.ContainsKey('PwdAgeDays')) {
        $pwdAgeDays = [double]$krbtgt.PwdAgeDays
    } elseif ($krbtgt.PwdLastSet) {
        $pwdLastSet = $krbtgt.PwdLastSet
        if ($pwdLastSet -is [datetime]) {
            $pwdAgeDays = ([datetime]::UtcNow - $pwdLastSet).TotalDays
        } elseif ($pwdLastSet -is [long] -or $pwdLastSet -is [int64]) {
            if ($pwdLastSet -ne 0 -and $pwdLastSet -ne [int64]::MaxValue) {
                try {
                    $pwdDate = [datetime]::FromFileTimeUtc($pwdLastSet)
                    $pwdAgeDays = ([datetime]::UtcNow - $pwdDate).TotalDays
                } catch { }
            }
        }
    }

    if ($pwdAgeDays -lt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'krbtgt password age could not be determined' `
            -Details @{ KrbtgtAccount = $krbtgt }
    }

    $roundedAge = [math]::Round($pwdAgeDays, 0)

    $status = if ($roundedAge -le 180) { 'PASS' }
              elseif ($roundedAge -le 365) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "krbtgt password age: $roundedAge days"
    if ($roundedAge -gt 180) {
        $currentValue += '. Password should be rotated (twice, with replication time between resets) at least every 180 days'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            PwdAgeDays       = $roundedAge
            KeyVersionNumber = if ($krbtgt.ContainsKey('KeyVersionNumber')) { $krbtgt.KeyVersionNumber } else { 'Unknown' }
            PwdLastSet       = $krbtgt.PwdLastSet
        }
}

# ── ADPRIV-023: krbtgt Account Exposure Assessment ───────────────────────
function Test-ReconADPRIV023 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $krbtgt = $null
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.ContainsKey('KrbtgtAccount')) {
        $krbtgt = $AuditData.PrivilegedAccounts.KrbtgtAccount
    }

    if (-not $krbtgt) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'krbtgt account data not available'
    }

    $pwdAgeDays = if ($krbtgt.ContainsKey('PwdAgeDays')) {
        [math]::Round([double]$krbtgt.PwdAgeDays, 0)
    } else { 'Unknown' }

    $kvno = if ($krbtgt.ContainsKey('KeyVersionNumber')) { $krbtgt.KeyVersionNumber } else { 'Unknown' }
    $isDisabled = if ($krbtgt.UACFlags) { $krbtgt.UACFlags.ACCOUNTDISABLE } else { 'Unknown' }

    $exposureDetails = [System.Collections.Generic.List[string]]::new()

    # krbtgt should be disabled (it is by default)
    if ($isDisabled -eq $false) {
        $exposureDetails.Add('krbtgt account is ENABLED (should be disabled)')
    }

    # Check if DES encryption types might be configured
    if ($krbtgt.UACFlags -and $krbtgt.UACFlags.USE_DES_KEY_ONLY -eq $true) {
        $exposureDetails.Add('krbtgt is configured for DES-only encryption')
    }

    $currentValue = "krbtgt account status: Disabled=$isDisabled, Password age=$pwdAgeDays days, Key version=$kvno"

    if ($exposureDetails.Count -gt 0) {
        $currentValue += ". Exposure indicators: $($exposureDetails -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                Disabled         = $isDisabled
                PwdAgeDays       = $pwdAgeDays
                KeyVersionNumber = $kvno
                ExposureItems    = @($exposureDetails)
                WhenCreated      = $krbtgt.WhenCreated
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            Disabled         = $isDisabled
            PwdAgeDays       = $pwdAgeDays
            KeyVersionNumber = $kvno
            ExposureItems    = @()
            WhenCreated      = $krbtgt.WhenCreated
        }
}

# ── ADPRIV-024: Service Accounts in Privileged Groups ─────────────────────
function Test-ReconADPRIV024 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    if (-not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged group data not available'
    }

    $groups = $AuditData.PrivilegedAccounts.PrivilegedGroups
    $serviceAccountsInGroups = [System.Collections.Generic.List[hashtable]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    foreach ($groupName in $groups.Keys) {
        $members = @($groups[$groupName])

        foreach ($member in $members) {
            if (-not $member) { continue }
            if ($member.ObjectClass -eq 'group' -or $member.IsGroup) { continue }

            $isServiceAccount = $false

            # Check IsServiceAccount flag from the collector
            if ($member.ContainsKey('IsServiceAccount') -and $member.IsServiceAccount) {
                $isServiceAccount = $true
            }

            # Check by object class (gMSA, sMSA)
            if ($member.ObjectClass -eq 'msDS-GroupManagedServiceAccount' -or
                $member.ObjectClass -eq 'msDS-ManagedServiceAccount') {
                $isServiceAccount = $true
            }

            # Check SamAccountName patterns commonly used for service accounts
            if ($member.SamAccountName -match '^svc[_\-\.]' -or
                $member.SamAccountName -match '[_\-\.]svc$' -or
                $member.SamAccountName -match '^sa[_\-]' -or
                $member.SamAccountName -match '^service[_\-]') {
                $isServiceAccount = $true
            }

            # Check if the account has SPNs (indicates it acts as a service)
            if ($member.ContainsKey('ServicePrincipalName') -and
                @($member.ServicePrincipalName).Count -gt 0) {
                $isServiceAccount = $true
            }

            if ($isServiceAccount) {
                # Deduplicate: same account may appear in multiple groups
                $dedupeKey = "$($member.SamAccountName)|$groupName"
                if ($seen.Contains($dedupeKey)) { continue }
                [void]$seen.Add($dedupeKey)

                $serviceAccountsInGroups.Add(@{
                    SamAccountName = $member.SamAccountName
                    Group          = $groupName
                    ObjectClass    = $member.ObjectClass
                    HasSPNs        = ($member.ContainsKey('ServicePrincipalName') -and @($member.ServicePrincipalName).Count -gt 0)
                    Enabled        = $member.Enabled
                })
            }
        }
    }

    if ($serviceAccountsInGroups.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No service accounts detected in privileged groups' `
            -Details @{ ServiceAccountCount = 0 }
    }

    $summary = @($serviceAccountsInGroups | ForEach-Object {
        "$($_.SamAccountName) in $($_.Group)"
    }) -join '; '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($serviceAccountsInGroups.Count) service account(s) found in privileged groups: $summary" `
        -Details @{
            ServiceAccountCount = $serviceAccountsInGroups.Count
            ServiceAccounts     = @($serviceAccountsInGroups)
        }
}

# ── ADPRIV-025: Computer Accounts in Privileged Groups ────────────────────
function Test-ReconADPRIV025 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    if (-not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged group data not available'
    }

    $groups = $AuditData.PrivilegedAccounts.PrivilegedGroups
    $computersInGroups = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($groupName in $groups.Keys) {
        $members = @($groups[$groupName])
        $computers = @($members | Where-Object {
            $_.ObjectClass -eq 'computer' -or $_.IsComputer
        })

        foreach ($comp in $computers) {
            $computersInGroups.Add(@{
                SamAccountName    = $comp.SamAccountName
                Group             = $groupName
                DistinguishedName = $comp.DistinguishedName
            })
        }
    }

    if ($computersInGroups.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No computer accounts found in privileged groups' `
            -Details @{ ComputerAccountCount = 0 }
    }

    $summary = @($computersInGroups | ForEach-Object {
        "$($_.SamAccountName) in $($_.Group)"
    }) -join '; '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($computersInGroups.Count) computer account(s) found in privileged groups: $summary" `
        -Details @{
            ComputerAccountCount = $computersInGroups.Count
            ComputerAccounts     = @($computersInGroups)
        }
}

# ═════════════════════════════════════════════════════════════════════════════
# Helper: evaluate a parsed User Rights Assignment from the DC-OU GptTmpl.inf.
# Returns a finding for ADPRIV-026/027.
#   * $null right (template not read)      => SKIP (Not Assessed; never PASS).
#   * any principal with IsExpected=$false => FAIL.
#   * only expected Tier-0 admins          => PASS.
# (MITRE T1078.002 / T1021.001; ANSSI dc_inappropriate_logon_rights; CIS URA.)
# ═════════════════════════════════════════════════════════════════════════════
function Resolve-DCLogonRightFinding {
    [CmdletBinding()]
    param(
        [hashtable]$AuditData,
        [hashtable]$CheckDefinition,
        [string]$RightField,     # 'InteractiveLogon' or 'RemoteInteractiveLogon'
        [string]$RightLabel,     # human label for messages
        [string]$ManualHint
    )

    $ura = $null
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.ContainsKey('UserRightsAssignment')) {
        $ura = $AuditData.PrivilegedAccounts.UserRightsAssignment
    }

    # Collector never ran, or the GptTmpl.inf could not be read at all.
    if ($null -eq $ura -or -not ($ura -is [hashtable]) -or $null -eq $ura[$RightField]) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "$RightLabel on domain controllers could not be assessed: the Domain Controllers OU security template (GptTmpl.inf) was not readable. Not Assessed." `
            -Details @{
                Note       = 'Requires SYSVOL read access to the Domain Controllers OU GPO security template.'
                ManualStep = $ManualHint
            }
    }

    $principals = @($ura[$RightField])
    $nonTier0   = @($principals | Where-Object { -not $_.IsExpected })

    $allNames = @($principals | ForEach-Object {
        if ($_.Name) { $_.Name } elseif ($_.Sid) { $_.Sid } else { 'unknown' }
    })

    if ($nonTier0.Count -gt 0) {
        $badNames = @($nonTier0 | ForEach-Object {
            if ($_.Name) { $_.Name } elseif ($_.Sid) { $_.Sid } else { 'unknown' }
        })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($nonTier0.Count) non-Tier-0 principal(s) hold $RightLabel on domain controllers: $($badNames -join ', ')" `
            -Details @{
                Right              = $RightField
                NonTier0Count      = $nonTier0.Count
                NonTier0Principals = @($badNames)
                AllPrincipals      = @($allNames)
                TemplatesRead      = @($ura.TemplatesRead)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$RightLabel on domain controllers is restricted to expected Tier-0 administrators ($($allNames -join ', '))" `
        -Details @{
            Right         = $RightField
            AllPrincipals = @($allNames)
            TemplatesRead = @($ura.TemplatesRead)
        }
}

# ── ADPRIV-026: Privileged Users Local Logon on DCs ──────────────────────
function Test-ReconADPRIV026 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # SeInteractiveLogonRight ("Allow log on locally") on the Domain Controllers OU.
    return Resolve-DCLogonRightFinding -AuditData $AuditData -CheckDefinition $CheckDefinition `
        -RightField 'InteractiveLogon' `
        -RightLabel 'local (interactive) logon rights' `
        -ManualHint 'Run gpresult /H report.html on a DC and review Allow log on locally on the Domain Controllers OU GPO'
}

# ── ADPRIV-027: Privileged Users RDP on DCs ──────────────────────────────
function Test-ReconADPRIV027 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # SeRemoteInteractiveLogonRight ("Allow log on through Remote Desktop Services").
    return Resolve-DCLogonRightFinding -AuditData $AuditData -CheckDefinition $CheckDefinition `
        -RightField 'RemoteInteractiveLogon' `
        -RightLabel 'Remote Desktop (RDP) logon rights' `
        -ManualHint 'Run gpresult /H report.html on a DC and review Allow log on through Remote Desktop Services on the Domain Controllers OU GPO'
}

# ── ADPRIV-028: Users with DCSync Rights ──────────────────────────────────
function Test-ReconADPRIV028 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'DCSync rights inputs'
    if ($na) { return $na }

    # DCSync requires two extended rights on the domain root:
    # DS-Replication-Get-Changes       = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
    # DS-Replication-Get-Changes-All   = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2

    # Check if DCSync analysis was pre-computed by a domain ACL collector
    $dcsyncAccounts = $null
    if ($AuditData.ContainsKey('DCSyncAccounts') -and $null -ne $AuditData.DCSyncAccounts) {
        $dcsyncAccounts = @($AuditData.DCSyncAccounts)
    } elseif ($AuditData.PrivilegedAccounts -and
              $AuditData.PrivilegedAccounts.ContainsKey('DCSyncAccounts')) {
        $dcsyncAccounts = @($AuditData.PrivilegedAccounts.DCSyncAccounts)
    }

    if ($null -ne $dcsyncAccounts) {
        if ($dcsyncAccounts.Count -eq 0) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'No non-default accounts have DCSync replication rights' `
                -Details @{ DCSyncAccountCount = 0 }
        }

        $accountNames = @($dcsyncAccounts | ForEach-Object {
            if ($_ -is [hashtable] -and $_.ContainsKey('SamAccountName')) { $_.SamAccountName } else { "$_" }
        }) -join ', '

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($dcsyncAccounts.Count) non-default account(s) have DCSync replication rights: $accountNames" `
            -Details @{
                DCSyncAccountCount = $dcsyncAccounts.Count
                DCSyncAccounts     = @($dcsyncAccounts)
            }
    }

    # Check if domain-level ACL data is available for parsing
    $domainACL = $null
    if ($AuditData.ContainsKey('DomainACL') -and $null -ne $AuditData.DomainACL) {
        $domainACL = $AuditData.DomainACL
    }

    if ($null -eq $domainACL) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain root ACL data not available for DCSync rights analysis. Manually audit replication rights using: (Get-ACL "AD:\<DomainDN>").Access | Where-Object {$_.ObjectType -match "1131f6a[a-d]"}' `
            -Details @{
                Note = 'DCSync rights require domain root ACL which is not collected by the privileged members collector. Add domain ACL analysis or check manually'
            }
    }

    # Parse domain ACL for replication rights
    $replGuidGetChanges = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    $replGuidGetChangesAll = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'

    # Default SIDs that should have replication rights
    $defaultReplSids = @('S-1-5-32-544', 'S-1-5-9')
    $defaultReplRids = @('500', '516', '498', '512', '519')

    $nonDefaultDCSync = [System.Collections.Generic.List[string]]::new()

    try {
        $acl = $null
        if ($domainACL -is [System.DirectoryServices.ActiveDirectorySecurity]) {
            $acl = $domainACL
        }

        if ($acl) {
            $accessRules = $acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

            # Find principals with both replication rights
            $hasGetChanges = @{}
            $hasGetChangesAll = @{}

            foreach ($ace in $accessRules) {
                if ($ace.AccessControlType -ne 'Allow') { continue }

                $objType = $ace.ObjectType.ToString().ToLower()
                $sid = $ace.IdentityReference.Value

                if ($objType -eq $replGuidGetChanges) {
                    $hasGetChanges[$sid] = $true
                }
                if ($objType -eq $replGuidGetChangesAll) {
                    $hasGetChangesAll[$sid] = $true
                }
            }

            # Find SIDs that have both rights (DCSync capable)
            foreach ($sid in $hasGetChanges.Keys) {
                if (-not $hasGetChangesAll.ContainsKey($sid)) { continue }

                $isDefault = $sid -in $defaultReplSids

                if (-not $isDefault -and $sid -match '-(\d+)$') {
                    $rid = $Matches[1]
                    if ($rid -in $defaultReplRids) { $isDefault = $true }
                }

                if (-not $isDefault) {
                    $nonDefaultDCSync.Add($sid)
                }
            }
        } else {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue 'Domain ACL was collected but could not be parsed for DCSync rights analysis' `
                -Details @{ RawData = $true }
        }
    } catch {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Failed to parse domain ACL for DCSync rights: $_" `
            -Details @{ Error = "$_" }
    }

    if ($nonDefaultDCSync.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($nonDefaultDCSync.Count) non-default principal(s) have DCSync replication rights: $($nonDefaultDCSync -join ', ')" `
            -Details @{
                DCSyncAccountCount = $nonDefaultDCSync.Count
                DCSyncPrincipals   = @($nonDefaultDCSync)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Only default accounts have DCSync replication rights on the domain root' `
        -Details @{ DCSyncAccountCount = 0 }
}

# ── ADPRIV-029: Protected Users Group Audit ───────────────────────────────
function Test-ReconADPRIV029 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $puMembers = $null
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.ContainsKey('ProtectedUsersMembers')) {
        $puMembers = @($AuditData.PrivilegedAccounts.ProtectedUsersMembers)
    }

    if ($null -eq $puMembers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Protected Users group data not available'
    }

    $validMembers = @($puMembers | Where-Object { $null -ne $_ })

    if ($validMembers.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Protected Users group is empty. All Tier 0 privileged accounts should be members for hardened authentication protections' `
            -Details @{ MemberCount = 0 }
    }

    $memberNames = @($validMembers | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Protected Users group has $($validMembers.Count) member(s): $memberNames" `
        -Details @{
            MemberCount = $validMembers.Count
            Members     = @($validMembers | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; Enabled = $_.Enabled }
            })
        }
}

# ── ADPRIV-030: Privileged Users Not in Protected Users ───────────────────
function Test-ReconADPRIV030 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PrivilegedMembers' -Subject 'privileged account inventory'
    if ($na) { return $na }

    $puMembers = $null
    if ($AuditData.PrivilegedAccounts -and
        $AuditData.PrivilegedAccounts.ContainsKey('ProtectedUsersMembers')) {
        $puMembers = @($AuditData.PrivilegedAccounts.ProtectedUsersMembers)
    }

    if ($null -eq $puMembers -or
        -not $AuditData.PrivilegedAccounts -or
        -not $AuditData.PrivilegedAccounts.PrivilegedGroups) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Protected Users or privileged group data not available'
    }

    # Build set of Protected Users member DNs for fast lookup
    $puDNs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($pu in @($puMembers)) {
        if ($pu -and $pu.DistinguishedName) {
            [void]$puDNs.Add($pu.DistinguishedName)
        }
    }

    # Get all privileged user accounts
    $allPriv = Get-AllPrivilegedMembers -AuditData $AuditData

    # Filter to enabled user accounts only (computers and gMSAs should NOT be in Protected Users)
    $eligibleAccounts = @($allPriv | Where-Object {
        $_.ObjectClass -eq 'user' -and
        $_.Enabled -eq $true -and
        -not $_.IsComputer -and
        -not $_.IsServiceAccount
    })

    if ($eligibleAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No eligible privileged user accounts found to evaluate' `
            -Details @{ EligibleCount = 0 }
    }

    $notProtected = @($eligibleAccounts | Where-Object {
        -not $puDNs.Contains($_.DistinguishedName)
    })

    if ($notProtected.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($eligibleAccounts.Count) eligible privileged user account(s) are members of the Protected Users group" `
            -Details @{
                EligibleCount  = $eligibleAccounts.Count
                ProtectedCount = $eligibleAccounts.Count
                NotProtected   = 0
            }
    }

    $accountNames = @($notProtected | ForEach-Object { $_.SamAccountName }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($notProtected.Count) of $($eligibleAccounts.Count) eligible privileged account(s) are NOT in the Protected Users group: $accountNames" `
        -Details @{
            EligibleCount        = $eligibleAccounts.Count
            ProtectedCount       = ($eligibleAccounts.Count - $notProtected.Count)
            NotProtectedCount    = $notProtected.Count
            NotProtectedAccounts = @($notProtected | ForEach-Object {
                @{ SamAccountName = $_.SamAccountName; DistinguishedName = $_.DistinguishedName }
            })
        }
}
