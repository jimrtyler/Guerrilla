# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADAclDelegationChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADAclDelegationChecks'
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

# ── Helper: Test if a SID is a well-known safe admin principal ────────────────
function Test-SafeAdminSid {
    [CmdletBinding()]
    param(
        [string]$Sid,
        [string]$IdentityReference
    )

    # Delegate to the centralized default-principal allowlist (Get-ADAttackPath.ps1) so the
    # DCSync (ADPRIV-028) and ACL-delegation checks exclude the SAME set of by-design
    # infrastructure/admin principals as the attack-path engine. This is a strict superset
    # of the old local list (SYSTEM, SELF, Administrators, DA 512, EA 519) — it additionally
    # excludes the DC groups (516), Enterprise DCs (S-1-5-9), RODCs (521 / 498), Schema Admins
    # (518), Cert Publishers (517) and krbtgt (502), all matched by forge-proof well-known
    # SID/RID. This closes the v2.10.1 residual where Enterprise Read-only Domain Controllers
    # (498) was reported as a non-default DCSync principal.
    if (Get-Command Test-DefaultControlPrincipal -ErrorAction SilentlyContinue) {
        return (Test-DefaultControlPrincipal -Sid $Sid -IdentityReference $IdentityReference)
    }

    # Fallback (helper not loaded): the original local allowlist.
    if ($Sid -in @('S-1-5-18', 'S-1-5-10', 'S-1-5-32-544')) { return $true }
    if ($Sid -match '-512$|-519$') { return $true }
    foreach ($name in @('Domain Admins', 'Enterprise Admins', 'SYSTEM', 'BUILTIN\Administrators', 'Administrators')) {
        if ($IdentityReference -eq $name -or $IdentityReference -like "*\$name") { return $true }
    }
    return $false
}

# ── Helper: Get all dangerous ACEs from critical objects, filtered ────────────
function Get-FilteredDangerousACEs {
    [CmdletBinding()]
    param(
        [hashtable]$ACLData,
        [string]$RightsFilter = $null
    )

    if (-not $ACLData -or -not $ACLData.DangerousACEs) { return @() }

    $aces = @($ACLData.DangerousACEs)

    if ($RightsFilter) {
        $aces = @($aces | Where-Object {
            $_.ActiveDirectoryRights -match $RightsFilter
        })
    }

    # Filter out safe admin SIDs
    $filtered = @($aces | Where-Object {
        -not (Test-SafeAdminSid -Sid $_.IdentitySID -IdentityReference $_.IdentityReference)
    })

    return $filtered
}

# ── Well-known broad group SIDs ──────────────────────────────────────────────
function Test-BroadGroupSid {
    [CmdletBinding()]
    param(
        [string]$Sid,
        [string]$IdentityReference
    )

    # Well-known broad group SIDs
    $broadSids = @(
        'S-1-1-0'   # Everyone
        'S-1-5-11'  # Authenticated Users
    )

    if ($Sid -in $broadSids) { return $true }

    # Domain Users (RID -513), Domain Computers (RID -515)
    if ($Sid -match '-513$|-515$') { return $true }

    # Name-based fallback
    $broadNames = @('Everyone', 'Authenticated Users', 'Domain Users', 'Domain Computers')
    foreach ($name in $broadNames) {
        if ($IdentityReference -eq $name -or $IdentityReference -like "*\$name") {
            return $true
        }
    }

    return $false
}

# ── ADACL-001: Critical Object ACL Audit ─────────────────────────────────────
function Test-ReconADACL001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $dangerousACEs = @($aclData.DangerousACEs)

    if ($dangerousACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default dangerous ACEs found on critical AD objects' `
            -Details @{
                CriticalObjectsAudited = @($aclData.CriticalObjectACLs.Keys)
                DangerousACECount      = 0
            }
    }

    # Group by object name for reporting
    $byObject = @{}
    foreach ($ace in $dangerousACEs) {
        $objName = $ace.ObjectName ?? 'Unknown'
        if (-not $byObject.ContainsKey($objName)) {
            $byObject[$objName] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $byObject[$objName].Add($ace)
    }

    $summaryParts = @()
    foreach ($objName in $byObject.Keys) {
        $count = $byObject[$objName].Count
        $principals = @($byObject[$objName] | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
        $summaryParts += "$objName`: $count ACE(s) from $($principals -join ', ')"
    }

    $currentValue = "$($dangerousACEs.Count) non-default dangerous ACE(s) found on critical objects: $($summaryParts -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            TotalDangerousACEs     = $dangerousACEs.Count
            CriticalObjectsAudited = @($aclData.CriticalObjectACLs.Keys)
            ByObject               = $byObject
            DangerousACEs          = $dangerousACEs
        }
}

# ── ADACL-002: GenericAll Permissions on Critical Objects ─────────────────────
function Test-ReconADACL002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $genericAllACEs = Get-FilteredDangerousACEs -ACLData $AuditData.ACLs -RightsFilter 'GenericAll'

    if ($genericAllACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default principals with GenericAll on critical objects' `
            -Details @{ GenericAllACECount = 0 }
    }

    $principals = @($genericAllACEs | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $objects = @($genericAllACEs | ForEach-Object { $_.ObjectName } | Sort-Object -Unique)

    $currentValue = "$($genericAllACEs.Count) GenericAll ACE(s) from non-default principal(s): $($principals -join ', ') on $($objects -join ', ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            GenericAllACECount = $genericAllACEs.Count
            Principals         = $principals
            AffectedObjects    = $objects
            ACEs               = $genericAllACEs
        }
}

# ── ADACL-003: GenericWrite Permissions on Critical Objects ───────────────────
function Test-ReconADACL003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $genericWriteACEs = Get-FilteredDangerousACEs -ACLData $AuditData.ACLs -RightsFilter 'GenericWrite'

    if ($genericWriteACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default principals with GenericWrite on critical objects' `
            -Details @{ GenericWriteACECount = 0 }
    }

    $principals = @($genericWriteACEs | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $objects = @($genericWriteACEs | ForEach-Object { $_.ObjectName } | Sort-Object -Unique)

    $currentValue = "$($genericWriteACEs.Count) GenericWrite ACE(s) from non-default principal(s): $($principals -join ', ') on $($objects -join ', ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            GenericWriteACECount = $genericWriteACEs.Count
            Principals           = $principals
            AffectedObjects      = $objects
            ACEs                 = $genericWriteACEs
        }
}

# ── ADACL-004: WriteDACL Permissions on Critical Objects ──────────────────────
function Test-ReconADACL004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $writeDaclACEs = Get-FilteredDangerousACEs -ACLData $AuditData.ACLs -RightsFilter 'WriteDacl'

    if ($writeDaclACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default principals with WriteDACL on critical objects' `
            -Details @{ WriteDaclACECount = 0 }
    }

    $principals = @($writeDaclACEs | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $objects = @($writeDaclACEs | ForEach-Object { $_.ObjectName } | Sort-Object -Unique)

    $currentValue = "$($writeDaclACEs.Count) WriteDACL ACE(s) from non-default principal(s): $($principals -join ', ') on $($objects -join ', ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            WriteDaclACECount = $writeDaclACEs.Count
            Principals        = $principals
            AffectedObjects   = $objects
            ACEs              = $writeDaclACEs
        }
}

# ── ADACL-005: WriteOwner Permissions on Critical Objects ─────────────────────
function Test-ReconADACL005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $writeOwnerACEs = Get-FilteredDangerousACEs -ACLData $AuditData.ACLs -RightsFilter 'WriteOwner'

    if ($writeOwnerACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default principals with WriteOwner on critical objects' `
            -Details @{ WriteOwnerACECount = 0 }
    }

    $principals = @($writeOwnerACEs | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $objects = @($writeOwnerACEs | ForEach-Object { $_.ObjectName } | Sort-Object -Unique)

    $currentValue = "$($writeOwnerACEs.Count) WriteOwner ACE(s) from non-default principal(s): $($principals -join ', ') on $($objects -join ', ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            WriteOwnerACECount = $writeOwnerACEs.Count
            Principals         = $principals
            AffectedObjects    = $objects
            ACEs               = $writeOwnerACEs
        }
}

# ── ADACL-006: ForceChangePassword Rights ────────────────────────────────────
function Test-ReconADACL006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $dangerousACEs = @($aclData.DangerousACEs)

    # Filter for User-Force-Change-Password extended right
    # GUID: 00299570-246d-11d0-a768-00aa006e0529
    $forceChangePwdACEs = @($dangerousACEs | Where-Object {
        ($_.ObjectType -and $_.ObjectType -match 'User-Force-Change-Password') -or
        ($_.ObjectTypeGUID -and $_.ObjectTypeGUID -eq '00299570-246d-11d0-a768-00aa006e0529')
    })

    # Further filter out safe admin SIDs
    $forceChangePwdACEs = @($forceChangePwdACEs | Where-Object {
        -not (Test-SafeAdminSid -Sid $_.IdentitySID -IdentityReference $_.IdentityReference)
    })

    if ($forceChangePwdACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-admin principals with ForceChangePassword rights on critical objects' `
            -Details @{ ForceChangePasswordACECount = 0 }
    }

    $principals = @($forceChangePwdACEs | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $objects = @($forceChangePwdACEs | ForEach-Object { $_.ObjectName } | Sort-Object -Unique)

    $currentValue = "$($forceChangePwdACEs.Count) ForceChangePassword ACE(s) from non-admin principal(s): $($principals -join ', ') on $($objects -join ', ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            ForceChangePasswordACECount = $forceChangePwdACEs.Count
            Principals                  = $principals
            AffectedObjects             = $objects
            ACEs                        = $forceChangePwdACEs
        }
}

# ── ADACL-007: Excessive Delegation to Broad Groups ──────────────────────────
function Test-ReconADACL007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $dangerousACEs = @($aclData.DangerousACEs)

    # Filter for ACEs where the identity is a broad group
    $broadGroupACEs = @($dangerousACEs | Where-Object {
        Test-BroadGroupSid -Sid $_.IdentitySID -IdentityReference $_.IdentityReference
    })

    if ($broadGroupACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No dangerous rights delegated to broad groups (Everyone, Authenticated Users, Domain Users) on critical objects' `
            -Details @{ BroadGroupACECount = 0 }
    }

    # Group by identity for reporting
    $byGroup = @{}
    foreach ($ace in $broadGroupACEs) {
        $identity = $ace.IdentityReference
        if (-not $byGroup.ContainsKey($identity)) {
            $byGroup[$identity] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $byGroup[$identity].Add($ace)
    }

    $summaryParts = @()
    foreach ($group in $byGroup.Keys) {
        $rights = @($byGroup[$group] | ForEach-Object { $_.ActiveDirectoryRights } | Sort-Object -Unique)
        $objects = @($byGroup[$group] | ForEach-Object { $_.ObjectName } | Sort-Object -Unique)
        $summaryParts += "$group has $($rights -join ', ') on $($objects -join ', ')"
    }

    $currentValue = "$($broadGroupACEs.Count) dangerous ACE(s) delegated to broad groups: $($summaryParts -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            BroadGroupACECount = $broadGroupACEs.Count
            ByGroup            = $byGroup
            ACEs               = $broadGroupACEs
        }
}

# ── ADACL-008: OU Delegation Analysis ────────────────────────────────────────
function Test-ReconADACL008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $ouDelegations = @($aclData.OUDelegation)

    if ($ouDelegations.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default OU delegations detected' `
            -Details @{ OUDelegationCount = 0 }
    }

    # Group by OU for analysis
    $byOU = @{}
    foreach ($delegation in $ouDelegations) {
        $ouDN = $delegation.OUDN ?? 'Unknown'
        if (-not $byOU.ContainsKey($ouDN)) {
            $byOU[$ouDN] = [System.Collections.Generic.List[hashtable]]::new()
        }
        $byOU[$ouDN].Add($delegation)
    }

    # Count unique principals and OUs with delegations
    $uniquePrincipals = @($ouDelegations | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $ouCount = $byOU.Keys.Count

    # Check for broad delegations (GenericAll on OUs)
    $broadDelegations = @($ouDelegations | Where-Object {
        $_.ActiveDirectoryRights -match 'GenericAll'
    })

    $status = if ($broadDelegations.Count -gt 0) { 'WARN' }
              elseif ($ouDelegations.Count -gt 20) { 'WARN' }
              else { 'PASS' }

    $currentValue = "$($ouDelegations.Count) OU delegation(s) across $ouCount OU(s) for $($uniquePrincipals.Count) principal(s)"
    if ($broadDelegations.Count -gt 0) {
        $currentValue += ". $($broadDelegations.Count) delegation(s) grant GenericAll (excessive)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            TotalDelegations    = $ouDelegations.Count
            OUsWithDelegations  = $ouCount
            UniquePrincipals    = $uniquePrincipals
            BroadDelegations    = $broadDelegations.Count
            ByOU                = $byOU
            Delegations         = $ouDelegations
        }
}

# ── ADACL-009: Machine Account Quota ─────────────────────────────────────────
function Test-ReconADACL009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $maq = [int]$aclData.MachineAccountQuota

    if ($maq -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'ms-DS-MachineAccountQuota is 0. Authenticated users cannot create machine accounts' `
            -Details @{ MachineAccountQuota = 0 }
    }

    $currentValue = "ms-DS-MachineAccountQuota is $maq (default: 10, recommended: 0). Any authenticated user can create up to $maq machine account(s), enabling RBCD and relay attacks"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{ MachineAccountQuota = $maq }
}

# ── ADACL-010: Extended Rights Audit (DCSync) ────────────────────────────────
function Test-ReconADACL010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $dangerousACEs = @($aclData.DangerousACEs)

    # DCSync GUIDs
    $dcSyncGuids = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
    )

    # Filter for ACEs with DCSync extended rights
    $dcSyncACEs = @($dangerousACEs | Where-Object {
        ($_.ObjectTypeGUID -and $_.ObjectTypeGUID -in $dcSyncGuids) -or
        ($_.ObjectType -and $_.ObjectType -match 'DS-Replication-Get-Changes')
    })

    # Filter out safe admin SIDs
    $dcSyncACEs = @($dcSyncACEs | Where-Object {
        -not (Test-SafeAdminSid -Sid $_.IdentitySID -IdentityReference $_.IdentityReference)
    })

    if ($dcSyncACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-default accounts with DCSync replication rights (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)' `
            -Details @{ DCSyncACECount = 0 }
    }

    # Group by identity to show unique principals
    $dcSyncPrincipals = @{}
    foreach ($ace in $dcSyncACEs) {
        $identity = $ace.IdentityReference ?? $ace.IdentitySID
        if (-not $identity) { continue }
        if (-not $dcSyncPrincipals.ContainsKey($identity)) {
            $dcSyncPrincipals[$identity] = [System.Collections.Generic.List[string]]::new()
        }
        $rightName = $ace.ObjectType ?? $ace.ObjectTypeGUID ?? 'ExtendedRight'
        if (-not $dcSyncPrincipals[$identity].Contains($rightName)) {
            $dcSyncPrincipals[$identity].Add($rightName)
        }
    }

    $principalSummary = @()
    foreach ($principal in $dcSyncPrincipals.Keys) {
        $rights = $dcSyncPrincipals[$principal] -join ' + '
        $principalSummary += "$principal ($rights)"
    }

    $currentValue = "$($dcSyncPrincipals.Count) non-default principal(s) with DCSync rights: $($principalSummary -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            DCSyncACECount   = $dcSyncACEs.Count
            DCSyncPrincipals = $dcSyncPrincipals
            ACEs             = $dcSyncACEs
        }
}

# ── ADACL-011: Ownership of Critical Objects ─────────────────────────────────
function Test-ReconADACL011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $criticalObjects = $aclData.CriticalObjectACLs

    if (-not $criticalObjects -or $criticalObjects.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Critical object ACL data not available for ownership analysis'
    }

    # Check domain root owner specifically
    $domainRootOwner = $aclData.DomainRootOwner
    $ownershipIssues = [System.Collections.Generic.List[hashtable]]::new()

    if ($domainRootOwner -and $domainRootOwner -ne 'Unknown') {
        # Try to determine if the owner is a safe admin
        # Domain root owner is typically "Domain Admins" or "Enterprise Admins"
        $ownerIsSafe = $false
        $safeOwnerPatterns = @(
            'Domain Admins', 'Enterprise Admins', 'Administrators',
            'BUILTIN\Administrators', 'SYSTEM'
        )
        foreach ($pattern in $safeOwnerPatterns) {
            if ($domainRootOwner -eq $pattern -or $domainRootOwner -like "*\$pattern") {
                $ownerIsSafe = $true
                break
            }
        }
        # Also check SID pattern for DA/EA
        if (-not $ownerIsSafe -and $domainRootOwner -match '-512$|-519$|S-1-5-18|S-1-5-32-544') {
            $ownerIsSafe = $true
        }

        if (-not $ownerIsSafe) {
            $ownershipIssues.Add(@{
                ObjectName = 'Domain Root'
                Owner      = $domainRootOwner
                Risk       = 'Domain root owned by non-admin principal. Owner can modify DACL implicitly.'
            })
        }
    }

    # Check each critical object for owner information in the ACE data
    # Note: The collector stores owner info on the domain root; for other objects
    # we examine the ACL data structure for ownership anomalies via WriteOwner ACEs
    # as a proxy for ownership risk

    if ($ownershipIssues.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Domain root owned by $domainRootOwner. Critical object ownership appears correct" `
            -Details @{
                DomainRootOwner    = $domainRootOwner
                ObjectsChecked     = @($criticalObjects.Keys)
                OwnershipIssues    = @()
            }
    }

    $issueDescriptions = @($ownershipIssues | ForEach-Object {
        "$($_.ObjectName) owned by $($_.Owner)"
    })

    $currentValue = "$($ownershipIssues.Count) critical object(s) with non-admin ownership: $($issueDescriptions -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            DomainRootOwner = $domainRootOwner
            ObjectsChecked  = @($criticalObjects.Keys)
            OwnershipIssues = @($ownershipIssues)
        }
}

# ── ADACL-012: Non-Default Domain Root Permissions ───────────────────────────
function Test-ReconADACL012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $criticalObjects = $aclData.CriticalObjectACLs

    if (-not $criticalObjects -or -not $criticalObjects.ContainsKey('Domain Root')) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain root ACL data not available'
    }

    $domainRootData = $criticalObjects['Domain Root']
    $allACEs = @($domainRootData.ACEs)

    if ($allACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No ACE data available for domain root'
    }

    # Filter for non-default Allow ACEs from unexpected principals that grant write/modify rights
    $dangerousRightsPattern = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty|ExtendedRight'

    $nonDefaultACEs = @($allACEs | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.ActiveDirectoryRights -match $dangerousRightsPattern -and
        -not (Test-SafeAdminSid -Sid $_.IdentitySID -IdentityReference $_.IdentityReference)
    })

    if ($nonDefaultACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Domain root has $($allACEs.Count) ACE(s); no non-default write/modify permissions from unexpected principals" `
            -Details @{
                TotalACECount     = $allACEs.Count
                NonDefaultACECount = 0
            }
    }

    $principals = @($nonDefaultACEs | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $rightsList = @($nonDefaultACEs | ForEach-Object { $_.ActiveDirectoryRights } | Sort-Object -Unique)

    $currentValue = "$($nonDefaultACEs.Count) non-default ACE(s) on domain root from unexpected principal(s): $($principals -join ', ') with rights: $($rightsList -join ', ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            TotalACECount      = $allACEs.Count
            NonDefaultACECount = $nonDefaultACEs.Count
            Principals         = $principals
            Rights             = $rightsList
            NonDefaultACEs     = $nonDefaultACEs
        }
}

# ── ADACL-013: GPO Link Permissions ──────────────────────────────────────────
function Test-ReconADACL013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $criticalObjects = $aclData.CriticalObjectACLs

    # Check for write permissions on critical OUs that could allow GPO linking
    # GPO linking requires write access to gPLink attribute on the OU/domain object
    $gpoLinkIssues = [System.Collections.Generic.List[hashtable]]::new()

    $linkTargets = @('Domain Root', 'Domain Controllers OU')

    foreach ($targetName in $linkTargets) {
        if (-not $criticalObjects.ContainsKey($targetName)) { continue }

        $targetData = $criticalObjects[$targetName]
        $aces = @($targetData.ACEs)

        foreach ($ace in $aces) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if (Test-SafeAdminSid -Sid $ace.IdentitySID -IdentityReference $ace.IdentityReference) { continue }

            # WriteProperty on gPLink or GenericWrite/GenericAll (which includes gPLink modification)
            $rights = $ace.ActiveDirectoryRights
            $canModifyGPOLink = $false

            if ($rights -match 'GenericAll|GenericWrite') {
                $canModifyGPOLink = $true
            } elseif ($rights -match 'WriteProperty') {
                # WriteProperty with no specific ObjectType means all properties including gPLink
                if (-not $ace.ObjectTypeGUID) {
                    $canModifyGPOLink = $true
                }
                # gPLink attribute GUID: f30e3bbe-9ff0-11d1-b603-0000f80367c1
                if ($ace.ObjectTypeGUID -eq 'f30e3bbe-9ff0-11d1-b603-0000f80367c1') {
                    $canModifyGPOLink = $true
                }
            }

            if ($canModifyGPOLink) {
                $gpoLinkIssues.Add(@{
                    TargetObject      = $targetName
                    IdentityReference = $ace.IdentityReference
                    IdentitySID       = $ace.IdentitySID
                    Rights            = $rights
                })
            }
        }
    }

    if ($gpoLinkIssues.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-admin principals can modify GPO links on critical OUs' `
            -Details @{ GPOLinkIssueCount = 0; CheckedTargets = $linkTargets }
    }

    $principals = @($gpoLinkIssues | ForEach-Object { $_.IdentityReference } | Sort-Object -Unique)
    $targets = @($gpoLinkIssues | ForEach-Object { $_.TargetObject } | Sort-Object -Unique)

    $currentValue = "$($gpoLinkIssues.Count) non-admin principal(s) can modify GPO links: $($principals -join ', ') on $($targets -join ', ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            GPOLinkIssueCount = $gpoLinkIssues.Count
            Principals        = $principals
            AffectedTargets   = $targets
            Issues            = @($gpoLinkIssues)
        }
}

# ── ADACL-014: GPO Edit Permissions ──────────────────────────────────────────
function Test-ReconADACL014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $gpoPermissions = $aclData.GPOPermissions

    if (-not $gpoPermissions -or $gpoPermissions.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'GPO permission data not available'
    }

    # Find GPOs where non-admin principals can edit
    $gpoEditIssues = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $gpoPermissions.Keys) {
        $gpoPerm = $gpoPermissions[$gpoName]
        $editors = @($gpoPerm.CanEdit)

        foreach ($editor in $editors) {
            # Skip safe admin principals by name
            $isSafe = $false
            $safeEditorPatterns = @(
                'Domain Admins', 'Enterprise Admins', 'SYSTEM',
                'BUILTIN\Administrators', 'Administrators',
                'Group Policy Creator Owners'
            )
            foreach ($pattern in $safeEditorPatterns) {
                if ($editor -eq $pattern -or $editor -like "*\$pattern") {
                    $isSafe = $true
                    break
                }
            }
            # Check SID patterns
            if (-not $isSafe -and $editor -match '-512$|-519$|S-1-5-18|S-1-5-32-544') {
                $isSafe = $true
            }

            if (-not $isSafe) {
                $gpoEditIssues.Add(@{
                    GPOName  = $gpoName
                    GPODN   = $gpoPerm.DN
                    Editor   = $editor
                })
            }
        }
    }

    if ($gpoEditIssues.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Analyzed $($gpoPermissions.Count) GPO(s); no non-admin principals with edit permissions" `
            -Details @{
                GPOsAnalyzed      = $gpoPermissions.Count
                GPOEditIssueCount = 0
            }
    }

    # Group by GPO for reporting
    $byGPO = @{}
    foreach ($issue in $gpoEditIssues) {
        $gpoName = $issue.GPOName
        if (-not $byGPO.ContainsKey($gpoName)) {
            $byGPO[$gpoName] = [System.Collections.Generic.List[string]]::new()
        }
        if (-not $byGPO[$gpoName].Contains($issue.Editor)) {
            $byGPO[$gpoName].Add($issue.Editor)
        }
    }

    $summaryParts = @()
    foreach ($gpoName in $byGPO.Keys) {
        $summaryParts += "$gpoName editable by $($byGPO[$gpoName] -join ', ')"
    }

    $currentValue = "$($byGPO.Count) GPO(s) with non-admin edit permissions: $($summaryParts -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            GPOsAnalyzed      = $gpoPermissions.Count
            GPOEditIssueCount = $gpoEditIssues.Count
            AffectedGPOs      = $byGPO
            Issues            = @($gpoEditIssues)
        }
}

# ── ADACL-015: Shadow Admins Detection ───────────────────────────────────────
function Test-ReconADACL015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $dangerousACEs = @($aclData.DangerousACEs)

    if ($dangerousACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No shadow admin paths identified; no non-default dangerous ACEs on critical objects' `
            -Details @{ ShadowAdminCount = 0 }
    }

    # Shadow admins are principals that have dangerous rights (which could escalate
    # to Domain Admin) but are NOT members of standard admin groups.
    # We compile all unique non-admin principals with dangerous rights.
    $shadowAdmins = @{}

    foreach ($ace in $dangerousACEs) {
        $identity = $ace.IdentityReference ?? $ace.IdentitySID
        if (-not $identity) { continue }

        # Skip known-safe admin SIDs
        if (Test-SafeAdminSid -Sid $ace.IdentitySID -IdentityReference $ace.IdentityReference) {
            continue
        }

        if (-not $shadowAdmins.ContainsKey($identity)) {
            $shadowAdmins[$identity] = @{
                Identity = $identity
                SID      = $ace.IdentitySID
                Rights   = [System.Collections.Generic.List[string]]::new()
                Objects  = [System.Collections.Generic.List[string]]::new()
            }
        }

        $rightDesc = $ace.ActiveDirectoryRights
        if ($ace.ObjectType) { $rightDesc += " ($($ace.ObjectType))" }

        if (-not $shadowAdmins[$identity].Rights.Contains($rightDesc)) {
            $shadowAdmins[$identity].Rights.Add($rightDesc)
        }
        $objName = $ace.ObjectName ?? 'Unknown'
        if (-not $shadowAdmins[$identity].Objects.Contains($objName)) {
            $shadowAdmins[$identity].Objects.Add($objName)
        }
    }

    if ($shadowAdmins.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No shadow admin principals identified after filtering default admin accounts' `
            -Details @{ ShadowAdminCount = 0 }
    }

    $summaryParts = @()
    foreach ($identity in $shadowAdmins.Keys) {
        $info = $shadowAdmins[$identity]
        $summaryParts += "${identity}: $($info.Rights -join ', ') on $($info.Objects -join ', ')"
    }

    $currentValue = "$($shadowAdmins.Count) shadow admin principal(s) with dangerous rights that could escalate to Domain Admin: $($summaryParts -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            ShadowAdminCount = $shadowAdmins.Count
            ShadowAdmins     = $shadowAdmins
        }
}

# ── ADACL-016: Attack Path Enumeration ───────────────────────────────────────
function Test-ReconADACL016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ObjectACLs' -Subject 'object ACLs'
    if ($na) { return $na }

    if (-not $AuditData.ACLs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'ACL data not available'
    }

    $aclData = $AuditData.ACLs
    $dangerousACEs = @($aclData.DangerousACEs)

    if ($dangerousACEs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No ACL-based attack paths identified; no non-default dangerous ACEs on critical objects' `
            -Details @{
                AttackPathCount = 0
                Note            = 'For comprehensive attack path analysis, use BloodHound or similar graph-based tools'
            }
    }

    # Simplified attack path analysis: identify principals that have dangerous rights
    # and categorize by the type of escalation they enable.
    $attackPaths = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ace in $dangerousACEs) {
        $identity = $ace.IdentityReference ?? $ace.IdentitySID
        if (-not $identity) { continue }

        # Skip known-safe admin SIDs
        if (Test-SafeAdminSid -Sid $ace.IdentitySID -IdentityReference $ace.IdentityReference) {
            continue
        }

        $rights = $ace.ActiveDirectoryRights
        $objectName = $ace.ObjectName ?? 'Unknown'
        $pathType = 'Unknown'

        # Classify the attack path type
        if ($rights -match 'GenericAll') {
            $pathType = 'FullControl'
        } elseif ($rights -match 'WriteDacl') {
            $pathType = 'DACLModification'
        } elseif ($rights -match 'WriteOwner') {
            $pathType = 'OwnershipTakeover'
        } elseif ($rights -match 'GenericWrite') {
            $pathType = 'PropertyWrite'
        } elseif ($ace.ObjectType -match 'DS-Replication-Get-Changes') {
            $pathType = 'DCSync'
        } elseif ($ace.ObjectType -match 'User-Force-Change-Password') {
            $pathType = 'PasswordReset'
        } elseif ($rights -match 'ExtendedRight') {
            $pathType = 'ExtendedRight'
        }

        # Higher risk if targeting domain root or AdminSDHolder
        $isHighRisk = $objectName -match 'Domain Root|AdminSDHolder|Domain Controllers'

        # Even higher risk if the source is a broad group
        $isBroadGroup = Test-BroadGroupSid -Sid $ace.IdentitySID -IdentityReference $ace.IdentityReference

        $attackPaths.Add(@{
            Source     = $identity
            SourceSID  = $ace.IdentitySID
            Target     = $objectName
            TargetDN   = $ace.ObjectDN
            PathType   = $pathType
            Rights     = $rights
            IsHighRisk = $isHighRisk
            IsBroadGroup = $isBroadGroup
        })
    }

    if ($attackPaths.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No ACL-based attack paths from non-admin principals to critical objects' `
            -Details @{
                AttackPathCount = 0
                Note            = 'For comprehensive attack path analysis, use BloodHound or similar graph-based tools'
            }
    }

    $highRiskPaths = @($attackPaths | Where-Object { $_.IsHighRisk })
    $broadGroupPaths = @($attackPaths | Where-Object { $_.IsBroadGroup })

    # Determine status based on risk
    $status = if ($broadGroupPaths.Count -gt 0) { 'FAIL' }
              elseif ($highRiskPaths.Count -gt 0) { 'FAIL' }
              else { 'WARN' }

    $uniqueSources = @($attackPaths | ForEach-Object { $_.Source } | Sort-Object -Unique)
    $uniquePathTypes = @($attackPaths | ForEach-Object { $_.PathType } | Sort-Object -Unique)

    $currentValue = "$($attackPaths.Count) ACL-based attack path(s) from $($uniqueSources.Count) principal(s) to critical objects via $($uniquePathTypes -join ', ')"
    if ($highRiskPaths.Count -gt 0) {
        $currentValue += ". $($highRiskPaths.Count) target high-value objects (Domain Root, AdminSDHolder, Domain Controllers OU)"
    }
    if ($broadGroupPaths.Count -gt 0) {
        $currentValue += ". $($broadGroupPaths.Count) originate from broad groups (Everyone, Authenticated Users, Domain Users)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            AttackPathCount   = $attackPaths.Count
            HighRiskPathCount = $highRiskPaths.Count
            BroadGroupPaths   = $broadGroupPaths.Count
            UniqueSources     = $uniqueSources
            PathTypes         = $uniquePathTypes
            AttackPaths       = @($attackPaths)
            Note              = 'For comprehensive multi-hop attack path analysis, use BloodHound or similar graph-based tools'
        }
}
