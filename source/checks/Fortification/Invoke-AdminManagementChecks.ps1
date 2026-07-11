# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-AdminManagementChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'AdminManagementChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Fortification$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_" -OrgUnitPath $OrgUnitPath))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented' -OrgUnitPath $OrgUnitPath))
        }
    }

    return @($findings)
}

# ── ADMIN-001: Super Admin Account Inventory ─────────────────────────────
function Test-FortificationADMIN001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    if (-not $AuditData.Users) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User data not available' -OrgUnitPath $OrgUnitPath
    }

    $superAdmins = @($AuditData.Users | Where-Object { $_.isAdmin -eq $true })
    $activeSuperAdmins = @($superAdmins | Where-Object { -not $_.suspended })
    $suspendedSuperAdmins = @($superAdmins | Where-Object { $_.suspended -eq $true })

    $adminEmails = @($activeSuperAdmins | ForEach-Object { $_.primaryEmail })

    $status = if ($activeSuperAdmins.Count -eq 0) { 'FAIL' } else { 'PASS' }
    $currentValue = "$($activeSuperAdmins.Count) active super admin(s), $($suspendedSuperAdmins.Count) suspended"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{
            ActiveSuperAdmins    = $adminEmails
            TotalSuperAdmins     = $superAdmins.Count
            ActiveCount          = $activeSuperAdmins.Count
            SuspendedCount       = $suspendedSuperAdmins.Count
        }
}

# ── ADMIN-002: Admin Role Assignments Audit ──────────────────────────────
function Test-FortificationADMIN002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('Roles', 'RoleAssignments') -Subject 'admin roles and assignments'
    if ($na) { return $na }

    if (-not $AuditData.Roles -or -not $AuditData.RoleAssignments) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Role and role assignment data not available. Verify in Admin Console > Account > Admin roles' `
            -OrgUnitPath $OrgUnitPath
    }

    $roles = @($AuditData.Roles)
    $assignments = @($AuditData.RoleAssignments)

    # Identify built-in vs custom roles
    $builtInRoles = @($roles | Where-Object { $_.isSystemRole -eq $true -or $_.isSuperAdminRole -eq $true })
    $customRoles = @($roles | Where-Object { $_.isSystemRole -ne $true -and $_.isSuperAdminRole -ne $true })

    $status = if ($assignments.Count -gt 0 -and $customRoles.Count -eq 0) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($assignments.Count) role assignment(s) across $($roles.Count) roles ($($builtInRoles.Count) built-in, $($customRoles.Count) custom)" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            TotalRoles       = $roles.Count
            BuiltInRoles     = $builtInRoles.Count
            CustomRoles      = $customRoles.Count
            TotalAssignments = $assignments.Count
        }
}

# ── ADMIN-003: Delegated Admin Permissions Review ────────────────────────
function Test-FortificationADMIN003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Roles' -Subject 'admin roles'
    if ($na) { return $na }

    if (-not $AuditData.Roles) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Role data not available. Verify custom admin roles in Admin Console > Account > Admin roles' `
            -OrgUnitPath $OrgUnitPath
    }

    $customRoles = @($AuditData.Roles | Where-Object { $_.isSystemRole -ne $true -and $_.isSuperAdminRole -ne $true })

    if ($customRoles.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No custom admin roles configured. Only built-in roles are in use' `
            -OrgUnitPath $OrgUnitPath
    }

    $roleNames = @($customRoles | ForEach-Object { $_.roleName ?? $_.name ?? 'Unknown' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($customRoles.Count) custom admin role(s) should be reviewed for appropriate permission scoping" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ CustomRoles = $roleNames; Count = $customRoles.Count }
}

# ── ADMIN-004: Inactive/Suspended Admin Accounts ────────────────────────
function Test-FortificationADMIN004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    if (-not $AuditData.Users) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User data not available' -OrgUnitPath $OrgUnitPath
    }

    # Find suspended users who still have admin roles
    $suspendedAdmins = @($AuditData.Users | Where-Object {
        $_.suspended -eq $true -and ($_.isAdmin -eq $true -or $_.isDelegatedAdmin -eq $true)
    })

    if ($suspendedAdmins.Count -gt 0) {
        $adminEmails = @($suspendedAdmins | ForEach-Object { $_.primaryEmail })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($suspendedAdmins.Count) suspended user(s) still have admin role assignments" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ SuspendedAdmins = $adminEmails }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No suspended users with active admin role assignments' `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-005: User Account Inventory ────────────────────────────────────
function Test-FortificationADMIN005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    if (-not $AuditData.Users) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User data not available' -OrgUnitPath $OrgUnitPath
    }

    $allUsers = @($AuditData.Users)
    $active = @($allUsers | Where-Object { -not $_.suspended -and -not $_.archived })
    $suspended = @($allUsers | Where-Object { $_.suspended -eq $true })
    $archived = @($allUsers | Where-Object { $_.archived -eq $true })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Total: $($allUsers.Count) users ($($active.Count) active, $($suspended.Count) suspended, $($archived.Count) archived)" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            TotalUsers    = $allUsers.Count
            ActiveCount   = $active.Count
            SuspendedCount = $suspended.Count
            ArchivedCount  = $archived.Count
        }
}

# ── ADMIN-006: Stale User Accounts ───────────────────────────────────────
function Test-FortificationADMIN006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    if (-not $AuditData.Users) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User data not available' -OrgUnitPath $OrgUnitPath
    }

    $staleDays = 90
    $now = [datetime]::UtcNow
    $activeUsers = @($AuditData.Users | Where-Object { -not $_.suspended })
    $staleUsers = [System.Collections.Generic.List[string]]::new()

    foreach ($user in $activeUsers) {
        $lastLogin = $null
        if ($user.lastLoginTime) {
            try { $lastLogin = [datetime]::Parse($user.lastLoginTime) } catch { }
        }
        if (-not $lastLogin -or ($now - $lastLogin).TotalDays -gt $staleDays) {
            $staleUsers.Add($user.primaryEmail)
        }
    }

    if ($staleUsers.Count -gt 0) {
        $staleRate = [Math]::Round(($staleUsers.Count / $activeUsers.Count) * 100, 1)
        $status = if ($staleRate -gt 20) { 'FAIL' }
                  elseif ($staleRate -gt 10) { 'WARN' }
                  else { 'PASS' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "$($staleUsers.Count) of $($activeUsers.Count) active users ($staleRate%) inactive for $staleDays+ days" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ StaleUsers = @($staleUsers | Select-Object -First 50); StaleCount = $staleUsers.Count; ThresholdDays = $staleDays }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($activeUsers.Count) active users have logged in within the last $staleDays days" `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-007: OU Structure Review ───────────────────────────────────────
function Test-FortificationADMIN007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OrgUnits' -Subject 'organizational units'
    if ($na) { return $na }

    if (-not $AuditData.Tenant -or -not $AuditData.Tenant.OrgUnits) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Organizational unit data not available. Verify OU structure in Admin Console > Directory > Organizational units' `
            -OrgUnitPath $OrgUnitPath
    }

    $orgUnits = @($AuditData.Tenant.OrgUnits)
    $ouPaths = @($orgUnits | ForEach-Object { $_.orgUnitPath ?? $_.OrgUnitPath ?? '/' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($orgUnits.Count) organizational unit(s) configured" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ OUCount = $orgUnits.Count; OUPaths = $ouPaths }
}

# ── ADMIN-008: Directory Sharing Settings ────────────────────────────────
function Test-FortificationADMIN008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: directory.workspace_resource_type_visibility { domainSharedContacts=bool }.
    # When true, domain shared contacts are exposed across the global directory — a directory-
    # exposure surface worth review (especially for K-12 / student OUs). This is intentionally
    # WARN-on-exposure ("review this"), not FAIL — appropriateness depends on the audience.
    # Grade the WEAKEST OU: if ANY targeted policy exposes shared contacts the tenant WARNs;
    # PASS only when every targeted policy keeps them hidden.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'directory.workspace_resource_type_visibility' -Field 'domainSharedContacts')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No directory.workspace_resource_type_visibility policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $visible = @($vals | Where-Object { $_ -eq $true })
    $note = "domainSharedContacts: $((@($vals | ForEach-Object { "$_" }) | Select-Object -Unique) -join ', ') ($($visible.Count) of $($vals.Count) targeted policies)"
    if ($visible.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Domain shared contacts visible in the directory — review whether this exposure is appropriate ($($visible.Count) of $($vals.Count) targeted policies)" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Domain shared contacts visible in the global directory expose contact information; review whether this is appropriate for the audience (e.g. K-12 / student OUs)'; ExposingPolicies = $visible.Count; TargetedPolicies = $vals.Count; DomainSharedContacts = $note }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Domain shared contacts not exposed in the directory in all $($vals.Count) targeted policies" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ DomainSharedContacts = $note }
}

# ── ADMIN-009: User Profile Visibility ───────────────────────────────────
function Test-FortificationADMIN009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: directory.workspace_resource_type_visibility { googleGroups=bool }. This is the
    # closest directory-visibility signal this policy type exposes — when true, groups are
    # visible in the global directory. Intentionally WARN-on-exposure ("review this"), not FAIL.
    # Grade the WEAKEST OU: if ANY targeted policy makes groups visible the tenant WARNs; PASS
    # only when every targeted policy keeps them hidden.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'directory.workspace_resource_type_visibility' -Field 'googleGroups')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No directory.workspace_resource_type_visibility policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $visible = @($vals | Where-Object { $_ -eq $true })
    $note = "googleGroups: $((@($vals | ForEach-Object { "$_" }) | Select-Object -Unique) -join ', ') ($($visible.Count) of $($vals.Count) targeted policies)"
    $detail = 'This policy type (directory.workspace_resource_type_visibility) exposes googleGroups + domainSharedContacts only; profile-level visibility may also warrant manual review in Admin Console > Directory > Directory settings > Profile sharing'
    if ($visible.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Groups visible in the global directory — review whether this exposure is appropriate ($($visible.Count) of $($vals.Count) targeted policies)" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = $detail; ExposingPolicies = $visible.Count; TargetedPolicies = $vals.Count; GoogleGroups = $note }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Groups not exposed in the global directory in all $($vals.Count) targeted policies" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = $detail; GoogleGroups = $note }
}

# ── ADMIN-010: Groups Settings and External Membership ───────────────────
function Test-FortificationADMIN010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: groups_for_business.groups_sharing { ownersCanAllowExternalMembers=bool }.
    # When true, group owners may add members outside the organization — an external data
    # exposure surface. Grade the WEAKEST OU: if ANY targeted policy allows external members
    # the tenant FAILs; PASS only when every targeted policy disallows it.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'groups_for_business.groups_sharing' -Field 'ownersCanAllowExternalMembers')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No groups_for_business.groups_sharing policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $allowed = @($vals | Where-Object { $_ -eq $true })
    if ($allowed.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Group owners can allow external members in $($allowed.Count) of $($vals.Count) targeted policies — external membership exposes organizational data" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Restrict in Admin Console > Apps > Groups for Business > Sharing settings'; AllowingPolicies = $allowed.Count; TargetedPolicies = $vals.Count }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "External members disallowed in all $($vals.Count) targeted policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-011: Group Creation Restrictions ───────────────────────────────
function Test-FortificationADMIN011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: groups_for_business.groups_sharing { createGroupsAccessLevel=enum }.
    # Open creation (anyone / any user in domain) is a weaker posture than admin-restricted
    # creation, because it lets unmanaged sharing channels proliferate. The Cloud Identity
    # Policy API documents a small enum set, but the exact spelling has varied, so we match
    # known OPEN and known ADMIN-RESTRICTED values case-insensitively and treat anything we
    # don't recognise as WARN (never PASS on an unknown enum). Grade the WEAKEST (most-open)
    # OU: if any targeted policy is open the tenant FAILs; an unrecognised value WARNs.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'groups_for_business.groups_sharing' -Field 'createGroupsAccessLevel')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No groups_for_business.groups_sharing policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $levels  = @($vals | ForEach-Object { "$_" })
    $note    = "Create-group access level: $((@($levels) | Select-Object -Unique) -join ', ') (across $($levels.Count) targeted policy/policies)"
    # Known OPEN spellings (any user / anyone in domain) — weakest posture.
    $openRe  = '(?i)^(ANYONE_CAN_CREATE|ALL|ANYONE|EVERYONE|USERS_IN_DOMAIN|DOMAIN_USERS)$'
    # Known ADMIN-RESTRICTED spellings — secure posture.
    $adminRe = '(?i)^(ADMIN_ONLY|ADMINS_ONLY|ADMIN)$'
    $open    = @($levels | Where-Object { $_ -match $openRe })
    $admin   = @($levels | Where-Object { $_ -match $adminRe })
    $unknown = @($levels | Where-Object { $_ -notmatch $openRe -and $_ -notmatch $adminRe })

    if ($unknown.Count -gt 0) {
        # Never PASS/FAIL on an enum value we don't recognise — surface it for manual review.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized group-creation access level — verify manually whether creation is admin-restricted — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Enum spelling not recognized; the known OPEN/ADMIN values are best-effort guesses (ANYONE_CAN_CREATE/ALL/ANYONE/EVERYONE/USERS_IN_DOMAIN/DOMAIN_USERS vs ADMIN_ONLY/ADMINS_ONLY/ADMIN)' }
    }
    if ($open.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Group creation is open (non-admin) in $($open.Count) of $($levels.Count) targeted policy/policies — restrict to admins — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Unrestricted group creation can lead to unmanaged data sharing channels; OPEN enum spellings (ANYONE_CAN_CREATE/ALL/ANYONE/EVERYONE/USERS_IN_DOMAIN/DOMAIN_USERS) are best-effort guesses' }
    }
    # All targeted OUs restrict creation to admins.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Group creation restricted to admins in all $($admin.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'ADMIN-restricted enum spellings (ADMIN_ONLY/ADMINS_ONLY/ADMIN) are best-effort guesses' }
}

# ── ADMIN-012: Groups for Business Settings ──────────────────────────────
function Test-FortificationADMIN012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: groups_for_business.service_status { serviceState=enum(ENABLED/DISABLED) }.
    # The Cloud Identity Policy API exposes whether Groups for Business is turned on, but NOT
    # the granular external-posting / member-visibility sub-settings. So we can only conclude
    # at the service level: DISABLED removes the Groups-for-Business sharing surface entirely
    # (secure -> PASS). When ENABLED we cannot see the granular sharing config, so we WARN and
    # point to manual review rather than inventing a PASS. Grade the WEAKEST (most-enabled) OU.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'groups_for_business.service_status' -Field 'serviceState')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No groups_for_business.service_status policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $states   = @($vals | ForEach-Object { "$_" })
    $note     = "Service state: $((@($states) | Select-Object -Unique) -join ', ') (across $($states.Count) targeted policy/policies)"
    $enabled  = @($states | Where-Object { $_ -match '(?i)^ENABLED$' })
    $disabled = @($states | Where-Object { $_ -match '(?i)^DISABLED$' })
    $unknown  = @($states | Where-Object { $_ -notmatch '(?i)^(ENABLED|DISABLED)$' })

    if ($unknown.Count -gt 0) {
        # Never PASS on an enum value we don't recognise.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized Groups for Business service state — verify granular sharing settings manually — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Granular external-posting/visibility settings are not exposed via the Cloud Identity Policy API' }
    }
    if ($enabled.Count -gt 0) {
        # Service is on somewhere; granular posting/sharing config is not in the policy API.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Groups for Business enabled in $($enabled.Count) of $($states.Count) targeted policy/policies — verify external posting/sharing in Admin Console > Apps > Groups for Business > Sharing settings — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Granular external-posting/visibility settings are not exposed via the Cloud Identity Policy API' }
    }
    # All targeted OUs have the service disabled -> no Groups-for-Business sharing surface.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Groups for Business disabled in all $($disabled.Count) targeted policy/policies — no group sharing surface — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-013: Super Admin Count ─────────────────────────────────────────
function Test-FortificationADMIN013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    if (-not $AuditData.Users) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User data not available' -OrgUnitPath $OrgUnitPath
    }

    $superAdmins = @($AuditData.Users | Where-Object { $_.isAdmin -eq $true -and -not $_.suspended })
    $count = $superAdmins.Count

    $status = if ($count -ge 2 -and $count -le 4) { 'PASS' }
              elseif ($count -eq 1) { 'FAIL' }
              elseif ($count -eq 0) { 'FAIL' }
              else { 'WARN' }

    $currentValue = switch ($true) {
        ($count -eq 0) { 'No active super admin accounts found - critical governance gap' }
        ($count -eq 1) { "Only 1 super admin - single point of failure. Recommended: 2-4" }
        ($count -ge 2 -and $count -le 4) { "$count super admin(s) - within recommended range of 2-4" }
        default { "$count super admin(s) - exceeds recommended maximum of 4. Review and reduce" }
    }

    $adminEmails = @($superAdmins | ForEach-Object { $_.primaryEmail })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{ SuperAdminCount = $count; SuperAdmins = $adminEmails; RecommendedRange = '2-4' }
}

# ── Assured Controls helper: read a field that the Policy API may return in camelCase
#    (live JSON) or snake_case (as the docs spell it). Returns @() when absent so the
#    caller SKIPs honestly rather than inventing a result. ────────────────────────────
function Get-AssuredControlsFieldValue {
    [CmdletBinding()]
    param(
        $Policies,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$CamelField,
        [Parameter(Mandatory)][string]$SnakeField
    )
    $objs = @(Resolve-GooglePolicyValue -Policies $Policies -Type $Type)
    if ($objs.Count -eq 0) { return @() }
    $out = foreach ($o in $objs) {
        if ($null -eq $o) { continue }
        $names = $o.PSObject.Properties.Name
        if ($names -contains $CamelField)      { $o.$CamelField }
        elseif ($names -contains $SnakeField)  { $o.$SnakeField }
    }
    return @($out)
}

# ── ADMIN-014: Assured Controls - Access Approvals Enabled (GWS.ASSUREDCONTROLS.1.1v1)
function Test-FortificationADMIN014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: access_approval.axa_user_scoping { requiresCustomerApproval=bool }.
    # Secure = approval required everywhere. Grade WEAKEST OU: WARN (SHOULD) if any targeted
    # policy does not require approval. SKIP when the type/field is absent (Assured Controls
    # not licensed/configured, or API doesn't surface it) — never PASS on uncollectable data.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Get-AssuredControlsFieldValue -Policies $pol -Type 'access_approval.axa_user_scoping' `
        -CamelField 'requiresCustomerApproval' -SnakeField 'requires_customer_approval')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Access Approvals setting not exposed for this tenant (Assured Controls may not be licensed/configured). Not Assessed — verify in Admin Console > Data > Compliance > Access Management / Access Approvals' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.ASSUREDCONTROLS.1.1 — access_approval.axa_user_scoping not returned by the Policy API for this tenant' }
    }
    $notRequired = @($vals | Where-Object { $_ -ne $true })
    if ($notRequired.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Access Approvals not required in $($notRequired.Count) of $($vals.Count) targeted policy/policies — SCuBA recommends requiring approval before Google staff access data" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.ASSUREDCONTROLS.1.1 recommends enabling Access Approvals' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Access Approvals required in all $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-015: Assured Controls - Support Access Restricted to U.S. Staff
#    (GWS.ASSUREDCONTROLS.1.2v1) ──────────────────────────────────────────────────────
function Test-FortificationADMIN015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: access_management.user_scoping { allowedAudience=enum }. Documented enums:
    # US_GOOGLE_STAFF / CJIS_IRS_1075_GOOGLE_STAFF (US-restricted, secure), EU_GOOGLE_STAFF
    # (non-US -> WARN), PREFERENCE_UNSPECIFIED (not configured -> WARN). Grade WEAKEST OU.
    # Unknown enum -> WARN; absent -> SKIP (never PASS on uncollectable data).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Get-AssuredControlsFieldValue -Policies $pol -Type 'access_management.user_scoping' `
        -CamelField 'allowedAudience' -SnakeField 'allowed_audience')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Support-access audience setting not exposed for this tenant (Assured Controls may not be licensed/configured). Not Assessed — verify in Admin Console > Data > Compliance > Access Management' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.ASSUREDCONTROLS.1.2 — access_management.user_scoping not returned by the Policy API for this tenant' }
    }
    $auds   = @($vals | ForEach-Object { "$_" })
    $note   = "Allowed support audience: $((@($auds) | Select-Object -Unique) -join ', ') (across $($auds.Count) targeted policy/policies)"
    $usOnly = @($auds | Where-Object { $_ -match '(?i)^(US_GOOGLE_STAFF|CJIS_IRS_1075_GOOGLE_STAFF)$' })
    $nonUs  = @($auds | Where-Object { $_ -match '(?i)^EU_GOOGLE_STAFF$' })
    $unset  = @($auds | Where-Object { $_ -match '(?i)^(PREFERENCE_UNSPECIFIED)?$' })
    $known  = @($auds | Where-Object { $_ -match '(?i)^(US_GOOGLE_STAFF|CJIS_IRS_1075_GOOGLE_STAFF|EU_GOOGLE_STAFF|PREFERENCE_UNSPECIFIED)$' })

    if ($known.Count -ne $auds.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized support-audience value — verify manually that support is restricted to U.S. staff — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    if ($nonUs.Count -gt 0 -or $unset.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Support access is not restricted to U.S. Google staff in $((@($nonUs) + @($unset)).Count) of $($auds.Count) targeted policy/policies — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.ASSUREDCONTROLS.1.2 recommends restricting support access to U.S. Google staff' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Support access restricted to U.S. Google staff in all $($usOnly.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-016: Assured Controls - Multi-Region Data Processing Disabled
#    (GWS.ASSUREDCONTROLS.2.1v1) ──────────────────────────────────────────────────────
function Test-FortificationADMIN016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: data_regions.data_processing_region { limitToStorageRegion=bool }. SCuBA:
    # processing should be limited to the storage region (multi-region disabled) -> true is
    # secure. Grade WEAKEST OU: WARN (SHOULD) if any targeted policy does not limit processing.
    # Absent -> SKIP (Data Regions / Assured Controls not licensed) — never PASS on missing data.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Get-AssuredControlsFieldValue -Policies $pol -Type 'data_regions.data_processing_region' `
        -CamelField 'limitToStorageRegion' -SnakeField 'limit_to_storage_region')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Data-processing-region setting not exposed for this tenant (Data Regions / Assured Controls may not be licensed/configured). Not Assessed — verify in Admin Console > Data > Compliance > Data regions' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.ASSUREDCONTROLS.2.1 — data_regions.data_processing_region not returned by the Policy API for this tenant' }
    }
    $notLimited = @($vals | Where-Object { $_ -ne $true })
    if ($notLimited.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Data processing is not limited to the storage region in $($notLimited.Count) of $($vals.Count) targeted policy/policies — multi-region processing remains possible" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.ASSUREDCONTROLS.2.1 recommends limiting data processing to the chosen storage region across all products' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Data processing limited to the storage region in all $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-017: GWS.COMMONCONTROLS.10.3 — Internal apps not auto-trusted ─────
function Test-FortificationADMIN017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'api_controls.internal_apps' -Field 'trustInternalApps' -SecureValue $false -Status 'WARN' `
        -BadMsg 'Internal apps are automatically trusted (granted access without review)' -GoodMsg 'Internal apps are not automatically trusted'
}

# ── ADMIN-018: GWS.COMMONCONTROLS.15.1 — Data at-rest region configured ────
function Test-FortificationADMIN018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available' -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'data_regions.data_at_rest_region' -Field 'region')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No data_regions.data_at_rest_region policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    # No region preference set = data may be stored anywhere (no residency control).
    $unset = @($vals | Where-Object { "$_" -in @('NO_PREFERENCE', '', 'REGION_UNSPECIFIED') -or $null -eq $_ })
    if ($unset.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "No data-at-rest region preference is set in $($unset.Count) of $($vals.Count) targeted policy/policies — confirm this matches your residency policy" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "A data-at-rest region is configured in all $($vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-019: Data processing restricted to storage region (GWS.COMMONCONTROLS.15.2) ──
function Test-FortificationADMIN019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'data_regions.data_processing_region' -Field 'limitToStorageRegion' -SecureValue $true -Status 'FAIL' `
        -BadMsg 'Data processing is not limited to the storage region' -GoodMsg 'Data processing is limited to the storage region'
}

# ── ADMIN-020: Access to unconfigured third-party apps blocked (GWS.COMMONCONTROLS.10.4) ──
function Test-FortificationADMIN020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    # Compliant value is BLOCK_ALL_SCOPES. Per the ScubaGoggles Rego, the API enum values are
    # UNSPECIFIED_UBER_BLOCK / BLOCK_ALL_SCOPES / ALLOW_SIGN_IN_SCOPES_ONLY (NOT the doc labels
    # ACCESS_LEVEL_UNSPECIFIED / BLOCK_ALL / ALLOW_SIGN_IN_ONLY). Type dot-placement is derived,
    # not live-confirmed: validate 'api_controls.unconfigured_third_party_apps' on first live run.
    Test-GwsPolicyEnum -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'api_controls.unconfigured_third_party_apps' -Field 'accessLevel' -CompliantValues @('BLOCK_ALL_SCOPES') -Status 'FAIL' `
        -BadMsg 'Access to unconfigured third-party apps is not blocked' -GoodMsg 'Access to unconfigured third-party apps is blocked'
}

# ── ADMIN-021: Additional Google services without individual control restricted (GWS.COMMONCONTROLS.16.1) ──
function Test-FortificationADMIN021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    # INVERTED SEMANTICS (do not "fix"): serviceState ENABLED means the enterprise_service_restrictions
    # service is ON, which BLOCKS access to additional services (the compliant "services OFF" outcome).
    # The ScubaGoggles Rego flags an OU non-compliant when serviceState != ENABLED.
    Test-GwsPolicyEnum -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'enterprise_service_restrictions.service_status' -Field 'serviceState' -CompliantValues @('ENABLED') -Status 'WARN' `
        -BadMsg 'Access to additional Google services without individual control is not restricted' -GoodMsg 'Access to additional Google services without individual control is restricted'
}

# ── ADMIN-022: Early Access applications disabled (GWS.COMMONCONTROLS.16.2) ──
function Test-FortificationADMIN022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    # Fails only when serviceState == ENABLED (early-access service on); DISABLED and any other value
    # pass, matching the ScubaGoggles Rego, so this uses -NonCompliantValues, not an allow-list.
    Test-GwsPolicyEnum -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'early_access_apps.service_status' -Field 'serviceState' -NonCompliantValues @('ENABLED') -Status 'WARN' `
        -BadMsg 'Early Access applications are enabled' -GoodMsg 'Early Access applications are disabled'
}
