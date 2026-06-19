# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
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

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Directory sharing settings not available via API. Verify in Admin Console > Directory > Directory settings > Sharing settings that contact sharing is restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'External directory sharing exposes organizational structure and contact information to external parties' }
}

# ── ADMIN-009: User Profile Visibility ───────────────────────────────────
function Test-FortificationADMIN009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'User profile visibility settings not available via API. Verify in Admin Console > Directory > Directory settings > Profile sharing that visibility is appropriately restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Profile information can aid reconnaissance; restrict visibility to internal users' }
}

# ── ADMIN-010: Groups Settings and External Membership ───────────────────
function Test-FortificationADMIN010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Groups data may be available if collected
    if ($AuditData.Groups) {
        $groups = @($AuditData.Groups)
        $externalGroups = @($groups | Where-Object {
            $_.allowExternalMembers -eq $true -or $_.whoCanJoin -eq 'ANYONE_CAN_JOIN'
        })

        if ($externalGroups.Count -gt 0) {
            $groupEmails = @($externalGroups | ForEach-Object { $_.email } | Select-Object -First 20)
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                -CurrentValue "$($externalGroups.Count) of $($groups.Count) group(s) allow external members" `
                -OrgUnitPath $OrgUnitPath `
                -Details @{ ExternalGroups = $groupEmails; TotalGroups = $groups.Count }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "None of the $($groups.Count) group(s) allow external members" `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Groups data not available. Verify in Admin Console > Apps > Groups for Business > Sharing settings that external membership is restricted' `
        -OrgUnitPath $OrgUnitPath
}

# ── ADMIN-011: Group Creation Restrictions ───────────────────────────────
function Test-FortificationADMIN011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Group creation restrictions not available via API. Verify in Admin Console > Apps > Groups for Business > Sharing settings that group creation is restricted to admins' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Unrestricted group creation can lead to unmanaged data sharing channels' }
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
