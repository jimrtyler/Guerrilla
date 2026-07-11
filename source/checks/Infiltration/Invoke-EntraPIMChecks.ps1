# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-EntraPIMChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraPIMChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
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

# ── EIDPIM-001: Global Administrator Enumeration ─────────────────────────
function Test-InfiltrationEIDPIM001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $globalAdmins = $AuditData.PIM.GlobalAdmins
    if (-not $globalAdmins) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Global Administrator data not available'
    }

    $count = $globalAdmins.Count
    $status = if ($count -ge 2 -and $count -le 4) { 'PASS' }
              elseif ($count -eq 1 -or $count -eq 5) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$count Global Administrators (recommended: 2-4)" `
        -Details @{
            Count  = $count
            Admins = @($globalAdmins | ForEach-Object {
                @{
                    Id                = $_.id
                    DisplayName       = $_.displayName
                    UserPrincipalName = $_.userPrincipalName
                    UserType          = $_.userType
                    AccountEnabled    = $_.accountEnabled
                }
            })
        }
}

# ── EIDPIM-002: All Privileged Role Assignments ─────────────────────────
function Test-InfiltrationEIDPIM002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'RoleAssignments', 'RoleEligibilitySchedules', 'RoleDefinitions') `
        -Subject 'privileged role assignments'
    if ($na) { return $na }

    $activeAssignments = $AuditData.PIM.RoleAssignments
    $eligibleAssignments = $AuditData.PIM.RoleEligibilitySchedules
    $roleDefinitions = $AuditData.PIM.RoleDefinitions

    $roleLookup = @{}
    foreach ($rd in $roleDefinitions) {
        $roleLookup[$rd.id] = $rd.displayName
    }

    $permanentCount = $activeAssignments.Count
    $eligibleCount = $eligibleAssignments.Count

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$permanentCount active assignments, $eligibleCount eligible assignments" `
        -Details @{
            ActiveCount   = $permanentCount
            EligibleCount = $eligibleCount
            ActiveAssignments = @($activeAssignments | Select-Object -First 100 | ForEach-Object {
                @{
                    PrincipalId    = $_.principalId
                    RoleId         = $_.roleDefinitionId
                    RoleName       = $roleLookup[$_.roleDefinitionId] ?? 'Unknown'
                    DirectoryScope = $_.directoryScopeId
                }
            })
        }
}

# ── EIDPIM-003: Permanent Privileged Assignments ────────────────────────
function Test-InfiltrationEIDPIM003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'RoleAssignments', 'RoleEligibilitySchedules', 'RoleDefinitions') `
        -Subject 'privileged role assignments'
    if ($na) { return $na }

    $activeAssignments = $AuditData.PIM.RoleAssignments
    $eligibleAssignments = $AuditData.PIM.RoleEligibilitySchedules
    $roleDefinitions = $AuditData.PIM.RoleDefinitions

    # Privileged role template IDs
    $privilegedRoleIds = @(
        '62e90394-69f5-4237-9190-012177145e10'  # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814'  # Privileged Role Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d'  # Security Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'  # Privileged Authentication Admin
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'  # Conditional Access Admin
    )

    $roleLookup = @{}
    foreach ($rd in $roleDefinitions) { $roleLookup[$rd.id] = $rd.displayName }

    # Active (permanent) assignments to privileged roles
    $permanentPrivileged = @($activeAssignments | Where-Object {
        $_.roleDefinitionId -in $privilegedRoleIds
    })

    # Eligible assignments to same roles
    $eligibleIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $eligibleAssignments) {
        if ($e.roleDefinitionId -in $privilegedRoleIds) {
            [void]$eligibleIds.Add("$($e.principalId)|$($e.roleDefinitionId)")
        }
    }

    # Permanent assignments that should be eligible
    $shouldBeEligible = @($permanentPrivileged | Where-Object {
        -not $eligibleIds.Contains("$($_.principalId)|$($_.roleDefinitionId)")
    })

    $status = if ($shouldBeEligible.Count -eq 0) { 'PASS' }
              elseif ($shouldBeEligible.Count -le 2) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($shouldBeEligible.Count) permanent privileged assignments should be converted to eligible (JIT)" `
        -Details @{
            PermanentPrivilegedCount = $permanentPrivileged.Count
            ShouldBeEligibleCount    = $shouldBeEligible.Count
            Assignments              = @($shouldBeEligible | ForEach-Object {
                @{
                    PrincipalId = $_.principalId
                    RoleName    = $roleLookup[$_.roleDefinitionId] ?? $_.roleDefinitionId
                }
            })
        }
}

# ── EIDPIM-004: Guest Users in Privileged Roles ─────────────────────────
function Test-InfiltrationEIDPIM004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'PrivilegedUsers') -Subject 'privileged user details'
    if ($na) { return $na }

    $privilegedUsers = $AuditData.PIM.PrivilegedUsers
    if (-not $privilegedUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged user details not available'
    }

    $guestAdmins = @($privilegedUsers | Where-Object { $_.userType -eq 'Guest' })

    $status = if ($guestAdmins.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($guestAdmins.Count) guest/external users have privileged role assignments" `
        -Details @{
            GuestAdminCount = $guestAdmins.Count
            GuestAdmins     = @($guestAdmins | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; UserPrincipalName = $_.userPrincipalName }
            })
        }
}

# ── EIDPIM-005: Synced Accounts in Privileged Roles ─────────────────────
function Test-InfiltrationEIDPIM005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'PrivilegedUsers') -Subject 'privileged user details'
    if ($na) { return $na }

    $privilegedUsers = $AuditData.PIM.PrivilegedUsers
    if (-not $privilegedUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged user details not available'
    }

    $syncedAdmins = @($privilegedUsers | Where-Object { $_.onPremisesSyncEnabled -eq $true })

    $status = if ($syncedAdmins.Count -eq 0) { 'PASS' }
              elseif ($syncedAdmins.Count -le 2) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($syncedAdmins.Count) on-premises synced accounts have privileged cloud roles" `
        -Details @{
            SyncedAdminCount = $syncedAdmins.Count
            SyncedAdmins     = @($syncedAdmins | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; UserPrincipalName = $_.userPrincipalName }
            })
        }
}

# ── EIDPIM-006: Privileged Users Without MFA ────────────────────────────
function Test-InfiltrationEIDPIM006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors, $AuditData.AuthMethods.Errors) `
        -SourceKey @('PIM', 'PrivilegedUsers', 'AuthMethods', 'UserRegistrationDetails') `
        -Subject 'privileged user or MFA registration details'
    if ($na) { return $na }

    $privilegedUsers = $AuditData.PIM.PrivilegedUsers
    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $privilegedUsers -or -not $registrationDetails) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged user or MFA registration data not available'
    }

    $mfaLookup = @{}
    foreach ($reg in $registrationDetails) {
        if ($reg.id) { $mfaLookup[$reg.id] = $reg }
    }

    $noMfaAdmins = @($privilegedUsers | Where-Object {
        $_.accountEnabled -eq $true -and
        (-not $mfaLookup.ContainsKey($_.id) -or $mfaLookup[$_.id].isMfaRegistered -ne $true)
    })

    $status = if ($noMfaAdmins.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($noMfaAdmins.Count) privileged users without MFA registered" `
        -Details @{
            NoMfaAdminCount = $noMfaAdmins.Count
            Users           = @($noMfaAdmins | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; UserPrincipalName = $_.userPrincipalName }
            })
        }
}

# ── EIDPIM-007: Privileged Users with Weak Auth Methods ─────────────────
function Test-InfiltrationEIDPIM007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors, $AuditData.AuthMethods.Errors) `
        -SourceKey @('PIM', 'PrivilegedUsers', 'AuthMethods', 'UserRegistrationDetails') `
        -Subject 'privileged user or MFA registration details'
    if ($na) { return $na }

    $privilegedUsers = $AuditData.PIM.PrivilegedUsers
    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $privilegedUsers -or -not $registrationDetails) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged user or MFA registration data not available'
    }

    $strongMethods = @('microsoftAuthenticatorPush', 'softwareOneTimePasscode',
        'hardwareOneTimePasscode', 'microsoftAuthenticatorPasswordless',
        'fido2', 'windowsHelloForBusiness', 'passKeyDeviceBound')

    $mfaLookup = @{}
    foreach ($reg in $registrationDetails) {
        if ($reg.id) { $mfaLookup[$reg.id] = $reg }
    }

    $weakAuthAdmins = @($privilegedUsers | Where-Object {
        $_.accountEnabled -eq $true -and
        $mfaLookup.ContainsKey($_.id) -and
        $mfaLookup[$_.id].isMfaRegistered -eq $true -and
        ($mfaLookup[$_.id].methodsRegistered | Where-Object { $_ -in $strongMethods }).Count -eq 0
    })

    $status = if ($weakAuthAdmins.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($weakAuthAdmins.Count) privileged users rely only on weak MFA methods (SMS/voice)" `
        -Details @{
            WeakAuthAdminCount = $weakAuthAdmins.Count
            Users              = @($weakAuthAdmins | ForEach-Object {
                @{
                    Id                = $_.id
                    DisplayName       = $_.displayName
                    Methods           = @($mfaLookup[$_.id].methodsRegistered)
                }
            })
        }
}

# ── EIDPIM-008: Disabled Accounts in Privileged Roles ───────────────────
function Test-InfiltrationEIDPIM008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'PrivilegedUsers') -Subject 'privileged user details'
    if ($na) { return $na }

    $privilegedUsers = $AuditData.PIM.PrivilegedUsers
    if (-not $privilegedUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged user details not available'
    }

    $disabledAdmins = @($privilegedUsers | Where-Object { $_.accountEnabled -eq $false })

    $status = if ($disabledAdmins.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($disabledAdmins.Count) disabled accounts still hold privileged role assignments" `
        -Details @{
            DisabledAdminCount = $disabledAdmins.Count
            Users              = @($disabledAdmins | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; UserPrincipalName = $_.userPrincipalName }
            })
        }
}

# ── EIDPIM-009: Never-Signed-In Privileged Accounts ─────────────────────
function Test-InfiltrationEIDPIM009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'PrivilegedUsers') -Subject 'privileged user details'
    if ($na) { return $na }

    $privilegedUsers = $AuditData.PIM.PrivilegedUsers
    if (-not $privilegedUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged user details not available'
    }

    $neverSignedIn = @($privilegedUsers | Where-Object {
        $_.accountEnabled -eq $true -and
        (-not $_.signInActivity -or -not $_.signInActivity.lastSignInDateTime)
    })

    $status = if ($neverSignedIn.Count -eq 0) { 'PASS' }
              elseif ($neverSignedIn.Count -le 2) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($neverSignedIn.Count) privileged accounts have never signed in" `
        -Details @{
            NeverSignedInCount = $neverSignedIn.Count
            Users              = @($neverSignedIn | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; CreatedDateTime = $_.createdDateTime }
            })
        }
}

# ── EIDPIM-010: PIM Configuration Audit ─────────────────────────────────
function Test-InfiltrationEIDPIM010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'RoleAssignmentSchedules', 'RoleEligibilitySchedules') `
        -Subject 'PIM role schedules'
    if ($na) { return $na }

    $roleAssignmentSchedules = $AuditData.PIM.RoleAssignmentSchedules
    $eligibilitySchedules = $AuditData.PIM.RoleEligibilitySchedules

    $hasPIM = ($eligibilitySchedules -and $eligibilitySchedules.Count -gt 0)

    if (-not $hasPIM) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'PIM does not appear to be configured — no eligible role assignments found' `
            -Details @{ PIMConfigured = $false }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "PIM configured with $($eligibilitySchedules.Count) eligible role assignments" `
        -Details @{
            PIMConfigured            = $true
            EligibleAssignmentCount  = $eligibilitySchedules.Count
            ActiveScheduleCount      = $roleAssignmentSchedules.Count
        }
}

# ── EIDPIM-011: PIM Activation History ──────────────────────────────────
function Test-InfiltrationEIDPIM011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $scheduleInstances = $AuditData.PIM.RoleAssignmentSchedules
    if (-not $scheduleInstances) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'PIM activation data not available'
    }

    $activeActivations = @($scheduleInstances | Where-Object {
        $_.assignmentType -eq 'Activated'
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($activeActivations.Count) currently active PIM activations out of $($scheduleInstances.Count) schedule instances" `
        -Details @{
            ActiveActivations    = $activeActivations.Count
            TotalScheduleInstances = $scheduleInstances.Count
        }
}

# ── EIDPIM-012: Break-Glass Account Validation ─────────────────────────
function Test-InfiltrationEIDPIM012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'GlobalAdmins') -Subject 'Global Administrator accounts'
    if ($na) { return $na }

    $globalAdmins = $AuditData.PIM.GlobalAdmins
    if (-not $globalAdmins -or $globalAdmins.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No Global Administrators found — cannot validate break-glass accounts'
    }

    # Heuristic: break-glass accounts are often cloud-only, with specific naming patterns
    $breakGlassPatterns = @('breakglass', 'break-glass', 'emergency', 'bg-', 'bg_')
    $cloudOnlyGAs = @($globalAdmins | Where-Object { $_.onPremisesSyncEnabled -ne $true })
    $potentialBG = @($cloudOnlyGAs | Where-Object {
        $name = ($_.displayName ?? '').ToLower()
        $upn = ($_.userPrincipalName ?? '').ToLower()
        $breakGlassPatterns | Where-Object { $name -match $_ -or $upn -match $_ }
    })

    # Also look for GA accounts excluded from most CA policies (from CA data)
    $status = if ($potentialBG.Count -ge 2) { 'PASS' }
              elseif ($potentialBG.Count -eq 1) { 'WARN' }
              else { 'WARN' }

    $currentValue = if ($potentialBG.Count -ge 2) {
        "$($potentialBG.Count) potential break-glass accounts identified"
    } elseif ($potentialBG.Count -eq 1) {
        '1 potential break-glass account found — recommend at least 2'
    } else {
        'No accounts matching break-glass naming patterns found — verify emergency access accounts exist'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            PotentialBreakGlassCount = $potentialBG.Count
            CloudOnlyGACount         = $cloudOnlyGAs.Count
            TotalGACount             = $globalAdmins.Count
        }
}

# ── EIDPIM-013: Separate Admin Account Enforcement ─────────────────────
function Test-InfiltrationEIDPIM013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.PIM.Errors) `
        -SourceKey @('PIM', 'PrivilegedUsers') -Subject 'privileged user details'
    if ($na) { return $na }

    $privilegedUsers = $AuditData.PIM.PrivilegedUsers
    if (-not $privilegedUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Privileged user details not available'
    }

    # Heuristic: admin accounts should have naming convention (admin, adm, -a, .admin)
    $adminPatterns = @('admin', 'adm-', 'adm_', '-adm', '_adm', '.admin', '-a@', '_a@')
    $adminAccounts = @($privilegedUsers | Where-Object {
        $upn = ($_.userPrincipalName ?? '').ToLower()
        $name = ($_.displayName ?? '').ToLower()
        ($adminPatterns | Where-Object { $upn -match $_ -or $name -match $_ }).Count -gt 0
    })

    $nonAdminPattern = $privilegedUsers.Count - $adminAccounts.Count
    $percentage = if ($privilegedUsers.Count -gt 0) {
        [Math]::Round(($adminAccounts.Count / $privilegedUsers.Count) * 100, 1)
    } else { 0 }

    $status = if ($percentage -ge 80) { 'PASS' }
              elseif ($percentage -ge 50) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($adminAccounts.Count) of $($privilegedUsers.Count) privileged accounts ($percentage%) follow admin naming convention" `
        -Details @{
            AdminPatternCount    = $adminAccounts.Count
            NonAdminPatternCount = $nonAdminPattern
            TotalPrivileged      = $privilegedUsers.Count
            Percentage           = $percentage
        }
}

# ── EIDPIM-014: Role Assignment Notification Settings ───────────────────
function Test-InfiltrationEIDPIM014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # PIM notification settings require roleManagement/directory/roleAssignmentApprovals
    # and specific PIM policy endpoints that may need beta API
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'PIM notification settings audit requires PIM-specific policy endpoints (beta API)'
}
