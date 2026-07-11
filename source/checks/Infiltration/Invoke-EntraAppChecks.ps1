# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-EntraAppChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraAppChecks'
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

# ── EIDAPP-001: Application Registration Inventory ──────────────────────
function Test-InfiltrationEIDAPP001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Applications.Errors) `
        -SourceKey @('Applications', 'AppRegistrations', 'ServicePrincipals') -Subject 'application inventory'
    if ($na) { return $na }

    $apps = $AuditData.Applications.AppRegistrations
    $sps = $AuditData.Applications.ServicePrincipals

    $appCount = if ($apps) { $apps.Count } else { 0 }
    $spCount = if ($sps) { $sps.Count } else { 0 }

    if ($appCount -eq 0 -and $spCount -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No application registrations or service principals found' `
            -Details @{ AppRegistrationCount = 0; ServicePrincipalCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$appCount app registrations, $spCount service principals" `
        -Details @{
            AppRegistrationCount  = $appCount
            ServicePrincipalCount = $spCount
            Apps                  = @($apps | Select-Object -First 100 | ForEach-Object {
                @{
                    AppId          = $_.appId
                    DisplayName    = $_.displayName
                    SignInAudience = $_.signInAudience
                    CreatedDateTime = $_.createdDateTime
                }
            })
        }
}

# ── EIDAPP-002: High-Risk API Permissions ────────────────────────────────
function Test-InfiltrationEIDAPP002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $apps = $AuditData.Applications.AppRegistrations
    if (-not $apps -or $apps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No application registrations available'
    }

    # Dangerous application permission IDs (Microsoft Graph)
    $dangerousPermissions = @{
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9' = 'Application.ReadWrite.All'
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8' = 'RoleManagement.ReadWrite.Directory'
        'e2a3a72e-5f79-4c64-b1b1-878b674786c9' = 'Mail.ReadWrite'
        '06b708a9-e830-4db3-a914-8e69da51d44f' = 'AppRoleAssignment.ReadWrite.All'
        '19dbc75e-c2e2-444c-a770-ec596d67b7e4' = 'Directory.ReadWrite.All'
        '741f803b-c850-494e-b5df-cde7c675a1ca' = 'User.ReadWrite.All'
        '62a82d76-70ea-41e2-9197-370581804d09' = 'Group.ReadWrite.All'
        '9492366f-7969-46a4-8d15-ed1a20078fff' = 'Sites.ReadWrite.All'
        'ef54d2bf-783f-4e0f-bca1-3210c0444d99' = 'Files.ReadWrite.All'
        '01d4f7ba-0ac5-41b9-838e-02e68906e5c8' = 'Mail.Send'
    }

    # Microsoft Graph resource app ID
    $graphResourceId = '00000003-0000-0000-c000-000000000000'

    $riskyApps = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($app in $apps) {
        if (-not $app.requiredResourceAccess) { continue }
        foreach ($resource in $app.requiredResourceAccess) {
            if ($resource.resourceAppId -ne $graphResourceId) { continue }
            foreach ($perm in @($resource.resourceAccess)) {
                # Only check Application permissions (type = 'Role')
                if ($perm.type -eq 'Role' -and $dangerousPermissions.ContainsKey($perm.id)) {
                    $riskyApps.Add(@{
                        AppId          = $app.appId
                        DisplayName    = $app.displayName
                        PermissionId   = $perm.id
                        PermissionName = $dangerousPermissions[$perm.id]
                    })
                }
            }
        }
    }

    if ($riskyApps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No applications request high-risk API permissions' `
            -Details @{ RiskyAppCount = 0 }
    }

    $uniqueApps = @($riskyApps | ForEach-Object { $_.AppId } | Select-Object -Unique).Count

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$uniqueApps apps request $($riskyApps.Count) high-risk API permissions" `
        -Details @{
            RiskyAppCount      = $uniqueApps
            TotalHighRiskPerms = $riskyApps.Count
            RiskyApps          = @($riskyApps)
        }
}

# ── EIDAPP-003: Apps with Credentials ────────────────────────────────────
function Test-InfiltrationEIDAPP003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $apps = $AuditData.Applications.AppRegistrations
    if (-not $apps -or $apps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No application registrations available'
    }

    $appsWithPasswords = @($apps | Where-Object {
        $_.passwordCredentials -and $_.passwordCredentials.Count -gt 0
    })
    $appsWithCerts = @($apps | Where-Object {
        $_.keyCredentials -and $_.keyCredentials.Count -gt 0
    })
    $appsWithAnyCredential = @($apps | Where-Object {
        ($_.passwordCredentials -and $_.passwordCredentials.Count -gt 0) -or
        ($_.keyCredentials -and $_.keyCredentials.Count -gt 0)
    })

    $totalCredentials = 0
    foreach ($app in $appsWithAnyCredential) {
        $totalCredentials += @($app.passwordCredentials).Count + @($app.keyCredentials).Count
    }

    $status = if ($appsWithAnyCredential.Count -eq 0) { 'PASS' }
              elseif ($appsWithAnyCredential.Count -le 10) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($appsWithAnyCredential.Count) apps have credentials ($($appsWithPasswords.Count) with passwords, $($appsWithCerts.Count) with certificates)" `
        -Details @{
            AppsWithCredentials = $appsWithAnyCredential.Count
            AppsWithPasswords   = $appsWithPasswords.Count
            AppsWithCerts       = $appsWithCerts.Count
            TotalCredentials    = $totalCredentials
            Apps                = @($appsWithAnyCredential | Select-Object -First 50 | ForEach-Object {
                @{
                    AppId           = $_.appId
                    DisplayName     = $_.displayName
                    PasswordCount   = @($_.passwordCredentials).Count
                    CertCount       = @($_.keyCredentials).Count
                }
            })
        }
}

# ── EIDAPP-004: First-Party Service Principals with Credentials ─────────
function Test-InfiltrationEIDAPP004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $sps = $AuditData.Applications.ServicePrincipals
    if (-not $sps -or $sps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No service principals available'
    }

    # Microsoft's tenant ID for first-party apps
    $microsoftTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

    $firstPartySPsWithCreds = @($sps | Where-Object {
        $_.appOwnerOrganizationId -eq $microsoftTenantId -and
        (($_.passwordCredentials -and $_.passwordCredentials.Count -gt 0) -or
         ($_.keyCredentials -and $_.keyCredentials.Count -gt 0))
    })

    if ($firstPartySPsWithCreds.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No first-party Microsoft service principals have custom credentials' `
            -Details @{ FirstPartyWithCredsCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($firstPartySPsWithCreds.Count) first-party Microsoft service principals have custom credentials — potential backdoor" `
        -Details @{
            FirstPartyWithCredsCount = $firstPartySPsWithCreds.Count
            ServicePrincipals        = @($firstPartySPsWithCreds | ForEach-Object {
                @{
                    Id              = $_.id
                    AppId           = $_.appId
                    DisplayName     = $_.displayName
                    PasswordCount   = @($_.passwordCredentials).Count
                    CertCount       = @($_.keyCredentials).Count
                }
            })
        }
}

# ── EIDAPP-005: High-Privilege Service Principals with Credentials ──────
function Test-InfiltrationEIDAPP005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $apps = $AuditData.Applications.AppRegistrations
    $sps = $AuditData.Applications.ServicePrincipals
    if (-not $apps -or -not $sps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Application or service principal data not available'
    }

    # Dangerous permission IDs (Application-level roles)
    $dangerousPermissionIds = @(
        '1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9'  # Application.ReadWrite.All
        '9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8'  # RoleManagement.ReadWrite.Directory
        '19dbc75e-c2e2-444c-a770-ec596d67b7e4'  # Directory.ReadWrite.All
        '06b708a9-e830-4db3-a914-8e69da51d44f'  # AppRoleAssignment.ReadWrite.All
    )

    $graphResourceId = '00000003-0000-0000-c000-000000000000'

    # Build set of appIds with high-priv permissions
    $highPrivAppIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($app in $apps) {
        if (-not $app.requiredResourceAccess) { continue }
        foreach ($resource in $app.requiredResourceAccess) {
            if ($resource.resourceAppId -ne $graphResourceId) { continue }
            foreach ($perm in @($resource.resourceAccess)) {
                if ($perm.type -eq 'Role' -and $perm.id -in $dangerousPermissionIds) {
                    [void]$highPrivAppIds.Add($app.appId)
                }
            }
        }
    }

    # Find SPs that match those appIds AND have credentials
    $highPrivSPsWithCreds = @($sps | Where-Object {
        $highPrivAppIds.Contains($_.appId) -and
        (($_.passwordCredentials -and $_.passwordCredentials.Count -gt 0) -or
         ($_.keyCredentials -and $_.keyCredentials.Count -gt 0))
    })

    if ($highPrivSPsWithCreds.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No high-privilege service principals have credentials' `
            -Details @{ HighPrivSPsWithCredsCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($highPrivSPsWithCreds.Count) high-privilege service principals have credentials attached" `
        -Details @{
            HighPrivSPsWithCredsCount = $highPrivSPsWithCreds.Count
            ServicePrincipals         = @($highPrivSPsWithCreds | ForEach-Object {
                @{
                    Id            = $_.id
                    AppId         = $_.appId
                    DisplayName   = $_.displayName
                    PasswordCount = @($_.passwordCredentials).Count
                    CertCount     = @($_.keyCredentials).Count
                }
            })
        }
}

# ── EIDAPP-006: Excessive Graph Permissions ──────────────────────────────
function Test-InfiltrationEIDAPP006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $consentGrants = $AuditData.Applications.ConsentGrants
    if (-not $consentGrants -or $consentGrants.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No consent grants available for analysis'
    }

    # Broad scope patterns indicating excessive permissions
    $broadScopePatterns = @('.ReadWrite.All', '.FullControl', 'Directory.ReadWrite', 'Sites.FullControl',
        'Mail.ReadWrite', 'Files.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All')

    $excessiveGrants = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($grant in $consentGrants) {
        if (-not $grant.scope) { continue }
        $scopes = $grant.scope -split ' '
        $broadScopes = @($scopes | Where-Object {
            $scope = $_
            ($broadScopePatterns | Where-Object { $scope -like "*$_*" }).Count -gt 0
        })
        if ($broadScopes.Count -gt 0) {
            $excessiveGrants.Add(@{
                ClientId     = $grant.clientId
                ConsentType  = $grant.consentType
                ResourceId   = $grant.resourceId
                BroadScopes  = @($broadScopes)
                AllScopes    = @($scopes)
            })
        }
    }

    if ($excessiveGrants.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No consent grants with excessive broad permissions detected'
    }

    $status = if ($excessiveGrants.Count -le 5) { 'WARN' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($excessiveGrants.Count) consent grants with excessive broad permissions" `
        -Details @{
            ExcessiveGrantCount = $excessiveGrants.Count
            Grants              = @($excessiveGrants | Select-Object -First 50)
        }
}

# ── EIDAPP-007: Apps with Azure IAM Roles ────────────────────────────────
function Test-InfiltrationEIDAPP007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Azure IAM role assignments require ARM data which is not part of the Entra data collection
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'Azure IAM role assignment analysis requires ARM data collection (not available in Entra-only audit)'
}

# ── EIDAPP-008: Expiring Credentials ─────────────────────────────────────
function Test-InfiltrationEIDAPP008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $apps = $AuditData.Applications.AppRegistrations
    if (-not $apps -or $apps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No application registrations available'
    }

    $now = [datetime]::UtcNow
    $thirtyDaysFromNow = $now.AddDays(30)

    $expiringSoon = [System.Collections.Generic.List[hashtable]]::new()
    $alreadyExpired = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($app in $apps) {
        foreach ($cred in @($app.passwordCredentials)) {
            if (-not $cred.endDateTime) { continue }
            $endDate = [datetime]::Parse($cred.endDateTime)
            if ($endDate -lt $now) {
                $alreadyExpired.Add(@{
                    AppId       = $app.appId
                    DisplayName = $app.displayName
                    CredType    = 'Password'
                    EndDate     = $cred.endDateTime
                    KeyId       = $cred.keyId
                })
            } elseif ($endDate -le $thirtyDaysFromNow) {
                $expiringSoon.Add(@{
                    AppId       = $app.appId
                    DisplayName = $app.displayName
                    CredType    = 'Password'
                    EndDate     = $cred.endDateTime
                    DaysLeft    = [Math]::Ceiling(($endDate - $now).TotalDays)
                    KeyId       = $cred.keyId
                })
            }
        }
        foreach ($cred in @($app.keyCredentials)) {
            if (-not $cred.endDateTime) { continue }
            $endDate = [datetime]::Parse($cred.endDateTime)
            if ($endDate -lt $now) {
                $alreadyExpired.Add(@{
                    AppId       = $app.appId
                    DisplayName = $app.displayName
                    CredType    = 'Certificate'
                    EndDate     = $cred.endDateTime
                    KeyId       = $cred.keyId
                })
            } elseif ($endDate -le $thirtyDaysFromNow) {
                $expiringSoon.Add(@{
                    AppId       = $app.appId
                    DisplayName = $app.displayName
                    CredType    = 'Certificate'
                    EndDate     = $cred.endDateTime
                    DaysLeft    = [Math]::Ceiling(($endDate - $now).TotalDays)
                    KeyId       = $cred.keyId
                })
            }
        }
    }

    if ($expiringSoon.Count -eq 0 -and $alreadyExpired.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No credentials expiring within 30 days or already expired'
    }

    $status = if ($alreadyExpired.Count -gt 0) { 'FAIL' }
              elseif ($expiringSoon.Count -gt 0) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($expiringSoon.Count) credentials expiring within 30 days, $($alreadyExpired.Count) already expired" `
        -Details @{
            ExpiringSoonCount  = $expiringSoon.Count
            AlreadyExpiredCount = $alreadyExpired.Count
            ExpiringSoon       = @($expiringSoon | Select-Object -First 50)
            AlreadyExpired     = @($alreadyExpired | Select-Object -First 50)
        }
}

# ── EIDAPP-009: Stale Applications ───────────────────────────────────────
function Test-InfiltrationEIDAPP009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $sps = $AuditData.Applications.ServicePrincipals
    if (-not $sps -or $sps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No service principals available for sign-in activity analysis'
    }

    # Check if any SP has signInActivity data (requires premium licensing)
    $spsWithActivity = @($sps | Where-Object { $_.signInActivity })
    if ($spsWithActivity.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Service principal sign-in activity data not available (requires Entra ID P1/P2)'
    }

    $now = [datetime]::UtcNow
    $ninetyDaysAgo = $now.AddDays(-90)

    $staleApps = @($spsWithActivity | Where-Object {
        $lastSignIn = $_.signInActivity.lastSignInDateTime
        if ($lastSignIn) {
            [datetime]::Parse($lastSignIn) -lt $ninetyDaysAgo
        } else {
            $true
        }
    })

    $status = if ($staleApps.Count -eq 0) { 'PASS' }
              elseif ($staleApps.Count -le 10) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($staleApps.Count) service principals have not signed in for 90+ days" `
        -Details @{
            StaleAppCount = $staleApps.Count
            TotalAnalyzed = $spsWithActivity.Count
            StaleApps     = @($staleApps | Select-Object -First 50 | ForEach-Object {
                @{
                    Id              = $_.id
                    AppId           = $_.appId
                    DisplayName     = $_.displayName
                    LastSignIn      = $_.signInActivity.lastSignInDateTime
                }
            })
        }
}

# ── EIDAPP-010: Multi-Tenant Application Analysis ───────────────────────
function Test-InfiltrationEIDAPP010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $apps = $AuditData.Applications.AppRegistrations
    if (-not $apps -or $apps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No application registrations available'
    }

    $multiTenantApps = @($apps | Where-Object {
        $_.signInAudience -eq 'AzureADMultipleOrgs' -or
        $_.signInAudience -eq 'AzureADandPersonalMicrosoftAccount' -or
        $_.signInAudience -eq 'PersonalMicrosoftAccount'
    })

    $singleTenantApps = @($apps | Where-Object {
        $_.signInAudience -eq 'AzureADMyOrg'
    })

    if ($multiTenantApps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($apps.Count) app registrations are single-tenant" `
            -Details @{ MultiTenantCount = 0; SingleTenantCount = $singleTenantApps.Count }
    }

    $status = if ($multiTenantApps.Count -le 3) { 'WARN' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($multiTenantApps.Count) multi-tenant app registrations found — review for necessity" `
        -Details @{
            MultiTenantCount  = $multiTenantApps.Count
            SingleTenantCount = $singleTenantApps.Count
            MultiTenantApps   = @($multiTenantApps | ForEach-Object {
                @{
                    AppId          = $_.appId
                    DisplayName    = $_.displayName
                    SignInAudience = $_.signInAudience
                    CreatedDateTime = $_.createdDateTime
                }
            })
        }
}

# ── EIDAPP-011: Consent Grant Analysis ───────────────────────────────────
function Test-InfiltrationEIDAPP011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Applications.Errors) `
        -SourceKey @('Applications', 'ConsentGrants') -Subject 'OAuth2 consent grants'
    if ($na) { return $na }

    $consentGrants = $AuditData.Applications.ConsentGrants
    if (-not $consentGrants -or $consentGrants.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No OAuth2 consent grants found' `
            -Details @{ TotalGrants = 0 }
    }

    $adminConsent = @($consentGrants | Where-Object { $_.consentType -eq 'AllPrincipals' })
    $userConsent = @($consentGrants | Where-Object { $_.consentType -eq 'Principal' })

    # User consent grants are higher risk as they may indicate consent phishing
    $status = if ($userConsent.Count -eq 0) { 'PASS' }
              elseif ($userConsent.Count -le 20) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($consentGrants.Count) consent grants: $($adminConsent.Count) admin consent, $($userConsent.Count) user consent" `
        -Details @{
            TotalGrants     = $consentGrants.Count
            AdminConsent    = $adminConsent.Count
            UserConsent     = $userConsent.Count
            AdminGrants     = @($adminConsent | Select-Object -First 30 | ForEach-Object {
                @{ ClientId = $_.clientId; ResourceId = $_.resourceId; Scope = $_.scope }
            })
            UserGrants      = @($userConsent | Select-Object -First 30 | ForEach-Object {
                @{ ClientId = $_.clientId; PrincipalId = $_.principalId; ResourceId = $_.resourceId; Scope = $_.scope }
            })
        }
}

# ── EIDAPP-012: User Consent Settings ────────────────────────────────────
function Test-InfiltrationEIDAPP012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Check AuthorizationPolicy for user consent configuration
    $authzPolicy = $AuditData.TenantConfig.AuthorizationPolicy
    if (-not $authzPolicy) {
        $authzPolicy = $AuditData.AuthMethods.AuthorizationPolicy
    }

    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available to check user consent settings'
    }

    $permissionGrantPolicies = $authzPolicy.permissionGrantPolicyIdsAssignedToDefaultUserRole
    $allowUserConsent = $permissionGrantPolicies -and $permissionGrantPolicies.Count -gt 0

    # Check if user consent is unrestricted
    $hasManagePermissionGrants = $permissionGrantPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
    $hasLowRiskOnly = $permissionGrantPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-low'

    $status = if (-not $allowUserConsent) { 'PASS' }
              elseif ($hasLowRiskOnly -and -not $hasManagePermissionGrants) { 'WARN' }
              else { 'FAIL' }

    $currentValue = if (-not $allowUserConsent) {
        'User consent is disabled — users cannot consent to apps'
    } elseif ($hasLowRiskOnly) {
        'User consent limited to low-risk permissions from verified publishers'
    } else {
        'User consent is enabled — users can consent to apps without admin approval'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            AllowUserConsent           = $allowUserConsent
            PermissionGrantPolicies    = @($permissionGrantPolicies ?? @())
            HasLegacyUserConsent       = $hasManagePermissionGrants
            HasLowRiskOnly             = $hasLowRiskOnly
        }
}

# ── EIDAPP-013: Admin Consent Workflow ───────────────────────────────────
function Test-InfiltrationEIDAPP013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'AdminConsentRequestPolicy') -Subject 'admin consent request policy'
    if ($na) { return $na }

    $adminConsentPolicy = $AuditData.TenantConfig.AdminConsentRequestPolicy
    if (-not $adminConsentPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Admin consent request policy not available' `
            -Details @{ PolicyAvailable = $false }
    }

    $isEnabled = $adminConsentPolicy.isEnabled

    if ($isEnabled) {
        $reviewers = $adminConsentPolicy.reviewers
        $reviewerCount = if ($reviewers) { $reviewers.Count } else { 0 }

        $status = if ($reviewerCount -gt 0) { 'PASS' } else { 'WARN' }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Admin consent workflow enabled with $reviewerCount reviewer(s)" `
            -Details @{
                IsEnabled      = $true
                ReviewerCount  = $reviewerCount
                Reviewers      = @($reviewers | ForEach-Object {
                    @{ Query = $_.query; QueryType = $_.queryType; QueryRoot = $_.queryRoot }
                })
                RequestExpiresInDays = $adminConsentPolicy.requestExpiresInDays
                NotificationsEnabled = $adminConsentPolicy.notificationsEnabled
                RemindersEnabled     = $adminConsentPolicy.remindersEnabled
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue 'Admin consent workflow is not enabled — users cannot request admin consent for blocked apps' `
        -Details @{ IsEnabled = $false }
}

# ── EIDAPP-014: Application Impersonation Permissions ────────────────────
function Test-InfiltrationEIDAPP014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Full EWS/EXO impersonation analysis requires Exchange Online data
    # Check for known impersonation permission IDs in app registrations
    $apps = $AuditData.Applications.AppRegistrations
    if (-not $apps -or $apps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Application impersonation check requires Exchange Online data for complete analysis'
    }

    # Exchange Online (Office 365 Exchange Online) resource app ID
    $exchangeResourceId = '00000002-0000-0ff1-ce00-000000000000'
    # full_access_as_app permission ID
    $fullAccessAsApp = 'dc890d15-9560-4a4c-9b7f-a736ec74ec40'

    $impersonationApps = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($app in $apps) {
        if (-not $app.requiredResourceAccess) { continue }
        foreach ($resource in $app.requiredResourceAccess) {
            if ($resource.resourceAppId -ne $exchangeResourceId) { continue }
            foreach ($perm in @($resource.resourceAccess)) {
                if ($perm.type -eq 'Role' -and $perm.id -eq $fullAccessAsApp) {
                    $impersonationApps.Add(@{
                        AppId       = $app.appId
                        DisplayName = $app.displayName
                    })
                }
            }
        }
    }

    if ($impersonationApps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No apps have Exchange full_access_as_app impersonation permission' `
            -Details @{ ImpersonationAppCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($impersonationApps.Count) apps have Exchange full_access_as_app impersonation permission" `
        -Details @{
            ImpersonationAppCount = $impersonationApps.Count
            Apps                  = @($impersonationApps)
        }
}

# ── EIDAPP-015: OAuth2 Permission Grants Detail ─────────────────────────
function Test-InfiltrationEIDAPP015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Applications.Errors) `
        -SourceKey @('Applications', 'ConsentGrants') -Subject 'OAuth2 permission grants'
    if ($na) { return $na }

    $consentGrants = $AuditData.Applications.ConsentGrants
    if (-not $consentGrants -or $consentGrants.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No OAuth2 permission grants to analyze'
    }

    # Analyze scope distributions
    $allScopes = [System.Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
    $readWriteScopes = [System.Collections.Generic.List[string]]::new()

    foreach ($grant in $consentGrants) {
        if (-not $grant.scope) { continue }
        foreach ($scope in ($grant.scope -split ' ')) {
            $scope = $scope.Trim()
            if (-not $scope) { continue }
            if ($allScopes.ContainsKey($scope)) {
                $allScopes[$scope]++
            } else {
                $allScopes[$scope] = 1
            }
            if ($scope -match '\.ReadWrite' -or $scope -match '\.FullControl') {
                if (-not $readWriteScopes.Contains($scope)) {
                    $readWriteScopes.Add($scope)
                }
            }
        }
    }

    $topScopes = @($allScopes.GetEnumerator() | Sort-Object -Property Value -Descending |
        Select-Object -First 20 | ForEach-Object {
            @{ Scope = $_.Key; Count = $_.Value }
        })

    $status = if ($readWriteScopes.Count -eq 0) { 'PASS' }
              elseif ($readWriteScopes.Count -le 10) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($allScopes.Count) unique scopes across $($consentGrants.Count) grants ($($readWriteScopes.Count) read-write scopes)" `
        -Details @{
            TotalGrants        = $consentGrants.Count
            UniqueScopes       = $allScopes.Count
            ReadWriteScopeCount = $readWriteScopes.Count
            ReadWriteScopes    = @($readWriteScopes)
            TopScopes          = $topScopes
        }
}

# ── EIDAPP-016: Managed Identity Inventory ───────────────────────────────
function Test-InfiltrationEIDAPP016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $sps = $AuditData.Applications.ServicePrincipals
    if (-not $sps -or $sps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No service principals available'
    }

    $managedIdentities = @($sps | Where-Object {
        $_.servicePrincipalType -eq 'ManagedIdentity'
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($managedIdentities.Count) managed identities found" `
        -Details @{
            TotalManagedIdentities = $managedIdentities.Count
            ManagedIdentities      = @($managedIdentities | Select-Object -First 100 | ForEach-Object {
                @{
                    Id              = $_.id
                    AppId           = $_.appId
                    DisplayName     = $_.displayName
                    AccountEnabled  = $_.accountEnabled
                }
            })
        }
}

# ── EIDAPP-017: Service Principal Sign-In Activity ──────────────────────
function Test-InfiltrationEIDAPP017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $sps = $AuditData.Applications.ServicePrincipals
    if (-not $sps -or $sps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No service principals available'
    }

    # Check if sign-in activity data is present on any SP
    $spsWithActivity = @($sps | Where-Object { $_.signInActivity })
    if ($spsWithActivity.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Service principal sign-in activity data not available (may require Entra ID P1/P2 or additional data collection)'
    }

    $now = [datetime]::UtcNow
    $active = @($spsWithActivity | Where-Object {
        $_.signInActivity.lastSignInDateTime -and
        ([datetime]::Parse($_.signInActivity.lastSignInDateTime)) -ge $now.AddDays(-30)
    })
    $inactive = @($spsWithActivity | Where-Object {
        -not $_.signInActivity.lastSignInDateTime -or
        ([datetime]::Parse($_.signInActivity.lastSignInDateTime)) -lt $now.AddDays(-30)
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($active.Count) active (30d), $($inactive.Count) inactive out of $($spsWithActivity.Count) SPs with activity data" `
        -Details @{
            ActiveCount   = $active.Count
            InactiveCount = $inactive.Count
            TotalAnalyzed = $spsWithActivity.Count
        }
}

# ── EIDAPP-018: Application Change Tracking ──────────────────────────────
function Test-InfiltrationEIDAPP018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Application change tracking requires audit log data
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'Application change tracking requires audit log data collection (not available in current data set)'
}

# ── EIDAPP-019: Dangling Reply URLs ──────────────────────────────────────
function Test-InfiltrationEIDAPP019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $apps = $AuditData.Applications.AppRegistrations
    if (-not $apps -or $apps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No application registrations available'
    }

    # Suspicious patterns in redirect URIs: localhost, non-HTTPS, IP addresses, wildcards
    $suspiciousPatterns = @(
        'http://'
        'localhost'
        '127.0.0.1'
        '0.0.0.0'
        'urn:ietf:wg:oauth:2.0:oob'
    )

    $danglingApps = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($app in $apps) {
        $redirectUris = @()
        if ($app.web -and $app.web.redirectUris) {
            $redirectUris += @($app.web.redirectUris)
        }
        if ($app.spa -and $app.spa.redirectUris) {
            $redirectUris += @($app.spa.redirectUris)
        }
        if ($app.publicClient -and $app.publicClient.redirectUris) {
            $redirectUris += @($app.publicClient.redirectUris)
        }

        if ($redirectUris.Count -eq 0) { continue }

        $suspiciousUris = @($redirectUris | Where-Object {
            $uri = $_
            if (-not $uri) { return $false }
            ($suspiciousPatterns | Where-Object { $uri -match [regex]::Escape($_) }).Count -gt 0
        })

        if ($suspiciousUris.Count -gt 0) {
            $danglingApps.Add(@{
                AppId          = $app.appId
                DisplayName    = $app.displayName
                SuspiciousUris = @($suspiciousUris)
                TotalUris      = $redirectUris.Count
            })
        }
    }

    if ($danglingApps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No applications with suspicious or dangling reply URLs detected'
    }

    $status = if ($danglingApps.Count -le 5) { 'WARN' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($danglingApps.Count) apps with suspicious reply URLs (localhost, HTTP, IP addresses)" `
        -Details @{
            DanglingAppCount = $danglingApps.Count
            Apps             = @($danglingApps | Select-Object -First 50)
        }
}

# ── EIDAPP-020: Group Owner Consent to Applications Blocked (MS.AAD.5.4) ──
function Test-InfiltrationEIDAPP020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Group-specific (group owner) consent is governed by the directory (group) settings
    # 'EnableGroupSpecificConsent' value within the Group.Unified settings template.
    # These directory settings are collected alongside password protection settings via /groupSettings.
    $settings = $AuditData.AuthMethods.DirectorySettings
    if (-not $settings -or $settings.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Directory (group) settings not available — group owner consent state Not Assessed'
    }

    $groupSetting = $settings | Where-Object {
        $_.displayName -eq 'Group.Unified' -or
        $_.templateId -eq '62375ab9-6b52-47ed-826b-58e47e0e304b'
    } | Select-Object -First 1

    $consentValue = $null
    if ($groupSetting) {
        $consentValue = ($groupSetting.values | Where-Object { $_.name -eq 'EnableGroupSpecificConsent' }).value
    }

    if ($null -eq $consentValue -or $consentValue -eq '') {
        # No explicit Group.Unified directory setting present. The tenant default for
        # EnableGroupSpecificConsent is false (group owner consent disabled), but absence of
        # evidence is not compliance — surface honestly rather than asserting PASS.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'EnableGroupSpecificConsent not present in directory (group) settings — group owner consent state Not Assessed' `
            -Details @{
                GroupSettingPresent = [bool]$groupSetting
                Note                = 'No explicit Group.Unified directory setting found. Verify group owner consent is disabled in the portal.'
            }
    }

    # 'false' = group owners cannot consent to apps (desired). 'true' = they can (finding).
    $enabled = $consentValue -eq 'true' -or $consentValue -eq $true
    $status = if ($enabled) { 'FAIL' } else { 'PASS' }

    $currentValue = if ($enabled) {
        'Group owners CAN consent to applications (EnableGroupSpecificConsent = true) — fails SCuBA MS.AAD.5.4'
    } else {
        'Group owners cannot consent to applications (EnableGroupSpecificConsent = false)'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            EnableGroupSpecificConsent = $consentValue
            GroupOwnerConsentAllowed   = $enabled
        }
}
