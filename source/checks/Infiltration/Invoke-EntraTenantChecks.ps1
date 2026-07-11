# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-EntraTenantChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraTenantChecks'
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

# ── EIDTNT-001: Tenant Settings Export ───────────────────────────────────
function Test-InfiltrationEIDTNT001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'Organization') -Subject 'tenant organization settings'
    if ($na) { return $na }

    $org = $AuditData.TenantConfig.Organization
    if (-not $org) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Organization data not available' `
            -Details @{ OrganizationAvailable = $false }
    }

    $tenantId = $org.id
    $displayName = $org.displayName
    $verifiedDomains = @($org.verifiedDomains)
    $technicalContacts = @($org.technicalNotificationMails ?? @())
    $securityComplianceContact = $org.securityComplianceNotificationMails

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Tenant: $displayName ($tenantId), $($verifiedDomains.Count) verified domains" `
        -Details @{
            TenantId                = $tenantId
            DisplayName             = $displayName
            Country                 = $org.countryLetterCode
            PreferredLanguage       = $org.preferredLanguage
            CreatedDateTime         = $org.createdDateTime
            VerifiedDomainCount     = $verifiedDomains.Count
            VerifiedDomains         = @($verifiedDomains | ForEach-Object {
                @{ Name = $_.name; Type = $_.type; IsDefault = $_.isDefault; IsInitial = $_.isInitial }
            })
            TechnicalContacts       = @($technicalContacts)
            SecurityComplianceContacts = @($securityComplianceContact ?? @())
            OnPremisesSyncEnabled   = $org.onPremisesSyncEnabled
            DirectorySizeQuota      = $org.directorySizeQuota
            AssignedPlans           = @($org.assignedPlans | Select-Object -First 20 | ForEach-Object {
                @{ Service = $_.service; CapabilityStatus = $_.capabilityStatus }
            })
        }
}

# ── EIDTNT-002: User Settings ────────────────────────────────────────────
function Test-InfiltrationEIDTNT002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $authzPolicy = $AuditData.TenantConfig.AuthorizationPolicy
    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available'
    }

    $defaultPerms = $authzPolicy.defaultUserRolePermissions
    $allowCreateApps = $defaultPerms.allowedToCreateApps ?? $true
    $allowCreateGroups = $defaultPerms.allowedToCreateSecurityGroups ?? $true
    $allowReadOtherUsers = $defaultPerms.allowedToReadOtherUsers ?? $true
    $allowCreateTenants = $defaultPerms.allowedToCreateTenants ?? $true

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($allowCreateApps) { $issues.Add('Users can create app registrations') }
    if ($allowCreateGroups) { $issues.Add('Users can create security groups') }
    if ($allowCreateTenants) { $issues.Add('Users can create tenants') }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -le 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Default user permissions: create apps=$allowCreateApps, create groups=$allowCreateGroups, read users=$allowReadOtherUsers, create tenants=$allowCreateTenants" `
        -Details @{
            AllowedToCreateApps           = $allowCreateApps
            AllowedToCreateSecurityGroups = $allowCreateGroups
            AllowedToReadOtherUsers       = $allowReadOtherUsers
            AllowedToCreateTenants        = $allowCreateTenants
            Issues                        = @($issues)
        }
}

# ── EIDTNT-003: Guest Access Restrictions ────────────────────────────────
function Test-InfiltrationEIDTNT003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $authzPolicy = $AuditData.TenantConfig.AuthorizationPolicy
    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available'
    }

    $guestUserRoleId = $authzPolicy.guestUserRoleId

    # Guest role GUIDs:
    # a0b1b346-4d3e-4e8b-98f8-753987be4970 = Same as member users (most permissive)
    # 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Limited access (default)
    # 2af84b1e-32c8-42b7-82bc-daa82404023b = Restricted access (most restrictive)

    $roleMapping = @{
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' = @{ Name = 'Same as member users'; Risk = 'High' }
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' = @{ Name = 'Limited access (default)'; Risk = 'Medium' }
        '2af84b1e-32c8-42b7-82bc-daa82404023b' = @{ Name = 'Restricted access'; Risk = 'Low' }
    }

    $roleInfo = $roleMapping[$guestUserRoleId]
    if (-not $roleInfo) {
        $roleInfo = @{ Name = "Unknown ($guestUserRoleId)"; Risk = 'Unknown' }
    }

    $status = switch ($roleInfo.Risk) {
        'Low'    { 'PASS' }
        'Medium' { 'WARN' }
        'High'   { 'FAIL' }
        default  { 'WARN' }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Guest user access level: $($roleInfo.Name)" `
        -Details @{
            GuestUserRoleId   = $guestUserRoleId
            AccessLevel       = $roleInfo.Name
            RiskLevel         = $roleInfo.Risk
        }
}

# ── EIDTNT-004: Guest Invitation Restrictions ───────────────────────────
function Test-InfiltrationEIDTNT004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $authzPolicy = $AuditData.TenantConfig.AuthorizationPolicy
    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available'
    }

    $allowInvitesFrom = $authzPolicy.allowInvitesFrom

    # allowInvitesFrom values:
    # none               = No one can invite (most restrictive)
    # adminsAndGuestInviters = Only admins and guest inviter role
    # adminsGuestInvitersAndAllMembers = Admins, guest inviters, and all members
    # everyone           = Anyone including guests can invite (least restrictive)

    $inviteMapping = @{
        'none'                                   = @{ Description = 'No one can invite guests'; Risk = 'Low' }
        'adminsAndGuestInviters'                  = @{ Description = 'Only admins and users in Guest Inviter role'; Risk = 'Low' }
        'adminsGuestInvitersAndAllMembers'        = @{ Description = 'Admins, Guest Inviters, and all member users'; Risk = 'Medium' }
        'everyone'                                = @{ Description = 'Everyone including guests can invite'; Risk = 'High' }
    }

    $inviteInfo = $inviteMapping[$allowInvitesFrom]
    if (-not $inviteInfo) {
        $inviteInfo = @{ Description = "Unknown ($allowInvitesFrom)"; Risk = 'Unknown' }
    }

    $status = switch ($inviteInfo.Risk) {
        'Low'    { 'PASS' }
        'Medium' { 'WARN' }
        'High'   { 'FAIL' }
        default  { 'WARN' }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Guest invitation setting: $($inviteInfo.Description)" `
        -Details @{
            AllowInvitesFrom = $allowInvitesFrom
            Description      = $inviteInfo.Description
            RiskLevel        = $inviteInfo.Risk
        }
}

# ── EIDTNT-005: External Collaboration Settings ─────────────────────────
function Test-InfiltrationEIDTNT005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $crossTenantAccess = $AuditData.TenantConfig.CrossTenantAccess
    if (-not $crossTenantAccess) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cross-tenant access policy not available'
    }

    $defaultPolicy = $crossTenantAccess.default ?? $crossTenantAccess

    $inboundDefault = $defaultPolicy.b2bCollaborationInbound
    $outboundDefault = $defaultPolicy.b2bCollaborationOutbound
    $inboundDirectConnect = $defaultPolicy.b2bDirectConnectInbound
    $outboundDirectConnect = $defaultPolicy.b2bDirectConnectOutbound

    $issues = [System.Collections.Generic.List[string]]::new()

    # Check if inbound is overly permissive
    if ($inboundDefault.usersAndGroups.accessType -eq 'allowed' -and
        ($inboundDefault.usersAndGroups.targets | Where-Object { $_.target -eq 'AllUsers' })) {
        $issues.Add('Inbound B2B collaboration allows all external users by default')
    }

    # Check if outbound is overly permissive
    if ($outboundDefault.usersAndGroups.accessType -eq 'allowed' -and
        ($outboundDefault.usersAndGroups.targets | Where-Object { $_.target -eq 'AllUsers' })) {
        $issues.Add('Outbound B2B collaboration allows all users to access external tenants')
    }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -eq 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Cross-tenant access default policy reviewed, $($issues.Count) issue(s) found" `
        -Details @{
            IssueCount               = $issues.Count
            Issues                   = @($issues)
            InboundB2BCollaboration  = $inboundDefault
            OutboundB2BCollaboration = $outboundDefault
            InboundDirectConnect     = $inboundDirectConnect
            OutboundDirectConnect    = $outboundDirectConnect
        }
}

# ── EIDTNT-006: B2B Cross-Tenant Access Partners ────────────────────────
function Test-InfiltrationEIDTNT006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'CrossTenantPartners') -Subject 'cross-tenant access partners'
    if ($na) { return $na }

    $partners = $AuditData.TenantConfig.CrossTenantPartners
    if (-not $partners -or $partners.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No cross-tenant access partner configurations — default policy applies to all external tenants' `
            -Details @{ PartnerCount = 0 }
    }

    $partnerDetails = @($partners | ForEach-Object {
        @{
            TenantId                 = $_.tenantId
            IsServiceProvider        = $_.isServiceProvider
            InboundTrust             = $_.inboundTrust
            B2BCollaborationInbound  = $_.b2bCollaborationInbound
            B2BCollaborationOutbound = $_.b2bCollaborationOutbound
            B2BDirectConnectInbound  = $_.b2bDirectConnectInbound
            B2BDirectConnectOutbound = $_.b2bDirectConnectOutbound
        }
    })

    # Warn if there are many partner configurations as they increase attack surface
    $status = if ($partners.Count -le 5) { 'PASS' }
              elseif ($partners.Count -le 20) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($partners.Count) cross-tenant partner configurations — review for necessity and trust level" `
        -Details @{
            PartnerCount = $partners.Count
            Partners     = @($partnerDetails | Select-Object -First 50)
        }
}

# ── EIDTNT-007: Security Defaults ────────────────────────────────────────
function Test-InfiltrationEIDTNT007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors, $AuditData.ConditionalAccess.Errors) `
        -SourceKey @('TenantConfig', 'SecurityDefaults', 'ConditionalAccess', 'Policies') -Subject 'security defaults and CA policies'
    if ($na) { return $na }

    $securityDefaults = $AuditData.TenantConfig.SecurityDefaults
    if (-not $securityDefaults) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Security defaults policy not available' `
            -Details @{ PolicyAvailable = $false }
    }

    $isEnabled = $securityDefaults.isEnabled

    if ($isEnabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Security defaults are enabled — baseline protections active' `
            -Details @{
                IsEnabled     = $true
                Description   = $securityDefaults.description
            }
    }

    # Security defaults disabled — check if CA policies exist as a replacement
    $caPolicies = $AuditData.ConditionalAccess.Policies
    $hasCAPolicies = $caPolicies -and $caPolicies.Count -gt 0
    $enabledCAPolicies = if ($hasCAPolicies) {
        @($caPolicies | Where-Object { $_.state -eq 'enabled' }).Count
    } else { 0 }

    if ($enabledCAPolicies -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Security defaults disabled but $enabledCAPolicies CA policies are active as replacement" `
            -Details @{
                IsEnabled         = $false
                CAReplacementCount = $enabledCAPolicies
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue 'Security defaults are disabled with no Conditional Access policies as replacement — tenant has no baseline protections' `
        -Details @{
            IsEnabled         = $false
            CAReplacementCount = 0
        }
}

# ── EIDTNT-008: License Inventory ────────────────────────────────────────
function Test-InfiltrationEIDTNT008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'SubscribedSkus') -Subject 'subscribed license SKUs'
    if ($na) { return $na }

    $skus = $AuditData.TenantConfig.SubscribedSkus
    if (-not $skus -or $skus.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No subscribed SKU data available' `
            -Details @{ SkuCount = 0 }
    }

    $enabledSkus = @($skus | Where-Object { $_.capabilityStatus -eq 'Enabled' })
    $suspendedSkus = @($skus | Where-Object { $_.capabilityStatus -eq 'Suspended' })
    $warningSkus = @($skus | Where-Object { $_.capabilityStatus -eq 'Warning' })

    $totalConsumed = ($enabledSkus | ForEach-Object { $_.consumedUnits } | Measure-Object -Sum).Sum
    $totalPrepaid = ($enabledSkus | ForEach-Object { $_.prepaidUnits.enabled } | Measure-Object -Sum).Sum

    # Check for premium security SKUs
    $premiumSkuPartNumbers = @('AAD_PREMIUM', 'AAD_PREMIUM_P2', 'IDENTITY_THREAT_PROTECTION',
        'EMSPREMIUM', 'EMS_E5', 'M365_E5', 'SPE_E5', 'MICROSOFT_365_E5_SECURITY')
    $hasPremiumSecurity = @($enabledSkus | Where-Object {
        $_.skuPartNumber -in $premiumSkuPartNumbers
    }).Count -gt 0

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($enabledSkus.Count) active license SKUs, $totalConsumed consumed of $totalPrepaid total. Premium security: $hasPremiumSecurity" `
        -Details @{
            TotalSkus         = $skus.Count
            EnabledSkus       = $enabledSkus.Count
            SuspendedSkus     = $suspendedSkus.Count
            WarningSkus       = $warningSkus.Count
            TotalConsumed     = $totalConsumed
            TotalPrepaid      = $totalPrepaid
            HasPremiumSecurity = $hasPremiumSecurity
            Licenses          = @($enabledSkus | ForEach-Object {
                @{
                    SkuId            = $_.skuId
                    SkuPartNumber    = $_.skuPartNumber
                    CapabilityStatus = $_.capabilityStatus
                    ConsumedUnits    = $_.consumedUnits
                    PrepaidEnabled   = $_.prepaidUnits.enabled
                    PrepaidSuspended = $_.prepaidUnits.suspended
                    PrepaidWarning   = $_.prepaidUnits.warning
                }
            })
        }
}

# ── EIDTNT-009: Administrative Units ─────────────────────────────────────
function Test-InfiltrationEIDTNT009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'AdminUnits') -Subject 'administrative units'
    if ($na) { return $na }

    $adminUnits = $AuditData.TenantConfig.AdminUnits
    if (-not $adminUnits -or $adminUnits.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No administrative units configured' `
            -Details @{ AdminUnitCount = 0 }
    }

    $restrictedMgmt = @($adminUnits | Where-Object {
        $_.isMemberManagementRestricted -eq $true
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($adminUnits.Count) administrative units configured ($($restrictedMgmt.Count) with restricted management)" `
        -Details @{
            AdminUnitCount         = $adminUnits.Count
            RestrictedMgmtCount    = $restrictedMgmt.Count
            AdminUnits             = @($adminUnits | ForEach-Object {
                @{
                    Id                            = $_.id
                    DisplayName                   = $_.displayName
                    Description                   = $_.description
                    IsMemberManagementRestricted  = $_.isMemberManagementRestricted
                    Visibility                    = $_.visibility
                }
            })
        }
}

# ── EIDTNT-010: Custom Domains ───────────────────────────────────────────
function Test-InfiltrationEIDTNT010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'Domains') -Subject 'tenant domains'
    if ($na) { return $na }

    $domains = $AuditData.TenantConfig.Domains
    if (-not $domains -or $domains.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No domain data available' `
            -Details @{ DomainCount = 0 }
    }

    $verified = @($domains | Where-Object { $_.isVerified -eq $true })
    $unverified = @($domains | Where-Object { $_.isVerified -ne $true })
    $defaultDomain = @($domains | Where-Object { $_.isDefault -eq $true })
    $customDomains = @($domains | Where-Object { $_.isInitial -ne $true })

    $status = if ($unverified.Count -gt 0) { 'WARN' } else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($domains.Count) domains: $($customDomains.Count) custom, $($verified.Count) verified, $($unverified.Count) unverified" `
        -Details @{
            TotalDomains     = $domains.Count
            CustomDomains    = $customDomains.Count
            VerifiedCount    = $verified.Count
            UnverifiedCount  = $unverified.Count
            DefaultDomain    = if ($defaultDomain.Count -gt 0) { $defaultDomain[0].id } else { 'None' }
            UnverifiedDomains = @($unverified | ForEach-Object { $_.id })
            Domains          = @($domains | ForEach-Object {
                @{
                    Id                 = $_.id
                    AuthenticationType = $_.authenticationType
                    IsVerified         = $_.isVerified
                    IsDefault          = $_.isDefault
                    IsInitial          = $_.isInitial
                    IsAdminManaged     = $_.isAdminManaged
                    SupportedServices  = @($_.supportedServices ?? @())
                }
            })
        }
}

# ── EIDTNT-011: Diagnostic Settings ─────────────────────────────────────
function Test-InfiltrationEIDTNT011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Diagnostic settings (log export to Log Analytics, Event Hub, Storage Account)
    # are configured at the Azure subscription level via ARM, not directly queryable
    # from Microsoft Graph. Flag as a review item.

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Diagnostic settings verification required — ensure Entra ID sign-in and audit logs are exported to SIEM or Log Analytics' `
        -Details @{
            Note               = 'Diagnostic settings for Entra ID logs are configured via Azure Monitor (ARM). Verify through Azure Portal > Entra ID > Diagnostic settings.'
            RecommendedExports = @(
                'SignInLogs'
                'AuditLogs'
                'NonInteractiveUserSignInLogs'
                'ServicePrincipalSignInLogs'
                'ManagedIdentitySignInLogs'
                'ProvisioningLogs'
                'ADFSSignInLogs'
                'RiskyUsers'
                'UserRiskEvents'
            )
        }
}

# ── EIDTNT-012: Audit Log Retention ──────────────────────────────────────
function Test-InfiltrationEIDTNT012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Audit log retention depends on the license tier:
    # - Free/P1: 7 days via Graph API, 30 days in Azure Portal
    # - P2: 30 days via Graph API
    # - Long-term retention requires export to Log Analytics or storage

    $skus = $AuditData.TenantConfig.SubscribedSkus
    $premiumP2SkuParts = @('AAD_PREMIUM_P2', 'EMS_E5', 'M365_E5', 'SPE_E5',
        'IDENTITY_THREAT_PROTECTION', 'MICROSOFT_365_E5_SECURITY')

    $hasP2 = $false
    if ($skus) {
        $hasP2 = @($skus | Where-Object {
            $_.capabilityStatus -eq 'Enabled' -and $_.skuPartNumber -in $premiumP2SkuParts
        }).Count -gt 0
    }

    $retentionDays = if ($hasP2) { 30 } else { 7 }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Default Entra ID audit log retention: $retentionDays days (P2: $hasP2) — verify long-term export is configured" `
        -Details @{
            HasP2License         = $hasP2
            DefaultRetentionDays = $retentionDays
            Note                 = 'For compliance and incident response, configure Diagnostic Settings to export logs to Log Analytics (90+ day retention) or Azure Storage (long-term).'
        }
}

# ── EIDTNT-013: Notification Settings ────────────────────────────────────
function Test-InfiltrationEIDTNT013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Notification settings for Entra ID (security alerts, PIM notifications, etc.)
    # are not directly accessible through a single Graph API endpoint.
    # Check what we can: technical notification contacts from Organization object.

    $org = $AuditData.TenantConfig.Organization
    if (-not $org) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Organization data not available for notification settings check'
    }

    $technicalContacts = @($org.technicalNotificationMails ?? @())
    $securityContacts = @($org.securityComplianceNotificationMails ?? @())
    $privacyProfile = $org.privacyProfile

    $hasTechnical = $technicalContacts.Count -gt 0
    $hasSecurity = $securityContacts.Count -gt 0

    if (-not $hasTechnical -and -not $hasSecurity) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No technical or security notification contacts configured' `
            -Details @{
                TechnicalContacts = @()
                SecurityContacts  = @()
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Notification contacts: $($technicalContacts.Count) technical, $($securityContacts.Count) security" `
        -Details @{
            TechnicalContacts      = @($technicalContacts)
            SecurityContacts       = @($securityContacts)
            HasPrivacyProfile      = $null -ne $privacyProfile
            Note                   = 'Additional notification settings (PIM, Identity Protection alerts) should be verified in their respective configurations.'
        }
}

# ── EIDTNT-014: User Password Expiration Disabled (MS.AAD.6.1) ───────────
function Test-InfiltrationEIDTNT014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Passwords never expire is signalled per domain by passwordValidityPeriodInDays.
    # The sentinel value 2147483647 (Int32.MaxValue) means "never expire".
    $neverExpireValue = 2147483647

    $domains = $AuditData.TenantConfig.Domains
    if (-not $domains -or $domains.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain data not available — password expiration policy Not Assessed'
    }

    # Only managed (non-federated) domains carry a meaningful password validity period.
    $managedDomains = @($domains | Where-Object {
        $_.authenticationType -eq 'Managed' -or -not $_.authenticationType
    })
    $assessable = @($managedDomains | Where-Object { $null -ne $_.passwordValidityPeriodInDays })

    if ($assessable.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No managed domains expose passwordValidityPeriodInDays — password expiration policy Not Assessed' `
            -Details @{
                ManagedDomainCount = $managedDomains.Count
                Note               = 'passwordValidityPeriodInDays was null on all managed domains; cannot assert never-expire.'
            }
    }

    $expiringDomains = @($assessable | Where-Object { $_.passwordValidityPeriodInDays -ne $neverExpireValue })
    $neverExpireDomains = @($assessable | Where-Object { $_.passwordValidityPeriodInDays -eq $neverExpireValue })

    $status = if ($expiringDomains.Count -eq 0) { 'PASS' } else { 'FAIL' }

    $currentValue = if ($expiringDomains.Count -eq 0) {
        "All $($assessable.Count) managed domain(s) have passwords set to never expire"
    } else {
        "$($expiringDomains.Count) of $($assessable.Count) managed domain(s) still enforce finite password expiration"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            AssessedDomainCount   = $assessable.Count
            NeverExpireCount      = $neverExpireDomains.Count
            ExpiringDomainCount   = $expiringDomains.Count
            ExpiringDomains       = @($expiringDomains | ForEach-Object {
                @{ Domain = $_.id; PasswordValidityPeriodInDays = $_.passwordValidityPeriodInDays }
            })
            NeverExpireDomains    = @($neverExpireDomains | ForEach-Object { $_.id })
        }
}

# ── EIDTNT-015: Privileged Partner Delegated Admin Access (GDAP) ──────────
function Test-InfiltrationEIDTNT015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'DelegatedAdminRelationships') `
        -Subject 'partner delegated admin (GDAP) relationships'
    if ($na) { return $na }

    # Tier-0 / high-impact directory roles. A partner holding any of these has
    # standing keys to the kingdom across the delegation. roleDefinitionId (GUID)
    # is stable and locale-independent, so match on it, not the display name.
    $privilegedRoleIds = @(
        '62e90394-69f5-4237-9190-012177145e10' # Global Administrator
        'e8611ab8-c189-46e8-94e1-60213ab1f814' # Privileged Role Administrator
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' # Privileged Authentication Administrator
        '194ae4cb-b126-40b2-bd5b-6091b380977d' # Security Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1' # User Administrator
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' # Application Administrator
        '158c047a-c907-4556-b7ef-446551a6b5f7' # Cloud Application Administrator
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' # Authentication Administrator
        '966707d0-3269-4727-9be2-8c3a10f19b9d' # Password Administrator
    )

    $relationships = @($AuditData.TenantConfig.DelegatedAdminRelationships)
    # Only 'active' relationships confer live access. 'created' / 'approvalPending'
    # / 'terminated' etc. are not standing access.
    $active = @($relationships | Where-Object { $_.status -eq 'active' })

    if ($active.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No active partner delegated admin (GDAP) relationships' `
            -Details @{
                TotalRelationships  = $relationships.Count
                ActiveRelationships = 0
            }
    }

    $privilegedGrants = [System.Collections.Generic.List[object]]::new()
    foreach ($rel in $active) {
        $roleIds = @($rel.accessDetails.unifiedRoles | ForEach-Object { $_.roleDefinitionId })
        $hit = @($roleIds | Where-Object { $privilegedRoleIds -contains $_ })
        if ($hit.Count -gt 0) {
            $privilegedGrants.Add([ordered]@{
                Partner           = $rel.displayName
                CustomerTenantId  = $rel.customer.tenantId
                PrivilegedRoleIds = $hit
                TotalRoleCount    = $roleIds.Count
            })
        }
    }

    if ($privilegedGrants.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($privilegedGrants.Count) of $($active.Count) active partner delegated admin relationship(s) grant a privileged directory role" `
            -Details @{
                ActiveRelationships = $active.Count
                PrivilegedCount     = $privilegedGrants.Count
                PrivilegedGrants    = @($privilegedGrants)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($active.Count) active partner delegated admin relationship(s) present with non-privileged roles — confirm each partner and scope are still required" `
        -Details @{
            ActiveRelationships = $active.Count
            PrivilegedCount     = 0
            Partners            = @($active | ForEach-Object { $_.displayName })
        }
}

# ── EIDTNT-016: Partner Delegated Admin Grant Hygiene (Long-Lived GDAP) ───
function Test-InfiltrationEIDTNT016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.TenantConfig.Errors) `
        -SourceKey @('TenantConfig', 'DelegatedAdminRelationships') `
        -Subject 'partner delegated admin (GDAP) relationships'
    if ($na) { return $na }

    # GDAP 'duration' is the auto-extension window (ISO-8601, e.g. P730D). A long
    # auto-extend is a standing, self-renewing grant that renews without review —
    # the opposite of just-in-time. Flag active relationships auto-extending
    # beyond a year. Parse the day count from P<n>D; an unparseable/absent
    # duration is treated as long-lived (conservative — an unknown must not read
    # as fine).
    $longLivedThresholdDays = 365

    $relationships = @($AuditData.TenantConfig.DelegatedAdminRelationships)
    $active = @($relationships | Where-Object { $_.status -eq 'active' })

    if ($active.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No active partner delegated admin (GDAP) relationships to review' `
            -Details @{ ActiveRelationships = 0 }
    }

    $longLived = [System.Collections.Generic.List[object]]::new()
    foreach ($rel in $active) {
        $days = $null
        if ($rel.duration -match '^P(\d+)D$') { $days = [int]$Matches[1] }
        $isLong = ($null -eq $days) -or ($days -gt $longLivedThresholdDays)
        if ($isLong) {
            $longLived.Add([ordered]@{
                Partner  = $rel.displayName
                Duration = $rel.duration
                Days     = $days
            })
        }
    }

    if ($longLived.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($longLived.Count) of $($active.Count) active partner delegated admin relationship(s) auto-extend beyond $longLivedThresholdDays days — long-lived standing grants that renew without review" `
            -Details @{
                ActiveRelationships = $active.Count
                LongLivedCount      = $longLived.Count
                LongLived           = @($longLived)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($active.Count) active partner delegated admin relationship(s) auto-extend within $longLivedThresholdDays days" `
        -Details @{ ActiveRelationships = $active.Count; LongLivedCount = 0 }
}
