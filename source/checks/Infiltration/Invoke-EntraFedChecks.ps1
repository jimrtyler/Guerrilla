# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-EntraFedChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraFedChecks'
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

# ── EIDFED-001: Domain Enumeration ───────────────────────────────────────
function Test-InfiltrationEIDFED001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Federation.Errors) `
        -SourceKey @('Federation', 'Domains') -Subject 'federated domain inventory'
    if ($na) { return $na }

    $domains = $AuditData.Federation.Domains
    if (-not $domains -or $domains.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No domain data available' `
            -Details @{ DomainCount = 0 }
    }

    $managed = @($domains | Where-Object { $_.authenticationType -eq 'Managed' })
    $federated = @($domains | Where-Object { $_.authenticationType -eq 'Federated' })
    $verified = @($domains | Where-Object { $_.isVerified -eq $true })
    $unverified = @($domains | Where-Object { $_.isVerified -ne $true })
    $defaultDomain = @($domains | Where-Object { $_.isDefault -eq $true })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($domains.Count) domains: $($managed.Count) managed, $($federated.Count) federated, $($verified.Count) verified, $($unverified.Count) unverified" `
        -Details @{
            TotalDomains    = $domains.Count
            ManagedCount    = $managed.Count
            FederatedCount  = $federated.Count
            VerifiedCount   = $verified.Count
            UnverifiedCount = $unverified.Count
            DefaultDomain   = if ($defaultDomain.Count -gt 0) { $defaultDomain[0].id } else { 'None' }
            Domains         = @($domains | ForEach-Object {
                @{
                    Id                  = $_.id
                    AuthenticationType  = $_.authenticationType
                    IsVerified          = $_.isVerified
                    IsDefault           = $_.isDefault
                    IsAdminManaged      = $_.isAdminManaged
                    SupportedServices   = @($_.supportedServices ?? @())
                }
            })
        }
}

# ── EIDFED-002: Federation Certificate Validity ─────────────────────────
function Test-InfiltrationEIDFED002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Federation.Errors) `
        -SourceKey @('Federation', 'Domains') -Subject 'federation configuration'
    if ($na) { return $na }

    $fedConfigs = $AuditData.Federation.FederationConfigs
    if (-not $fedConfigs -or $fedConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No federated domains configured — no federation certificates to validate' `
            -Details @{ FederatedDomainCount = 0 }
    }

    $now = [datetime]::UtcNow
    $thirtyDaysFromNow = $now.AddDays(30)
    $certIssues = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fedConfig in $fedConfigs) {
        $config = $fedConfig.Config
        if (-not $config) { continue }

        # Handle both single config and array of configs
        $configs = if ($config -is [array]) { $config } else { @($config) }

        foreach ($cfg in $configs) {
            $signingCert = $cfg.signingCertificate
            if (-not $signingCert) { continue }

            # Try to extract certificate validity from base64 encoded cert
            try {
                $certBytes = [Convert]::FromBase64String($signingCert)
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)
                $notAfter = $cert.NotAfter.ToUniversalTime()

                if ($notAfter -lt $now) {
                    $certIssues.Add(@{
                        Domain   = $fedConfig.DomainName
                        Issue    = 'Expired'
                        NotAfter = $notAfter.ToString('o')
                        Subject  = $cert.Subject
                    })
                } elseif ($notAfter -le $thirtyDaysFromNow) {
                    $certIssues.Add(@{
                        Domain   = $fedConfig.DomainName
                        Issue    = 'ExpiringSoon'
                        NotAfter = $notAfter.ToString('o')
                        DaysLeft = [Math]::Ceiling(($notAfter - $now).TotalDays)
                        Subject  = $cert.Subject
                    })
                }
            } catch {
                $certIssues.Add(@{
                    Domain = $fedConfig.DomainName
                    Issue  = 'ParseError'
                    Error  = $_.Exception.Message
                })
            }
        }
    }

    if ($certIssues.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Federation certificates valid across $($fedConfigs.Count) federated domain(s)" `
            -Details @{ FederatedDomainCount = $fedConfigs.Count; CertIssueCount = 0 }
    }

    $expired = @($certIssues | Where-Object { $_.Issue -eq 'Expired' })
    $expiring = @($certIssues | Where-Object { $_.Issue -eq 'ExpiringSoon' })
    $status = if ($expired.Count -gt 0) { 'FAIL' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($expired.Count) expired, $($expiring.Count) expiring soon across $($fedConfigs.Count) federated domain(s)" `
        -Details @{
            FederatedDomainCount = $fedConfigs.Count
            CertIssueCount       = $certIssues.Count
            ExpiredCount         = $expired.Count
            ExpiringCount        = $expiring.Count
            Issues               = @($certIssues)
        }
}

# ── EIDFED-003: Federation Certificate Issuer/Subject Mismatch ──────────
function Test-InfiltrationEIDFED003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Federation.Errors) `
        -SourceKey @('Federation', 'Domains') -Subject 'federation configuration'
    if ($na) { return $na }

    $fedConfigs = $AuditData.Federation.FederationConfigs
    if (-not $fedConfigs -or $fedConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No federated domains — certificate issuer check not applicable' `
            -Details @{ FederatedDomainCount = 0 }
    }

    $mismatches = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fedConfig in $fedConfigs) {
        $config = $fedConfig.Config
        if (-not $config) { continue }

        $configs = if ($config -is [array]) { $config } else { @($config) }

        foreach ($cfg in $configs) {
            $signingCert = $cfg.signingCertificate
            if (-not $signingCert) { continue }

            try {
                $certBytes = [Convert]::FromBase64String($signingCert)
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes)

                # Self-signed certs are normal for AD FS; external CA certs may indicate tampering
                $isSelfSigned = $cert.Subject -eq $cert.Issuer

                # Check for suspicious issuers (not typical AD FS self-signed patterns)
                $suspiciousIssuer = -not $isSelfSigned -and
                    $cert.Issuer -notmatch 'ADFS|AD FS|Federation|Microsoft' -and
                    $cert.Issuer -notmatch 'DigiCert|Entrust|GlobalSign|Comodo|Let''s Encrypt'

                if ($suspiciousIssuer) {
                    $mismatches.Add(@{
                        Domain    = $fedConfig.DomainName
                        Subject   = $cert.Subject
                        Issuer    = $cert.Issuer
                        Thumbprint = $cert.Thumbprint
                    })
                }
            } catch {
                # Certificate parse errors are handled in EIDFED-002
            }
        }
    }

    if ($mismatches.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No suspicious federation certificate issuer/subject mismatches found' `
            -Details @{ MismatchCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($mismatches.Count) federation certificate(s) with suspicious issuer — possible token-signing certificate replacement attack" `
        -Details @{
            MismatchCount = $mismatches.Count
            Mismatches    = @($mismatches)
        }
}

# ── EIDFED-004: Federation Metadata Analysis ────────────────────────────
function Test-InfiltrationEIDFED004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Federation.Errors) `
        -SourceKey @('Federation', 'Domains') -Subject 'federation configuration'
    if ($na) { return $na }

    $fedConfigs = $AuditData.Federation.FederationConfigs
    if (-not $fedConfigs -or $fedConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No federated domains — federation metadata analysis not applicable'
    }

    $findings = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fedConfig in $fedConfigs) {
        $config = $fedConfig.Config
        if (-not $config) { continue }

        $configs = if ($config -is [array]) { $config } else { @($config) }

        foreach ($cfg in $configs) {
            $detail = @{
                Domain                 = $fedConfig.DomainName
                IssuerUri              = $cfg.issuerUri
                PassiveSignInUri       = $cfg.passiveSignInUri
                MetadataExchangeUri    = $cfg.metadataExchangeUri
                ActiveSignInUri        = $cfg.activeSignInUri
                SignOutUri             = $cfg.signOutUri
                FederatedIdpMfaBehavior = $cfg.federatedIdpMfaBehavior
                PreferredAuthenticationProtocol = $cfg.preferredAuthenticationProtocol
                PromptLoginBehavior    = $cfg.promptLoginBehavior
            }
            $findings.Add($detail)
        }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Analyzed federation metadata for $($findings.Count) configuration(s) across $($fedConfigs.Count) domain(s)" `
        -Details @{
            ConfigurationCount = $findings.Count
            DomainCount        = $fedConfigs.Count
            Configurations     = @($findings)
        }
}

# ── EIDFED-005: Azure AD Connect Configuration ──────────────────────────
function Test-InfiltrationEIDFED005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $syncSettings = $AuditData.Federation.OnPremisesSyncSettings
    if (-not $syncSettings) {
        # Distinguish a genuine cloud-only tenant from a hybrid tenant whose sync-config endpoint is
        # unreadable (the collector 403s on /directory/onPremisesSynchronization without
        # OnPremDirectorySynchronization.Read.All). Never score "config unreadable" as PASS —
        # absence of evidence is not compliance.
        $syncEnabled = [bool]$AuditData.Federation.OnPremisesSyncEnabled -or
                       (($AuditData.Federation.Users.SyncedCount ?? 0) -gt 0)
        if ($syncEnabled) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
                -CurrentValue 'Directory synchronization is enabled but the Azure AD Connect configuration could not be read (requires OnPremDirectorySynchronization.Read.All, or the endpoint returned an error). Not Assessed — grant the scope or verify on the Connect server.' `
                -Details @{ SyncConfigured = $true; ConfigReadable = $false }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No on-premises synchronization configured — cloud-only tenant; no Azure AD Connect to assess.' `
            -Details @{ SyncConfigured = $false }
    }

    # Handle both single object and array (value wrapper)
    $settings = if ($syncSettings.value) { $syncSettings.value } else { @($syncSettings) }
    $config = if ($settings -is [array] -and $settings.Count -gt 0) { $settings[0] } else { $settings }

    $features = $config.features
    $configDetails = @{
        SyncConfigured           = $true
        PasswordHashSyncEnabled  = $features.passwordHashSyncEnabled ?? $false
        PassthroughAuthEnabled   = $features.passThroughAuthenticationEnabled ?? $false
        SeamlessSsoEnabled       = $features.seamlessSingleSignOnEnabled ?? $false
        SyncFrequencyInMinutes   = $config.configuration.synchronizationInterval
        DirectoryExtensionsEnabled = $features.directoryExtensionsEnabled ?? $false
        GroupWritebackEnabled    = $features.groupWriteBackEnabled ?? $false
        UserWritebackEnabled     = $features.userWritebackEnabled ?? $false
        DeviceWritebackEnabled   = $features.deviceWritebackEnabled ?? $false
    }

    $status = 'PASS'
    $issues = [System.Collections.Generic.List[string]]::new()

    if (-not $configDetails.PasswordHashSyncEnabled -and -not $configDetails.PassthroughAuthEnabled) {
        $issues.Add('Neither PHS nor PTA is enabled')
        $status = 'WARN'
    }

    $currentValue = "Azure AD Connect configured. PHS: $($configDetails.PasswordHashSyncEnabled), PTA: $($configDetails.PassthroughAuthEnabled), Seamless SSO: $($configDetails.SeamlessSsoEnabled)"
    if ($issues.Count -gt 0) {
        $currentValue += ". Issues: $($issues -join '; ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details $configDetails
}

# ── EIDFED-006: Synchronization Scope ────────────────────────────────────
function Test-InfiltrationEIDFED006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Detailed sync scope (OU filtering, connector details) requires
    # direct access to Azure AD Connect server configuration or advanced API calls
    $syncSettings = $AuditData.Federation.OnPremisesSyncSettings
    if (-not $syncSettings) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No on-premises synchronization configured — sync scope check not applicable'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'Sync scope analysis requires detailed connector configuration data from the Azure AD Connect server'
}

# ── EIDFED-007: Password Hash Synchronization Status ─────────────────────
function Test-InfiltrationEIDFED007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $syncSettings = $AuditData.Federation.OnPremisesSyncSettings
    if (-not $syncSettings) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No on-premises synchronization configured — PHS check not applicable'
    }

    $settings = if ($syncSettings.value) { $syncSettings.value } else { @($syncSettings) }
    $config = if ($settings -is [array] -and $settings.Count -gt 0) { $settings[0] } else { $settings }

    $phsEnabled = $config.features.passwordHashSyncEnabled ?? $false

    if ($phsEnabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Password hash synchronization is enabled — provides backup authentication and leaked credential detection' `
            -Details @{ PasswordHashSyncEnabled = $true }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue 'Password hash synchronization is disabled — no backup authentication if federation fails, and no leaked credential detection' `
        -Details @{ PasswordHashSyncEnabled = $false }
}

# ── EIDFED-008: Pass-Through Authentication Agent Status ────────────────
function Test-InfiltrationEIDFED008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $syncSettings = $AuditData.Federation.OnPremisesSyncSettings
    if (-not $syncSettings) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No on-premises synchronization configured — PTA check not applicable'
    }

    $settings = if ($syncSettings.value) { $syncSettings.value } else { @($syncSettings) }
    $config = if ($settings -is [array] -and $settings.Count -gt 0) { $settings[0] } else { $settings }

    $ptaEnabled = $config.features.passThroughAuthenticationEnabled ?? $false

    if (-not $ptaEnabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Pass-through authentication is not enabled (PHS or federation in use)' `
            -Details @{ PassThroughAuthEnabled = $false }
    }

    # PTA is enabled; we can note it but detailed agent health requires additional API calls
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Pass-through authentication is enabled — verify multiple PTA agents are deployed for redundancy' `
        -Details @{
            PassThroughAuthEnabled = $true
            Note                   = 'PTA agent health and count verification requires publishingProfiles API or Azure Portal check'
        }
}

# ── EIDFED-009: AD FS Configuration Assessment ──────────────────────────
function Test-InfiltrationEIDFED009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Federation.Errors) `
        -SourceKey @('Federation', 'Domains') -Subject 'federation configuration'
    if ($na) { return $na }

    $fedConfigs = $AuditData.Federation.FederationConfigs
    if (-not $fedConfigs -or $fedConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No federated domains — AD FS assessment not applicable'
    }

    $issues = [System.Collections.Generic.List[string]]::new()
    $domainDetails = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fedConfig in $fedConfigs) {
        $config = $fedConfig.Config
        if (-not $config) { continue }

        $configs = if ($config -is [array]) { $config } else { @($config) }

        foreach ($cfg in $configs) {
            $detail = @{ Domain = $fedConfig.DomainName }

            # Check if MFA behavior is properly configured
            if ($cfg.federatedIdpMfaBehavior -eq 'acceptIfMfaDoneByFederatedIdp') {
                $detail['MfaBehavior'] = $cfg.federatedIdpMfaBehavior
            } elseif (-not $cfg.federatedIdpMfaBehavior) {
                $issues.Add("$($fedConfig.DomainName): No federated IdP MFA behavior configured")
                $detail['MfaBehavior'] = 'Not configured'
            } else {
                $detail['MfaBehavior'] = $cfg.federatedIdpMfaBehavior
            }

            # Check preferred protocol
            $detail['PreferredProtocol'] = $cfg.preferredAuthenticationProtocol ?? 'Not specified'

            # Check prompt login behavior
            $detail['PromptLoginBehavior'] = $cfg.promptLoginBehavior ?? 'Not specified'

            $domainDetails.Add($detail)
        }
    }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -le 2) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($fedConfigs.Count) federated domain(s) assessed, $($issues.Count) configuration issue(s)" `
        -Details @{
            FederatedDomainCount = $fedConfigs.Count
            IssueCount           = $issues.Count
            Issues               = @($issues)
            DomainDetails        = @($domainDetails)
        }
}

# ── EIDFED-010: AD FS Extranet Lockout Settings ─────────────────────────
function Test-InfiltrationEIDFED010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Federation.Errors) `
        -SourceKey @('Federation', 'Domains') -Subject 'federation configuration'
    if ($na) { return $na }

    $fedConfigs = $AuditData.Federation.FederationConfigs
    if (-not $fedConfigs -or $fedConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No federated domains — extranet lockout check not applicable'
    }

    # Extranet lockout settings are typically configured directly on AD FS servers
    # and are not exposed through the Graph API federation configuration endpoints.
    # We can flag this as a review item for federated tenants.

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($fedConfigs.Count) federated domain(s) detected — verify AD FS extranet lockout is configured on AD FS servers" `
        -Details @{
            FederatedDomainCount = $fedConfigs.Count
            Domains              = @($fedConfigs | ForEach-Object { $_.DomainName })
            Note                 = 'Extranet lockout settings must be verified directly on AD FS servers (Get-AdfsProperties). Recommend Extranet Smart Lockout be enabled.'
        }
}

# ── EIDFED-011: Hybrid Join Assessment ───────────────────────────────────
function Test-InfiltrationEIDFED011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $syncSettings = $AuditData.Federation.OnPremisesSyncSettings
    if (-not $syncSettings) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No on-premises synchronization configured — hybrid join check not applicable'
    }

    $settings = if ($syncSettings.value) { $syncSettings.value } else { @($syncSettings) }
    $config = if ($settings -is [array] -and $settings.Count -gt 0) { $settings[0] } else { $settings }

    $deviceWriteback = $config.features.deviceWritebackEnabled ?? $false

    $status = if ($deviceWriteback) { 'PASS' } else { 'WARN' }
    $currentValue = if ($deviceWriteback) {
        'Device writeback is enabled — hybrid Azure AD join is likely configured'
    } else {
        'Device writeback is not enabled — hybrid Azure AD join may not be fully configured'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            DeviceWritebackEnabled = $deviceWriteback
            Note                   = 'Full hybrid join validation requires device registration data and Azure AD Connect configuration review'
        }
}

# ── EIDFED-012: Cloud vs Synced User Analysis ───────────────────────────
function Test-InfiltrationEIDFED012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $users = $AuditData.Federation.Users
    if (-not $users) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User count data not available'
    }

    $cloudOnlyCount = $users.CloudOnlyCount
    $syncedCount = $users.SyncedCount

    # If counts returned -1, data collection failed
    if ($cloudOnlyCount -eq -1 -or $syncedCount -eq -1) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User count data collection failed'
    }

    $totalCount = $cloudOnlyCount + $syncedCount
    $syncedPercentage = if ($totalCount -gt 0) { [Math]::Round(($syncedCount / $totalCount) * 100, 1) } else { 0 }
    $cloudPercentage = if ($totalCount -gt 0) { [Math]::Round(($cloudOnlyCount / $totalCount) * 100, 1) } else { 0 }

    # Determine identity posture
    $identityPosture = if ($syncedCount -eq 0) { 'Cloud-Only' }
                       elseif ($cloudOnlyCount -eq 0) { 'Fully Synced' }
                       else { 'Hybrid' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$totalCount total users: $cloudOnlyCount cloud-only ($cloudPercentage%), $syncedCount synced ($syncedPercentage%) — $identityPosture identity model" `
        -Details @{
            TotalUsers       = $totalCount
            CloudOnlyCount   = $cloudOnlyCount
            SyncedCount      = $syncedCount
            CloudPercentage  = $cloudPercentage
            SyncedPercentage = $syncedPercentage
            IdentityPosture  = $identityPosture
        }
}

# ── EIDFED-013: Entra Connect Sync-Client Version Currency ──────────────
function Test-InfiltrationEIDFED013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # The Entra Connect (formerly Azure AD Connect) build is an attribute of the
    # on-premises Connect SERVER, not a cloud directory property. Guerrilla's Entra
    # theater is agentless Graph, so we read the version authoritatively only when the
    # audit is running on/near the Connect host. Detection layers, in order of trust:
    #   1. Server-side authoritative read (registry / ADSync module) — best.
    #   2. Cloud best-effort — confirm directory sync is enabled at all.
    #   3. Honest verdict — PASS/FAIL only with a real version; otherwise WARN/SKIP.

    $minimumSafe = $script:EntraConnectMinimumSafeVersion

    # ── Layer 2 (cloud): is on-premises synchronization enabled at all? ──
    # Don't depend solely on /directory/onPremisesSynchronization — it requires
    # OnPremDirectorySynchronization.Read.All and 403s without it, which would make a hybrid tenant
    # look cloud-only and SKIP. Fall back to authorized signals: organization.onPremisesSyncEnabled
    # and the synced-user count.
    $syncSettings = $AuditData.Federation.OnPremisesSyncSettings
    $syncEnabled  = ($null -ne $syncSettings) -or
                    [bool]$AuditData.Federation.OnPremisesSyncEnabled -or
                    (($AuditData.Federation.Users.SyncedCount ?? 0) -gt 0)
    $lastSyncDateTime = $AuditData.Federation.OnPremisesLastSyncDateTime
    if ($syncSettings) {
        # Only derive last-sync from the sync-config object when it was actually readable; otherwise
        # keep the organization-level value above (don't overwrite it with null on a 403).
        $settings = if ($syncSettings.value) { $syncSettings.value } else { @($syncSettings) }
        $config   = if ($settings -is [array] -and $settings.Count -gt 0) { $settings[0] } else { $settings }
        $lastSyncDateTime = ($config.configuration.lastImportFromAd ?? $config.lastSyncDateTime) ?? $lastSyncDateTime
    }

    # ── Layer 1 (authoritative): read the installed build from the Connect host ──
    $installedVersion = $null
    $versionSource    = $null

    if ($IsWindows -or ($null -eq $IsWindows)) {
        # (a) Registry — present on the Connect server only.
        try {
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Azure AD Connect'
            if (Test-Path $regPath) {
                $reg = Get-ItemProperty -Path $regPath -ErrorAction Stop
                $regVer = $reg.InstallationVersion ?? $reg.Version ?? $reg.ProductVersion
                if (-not [string]::IsNullOrWhiteSpace($regVer)) {
                    $installedVersion = "$regVer"
                    $versionSource    = "registry ($regPath)"
                }
            }
        } catch {
            # Not on the Connect server, or key inaccessible — fall through to ADSync.
        }

        # (b) ADSync module — Get-ADSyncGlobalSettings, only on the Connect host.
        if (-not $installedVersion -and (Get-Command -Name 'Get-ADSyncGlobalSettings' -ErrorAction SilentlyContinue)) {
            try {
                $global = Get-ADSyncGlobalSettings -ErrorAction Stop
                $adsyncVer = ($global.Parameters | Where-Object { $_.Name -match 'Version' } |
                    Select-Object -First 1).Value
                if (-not [string]::IsNullOrWhiteSpace($adsyncVer)) {
                    $installedVersion = "$adsyncVer"
                    $versionSource    = 'Get-ADSyncGlobalSettings'
                }
            } catch {
                # ADSync present but unreadable — leave version unresolved.
            }
        }
    }

    # ── Verdict logic ──
    # If sync is NOT enabled at all → cloud-only tenant, no Entra Connect to assess.
    if (-not $syncEnabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No on-premises synchronization configured — cloud-only tenant, no Entra Connect to assess' `
            -Details @{
                SyncEnabled        = $false
                MinimumSafeVersion = $minimumSafe
            }
    }

    # If we obtained an authoritative version → compare against the baseline (real PASS/FAIL).
    if (-not [string]::IsNullOrWhiteSpace($installedVersion)) {
        $cmp = Test-EntraConnectVersionCurrent -InstalledVersion $installedVersion -MinimumSafeVersion $minimumSafe

        if (-not $cmp.IsAssessable) {
            # We read *something* but it didn't parse as a version — do NOT pass.
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue "Entra Connect version '$installedVersion' (from $versionSource) could not be parsed — verify the Connect build is >= $minimumSafe on the Connect server" `
                -Details @{
                    SyncEnabled        = $true
                    InstalledVersion   = $installedVersion
                    VersionSource      = $versionSource
                    MinimumSafeVersion = $minimumSafe
                    IsAssessable       = $false
                }
        }

        $status = if ($cmp.IsCurrent) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($cmp.IsCurrent) {
            "Entra Connect $installedVersion is at or above the minimum-safe baseline $minimumSafe (read via $versionSource)"
        } else {
            "Entra Connect $installedVersion is BELOW the minimum-safe baseline $minimumSafe — unpatched Tier-0 hybrid component; update immediately (read via $versionSource)"
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue `
            -Details @{
                SyncEnabled        = $true
                InstalledVersion   = $installedVersion
                VersionSource      = $versionSource
                MinimumSafeVersion = $minimumSafe
                IsCurrent          = $cmp.IsCurrent
                LastSyncDateTime   = $lastSyncDateTime
            }
    }

    # Sync is enabled but the version could not be obtained (agentless cloud-only audit) →
    # Not-Assessed. NEVER PASS without an actual version.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "On-premises sync is enabled but the Entra Connect version could not be read from this host. Verify Entra Connect is >= $minimumSafe on the Connect server (registry HKLM\SOFTWARE\Microsoft\Azure AD Connect or Get-ADSyncGlobalSettings)." `
        -Details @{
            SyncEnabled        = $true
            InstalledVersion   = $null
            VersionSource      = $null
            MinimumSafeVersion = $minimumSafe
            LastSyncDateTime   = $lastSyncDateTime
            Note               = 'Entra Connect build is an on-premises Connect-server attribute and is not exposed through agentless Graph collection. Run the audit on/near the Connect server, or confirm the build manually.'
        }
}
