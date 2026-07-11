# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-M365ExchangeChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'M365ExchangeChecks'
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

# ── M365EXO-001: Exchange Organization Configuration ────────────────────
function Test-InfiltrationM365EXO001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.OrganizationConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange Online data not available (EXO module not connected)'
    }

    $orgConfig = $exo.OrganizationConfig
    $auditDisabled = $orgConfig.AuditDisabled
    $oauth2ClientProfileEnabled = $orgConfig.OAuth2ClientProfileEnabled

    $status = if ($auditDisabled -eq $false) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Exchange Org: AuditDisabled=$auditDisabled, OAuth2ClientProfile=$oauth2ClientProfileEnabled" `
        -Details @{
            AuditDisabled = $auditDisabled
            OAuth2ClientProfileEnabled = $oauth2ClientProfileEnabled
            Name = $orgConfig.Name
            DefaultGroupAccessType = $orgConfig.DefaultGroupAccessType
        }
}

# ── M365EXO-002: Anti-Spam Policies ────────────────────────────────────
function Test-InfiltrationM365EXO002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.AntiSpamPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange anti-spam data not available'
    }

    $policies = $exo.AntiSpamPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No anti-spam policies found'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) anti-spam (hosted content filter) policies configured" `
        -Details @{
            PolicyCount = $policies.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    Identity = $_.Identity
                    IsDefault = $_.IsDefault
                    SpamAction = $_.SpamAction
                    HighConfidenceSpamAction = $_.HighConfidenceSpamAction
                    BulkSpamAction = $_.BulkSpamAction
                    BulkThreshold = $_.BulkThreshold
                }
            })
        }
}

# ── M365EXO-003: Anti-Phish Policies ───────────────────────────────────
function Test-InfiltrationM365EXO003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiPhishPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange anti-phish data not available'
    }

    $policies = $exo.AntiPhishPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No anti-phish policies found'
    }

    # Check if impersonation protection is enabled
    $impersonationEnabled = @($policies | Where-Object {
        $_.EnableTargetedUserProtection -eq $true -or
        $_.EnableTargetedDomainsProtection -eq $true -or
        $_.EnableMailboxIntelligenceProtection -eq $true
    })

    $status = if ($impersonationEnabled.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) anti-phish policies ($($impersonationEnabled.Count) with impersonation protection)" `
        -Details @{
            PolicyCount = $policies.Count
            ImpersonationProtectedCount = $impersonationEnabled.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    Enabled = $_.Enabled
                    EnableTargetedUserProtection = $_.EnableTargetedUserProtection
                    EnableTargetedDomainsProtection = $_.EnableTargetedDomainsProtection
                    EnableMailboxIntelligenceProtection = $_.EnableMailboxIntelligenceProtection
                    PhishThresholdLevel = $_.PhishThresholdLevel
                }
            })
        }
}

# ── M365EXO-004: Malware Filter Policies ───────────────────────────────
function Test-InfiltrationM365EXO004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.MalwarePolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange malware filter data not available'
    }

    $policies = $exo.MalwarePolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No malware filter policies found'
    }

    # Check ZAP and common attachment filter
    $zapEnabled = @($policies | Where-Object { $_.ZapEnabled -eq $true })
    $fileFilterEnabled = @($policies | Where-Object { $_.EnableFileFilter -eq $true })

    $status = if ($zapEnabled.Count -eq $policies.Count) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) malware policies ($($zapEnabled.Count) ZAP enabled, $($fileFilterEnabled.Count) file filter enabled)" `
        -Details @{
            PolicyCount = $policies.Count
            ZapEnabledCount = $zapEnabled.Count
            FileFilterEnabledCount = $fileFilterEnabled.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    ZapEnabled = $_.ZapEnabled
                    EnableFileFilter = $_.EnableFileFilter
                    EnableInternalSenderAdminNotifications = $_.EnableInternalSenderAdminNotifications
                }
            })
        }
}

# ── M365EXO-005: Safe Attachments Policies ─────────────────────────────
function Test-InfiltrationM365EXO005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.SafeAttachmentPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Safe Attachments data not available (requires Defender for Office 365)'
    }

    $policies = $exo.SafeAttachmentPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Safe Attachment policies configured — Defender for Office 365 may not be licensed' `
            -Details @{ PolicyCount = 0 }
    }

    $dynamicDelivery = @($policies | Where-Object { $_.Action -eq 'DynamicDelivery' })
    $block = @($policies | Where-Object { $_.Action -eq 'Block' })
    $replace = @($policies | Where-Object { $_.Action -eq 'Replace' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) Safe Attachment policies ($($dynamicDelivery.Count) dynamic delivery, $($block.Count) block)" `
        -Details @{
            PolicyCount = $policies.Count
            DynamicDelivery = $dynamicDelivery.Count
            Block = $block.Count
            Replace = $replace.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    Action = $_.Action
                    Enable = $_.Enable
                    Redirect = $_.Redirect
                }
            })
        }
}

# ── M365EXO-006: Safe Links Policies ───────────────────────────────────
function Test-InfiltrationM365EXO006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.SafeLinksPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Safe Links data not available (requires Defender for Office 365)'
    }

    $policies = $exo.SafeLinksPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Safe Links policies configured — Defender for Office 365 may not be licensed' `
            -Details @{ PolicyCount = 0 }
    }

    $urlTracking = @($policies | Where-Object { $_.EnableSafeLinksForEmail -eq $true -or $_.IsEnabled -eq $true })
    $scanUrls = @($policies | Where-Object { $_.ScanUrls -eq $true })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) Safe Links policies ($($urlTracking.Count) enabled for email, $($scanUrls.Count) scan URLs)" `
        -Details @{
            PolicyCount = $policies.Count
            EnabledForEmail = $urlTracking.Count
            ScanUrls = $scanUrls.Count
            Policies = @($policies | ForEach-Object {
                @{
                    Name = $_.Name
                    EnableSafeLinksForEmail = $_.EnableSafeLinksForEmail
                    ScanUrls = $_.ScanUrls
                    EnableForInternalSenders = $_.EnableForInternalSenders
                    DeliverMessageAfterScan = $_.DeliverMessageAfterScan
                    DisableUrlRewrite = $_.DisableUrlRewrite
                }
            })
        }
}

# ── M365EXO-007: Transport Rules ───────────────────────────────────────
function Test-InfiltrationM365EXO007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.TransportRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange transport rule data not available'
    }

    $rules = $exo.TransportRules
    if ($rules.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No mail flow (transport) rules configured' `
            -Details @{ RuleCount = 0 }
    }

    $enabled = @($rules | Where-Object { $_.State -eq 'Enabled' })
    $disabled = @($rules | Where-Object { $_.State -ne 'Enabled' })

    # Flag rules that redirect or forward mail externally
    $forwardingRules = @($rules | Where-Object {
        $_.RedirectMessageTo -or
        $_.BlindCopyTo -or
        $_.CopyTo -or
        $_.AddToRecipients
    })

    $status = if ($forwardingRules.Count -gt 0) { 'WARN' } else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($rules.Count) transport rules ($($enabled.Count) enabled, $($forwardingRules.Count) with redirect/forward actions)" `
        -Details @{
            RuleCount = $rules.Count
            EnabledCount = $enabled.Count
            DisabledCount = $disabled.Count
            ForwardingRuleCount = $forwardingRules.Count
            Rules = @($rules | ForEach-Object {
                @{
                    Name = $_.Name
                    State = $_.State
                    Priority = $_.Priority
                    Mode = $_.Mode
                }
            })
        }
}

# ── M365EXO-008: Remote Domains ────────────────────────────────────────
function Test-InfiltrationM365EXO008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.RemoteDomains) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange remote domain data not available'
    }

    $domains = $exo.RemoteDomains
    # Check default remote domain settings
    $defaultDomain = $domains | Where-Object { $_.DomainName -eq '*' } | Select-Object -First 1

    $autoForwardEnabled = $false
    if ($defaultDomain) {
        $autoForwardEnabled = $defaultDomain.AutoForwardEnabled -eq $true
    }

    $status = if ($autoForwardEnabled) { 'FAIL' } else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Remote domains: $($domains.Count) configured. Default domain auto-forward: $autoForwardEnabled" `
        -Details @{
            DomainCount = $domains.Count
            DefaultAutoForward = $autoForwardEnabled
            Domains = @($domains | ForEach-Object {
                @{
                    DomainName = $_.DomainName
                    AutoForwardEnabled = $_.AutoForwardEnabled
                    AutoReplyEnabled = $_.AutoReplyEnabled
                    AllowedOOFType = $_.AllowedOOFType
                }
            })
        }
}

# ── M365EXO-009: DKIM Signing Configuration ────────────────────────────
function Test-InfiltrationM365EXO009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DkimSigningConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DKIM signing configuration data not available'
    }

    $configs = $exo.DkimSigningConfig
    if ($configs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No DKIM signing configurations found'
    }

    $enabled = @($configs | Where-Object { $_.Enabled -eq $true })
    $disabled = @($configs | Where-Object { $_.Enabled -ne $true })

    $status = if ($disabled.Count -eq 0) { 'PASS' }
              elseif ($enabled.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($configs.Count) DKIM configs: $($enabled.Count) enabled, $($disabled.Count) disabled" `
        -Details @{
            TotalConfigs = $configs.Count
            EnabledCount = $enabled.Count
            DisabledCount = $disabled.Count
            Configs = @($configs | ForEach-Object {
                @{
                    Domain = $_.Domain
                    Enabled = $_.Enabled
                    Status = $_.Status
                    Selector1CNAME = $_.Selector1CNAME
                    Selector2CNAME = $_.Selector2CNAME
                    KeyCreationTime = $_.KeyCreationTime
                }
            })
        }
}

# ── M365EXO-010: CAS Mailbox Plans (Protocol Access) ──────────────────
function Test-InfiltrationM365EXO010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.CASMailboxPlans) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'CAS mailbox plan data not available'
    }

    $plans = $exo.CASMailboxPlans
    if ($plans.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No CAS mailbox plans found'
    }

    # Check for legacy protocols enabled
    $legacyEnabled = @($plans | Where-Object {
        $_.ImapEnabled -eq $true -or
        $_.PopEnabled -eq $true
    })

    $status = if ($legacyEnabled.Count -eq 0) { 'PASS' }
              elseif ($legacyEnabled.Count -le 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($plans.Count) CAS mailbox plans ($($legacyEnabled.Count) with IMAP/POP enabled)" `
        -Details @{
            PlanCount = $plans.Count
            LegacyProtocolEnabledCount = $legacyEnabled.Count
            Plans = @($plans | ForEach-Object {
                @{
                    Name = $_.Name
                    ImapEnabled = $_.ImapEnabled
                    PopEnabled = $_.PopEnabled
                    ActiveSyncEnabled = $_.ActiveSyncEnabled
                    OWAEnabled = $_.OWAEnabled
                    MAPIEnabled = $_.MAPIEnabled
                    EwsEnabled = $_.EwsEnabled
                }
            })
        }
}

# ── M365EXO-011: External Email Forwarding ─────────────────────────────
function Test-InfiltrationM365EXO011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange Online data not available'
    }

    # Check transport rules for forwarding AND remote domain auto-forward
    $issues = [System.Collections.Generic.List[string]]::new()

    # Check remote domain auto-forward
    if ($exo.RemoteDomains) {
        $defaultDomain = $exo.RemoteDomains | Where-Object { $_.DomainName -eq '*' } | Select-Object -First 1
        if ($defaultDomain -and $defaultDomain.AutoForwardEnabled -eq $true) {
            $issues.Add('Default remote domain allows auto-forwarding')
        }
    }

    # Check transport rules for forwarding
    if ($exo.TransportRules) {
        $forwardRules = @($exo.TransportRules | Where-Object {
            $_.State -eq 'Enabled' -and
            ($_.RedirectMessageTo -or $_.BlindCopyTo)
        })
        if ($forwardRules.Count -gt 0) {
            $issues.Add("$($forwardRules.Count) active transport rules redirect/BCC mail")
        }
    }

    $status = if ($issues.Count -eq 0) { 'PASS' }
              elseif ($issues.Count -eq 1) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "External forwarding controls: $($issues.Count) issue(s). $(if ($issues.Count -gt 0) { $issues -join '; ' } else { 'All controls in place' })" `
        -Details @{
            IssueCount = $issues.Count
            Issues = @($issues)
        }
}

# ── M365EXO-012: Exchange Audit Configuration ──────────────────────────
function Test-InfiltrationM365EXO012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.OrganizationConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Exchange organization config not available'
    }

    $orgConfig = $exo.OrganizationConfig
    $auditDisabled = $orgConfig.AuditDisabled

    if ($auditDisabled -eq $true) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Exchange mailbox auditing is DISABLED at the organization level' `
            -Details @{ AuditDisabled = $true }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Exchange mailbox auditing is enabled at the organization level' `
        -Details @{
            AuditDisabled = $false
        }
}

# ════════════════════════════════════════════════════════════════════════
#  SCuBA EXO baseline — dedicated per-control checks (MS.EXO.1.1 .. 17.3)
#  Each reads $AuditData.M365Services.Exchange.<prop>. Honesty rule:
#  return SKIP / Not Assessed when the underlying data is null/empty —
#  never PASS on uncollectable data.
# ════════════════════════════════════════════════════════════════════════

# ── M365EXO-013: MS.EXO.1.1 — Auto-forwarding to external domains disabled ──
function Test-InfiltrationM365EXO013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.RemoteDomains -or @($exo.RemoteDomains).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Remote domain data not available — Not Assessed'
    }

    $domains = @($exo.RemoteDomains)
    $autoFwd = @($domains | Where-Object { $_.AutoForwardEnabled -eq $true })

    $status = if ($autoFwd.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($domains.Count) remote domains; $($autoFwd.Count) permit auto-forwarding" `
        -Details @{
            DomainCount = $domains.Count
            AutoForwardEnabledDomains = @($autoFwd | ForEach-Object { $_.DomainName })
            Domains = @($domains | ForEach-Object {
                @{ DomainName = $_.DomainName; AutoForwardEnabled = $_.AutoForwardEnabled }
            })
        }
}

# ── M365EXO-014: MS.EXO.2.1 — Approved sending IP list maintained ──
function Test-InfiltrationM365EXO014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    # The approved-sender list is an organizational artifact reflected in SPF.
    # Agentless, we can only confirm SPF records exist; the maintained list
    # itself is a process control we cannot verify -> Not Assessed.
    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DomainMailSecurity -or @($exo.DomainMailSecurity).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Approved sender list is a process artifact not directly collectable; no SPF data to corroborate — Not Assessed'
    }

    $domains = @($exo.DomainMailSecurity)
    $withSpf = @($domains | Where-Object { $_.SPF -and $_.SPF.Record })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Maintained approved-sender list cannot be verified agentlessly; $($withSpf.Count)/$($domains.Count) domains publish an SPF record (corroborating evidence only) — verify the approved IP list manually" `
        -Details @{
            DomainCount = $domains.Count
            DomainsWithSpf = $withSpf.Count
            Note = 'Process control: approved sending IP list maintained per domain. Confirm out-of-band.'
        }
}

# ── M365EXO-015: MS.EXO.2.2 — SPF published for each domain (DNS) ──
function Test-InfiltrationM365EXO015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DomainMailSecurity -or @($exo.DomainMailSecurity).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DNS-based check — SPF records not resolved (no accepted-domain DNS data). Verify SPF (-all) for accepted domains — Not Assessed'
    }

    $domains = @($exo.DomainMailSecurity)
    $valid = @($domains | Where-Object { $_.SPF -and $_.SPF.Valid -eq $true })
    $missing = @($domains | Where-Object { -not ($_.SPF -and $_.SPF.Record) })

    $status = if ($domains.Count -gt 0 -and $valid.Count -eq $domains.Count) { 'PASS' }
              elseif ($valid.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($valid.Count)/$($domains.Count) domains publish a valid SPF policy; $($missing.Count) missing SPF" `
        -Details @{
            DomainCount = $domains.Count
            ValidSpfCount = $valid.Count
            MissingSpfDomains = @($missing | ForEach-Object { $_.Domain })
            Domains = @($domains | ForEach-Object {
                @{ Domain = $_.Domain; SpfValid = $_.SPF.Valid; SpfRecord = $_.SPF.Record; Details = $_.SPF.Details }
            })
        }
}

# ── M365EXO-016: MS.EXO.3.1 — DKIM enabled for all domains ──
function Test-InfiltrationM365EXO016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DkimSigningConfig -or @($exo.DkimSigningConfig).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DKIM signing configuration not available — Not Assessed'
    }

    $configs = @($exo.DkimSigningConfig)
    $enabled = @($configs | Where-Object { $_.Enabled -eq $true })
    $disabled = @($configs | Where-Object { $_.Enabled -ne $true })

    $status = if ($disabled.Count -eq 0) { 'PASS' }
              elseif ($enabled.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($enabled.Count)/$($configs.Count) domains have DKIM signing enabled" `
        -Details @{
            TotalConfigs = $configs.Count
            EnabledCount = $enabled.Count
            DisabledDomains = @($disabled | ForEach-Object { $_.Domain })
        }
}

# ── M365EXO-017: MS.EXO.4.1 — DMARC published for each domain (DNS) ──
function Test-InfiltrationM365EXO017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DomainMailSecurity -or @($exo.DomainMailSecurity).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DNS-based check — DMARC records not resolved. Verify _dmarc TXT for accepted domains — Not Assessed'
    }

    $domains = @($exo.DomainMailSecurity)
    $valid = @($domains | Where-Object { $_.DMARC -and $_.DMARC.Valid -eq $true })
    $missing = @($domains | Where-Object { -not ($_.DMARC -and $_.DMARC.Record) })

    $status = if ($domains.Count -gt 0 -and $valid.Count -eq $domains.Count) { 'PASS' }
              elseif ($valid.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($valid.Count)/$($domains.Count) domains publish a DMARC record; $($missing.Count) missing DMARC" `
        -Details @{
            DomainCount = $domains.Count
            ValidDmarcCount = $valid.Count
            MissingDmarcDomains = @($missing | ForEach-Object { $_.Domain })
            Domains = @($domains | ForEach-Object {
                @{ Domain = $_.Domain; DmarcValid = $_.DMARC.Valid; Policy = $_.DMARC.Policy; Record = $_.DMARC.Record }
            })
        }
}

# ── M365EXO-018: MS.EXO.4.2 — DMARC p=reject (DNS) ──
function Test-InfiltrationM365EXO018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DomainMailSecurity -or @($exo.DomainMailSecurity).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DNS-based check — DMARC policy not resolved. Verify p=reject for accepted domains — Not Assessed'
    }

    $domains = @($exo.DomainMailSecurity | Where-Object { $_.DMARC -and $_.DMARC.Record })
    if ($domains.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No DMARC records found to evaluate enforcement policy' `
            -Details @{ DomainsWithDmarc = 0 }
    }

    $reject = @($domains | Where-Object { $_.DMARC.Policy -eq 'reject' })

    $status = if ($reject.Count -eq $domains.Count) { 'PASS' }
              elseif ($reject.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($reject.Count)/$($domains.Count) DMARC-enabled domains use p=reject" `
        -Details @{
            DomainsWithDmarc = $domains.Count
            RejectCount = $reject.Count
            Policies = @($domains | ForEach-Object { @{ Domain = $_.Domain; Policy = $_.DMARC.Policy } })
        }
}

# ── M365EXO-019: MS.EXO.4.3 — DMARC aggregate report contact (DNS) ──
function Test-InfiltrationM365EXO019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.DomainMailSecurity -or @($exo.DomainMailSecurity).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DNS-based check — DMARC RUA not resolved. Verify rua= aggregate report destination for accepted domains — Not Assessed'
    }

    $domains = @($exo.DomainMailSecurity | Where-Object { $_.DMARC -and $_.DMARC.Record })
    if ($domains.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No DMARC records found to evaluate aggregate report (rua) contact' `
            -Details @{ DomainsWithDmarc = 0 }
    }

    $withRua = @($domains | Where-Object { $_.DMARC.Record -match 'rua=' })

    $status = if ($withRua.Count -eq $domains.Count) { 'PASS' }
              elseif ($withRua.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($withRua.Count)/$($domains.Count) DMARC records specify an aggregate report (rua) destination" `
        -Details @{
            DomainsWithDmarc = $domains.Count
            WithRuaCount = $withRua.Count
            Note = 'Federal executive-branch agencies must include reports@dmarc.cyber.dhs.gov in RUA.'
            Domains = @($domains | ForEach-Object { @{ Domain = $_.Domain; Record = $_.DMARC.Record } })
        }
}

# ── M365EXO-020: MS.EXO.5.1 — SMTP AUTH disabled org-wide ──
function Test-InfiltrationM365EXO020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.TransportConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Transport configuration not available — Not Assessed'
    }

    $disabled = $exo.TransportConfig.SmtpClientAuthenticationDisabled

    if ($null -eq $disabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SmtpClientAuthenticationDisabled not present on transport config — Not Assessed'
    }

    $status = if ($disabled -eq $true) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "SMTP AUTH org-wide default disabled: $disabled" `
        -Details @{ SmtpClientAuthenticationDisabled = $disabled }
}

# ── M365EXO-021: MS.EXO.6.1 — Contact sharing not open to all domains ──
function Test-InfiltrationM365EXO021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.SharingPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Sharing policy data not available — Not Assessed'
    }

    $policies = @($exo.SharingPolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No sharing policies defined — contacts not shared externally by policy' `
            -Details @{ PolicyCount = 0 }
    }

    # A wildcard-domain contact-sharing rule looks like "*:ContactsSharing" in Domains
    $offenders = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $policies) {
        foreach ($d in @($p.Domains)) {
            $dStr = "$d"
            if ($dStr -match '^\*' -and $dStr -match 'Contact') {
                $offenders.Add("$($p.Name): $dStr")
            }
        }
    }

    $status = if ($offenders.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) sharing policies; $($offenders.Count) share contacts with all domains (*)" `
        -Details @{
            PolicyCount = $policies.Count
            WildcardContactSharing = @($offenders)
            Policies = @($policies | ForEach-Object { @{ Name = $_.Name; Default = $_.Default; Domains = @($_.Domains | ForEach-Object { "$_" }) } })
        }
}

# ── M365EXO-022: MS.EXO.6.2 — Calendar sharing not open to all domains ──
function Test-InfiltrationM365EXO022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.SharingPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Sharing policy data not available — Not Assessed'
    }

    $policies = @($exo.SharingPolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No sharing policies defined — calendar details not shared externally by policy' `
            -Details @{ PolicyCount = 0 }
    }

    $offenders = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $policies) {
        foreach ($d in @($p.Domains)) {
            $dStr = "$d"
            if ($dStr -match '^\*' -and $dStr -match 'Calendar') {
                $offenders.Add("$($p.Name): $dStr")
            }
        }
    }

    $status = if ($offenders.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) sharing policies; $($offenders.Count) share calendar details with all domains (*)" `
        -Details @{
            PolicyCount = $policies.Count
            WildcardCalendarSharing = @($offenders)
        }
}

# ── M365EXO-023: MS.EXO.7.1 — External sender warning implemented ──
function Test-InfiltrationM365EXO023 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    $haveTag = $null -ne $exo.ExternalInOutlook
    $haveRules = $null -ne $exo.TransportRules
    if (-not $exo -or (-not $haveTag -and -not $haveRules)) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Neither external-tag nor transport-rule data available — Not Assessed'
    }

    # Native external sender tag
    $tagEnabled = $false
    if ($haveTag) {
        $tagEnabled = @($exo.ExternalInOutlook | Where-Object { $_.Enabled -eq $true }).Count -gt 0
    }

    # Mail flow rule that prepends an external marker to the subject
    $ruleMarker = $false
    if ($haveRules) {
        $ruleMarker = @($exo.TransportRules | Where-Object {
            $_.State -eq 'Enabled' -and
            ($_.PrependSubject -or $_.ApplyHtmlDisclaimerText) -and
            ($_.FromScope -eq 'NotInOrganization' -or "$($_.SenderAddressLocation)" -match 'Header')
        }).Count -gt 0
    }

    $status = if ($tagEnabled -or $ruleMarker) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "External sender warning: native tag=$tagEnabled, mail-flow-rule marker=$ruleMarker" `
        -Details @{
            NativeExternalTagEnabled = $tagEnabled
            SubjectMarkerRulePresent = $ruleMarker
        }
}

# ── M365EXO-024: MS.EXO.8.1 — DLP solution in use ──
function Test-InfiltrationM365EXO024 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.DlpCompliancePolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DLP policy data not available (Purview/IPPSSession may not be connected). A comparable third-party DLP cannot be detected agentlessly — Not Assessed'
    }

    $policies = @($exo.DlpCompliancePolicies)
    # Policies covering Exchange workload and enabled
    $exoEnabled = @($policies | Where-Object {
        $_.Enabled -eq $true -and (
            $_.Mode -match 'Enforce' -or $_.Mode -eq $null
        ) -and (
            -not $_.ExchangeLocation -or @($_.ExchangeLocation).Count -gt 0
        )
    })

    $status = if ($policies.Count -gt 0 -and $exoEnabled.Count -gt 0) { 'PASS' }
              elseif ($policies.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) DLP policies; $($exoEnabled.Count) enabled and scoped to Exchange" `
        -Details @{
            PolicyCount = $policies.Count
            ExchangeEnabledCount = $exoEnabled.Count
            Policies = @($policies | ForEach-Object { @{ Name = $_.Name; Enabled = $_.Enabled; Mode = $_.Mode } })
        }
}

# ── M365EXO-025: MS.EXO.8.2 — DLP protects PII (CCN/TIN/SSN) ──
function Test-InfiltrationM365EXO025 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.DlpCompliancePolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DLP policy data not available; sensitive-info-type coverage cannot be confirmed agentlessly — Not Assessed'
    }

    $policies = @($exo.DlpCompliancePolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No DLP policies present — PII (credit card/TIN/SSN) restriction not in place' `
            -Details @{ PolicyCount = 0 }
    }

    # Sensitive information types live in DLP rules (Get-DlpComplianceRule), not in the
    # policy object. Without rule-level data we cannot confirm CCN/TIN/SSN coverage.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($policies.Count) DLP policies present; sensitive-info-type coverage (credit card/TIN/SSN) requires rule-level inspection — verify CCN/TIN/SSN rules manually" `
        -Details @{
            PolicyCount = $policies.Count
            Note = 'Confirm DLP rules include Credit Card Number, U.S. Taxpayer Identification Number, and U.S. SSN sensitive info types with a block/restrict action.'
        }
}

# ── M365EXO-026: MS.EXO.9.1 — Email filtered by attachment file type ──
function Test-InfiltrationM365EXO026 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.MalwarePolicies -or @($exo.MalwarePolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Malware filter policy data not available — Not Assessed'
    }

    $policies = @($exo.MalwarePolicies)
    $fileFilter = @($policies | Where-Object { $_.EnableFileFilter -eq $true })

    $status = if ($fileFilter.Count -gt 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($fileFilter.Count)/$($policies.Count) malware policies have the common attachment filter enabled" `
        -Details @{
            PolicyCount = $policies.Count
            FileFilterEnabledCount = $fileFilter.Count
        }
}

# ── M365EXO-027: MS.EXO.9.2 — Attachment filter assesses true file type ──
function Test-InfiltrationM365EXO027 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.MalwarePolicies -or @($exo.MalwarePolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Malware filter policy data not available — Not Assessed'
    }

    $policies = @($exo.MalwarePolicies)
    # The common attachment filter performs true-type detection when enabled.
    $fileFilter = @($policies | Where-Object { $_.EnableFileFilter -eq $true })

    if ($fileFilter.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Common attachment filter disabled — true-file-type assessment not active' `
            -Details @{ FileFilterEnabledCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($fileFilter.Count)/$($policies.Count) policies use the common attachment filter (true-type detection)" `
        -Details @{
            PolicyCount = $policies.Count
            FileFilterEnabledCount = $fileFilter.Count
            Note = 'Common attachment filter inspects true file type, not just the extension.'
        }
}

# ── M365EXO-028: MS.EXO.9.3 — Disallowed file types set ──
function Test-InfiltrationM365EXO028 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.MalwarePolicies -or @($exo.MalwarePolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Malware filter policy data not available — Not Assessed'
    }

    $policies = @($exo.MalwarePolicies)
    $clickToRun = @('exe','cmd','vbe','vbs','js','ps1','bat')

    # Evaluate policies that have the filter enabled and a populated block list
    $enabledPolicies = @($policies | Where-Object { $_.EnableFileFilter -eq $true })
    if ($enabledPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Common attachment filter disabled — no disallowed file types in effect' `
            -Details @{ FileFilterEnabledCount = 0 }
    }

    $weak = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $enabledPolicies) {
        $types = @($p.FileTypes | ForEach-Object { "$_".ToLower() })
        if ($types.Count -eq 0) {
            $weak.Add("$($p.Name): block list empty")
        } else {
            $missing = @($clickToRun | Where-Object { $_ -notin $types })
            if ($missing.Count -gt 0) {
                $weak.Add("$($p.Name): missing $($missing -join ',')")
            }
        }
    }

    $status = if ($weak.Count -eq 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($enabledPolicies.Count) filter-enabled policies; $($weak.Count) miss core click-to-run types" `
        -Details @{
            FilterEnabledCount = $enabledPolicies.Count
            WeakPolicies = @($weak)
            RequiredMinimum = $clickToRun
        }
}

# ── M365EXO-029: MS.EXO.10.1 — Emails scanned for malware ──
function Test-InfiltrationM365EXO029 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.MalwarePolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Malware filter policy data not available — Not Assessed'
    }

    $policies = @($exo.MalwarePolicies)
    # Presence of an anti-malware policy means inbound mail is scanned; zero
    # policies on a connected tenant means inbound mail is NOT scanned.
    $status = if ($policies.Count -gt 0) { 'PASS' } else { 'FAIL' }
    $current = if ($policies.Count -gt 0) {
        "$($policies.Count) anti-malware policies active — inbound mail is scanned for malware"
    } else {
        'No anti-malware policies configured — inbound mail is NOT scanned for malware'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $current `
        -Details @{ PolicyCount = $policies.Count }
}

# ── M365EXO-030: MS.EXO.10.2 — Malware emails quarantined/dropped ──
function Test-InfiltrationM365EXO030 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.MalwarePolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Malware filter policy data not available — Not Assessed'
    }

    $policies = @($exo.MalwarePolicies)
    # Anti-malware always quarantines positive detections; flag any policy that
    # is explicitly weakened (filter disabled would still quarantine, so this
    # is informational). Pass when policies exist; zero policies means malware
    # is not being quarantined.
    $status = if ($policies.Count -gt 0) { 'PASS' } else { 'FAIL' }
    $current = if ($policies.Count -gt 0) {
        "$($policies.Count) anti-malware policies — malware-positive messages are quarantined"
    } else {
        'No anti-malware policies configured — malware-positive messages are NOT quarantined'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $current `
        -Details @{
            PolicyCount = $policies.Count
            Note = 'Exchange Online anti-malware quarantines malware detections by default; verify no custom routing weakens this.'
        }
}

# ── M365EXO-031: MS.EXO.10.3 — Post-delivery (ZAP) scanning ──
function Test-InfiltrationM365EXO031 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.MalwarePolicies -or @($exo.MalwarePolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Malware filter policy data not available — Not Assessed'
    }

    $policies = @($exo.MalwarePolicies)
    $zap = @($policies | Where-Object { $_.ZapEnabled -eq $true })

    $status = if ($zap.Count -eq $policies.Count) { 'PASS' }
              elseif ($zap.Count -gt 0) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($zap.Count)/$($policies.Count) anti-malware policies have zero-hour auto purge (ZAP) enabled" `
        -Details @{
            PolicyCount = $policies.Count
            ZapEnabledCount = $zap.Count
        }
}

# ── M365EXO-032: MS.EXO.11.1 — Impersonation protection ──
function Test-InfiltrationM365EXO032 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiPhishPolicies -or @($exo.AntiPhishPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Anti-phish policy data not available (requires Defender for Office 365) — Not Assessed'
    }

    $policies = @($exo.AntiPhishPolicies)
    $impersonation = @($policies | Where-Object {
        $_.EnableTargetedUserProtection -eq $true -or
        $_.EnableTargetedDomainsProtection -eq $true -or
        $_.EnableOrganizationDomainsProtection -eq $true
    })

    $status = if ($impersonation.Count -gt 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($impersonation.Count)/$($policies.Count) anti-phish policies enable user/domain impersonation protection" `
        -Details @{
            PolicyCount = $policies.Count
            ImpersonationEnabledCount = $impersonation.Count
        }
}

# ── M365EXO-033: MS.EXO.11.2 — User safety tips/warnings ──
function Test-InfiltrationM365EXO033 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiPhishPolicies -or @($exo.AntiPhishPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Anti-phish policy data not available — Not Assessed'
    }

    $policies = @($exo.AntiPhishPolicies)
    $tips = @($policies | Where-Object {
        $_.EnableFirstContactSafetyTips -eq $true -or
        $_.EnableSimilarUsersSafetyTips -eq $true -or
        $_.EnableSimilarDomainsSafetyTips -eq $true -or
        $_.EnableSpoofIntelligence -eq $true
    })

    $status = if ($tips.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($tips.Count)/$($policies.Count) anti-phish policies enable user safety tips/spoof intelligence" `
        -Details @{
            PolicyCount = $policies.Count
            SafetyTipsEnabledCount = $tips.Count
        }
}

# ── M365EXO-034: MS.EXO.11.3 — AI-based (mailbox intelligence) detection ──
function Test-InfiltrationM365EXO034 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiPhishPolicies -or @($exo.AntiPhishPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Anti-phish policy data not available (mailbox intelligence requires Defender for Office 365) — Not Assessed'
    }

    $policies = @($exo.AntiPhishPolicies)
    $mbi = @($policies | Where-Object { $_.EnableMailboxIntelligence -eq $true })

    $status = if ($mbi.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($mbi.Count)/$($policies.Count) anti-phish policies enable mailbox intelligence (AI-based detection)" `
        -Details @{
            PolicyCount = $policies.Count
            MailboxIntelligenceEnabledCount = $mbi.Count
        }
}

# ── M365EXO-035: MS.EXO.12.1 — No IP allow list in connection filter ──
function Test-InfiltrationM365EXO035 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.ConnectionFilterPolicies -or @($exo.ConnectionFilterPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Connection filter policy data not available — Not Assessed'
    }

    $policies = @($exo.ConnectionFilterPolicies)
    $withAllow = @($policies | Where-Object { @($_.IPAllowList).Count -gt 0 })

    $status = if ($withAllow.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($withAllow.Count)/$($policies.Count) connection filter policies have a non-empty IP allow list" `
        -Details @{
            PolicyCount = $policies.Count
            PoliciesWithAllowList = @($withAllow | ForEach-Object { @{ Name = $_.Name; IPAllowList = @($_.IPAllowList) } })
        }
}

# ── M365EXO-036: MS.EXO.12.2 — Connection filter safe list disabled ──
function Test-InfiltrationM365EXO036 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.ConnectionFilterPolicies -or @($exo.ConnectionFilterPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Connection filter policy data not available — Not Assessed'
    }

    $policies = @($exo.ConnectionFilterPolicies)
    $safeOn = @($policies | Where-Object { $_.EnableSafeList -eq $true })

    $status = if ($safeOn.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($safeOn.Count)/$($policies.Count) connection filter policies have the safe list enabled" `
        -Details @{
            PolicyCount = $policies.Count
            PoliciesWithSafeList = @($safeOn | ForEach-Object { $_.Name })
        }
}

# ── M365EXO-037: MS.EXO.13.1 — Mailbox auditing enabled ──
function Test-InfiltrationM365EXO037 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.OrganizationConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Organization configuration not available — Not Assessed'
    }

    $auditDisabled = $exo.OrganizationConfig.AuditDisabled

    if ($null -eq $auditDisabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'AuditDisabled not present on organization config — Not Assessed'
    }

    $status = if ($auditDisabled -eq $false) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Mailbox auditing enabled org-wide (AuditDisabled=$auditDisabled)" `
        -Details @{ AuditDisabled = $auditDisabled }
}

# ── M365EXO-038: MS.EXO.14.1 — Inbound spam filter enabled ──
function Test-InfiltrationM365EXO038 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.AntiSpamPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Anti-spam (hosted content filter) policy data not available — Not Assessed'
    }

    $policies = @($exo.AntiSpamPolicies)
    $status = if ($policies.Count -gt 0) { 'PASS' } else { 'FAIL' }
    $current = if ($policies.Count -gt 0) {
        "$($policies.Count) inbound anti-spam policies active"
    } else {
        'No inbound anti-spam policies configured'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $current `
        -Details @{ PolicyCount = $policies.Count }
}

# ── M365EXO-039: MS.EXO.14.2 — Spam routed to junk or quarantine ──
function Test-InfiltrationM365EXO039 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiSpamPolicies -or @($exo.AntiSpamPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Anti-spam policy data not available — Not Assessed'
    }

    $policies = @($exo.AntiSpamPolicies)
    $good = @('MoveToJmf','Quarantine','Redirect')
    $bad = @($policies | Where-Object {
        ($_.SpamAction -and $_.SpamAction -notin $good) -or
        ($_.HighConfidenceSpamAction -and $_.HighConfidenceSpamAction -notin $good)
    })

    $status = if ($bad.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($bad.Count)/$($policies.Count) anti-spam policies deliver spam to the inbox instead of junk/quarantine" `
        -Details @{
            PolicyCount = $policies.Count
            NonCompliant = @($bad | ForEach-Object { @{ Name = $_.Name; SpamAction = $_.SpamAction; HighConfidenceSpamAction = $_.HighConfidenceSpamAction } })
        }
}

# ── M365EXO-040: MS.EXO.14.3 — No allowed domains in anti-spam policy ──
function Test-InfiltrationM365EXO040 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.AntiSpamPolicies -or @($exo.AntiSpamPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Anti-spam policy data not available — Not Assessed'
    }

    $policies = @($exo.AntiSpamPolicies)
    $withAllowedDomains = @($policies | Where-Object { @($_.AllowedSenderDomains).Count -gt 0 })

    $status = if ($withAllowedDomains.Count -eq 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($withAllowedDomains.Count)/$($policies.Count) anti-spam policies contain allowed sender domains" `
        -Details @{
            PolicyCount = $policies.Count
            PoliciesWithAllowedDomains = @($withAllowedDomains | ForEach-Object {
                @{ Name = $_.Name; AllowedSenderDomains = @($_.AllowedSenderDomains | ForEach-Object { "$_" }) }
            })
        }
}

# ── M365EXO-041: MS.EXO.15.1 — URL block-list comparison (Safe Links) ──
function Test-InfiltrationM365EXO041 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.SafeLinksPolicies -or @($exo.SafeLinksPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Safe Links data not available (requires Defender for Office 365). A comparable third-party solution cannot be detected agentlessly — Not Assessed'
    }

    $policies = @($exo.SafeLinksPolicies)
    $email = @($policies | Where-Object { $_.EnableSafeLinksForEmail -eq $true -or $_.IsEnabled -eq $true })

    $status = if ($email.Count -gt 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($email.Count)/$($policies.Count) Safe Links policies enable URL scanning for email" `
        -Details @{
            PolicyCount = $policies.Count
            EnabledForEmailCount = $email.Count
        }
}

# ── M365EXO-042: MS.EXO.15.2 — Direct download links scanned ──
function Test-InfiltrationM365EXO042 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.SafeLinksPolicies -or @($exo.SafeLinksPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Safe Links data not available — Not Assessed'
    }

    $policies = @($exo.SafeLinksPolicies)
    $scan = @($policies | Where-Object { $_.ScanUrls -eq $true })

    $status = if ($scan.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($scan.Count)/$($policies.Count) Safe Links policies scan links/direct downloads in real time" `
        -Details @{
            PolicyCount = $policies.Count
            ScanUrlsCount = $scan.Count
        }
}

# ── M365EXO-043: MS.EXO.15.3 — User click tracking enabled ──
function Test-InfiltrationM365EXO043 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or -not $exo.SafeLinksPolicies -or @($exo.SafeLinksPolicies).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Safe Links data not available — Not Assessed'
    }

    $policies = @($exo.SafeLinksPolicies)
    # Click tracking on means DoNotTrackUserClicks is False.
    $tracked = @($policies | Where-Object { $_.DoNotTrackUserClicks -eq $false })

    $status = if ($tracked.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($tracked.Count)/$($policies.Count) Safe Links policies enable user click tracking" `
        -Details @{
            PolicyCount = $policies.Count
            ClickTrackingEnabledCount = $tracked.Count
        }
}

# ── M365EXO-044: MS.EXO.16.1 — Required EXO alerts enabled ──
function Test-InfiltrationM365EXO044 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.ProtectionAlerts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Protection alert policy data not available — Not Assessed'
    }

    $alerts = @($exo.ProtectionAlerts)
    if ($alerts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No alert policies present — required EXO alerts not enabled' `
            -Details @{ AlertCount = 0 }
    }

    $required = @(
        'Suspicious email sending patterns detected',
        'Suspicious Connector Activity',
        'Suspicious Email Forwarding Activity',
        'Messages have been delayed',
        'Tenant restricted from sending unprovisioned email',
        'Tenant restricted from sending email',
        'A potentially malicious URL click was detected'
    )

    $enabledNames = @($alerts | Where-Object { $_.Disabled -ne $true } | ForEach-Object { "$($_.Name)" })
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $required) {
        $hit = $enabledNames | Where-Object { $_ -like "*$r*" -or $r -like "*$_*" }
        if (-not $hit) { $missing.Add($r) }
    }

    $status = if ($missing.Count -eq 0) { 'PASS' }
              elseif ($missing.Count -lt $required.Count) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($required.Count - $missing.Count)/$($required.Count) required EXO alerts enabled" `
        -Details @{
            TotalAlertPolicies = $alerts.Count
            MissingRequiredAlerts = @($missing)
        }
}

# ── M365EXO-045: MS.EXO.16.2 — Alerts routed to monitored destination ──
function Test-InfiltrationM365EXO045 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.ProtectionAlerts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Protection alert policy data not available — Not Assessed'
    }

    $alerts = @($exo.ProtectionAlerts | Where-Object { $_.Disabled -ne $true })
    if ($alerts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No enabled alert policies to evaluate notification routing — Not Assessed'
    }

    $noRecipient = @($alerts | Where-Object {
        $_.NotifyUser -eq $null -or @($_.NotifyUser).Count -eq 0
    })

    $status = if ($noRecipient.Count -eq 0) { 'PASS' }
              elseif ($noRecipient.Count -lt $alerts.Count) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($alerts.Count - $noRecipient.Count)/$($alerts.Count) enabled alert policies notify a recipient (SIEM ingestion not detectable agentlessly)" `
        -Details @{
            EnabledAlertCount = $alerts.Count
            AlertsWithoutRecipient = @($noRecipient | ForEach-Object { "$($_.Name)" })
            Note = 'SIEM-based ingestion satisfies this control but cannot be confirmed from EXO config.'
        }
}

# ── M365EXO-046: MS.EXO.17.1 — Purview Audit (Standard) / UAL enabled ──
function Test-InfiltrationM365EXO046 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    $cfg = $exo.AdminAuditLogConfig
    if (-not $exo -or -not $cfg) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Admin audit log configuration not available — Not Assessed'
    }

    $ual = $cfg.UnifiedAuditLogIngestionEnabled
    if ($null -eq $ual) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'UnifiedAuditLogIngestionEnabled not present — Not Assessed'
    }

    $status = if ($ual -eq $true) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Unified audit log ingestion enabled: $ual" `
        -Details @{ UnifiedAuditLogIngestionEnabled = $ual }
}

# ── M365EXO-047: MS.EXO.17.2 — Purview Audit (Premium) enabled ──
function Test-InfiltrationM365EXO047 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    # Premium audit status (e.g. MailItemsAccessed event availability) is not
    # exposed by Get-AdminAuditLogConfig and depends on E5/G5 licensing, which
    # is not collected in this agentless EXO model -> Not Assessed.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'Purview Audit (Premium) status and E5/G5 licensing are not exposed via EXO config — Not Assessed. Verify Premium audit event types (e.g. MailItemsAccessed) and licensing manually.' `
        -Details @{
            Note = 'Premium audit features and required licensing cannot be confirmed agentlessly.'
        }
}

# ── M365EXO-048: MS.EXO.17.3 — Audit log retention >= OMB minimum ──
function Test-InfiltrationM365EXO048 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    # Audit log retention policies are managed in Purview (Get-UnifiedAuditLogRetentionPolicy)
    # which is not collected in this EXO model. Retention duration therefore cannot be
    # confirmed -> Not Assessed.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'Audit log retention policy (>=12 months per OMB M-21-31) is managed in Purview and not collected here — Not Assessed. Verify a retention policy of at least 12 months for unified audit logs.' `
        -Details @{
            Note = 'Custom audit log retention requires E5/G5 or add-on licensing and Purview inspection; not confirmable agentlessly.'
        }
}

# ── M365EXO-049: MS.EXO.9.5 — Executable attachment types blocked ──────────
function Test-InfiltrationM365EXO049 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    if (-not $exo -or $null -eq $exo.MalwarePolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Anti-malware policy data not available — executable-attachment blocking Not Assessed'
    }

    $policies = @($exo.MalwarePolicies)
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No anti-malware policies found — cannot confirm executable attachments are blocked'
    }

    # SCuBA 9.5 minimum: .exe, .cmd, .vbe. FileTypes is the Common Attachment Filter
    # list; match case-insensitively and tolerate a leading dot.
    $required = @('exe', 'cmd', 'vbe')
    $norm = { param($ft) @($ft | ForEach-Object { "$_".TrimStart('.').ToLowerInvariant() }) }

    $compliant = @($policies | Where-Object {
        $p = $_
        $blocked = & $norm $p.FileTypes
        $p.EnableFileFilter -eq $true -and
        (@($required | Where-Object { $blocked -notcontains $_ }).Count -eq 0)
    })

    $status = if ($compliant.Count -eq $policies.Count) { 'PASS' } else { 'FAIL' }
    $cv = if ($status -eq 'PASS') {
        "All $($policies.Count) anti-malware policies block executable attachments (.exe/.cmd/.vbe) via the Common Attachment Filter"
    } else {
        "$($policies.Count - $compliant.Count) of $($policies.Count) anti-malware policies do not block the minimum executable types (.exe/.cmd/.vbe)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $cv `
        -Details @{
            PolicyCount    = $policies.Count
            CompliantCount = $compliant.Count
            Required       = $required
        }
}

# ── M365EXO-050: MS.EXO.8.4 — DLP restricts SSN / ITIN / credit-card ───────
function Test-InfiltrationM365EXO050 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Exchange') -Subject 'Exchange Online configuration'
    if ($na) { return $na }

    $exo = $AuditData.M365Services.Exchange
    # DLP rules carry the sensitive-info-types. Get-DlpComplianceRule cannot tell an
    # unconfigured DLP solution from an unreadable one, so absent OR empty is Not
    # Assessed — never a false FAIL and never a pass. FAIL only on positive evidence
    # that present rules miss a required type.
    if (-not $exo -or $null -eq $exo.DlpComplianceRules -or @($exo.DlpComplianceRules).Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No DLP rules returned — cannot distinguish "no DLP configured" from "rules not readable" (may require Purview/IPPS permissions). Not Assessed; verify SSN/ITIN/credit-card DLP rules in Microsoft Purview.' `
            -Details @{ Note = 'Absent/empty DLP-rule data is Not Assessed, never a pass or a fabricated fail.' }
    }

    # Best-effort match on the standard Microsoft sensitive-information-type names.
    $enabled = @($exo.DlpComplianceRules | Where-Object { $_.Disabled -ne $true })
    $allText = (@($enabled | ForEach-Object {
        @($_.ContentContainsSensitiveInformation | ForEach-Object { "$($_.name)" }) -join '|'
    }) -join ' | ').ToLowerInvariant()

    $covers = [ordered]@{
        SSN        = [bool]($allText -match 'social security|ssn')
        ITIN       = [bool]($allText -match 'individual taxpayer|itin')
        CreditCard = [bool]($allText -match 'credit card')
    }
    $missing = @($covers.Keys | Where-Object { -not $covers[$_] })

    $status = if ($missing.Count -eq 0) { 'PASS' } else { 'FAIL' }
    $cv = if ($status -eq 'PASS') {
        'DLP rules restrict all three required sensitive types (SSN, ITIN, credit-card numbers)'
    } else {
        "DLP rules present but do not cover: $($missing -join ', ') (MS.EXO.8.4 minimum)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $cv `
        -Details @{
            EnabledRuleCount = $enabled.Count
            Covers           = $covers
            Missing          = @($missing)
            Note             = 'Sensitive-information-type names matched by pattern; confirm against live DLP rules.'
        }
}
