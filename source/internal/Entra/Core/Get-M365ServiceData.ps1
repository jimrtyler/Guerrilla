# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-M365ServiceData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,

        [hashtable]$ModuleAvailability,

        [switch]$Quiet
    )

    $data = @{
        Exchange     = @{}
        SharePoint   = @{}
        Teams        = @{}
        Defender     = @{}
        Audit        = @{}
        PowerPlatform = @{}
        Errors       = @{}
    }

    $hasEXO = $ModuleAvailability -and $ModuleAvailability.ExchangeOnlineManagement

    # ── Exchange Online ───────────────────────────────────────────────────
    if ($hasEXO) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Exchange Online configuration (EXO module)'
        }
        try {
            # Verify EXO connection
            $exoConnected = Get-Command Get-OrganizationConfig -ErrorAction SilentlyContinue
            if ($exoConnected) {
                $data.Exchange.OrganizationConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
                $data.Exchange.AntiSpamPolicies = @(Get-HostedContentFilterPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.AntiPhishPolicies = @(Get-AntiPhishPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.MalwarePolicies = @(Get-MalwareFilterPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.SafeAttachmentPolicies = @(Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.SafeLinksPolicies = @(Get-SafeLinksPolicy -ErrorAction SilentlyContinue)
                $data.Exchange.TransportRules = @(Get-TransportRule -ErrorAction SilentlyContinue)
                $data.Exchange.RemoteDomains = @(Get-RemoteDomain -ErrorAction SilentlyContinue)
                $data.Exchange.DkimSigningConfig = @(Get-DkimSigningConfig -ErrorAction SilentlyContinue)
                $data.Exchange.CASMailboxPlans = @(Get-CASMailboxPlan -ErrorAction SilentlyContinue)

                # ── Additional collectors for SCuBA EXO baseline coverage ──
                # Transport config: SMTP AUTH global default (MS.EXO.5.1)
                if (Get-Command Get-TransportConfig -ErrorAction SilentlyContinue) {
                    $data.Exchange.TransportConfig = Get-TransportConfig -ErrorAction SilentlyContinue
                }
                # Accepted domains: input set for DNS-based SPF/DMARC validation (MS.EXO.2.x / 4.x)
                if (Get-Command Get-AcceptedDomain -ErrorAction SilentlyContinue) {
                    $data.Exchange.AcceptedDomains = @(Get-AcceptedDomain -ErrorAction SilentlyContinue)
                }
                # Sharing policies: external calendar/contact sharing (MS.EXO.6.1 / 6.2)
                if (Get-Command Get-SharingPolicy -ErrorAction SilentlyContinue) {
                    $data.Exchange.SharingPolicies = @(Get-SharingPolicy -ErrorAction SilentlyContinue)
                }
                # Connection filter policy: IP allow list / safe list (MS.EXO.12.1 / 12.2)
                if (Get-Command Get-HostedConnectionFilterPolicy -ErrorAction SilentlyContinue) {
                    $data.Exchange.ConnectionFilterPolicies = @(Get-HostedConnectionFilterPolicy -ErrorAction SilentlyContinue)
                }
                # Outbound spam filter policy: external auto-forward enforcement (MS.EXO.1.1)
                if (Get-Command Get-HostedOutboundSpamFilterPolicy -ErrorAction SilentlyContinue) {
                    $data.Exchange.OutboundSpamPolicies = @(Get-HostedOutboundSpamFilterPolicy -ErrorAction SilentlyContinue)
                }
                # ATP policy for O365: Safe Attachments for SPO/OneDrive/Teams (MS.EXO.9.x / 10.x)
                if (Get-Command Get-AtpPolicyForO365 -ErrorAction SilentlyContinue) {
                    $data.Exchange.AtpPolicyForO365 = @(Get-AtpPolicyForO365 -ErrorAction SilentlyContinue)
                }
                # External-in-Outlook: native external sender tag (MS.EXO.7.1)
                if (Get-Command Get-ExternalInOutlook -ErrorAction SilentlyContinue) {
                    $data.Exchange.ExternalInOutlook = @(Get-ExternalInOutlook -ErrorAction SilentlyContinue)
                }
                # Protection alert policies: EXO alerting requirements (MS.EXO.16.x)
                if (Get-Command Get-ProtectionAlert -ErrorAction SilentlyContinue) {
                    $data.Exchange.ProtectionAlerts = @(Get-ProtectionAlert -ErrorAction SilentlyContinue)
                }
                # Unified audit log ingestion status (MS.EXO.17.1)
                if (Get-Command Get-AdminAuditLogConfig -ErrorAction SilentlyContinue) {
                    $data.Exchange.AdminAuditLogConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
                }
                # DLP compliance policies for EXO workload (MS.EXO.8.x)
                if (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue) {
                    $data.Exchange.DlpCompliancePolicies = @(Get-DlpCompliancePolicy -ErrorAction SilentlyContinue)
                }
                # DLP compliance rules carry the sensitive-information-types (MS.EXO.8.4).
                # Kept separate from policies; M365EXO-050 treats an absent/empty result as
                # Not Assessed (cannot tell "no DLP" from "not readable"), never a pass.
                if (Get-Command Get-DlpComplianceRule -ErrorAction SilentlyContinue) {
                    $data.Exchange.DlpComplianceRules = @(Get-DlpComplianceRule -ErrorAction SilentlyContinue)
                }

                # ── DNS-based email authentication for accepted domains (SPF/DMARC) ──
                # MS.EXO.2.2 (SPF) and MS.EXO.4.x (DMARC) live in DNS, not EXO config.
                # Resolve them per accepted domain using the existing DNS helper when present.
                if ($data.Exchange.AcceptedDomains -and
                    (Get-Command Resolve-DomainMailSecurity -ErrorAction SilentlyContinue)) {
                    $mailSec = [System.Collections.Generic.List[object]]::new()
                    foreach ($dom in @($data.Exchange.AcceptedDomains)) {
                        $domName = $dom.DomainName
                        if (-not $domName) { continue }
                        # Skip the *.onmicrosoft.com routing domain noise where possible; still resolve customs
                        try {
                            $mailSec.Add((Resolve-DomainMailSecurity -Domain $domName))
                        } catch {
                            $mailSec.Add(@{ Domain = $domName; Error = $_.Exception.Message })
                        }
                    }
                    $data.Exchange.DomainMailSecurity = @($mailSec)
                }
            } else {
                $data.Errors['Exchange'] = 'EXO module available but not connected. Run Connect-ExchangeOnline first.'
            }
        } catch {
            $data.Errors['Exchange'] = $_.Exception.Message
        }
    } else {
        $data.Errors['Exchange'] = 'ExchangeOnlineManagement module not available — Exchange checks will be skipped'
    }

    # ── SharePoint / OneDrive ─────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting SharePoint/OneDrive settings via Graph'
    }
    try {
        # SharePoint admin settings via Graph (limited)
        $data.SharePoint.Sites = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/sites' -QueryParameters @{ 'search' = '*'; '$top' = '10' } `
            -Paginate -MaxPages 1 -Quiet:$Quiet)
    } catch {
        $data.Errors['SharePoint'] = $_.Exception.Message
    }

    # ── Teams ─────────────────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Teams configuration via Graph'
    }
    try {
        $data.Teams.AppCatalogs = @(Invoke-GraphApi -AccessToken $AccessToken `
            -Uri '/appCatalogs/teamsApps' `
            -QueryParameters @{ '$filter' = "distributionMethod eq 'organization'" } `
            -Paginate -Quiet:$Quiet)
    } catch {
        $data.Errors['TeamsApps'] = $_.Exception.Message
    }

    # Teams policies require Teams admin module or beta Graph
    $hasTeams = $ModuleAvailability -and $ModuleAvailability.MicrosoftTeams
    if ($hasTeams) {
        try {
            $teamsConnected = Get-Command Get-CsTeamsMeetingPolicy -ErrorAction SilentlyContinue
            if ($teamsConnected) {
                $data.Teams.MeetingPolicies = @(Get-CsTeamsMeetingPolicy -ErrorAction SilentlyContinue)
                $data.Teams.MessagingPolicies = @(Get-CsTeamsMessagingPolicy -ErrorAction SilentlyContinue)
                $data.Teams.ExternalAccessConfig = Get-CsTenantFederationConfiguration -ErrorAction SilentlyContinue
                $data.Teams.GuestConfig = Get-CsTeamsClientConfiguration -ErrorAction SilentlyContinue
            } else {
                $data.Errors['TeamsAdmin'] = 'Teams module available but not connected. Run Connect-MicrosoftTeams first.'
            }
        } catch {
            $data.Errors['TeamsAdmin'] = $_.Exception.Message
        }
    }

    # ── Defender for Office 365 ───────────────────────────────────────────
    if ($hasEXO) {
        try {
            $exoConnected = Get-Command Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue
            if ($exoConnected) {
                $data.Defender.ProtectionPolicyRules = @(Get-EOPProtectionPolicyRule -ErrorAction SilentlyContinue)
                $data.Defender.ProtectionAlerts = @(Get-ProtectionAlert -ErrorAction SilentlyContinue)
            }
        } catch {
            $data.Errors['Defender'] = $_.Exception.Message
        }
    }

    # ── Unified Audit Log ─────────────────────────────────────────────────
    if ($hasEXO) {
        try {
            $exoConnected = Get-Command Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
            if ($exoConnected) {
                $data.Audit.AdminAuditLogConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
            }
        } catch {
            $data.Errors['Audit'] = $_.Exception.Message
        }
    }

    # ── Power Platform ────────────────────────────────────────────────────
    $hasPP = $ModuleAvailability -and $ModuleAvailability.PowerAppsAdmin
    if ($hasPP) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase INFILTRATE -Message 'Collecting Power Platform configuration'
        }
        try {
            $ppConnected = Get-Command Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue
            if ($ppConnected) {
                $data.PowerPlatform.Environments = @(Get-AdminPowerAppEnvironment -ErrorAction SilentlyContinue)
                $data.PowerPlatform.DlpPolicies = @(Get-DlpPolicy -ErrorAction SilentlyContinue)
                $data.PowerPlatform.TenantSettings = Get-TenantSettings -ErrorAction SilentlyContinue
            }
        } catch {
            $data.Errors['PowerPlatform'] = $_.Exception.Message
        }
    } else {
        $data.Errors['PowerPlatform'] = 'Power Platform admin module not available'
    }

    if (-not $Quiet) {
        $collected = @()
        if ($data.Exchange.Count -gt 1) { $collected += 'Exchange' }
        if ($data.SharePoint.Count -gt 0) { $collected += 'SharePoint' }
        if ($data.Teams.Count -gt 0) { $collected += 'Teams' }
        Write-ProgressLine -Phase INFILTRATE -Message "M365 data collected: $($collected -join ', ')"
    }

    return $data
}
