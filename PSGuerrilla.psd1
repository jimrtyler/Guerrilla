@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.9.3'
    GUID              = 'f7a3b2c1-4d5e-6f78-9a0b-1c2d3e4f5a6b'
    Author            = 'Jim Tyler, Microsoft MVP'
    CompanyName       = 'Jim Tyler'
    Copyright         = '(c) 2026 Jim Tyler. All rights reserved.'
    Description       = 'Security assessment, threat detection, and continuous monitoring module for Google Workspace, Active Directory, and Microsoft cloud environments. Includes Google Workspace compromise assessment with 23 detection signals, Active Directory reconnaissance (203 security checks across 14 categories including NTLM-relay preconditions, Tier-0 hygiene, telemetry posture, and adversary tradecraft indicators), Entra ID / Azure / Intune / M365 infiltration audit (158 checks), and continuous monitoring across all four theaters (Entra ID sign-in risk, AD baseline monitoring, M365 audit log monitoring). Supports alerting via SendGrid, Mailgun, Twilio SMS, Teams, Slack, generic webhooks, PagerDuty, Pushover, Syslog (CEF/LEEF), and Windows Event Log.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Invoke-Recon'
        'Invoke-Surveillance'
        'Invoke-Watchtower'
        'Invoke-Wiretap'
        'Get-DeadDrop'
        'Send-Signal'
        'Send-SignalSendGrid'
        'Send-SignalMailgun'
        'Send-SignalTwilio'
        'Send-SignalTeams'
        'Send-SignalSlack'
        'Send-SignalWebhook'
        'Send-SignalPagerDuty'
        'Send-SignalPushover'
        'Send-SignalSyslog'
        'Send-SignalEventLog'
        'Send-SignalDigest'
        'Set-Safehouse'
        'Test-Safehouse'
        'Get-Safehouse'
        'Register-Patrol'
        'Unregister-Patrol'
        'Get-Patrol'
        'Update-ThreatIntel'
        'Invoke-ReconDemo'
        'Invoke-Fortification'
        'Invoke-Reconnaissance'
        'Invoke-Infiltration'
        'Invoke-Campaign'
        'Get-GuerrillaScore'
        'Get-QuickWins'
        'Get-ComplianceCrosswalk'
        'Export-BudgetJustification'
        'Export-ExecutiveSummary'
        'Export-TechnicalReport'
        'Export-RemediationPlaybook'
        'Export-RemediationScripts'
        'Set-RiskAcceptance'
        'Get-RiskAcceptance'
        'Get-TrendReport'
        'Export-ReportPdf'
        'Export-Dashboard'
        'Show-Guerrilla'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @(
        # PSRecon -> PSGuerrilla rename aliases
        'Invoke-GoogleRecon'
        'Get-ReconAlerts'
        'Send-ReconAlert'
        'Send-ReconAlertSendGrid'
        'Send-ReconAlertMailgun'
        'Send-ReconAlertTwilio'
        'Set-ReconConfig'
        'Get-ReconConfig'
        'Register-ReconScheduledTask'
        'Unregister-ReconScheduledTask'
        'Get-ReconScheduledTask'
        # Theater-disambiguating aliases
        'Invoke-WorkspaceRecon'
        'Invoke-ADRecon'
        'Invoke-CloudRecon'
    )
    FormatsToProcess   = @('PSGuerrilla.format.ps1xml')
    PrivateData = @{
        PSData = @{
            Tags       = @('GoogleWorkspace', 'ActiveDirectory', 'EntraID', 'AzureAD', 'Intune', 'M365', 'Security', 'CompromiseAssessment', 'IncidentResponse', 'ThreatDetection', 'ADSecurity', 'CloudSecurity', 'NTLMRelay', 'TierZero', 'GUI', 'WPF', 'PSGuerrilla')
            LicenseUri = 'https://creativecommons.org/licenses/by/4.0/'
            ProjectUri = 'https://guerrilla.army'
            ReleaseNotes = 'v2.9.3 (patch): More live-validation backlog fixes. (REP-2) Get-ComplianceCrosswalk now exposes the technical frameworks already carried on every check — added NIST-800-53, MITRE-ATTACK and CIS to -Framework, built directly from each finding''s compliance map (previously only the education frameworks FERPA/COPPA/CIPA/NIST-171/STATE-EDTECH were surfaced). (GWS-2) Sampled Google Workspace Gmail checks (EMAIL-009/010/011/022) now append a "SAMPLED N of M active mailboxes" qualifier to a clean PASS so a partial scan can''t read as full coverage. (ENT-3) Invoke-GraphApi treats license-gated 400s (AadPremiumLicenseRequired, e.g. PIM schedule endpoints) as a quiet verbose note instead of an alarming warning on tenants without Entra ID P2. (ADTRADE-002) DCShadow indicator softened Critical->High — an unmatched server object under CN=Sites,CN=Configuration is usually lingering DC metadata, not an attack; the finding now says so and points at whenCreated. Remaining backlog tracked: GWS-1 (Cloud Identity Policy API — blocked until the SA gets the cloud-identity.policies.readonly DWD scope; adding it before delegation would break all Google auth), ENT-4/ENT-5, GWS-3, ADDOM-007. v2.9.2 (patch): Part-2 live-validation fixes (Google Workspace, monitoring, reporting). (1) Continuous monitoring couldn''t use the safehouse vault — Invoke-Surveillance/Invoke-Wiretap never read it, so a vault-only setup failed with "TenantId is required" (and broke Register-Patrol for vault installs). Both now have -VaultName and resolve TenantId/ClientId/ClientSecret from GUERRILLA_GRAPH_* as the last resort, like the audit cmdlets since v2.5.0. (2) Invoke-Surveillance aborted the whole run on the first Graph 403; each collector is now wrapped in try/catch and the risk-detection 403/AadPremiumLicenseRequired case degrades to a clear "requires IdentityRiskEvent.Read.All + IdentityRiskyUser.Read.All + Entra ID P2" skip while sign-in/audit signals still run. (3) Google Workspace Gmail sampling was non-random (Select-Object -First always inspected the same directory-order prefix, so a compromised mailbox later in the list was never seen) — now a random sample. (4) Export-RemediationScripts gained an -OutputPath alias (was the only Export-* using -OutputDirectory). (5) Invoke-Watchtower gained comment-based help. v2.9.1 (patch): Fixes from a live-environment validation pass (production AD domain + Entra tenant). (1) AD ACL/DCSync/GPO-delegation checks were silently dead: Resolve-ADSid referenced three module-scope caches ($script:SidCache/WellKnownSids/WellKnownRids) the .psm1 never initialized, so every ACL read threw and Get-ADObjectACLs swallowed it — turning ADACL-012/014, ADGPO-007/009 and the DCSync check ADPRIV-028 into false SKIPs. Caches now initialized at load (with well-known SID/RID tables) + a guard in Resolve-ADSid; domain-RID lookup gated on S-1-5-21-* SIDs. (2) Tier-0 tier-bleed checks ADTIER-002/003/004/005 ERRORed on CLEAN environments because New-TierBleedFinding''s [Parameter(Mandatory)][array]$Hits rejected an empty collection — the secure (zero-hit) state threw instead of PASS. Added [AllowEmptyCollection()]. (3) Entra password-protection checks EIDAUTH-013/014 falsely reported "settings not found": Get-EntraAuthMethodsData queried /settings (beta-only, 400s on v1.0); now uses v1.0 /groupSettings. (4) Removed a redundant always-400 Graph call (authenticationMethodConfigurations sourced from the parent policy object). (5) Invoke-LdapQuery now treats "no such object" (no AD CS / empty DNS partition) as verbose + empty instead of an alarming warning. Added Tests/verify-core-fixes.ps1. v2.9.0: Test mode. A new -TestMode switch on Invoke-Reconnaissance / Invoke-Fortification / Invoke-Infiltration / Invoke-Campaign, and a "Test mode" checkbox in the Show-Guerrilla Operations tab. When enabled the scan makes NO live connection and synthesizes a complete all-FAIL report straight from the shipped check definitions — every downstream feature works exactly like a real scan: report styles/themes, white-label branding, affected-account lists, scoring, and CSV/JSON output. Lets a consultant preview a fully-populated report and dial in branding/theme without a tenant or domain. Works for all three theaters and the big Campaign report (which simulates all 459 checks across AD + Google Workspace + Entra/M365). Test mode ignores the category selection — it always simulates the full theater check set. Also: the Campaign (big report) now honours report themes + white-label branding too — Invoke-Campaign gains -ReportStyle, reads branding from config, and Export-CampaignReportHtml moved onto the shared theming engine (Guerrilla/Professional/Slate) with plain risk-based per-theater labels in the plain themes (previously only the three single-theater reports were themed). Backward compatible: default Guerrilla output unchanged. v2.8.1 (patch): Fix Show-Guerrilla GUI Entra/Azure/M365 (Infiltration) scans appearing to HANG — the scan completed but the OnComplete callback called the module-private Get-PSGuerrillaDataRoot, which is not resolvable inside a GetNewClosure() closure, so the callback threw before resetting the UI and the progress bar kept spinning. (AD/Workspace were unaffected because their results carry HtmlReportPath and skipped that branch.) The callback now uses the captured $session.ReportsDir, and Invoke-Infiltration now returns HtmlReportPath like the other theaters so the GUI opens the exact report. Also fixed poor GUI contrast: the Report style / Settings dropdown popups used WPF''s default light theme, making the near-white item text invisible — ComboBoxItem now has an explicit dark template (light text, amber highlight with dark text) — and the left-nav buttons were brightened for legibility. v2.8.0: Report themes + white-label branding. (1) Reports can now be generated in three visual STYLES, picked per scan from the Operations tab''s new "Report style" dropdown (or a new -ReportStyle parameter on Invoke-Reconnaissance / Invoke-Fortification / Invoke-Infiltration): Guerrilla (default, unchanged dark tactical theme with FORTRESS/EXPOSED FLANK/OVERRUN labels), Professional (light white corporate theme, sans-serif, plain risk-based labels Secure/Hardened/Moderate Risk/Elevated Risk/High Risk/Critical Risk), and Slate (modern dark dashboard, plain labels). A shared theming engine drives a common palette of CSS variables so all three audit reports look consistent per style. (2) A new "Branding" tab in Show-Guerrilla white-labels reports with firm name, logo, consultant name/email, client name, and a confidentiality banner (rendered in the report header). Branding is saved to config and applied on every subsequent scan. The "Generated with PSGuerrilla by Jim Tyler, Microsoft MVP" footer attribution is ALWAYS preserved regardless of theme or branding. Default look is unchanged (existing scans render identically as Guerrilla); themes/branding currently cover the three audit reports, with the Campaign roll-up and monitoring reports to follow. v2.7.0: The Show-Guerrilla GUI gains an "Inspector" tab — a built-in source browser for every scan, check, and helper function in the module (801 today). Filter by area (Active Directory / Google Workspace / Entra-Azure-M365 / Monitoring / Reporting / Public cmdlets / Core / GUI) or search by name, then select a function to read its full source along with the file path and line number it lives at, plus a Copy button. This lets an operator verify exactly what any scan is doing without leaving the console; open directly with Show-Guerrilla -StartOn Source. Also: the GUI now leaves Google Workspace "Email Security" unchecked by default in the category picker (opt-in — the noisier/slower set); every other Workspace category stays checked and the "All" toggle reflects the partial selection. AD and Entra/M365 category defaults are unchanged. v2.6.0: The Google Workspace (Fortification) report is now far more actionable, with the Authentication category built out as the first pass. (1) Affected accounts are now LISTED: when a check flags specific accounts (users without 2SV enforced/enrolled, super admins not enrolled in 2SV, stale or recovery-enabled super admins) the report lists the actual accounts beneath the finding (capped at 25 with a "+N more" indicator) instead of only a count; the renderer also auto-surfaces affected-object lists that existing checks already capture, so every category benefits. (2) "Fix in Admin Console" deep-links now appear on EVERY actionable finding in the per-category detail tables, not just the Critical/High priority table. (3) "Why this is unsafe" reference articles: each Authentication check now links to an authoritative source explaining why the misconfiguration is dangerous (Google Workspace official docs where available, supplemented by NIST/CIS/MITRE and reputable security research) via new referenceUrl/referenceTitle fields — all 13 URLs verified to resolve. The rendering changes apply to all Google Workspace categories now; the curated reference articles currently cover the 13 Authentication checks and will be extended to the remaining categories. See CHANGELOG.md for v2.5.2 and earlier.'
        }
    }
}
