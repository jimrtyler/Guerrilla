@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.8.1'
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
            ReleaseNotes = 'v2.8.1 (patch): Fix Show-Guerrilla GUI Entra/Azure/M365 (Infiltration) scans appearing to HANG — the scan completed but the OnComplete callback called the module-private Get-PSGuerrillaDataRoot, which is not resolvable inside a GetNewClosure() closure, so the callback threw before resetting the UI and the progress bar kept spinning. (AD/Workspace were unaffected because their results carry HtmlReportPath and skipped that branch.) The callback now uses the captured $session.ReportsDir, and Invoke-Infiltration now returns HtmlReportPath like the other theaters so the GUI opens the exact report. Also fixed poor GUI contrast: the Report style / Settings dropdown popups used WPF''s default light theme, making the near-white item text invisible — ComboBoxItem now has an explicit dark template (light text, amber highlight with dark text) — and the left-nav buttons were brightened for legibility. v2.8.0: Report themes + white-label branding. (1) Reports can now be generated in three visual STYLES, picked per scan from the Operations tab''s new "Report style" dropdown (or a new -ReportStyle parameter on Invoke-Reconnaissance / Invoke-Fortification / Invoke-Infiltration): Guerrilla (default, unchanged dark tactical theme with FORTRESS/EXPOSED FLANK/OVERRUN labels), Professional (light white corporate theme, sans-serif, plain risk-based labels Secure/Hardened/Moderate Risk/Elevated Risk/High Risk/Critical Risk), and Slate (modern dark dashboard, plain labels). A shared theming engine drives a common palette of CSS variables so all three audit reports look consistent per style. (2) A new "Branding" tab in Show-Guerrilla white-labels reports with firm name, logo, consultant name/email, client name, and a confidentiality banner (rendered in the report header). Branding is saved to config and applied on every subsequent scan. The "Generated with PSGuerrilla by Jim Tyler, Microsoft MVP" footer attribution is ALWAYS preserved regardless of theme or branding. Default look is unchanged (existing scans render identically as Guerrilla); themes/branding currently cover the three audit reports, with the Campaign roll-up and monitoring reports to follow. v2.7.0: The Show-Guerrilla GUI gains an "Inspector" tab — a built-in source browser for every scan, check, and helper function in the module (801 today). Filter by area (Active Directory / Google Workspace / Entra-Azure-M365 / Monitoring / Reporting / Public cmdlets / Core / GUI) or search by name, then select a function to read its full source along with the file path and line number it lives at, plus a Copy button. This lets an operator verify exactly what any scan is doing without leaving the console; open directly with Show-Guerrilla -StartOn Source. Also: the GUI now leaves Google Workspace "Email Security" unchecked by default in the category picker (opt-in — the noisier/slower set); every other Workspace category stays checked and the "All" toggle reflects the partial selection. AD and Entra/M365 category defaults are unchanged. v2.6.0: The Google Workspace (Fortification) report is now far more actionable, with the Authentication category built out as the first pass. (1) Affected accounts are now LISTED: when a check flags specific accounts (users without 2SV enforced/enrolled, super admins not enrolled in 2SV, stale or recovery-enabled super admins) the report lists the actual accounts beneath the finding (capped at 25 with a "+N more" indicator) instead of only a count; the renderer also auto-surfaces affected-object lists that existing checks already capture, so every category benefits. (2) "Fix in Admin Console" deep-links now appear on EVERY actionable finding in the per-category detail tables, not just the Critical/High priority table. (3) "Why this is unsafe" reference articles: each Authentication check now links to an authoritative source explaining why the misconfiguration is dangerous (Google Workspace official docs where available, supplemented by NIST/CIS/MITRE and reputable security research) via new referenceUrl/referenceTitle fields — all 13 URLs verified to resolve. The rendering changes apply to all Google Workspace categories now; the curated reference articles currently cover the 13 Authentication checks and will be extended to the remaining categories. v2.5.2 (patch): Fix the sample-report generator (Samples\Generate-SampleReports.ps1) undercounting Active Directory checks as 175 instead of the real 203. Its $adFiles list was hardcoded to only 10 of the 14 AD check-definition files, silently omitting ADLoggingChecks, ADNetworkChecks, ADTradecraftChecks and TierZeroChecks (28 checks added in v2.2.0). The generator now discovers every AD check file automatically (case-sensitive match so the Google Workspace AdminManagementChecks.json is not captured), so new categories can never silently drop out again, and regenerated the committed Samples\Reconnaissance-AllFail.html now shows all 203. This was purely a sample/count bug — all 203 AD checks were always implemented and run by Invoke-Reconnaissance (verified 1:1 between the 203 JSON check IDs and the 203 Test-Recon* dispatch functions); the advertised "203 AD checks / 459 total" was correct. v2.5.1 (patch): The Active Directory report''s "Findings by Priority" table now includes a Remediation column (it previously showed only ID/Severity/Status/Category/Check/Finding, with remediation buried in the per-category detail below). Falls back to the recommended value when a check has no explicit remediation steps. Other theaters already surfaced remediation in their findings tables. Regenerated the committed sample reports. v2.5.0: Scans now auto-resolve credentials from the safehouse vault. Previously Invoke-Fortification / Invoke-Infiltration / Invoke-Campaign only read the vault when given a -ConfigFile (guerrilla-config.json) mission file; an interactive Set-Safehouse setup (no config file) could not scan and failed with "ServiceAccountKeyPath is required" / "TenantId is required" — including from the Show-Guerrilla GUI. These cmdlets now fall back, as a last resort after parameters and config.json, to the default vault keys Set-Safehouse stores (GUERRILLA_GWS_SA + GUERRILLA_GWS_SA_ADMIN_EMAIL, GUERRILLA_GRAPH_TENANT/CLIENTID/SECRET) via a new graceful Get-SafehouseSecret helper. Added a -VaultName parameter (default PSGuerrilla) to Invoke-Fortification / Invoke-Infiltration / Invoke-Campaign, and the GUI now passes the active vault name so a populated safehouse "just works" for every theater. AD was already covered by its Kerberos fallback. See CHANGELOG.md for v2.4.4 and earlier.'
        }
    }
}
