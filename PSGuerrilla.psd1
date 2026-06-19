@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.11.0'
    GUID              = 'f7a3b2c1-4d5e-6f78-9a0b-1c2d3e4f5a6b'
    Author            = 'Jim Tyler, Microsoft MVP'
    CompanyName       = 'Jim Tyler'
    Copyright         = '(c) 2026 Jim Tyler. All rights reserved.'
    Description       = 'Security assessment, threat detection, and continuous monitoring module for Google Workspace, Active Directory, and Microsoft cloud environments. Includes Google Workspace compromise assessment with 23 detection signals, Active Directory reconnaissance (204 security checks across 15 categories including a Tier-0 attack-path analysis, NTLM-relay preconditions, Tier-0 hygiene, telemetry posture, and adversary tradecraft indicators), Entra ID / Azure / Intune / M365 infiltration audit (158 checks), and continuous monitoring across all four theaters (Entra ID sign-in risk, AD baseline monitoring, M365 audit log monitoring). Supports alerting via SendGrid, Mailgun, Twilio SMS, Teams, Slack, generic webhooks, PagerDuty, Pushover, Syslog (CEF/LEEF), and Windows Event Log.'
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
            ReleaseNotes = 'v2.11.0: GWS-1 complete - the v2.10.8 Cloud Identity policy collector is now wired into real checks. 26 placeholder checks across 7 Fortification categories now evaluate live policy instead of an always-WARN verify-in-Admin-Console: Authentication (AUTH-003/004/005/006/008/011), Email (EMAIL-013/015/016/017/020/021), Collaboration (COLLAB-001/002/003/005/006), Drive (DRIVE-001/004/008), OAuth (OAUTH-001/006/007), Logging (LOG-004/005), Admin (ADMIN-012). New shape-immune helper Resolve-GooglePolicyValue normalizes the lookup, returns per-OU field values, distinguishes API-unavailable (SKIP) from policy-absent, and grades weakest-OU-wins. Checks with no policy-API equivalent (mobile/MDM, mail routing/compliance, several sharing sub-settings) stay documented manual-verify; an unrecognized enum value grades WARN, never PASS. Check counts unchanged (204/98/158). 9 regression suites green. v2.10.8 (patch): (1) GWS-1 enabling infrastructure — a new Get-GoogleCloudIdentityPolicies collector pulls the full Workspace settings set from the Cloud Identity Policy API (policies.list, paginated), indexes it by setting type, and exposes a Get-GooglePolicySetting lookup helper; wired into Get-FortificationData as CloudIdentityPolicies. This is the data layer that turns the ~60 "verify in Admin Console" placeholder checks (Gmail/Drive/Auth/Chat/Meet/Calendar/DLP/service-status) into real ones — check conversions follow once live value shapes are confirmed. The cloud-identity.policies.readonly scope is requested in an isolated token so a tenant that hasn''t delegated it degrades gracefully (collector returns null, dependent checks SKIP) instead of breaking the whole Google scan with unauthorized_client. (2) Chrome-policy collection no longer hardcodes a tenant-specific org-unit id — it resolves the customer root OU dynamically and skips gracefully if it can''t (was a bug for every other tenant). Teams /appCatalogs/teamsApps needs no change (the collector already uses $filter, not $top). Test: verify-gws1-policy-collector.ps1 (8/8). v2.10.7 (patch): (1) Spectre.Console console rendering restored — when PwshSpectreConsole is installed the bar charts and tables were calling Spectre.Console C# extension methods as instance methods ($chart.AddItem, $table.AddRow, $table.BorderColor, $tree.AddNode), which PowerShell cannot do, so every non-Quiet scan spammed "does not contain a method named …" and the chart/table/tree rendered blank. They now use the correct static extension classes (BarChartExtensions::AddItem, TableExtensions::AddRow, HasTreeNodeExtensions::AddNode) and set the border via BorderStyle, so the category bar charts, Findings-by-severity chart, and Priority-findings table render again; each enhanced renderer also falls back to the text renderer on error so a future Spectre API change degrades gracefully. (2) Test mode now uses a zeroed report-filename timestamp (…_report_00000000_000000.… / …-00000000-000000.…) so demo/sample output is fully deterministic, completing the test-mode determinism from v2.10.5 (real scans keep the real timestamp). v2.10.6 (docs): Endpoint-protection guidance + a Graph scope. README now documents — prominently in Requirements + a Troubleshooting section — that Microsoft Defender / EDR can false-positive on PSGuerrilla''s AD attack-detection files and block read access, so Import-Module fails with "Access to the path …Invoke-ADAclDelegationChecks.ps1 is denied"; fix is a Defender path exclusion (Add-MpPreference -ExclusionPath) or a Protection-history Allow. This is the most common first-run failure on a hardened host. Also added AppCatalog.Read.All to the documented Entra app scopes (Teams app-catalog collection), plus Troubleshooting entries for the Teams 403 and the "No accessible Azure subscriptions" SKIP. Surfaced by the v2.10.4 live validation. v2.10.5 (patch): Test mode renders deterministic (zeroed) timestamps. With -TestMode (or the GUI "Test mode" checkbox) all console timestamps read 00:00 / 00:00:00 instead of the live clock, so demo/sample/screenshot output is stable — the operation header shows "0000 UTC" (date kept real), Write-ProgressLine shows "[0000 UTC]", and the GUI Operations log prefixes each line with "[00:00:00]". Driven by a self-healing module flag the audit cmdlets set per run (a real run resets it). Report filenames keep the real timestamp (zeroing would collide). v2.10.4 (patch): Backlog sweep — code-only gaps that don''t need a live tenant/DC. (GUI-1) The Safehouse tab "Add Credential" button now opens a real dark-themed WPF dialog (not a redirect-to-terminal stub) that stores Microsoft Entra/Graph (tenant/client/secret + optional expiry) or Google Workspace (service-account JSON via file picker + delegated-admin email) credentials straight into the vault and refreshes the grid, with GUID/email/SA-JSON validation before any write (non-interactive Save-SafehouseCredentialSet; builder/validator unit-tested; window render-verified). (ENT-5) Azure IAM checks now distinguish "no ARM access / no accessible subscriptions" — a single clear SKIP pointing at "grant the app Reader at the root management group" — from "no resources of this type found" (WARN, only when subscriptions exist). Previously every AZIAM check emitted a misleading "No X found in scanned subscriptions" WARN even with zero Azure access. (ENT-4 partial) Invoke-Infiltration collapses the ~40 individual "workload module not connected" SKIP lines into one pre-flight banner (EXO/Teams/SharePoint/Power Platform); net-new workload checks still need live validation. (DSInternals) One pre-flight note that the 5 password-hash checks (ADPWD-010..014) will SKIP, instead of five identical lines. Regression tests: verify-ent5-azure-skip.ps1 (7/7), verify-gui-credential-entry.ps1 (15/15); check counts unchanged (204/98/158). See CHANGELOG.md for v2.10.3 and earlier.'
        }
    }
}
