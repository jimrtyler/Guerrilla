@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.6.0'
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
            ReleaseNotes = 'v2.6.0: The Google Workspace (Fortification) report is now far more actionable, with the Authentication category built out as the first pass. (1) Affected accounts are now LISTED: when a check flags specific accounts (users without 2SV enforced/enrolled, super admins not enrolled in 2SV, stale or recovery-enabled super admins) the report lists the actual accounts beneath the finding (capped at 25 with a "+N more" indicator) instead of only a count; the renderer also auto-surfaces affected-object lists that existing checks already capture, so every category benefits. (2) "Fix in Admin Console" deep-links now appear on EVERY actionable finding in the per-category detail tables, not just the Critical/High priority table. (3) "Why this is unsafe" reference articles: each Authentication check now links to an authoritative source explaining why the misconfiguration is dangerous (Google Workspace official docs where available, supplemented by NIST/CIS/MITRE and reputable security research) via new referenceUrl/referenceTitle fields — all 13 URLs verified to resolve. The rendering changes apply to all Google Workspace categories now; the curated reference articles currently cover the 13 Authentication checks and will be extended to the remaining categories. v2.5.2 (patch): Fix the sample-report generator (Samples\Generate-SampleReports.ps1) undercounting Active Directory checks as 175 instead of the real 203. Its $adFiles list was hardcoded to only 10 of the 14 AD check-definition files, silently omitting ADLoggingChecks, ADNetworkChecks, ADTradecraftChecks and TierZeroChecks (28 checks added in v2.2.0). The generator now discovers every AD check file automatically (case-sensitive match so the Google Workspace AdminManagementChecks.json is not captured), so new categories can never silently drop out again, and regenerated the committed Samples\Reconnaissance-AllFail.html now shows all 203. This was purely a sample/count bug — all 203 AD checks were always implemented and run by Invoke-Reconnaissance (verified 1:1 between the 203 JSON check IDs and the 203 Test-Recon* dispatch functions); the advertised "203 AD checks / 459 total" was correct. v2.5.1 (patch): The Active Directory report''s "Findings by Priority" table now includes a Remediation column (it previously showed only ID/Severity/Status/Category/Check/Finding, with remediation buried in the per-category detail below). Falls back to the recommended value when a check has no explicit remediation steps. Other theaters already surfaced remediation in their findings tables. Regenerated the committed sample reports. v2.5.0: Scans now auto-resolve credentials from the safehouse vault. Previously Invoke-Fortification / Invoke-Infiltration / Invoke-Campaign only read the vault when given a -ConfigFile (guerrilla-config.json) mission file; an interactive Set-Safehouse setup (no config file) could not scan and failed with "ServiceAccountKeyPath is required" / "TenantId is required" — including from the Show-Guerrilla GUI. These cmdlets now fall back, as a last resort after parameters and config.json, to the default vault keys Set-Safehouse stores (GUERRILLA_GWS_SA + GUERRILLA_GWS_SA_ADMIN_EMAIL, GUERRILLA_GRAPH_TENANT/CLIENTID/SECRET) via a new graceful Get-SafehouseSecret helper. Added a -VaultName parameter (default PSGuerrilla) to Invoke-Fortification / Invoke-Infiltration / Invoke-Campaign, and the GUI now passes the active vault name so a populated safehouse "just works" for every theater. AD was already covered by its Kerberos fallback. v2.4.4 (patch): Fix Show-Guerrilla Google Workspace / Entra / Campaign scans failing with "A parameter cannot be found that matches parameter name ''ScanMode''." The GUI built its scan arguments from hardcoded per-cmdlet name lists that did not match the cmdlets'' real parameters — Invoke-Fortification / Invoke-Infiltration / Invoke-Reconnaissance have no -ScanMode, and Invoke-Campaign has no -Categories or -NoReports. The GUI now inspects the target cmdlet''s actual parameter set with (Get-Command).Parameters and only passes options the cmdlet declares, so every theater binds cleanly. (AD scans already worked because Invoke-Reconnaissance happened not to be on the -ScanMode list.) v2.4.3 (patch): Fix Show-Guerrilla scans failing immediately with "The term ''Invoke-Reconnaissance'' is not recognized." The background worker runspace was never actually importing PSGuerrilla: it relied on InitialSessionState.ImportPSModule() with a full .psd1 PATH, which expects a module NAME and silently no-ops on a path. Compounding it, the scan action scriptblock was marshalled into the worker as a live scriptblock object — which keeps affinity to the GUI runspace that created it, so even after a correct import the cmdlet would not resolve (and could corrupt the engine). The worker now Import-Modules the manifest explicitly (-ErrorAction Stop, -Verbose:$false so the import does not flood the log) and rehydrates the action from source text via [scriptblock]::Create() so it binds to the worker runspace. No GUI scan could run before this fix. v2.4.2 (patch): Show-Guerrilla scan log now shows live, readable progress. The runspace''s Write-ProgressLine output (per-phase/per-collector status like "Connecting to Active Directory", "Enumerating certificate templates") is emitted as several Write-Host -NoNewline fragments carrying ANSI colour codes — the GUI now strips the ANSI escapes and reassembles the fragments into clean whole lines instead of dropping or garbling them. Also drains the Warning stream and adds a "... still working (Ns elapsed)" heartbeat so long, quiet collection phases no longer look hung. Footer version now reads from the manifest instead of a hardcoded "v2.3.0". v2.4.1 (patch): Fix Show-Guerrilla "Run Scan" crashing with "The expression after ''&'' ... was not valid" when a scan completed or failed. The OnLog/OnComplete/OnError callbacks were built with GetNewClosure() inside the Run-button click handler, which snapshots only that handler''s own locals — not the function-scope helpers ($appendLog/$resetOperationsUI/$session/$brushes) they reference — so those resolved to $null when the DispatcherTimer fired the callbacks. (Latent since 2.3.0; only surfaced in 2.4.0 once the async completion path was fixed to actually fire callbacks.) The helpers are now localized into the handler scope before the closures are built. Also hardened Invoke-GuerrillaGuiAsync so a throwing callback is downgraded to a warning instead of escaping the timer tick and wedging the window. v2.4.0 (audit release): Show-Guerrilla scans now actually deliver results — the async DispatcherTimer handler was not a closure so completion callbacks could never fire, and results were read from EndInvoke (always empty with the explicit-output BeginInvoke overload) instead of the output collection; a stray non-terminating error mid-scan no longer discards a successful run. Security: vault-staged Google service-account keys are now removed from %TEMP% via try/finally in Invoke-Recon/Invoke-Fortification/Invoke-Campaign (previously the private key lingered after every vault-based scan); Set-Safehouse offers to delete the original key file only AFTER the vault write succeeds; Send-SignalSyslog escapes CEF/LEEF metacharacters and flattens CR/LF/tab in threat-derived fields (log-forgery hardening); Get-Safehouse again masks plaintext secrets found in config.json unless -ShowSecrets. Reliability: every Invoke-RestMethod call now has an explicit timeout (30s alert senders/token/geo, 120s Graph/ARM/Google API wrappers) so a hung endpoint cannot stall a patrol; Save-TheaterState writes atomically; Register-Patrol escapes quotes in generated runner paths; Show-Guerrilla validates STA. Cleanup: ~30 dead assignments removed, shadowed automatic variables ($error, $matches) renamed, stale Set-Safehouse/Get-Safehouse tests rewritten against the vault API (suite: 453 passing). v2.3.1 (patch): Fix Show-Guerrilla scan dispatch — PowerShell.BeginInvoke($null, $output) failed with "Cannot find an overload" because the typed PSDataCollection<T> overload can''t infer the generic from $null. Now uses an explicit empty input collection. Also: banner now reads the version from the manifest instead of a hardcoded string, so it can''t drift again. v2.3.0: New Show-Guerrilla cmdlet — a WPF Operations Console with five tabs for managing the safehouse, running scans, browsing reports, and configuring patrols. Windows-only; the CLI continues to work everywhere else. v2.2.1: ProjectUri now points at https://guerrilla.army. v2.2.0: 28 new AD checks across 4 new categories — Network (NTLM-relay preconditions: LDAP/SMB signing, LLMNR/NetBIOS/WPAD, IPv6 mitm6, Spooler/WebClient), TierZero (AAD Connect MSOL_ audit, tier-bleed by service-account name pattern for Veeam/vCenter/SCCM/SQL), Logging (Advanced Audit Policy, PowerShell Script Block/Module Logging, 4688 cmdline, Defender Tamper Protection, WEF, Sysmon), Tradecraft (GPP cpassword scan, DCShadow indicator, stale BitLocker keys, RODC PRP). Plus: cross-platform data paths via Get-PSGuerrillaDataRoot, Set-Safehouse asks ''which environments?'' first, banner suppressed in non-interactive sessions, SupportsShouldProcess on state-mutating cmdlets, theater-disambiguating aliases (Invoke-WorkspaceRecon/ADRecon/CloudRecon), score no longer inflates for missing categories, atomic state writes, 30+ bug fixes. Total checks: 459.'
        }
    }
}
