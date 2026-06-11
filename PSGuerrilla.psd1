@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.4.0'
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
            ReleaseNotes = 'v2.4.0 (audit release): Show-Guerrilla scans now actually deliver results — the async DispatcherTimer handler was not a closure so completion callbacks could never fire, and results were read from EndInvoke (always empty with the explicit-output BeginInvoke overload) instead of the output collection; a stray non-terminating error mid-scan no longer discards a successful run. Security: vault-staged Google service-account keys are now removed from %TEMP% via try/finally in Invoke-Recon/Invoke-Fortification/Invoke-Campaign (previously the private key lingered after every vault-based scan); Set-Safehouse offers to delete the original key file only AFTER the vault write succeeds; Send-SignalSyslog escapes CEF/LEEF metacharacters and flattens CR/LF/tab in threat-derived fields (log-forgery hardening); Get-Safehouse again masks plaintext secrets found in config.json unless -ShowSecrets. Reliability: every Invoke-RestMethod call now has an explicit timeout (30s alert senders/token/geo, 120s Graph/ARM/Google API wrappers) so a hung endpoint cannot stall a patrol; Save-TheaterState writes atomically; Register-Patrol escapes quotes in generated runner paths; Show-Guerrilla validates STA. Cleanup: ~30 dead assignments removed, shadowed automatic variables ($error, $matches) renamed, stale Set-Safehouse/Get-Safehouse tests rewritten against the vault API (suite: 453 passing). v2.3.1 (patch): Fix Show-Guerrilla scan dispatch — PowerShell.BeginInvoke($null, $output) failed with "Cannot find an overload" because the typed PSDataCollection<T> overload can''t infer the generic from $null. Now uses an explicit empty input collection. Also: banner now reads the version from the manifest instead of a hardcoded string, so it can''t drift again. v2.3.0: New Show-Guerrilla cmdlet — a WPF Operations Console with five tabs for managing the safehouse, running scans, browsing reports, and configuring patrols. Windows-only; the CLI continues to work everywhere else. v2.2.1: ProjectUri now points at https://guerrilla.army. v2.2.0: 28 new AD checks across 4 new categories — Network (NTLM-relay preconditions: LDAP/SMB signing, LLMNR/NetBIOS/WPAD, IPv6 mitm6, Spooler/WebClient), TierZero (AAD Connect MSOL_ audit, tier-bleed by service-account name pattern for Veeam/vCenter/SCCM/SQL), Logging (Advanced Audit Policy, PowerShell Script Block/Module Logging, 4688 cmdline, Defender Tamper Protection, WEF, Sysmon), Tradecraft (GPP cpassword scan, DCShadow indicator, stale BitLocker keys, RODC PRP). Plus: cross-platform data paths via Get-PSGuerrillaDataRoot, Set-Safehouse asks ''which environments?'' first, banner suppressed in non-interactive sessions, SupportsShouldProcess on state-mutating cmdlets, theater-disambiguating aliases (Invoke-WorkspaceRecon/ADRecon/CloudRecon), score no longer inflates for missing categories, atomic state writes, 30+ bug fixes. Total checks: 459.'
        }
    }
}
