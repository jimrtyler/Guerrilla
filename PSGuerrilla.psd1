@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.2.1'
    GUID              = 'f7a3b2c1-4d5e-6f78-9a0b-1c2d3e4f5a6b'
    Author            = 'Jim Tyler, Microsoft MVP'
    CompanyName       = 'Jim Tyler'
    Copyright         = '(c) 2026 Jim Tyler. All rights reserved.'
    Description       = 'Security assessment, threat detection, and continuous monitoring module for Google Workspace, Active Directory, and Microsoft cloud environments. Includes Google Workspace compromise assessment with 23 detection signals, Active Directory reconnaissance (203 security checks across 14 categories including NTLM-relay preconditions, Tier-0 hygiene, telemetry posture, and adversary tradecraft indicators), Entra ID / Azure / Intune / M365 infiltration audit (159 checks), and continuous monitoring across all four theaters (Entra ID sign-in risk, AD baseline monitoring, M365 audit log monitoring). Supports alerting via SendGrid, Mailgun, Twilio SMS, Teams, Slack, generic webhooks, PagerDuty, Pushover, Syslog (CEF/LEEF), and Windows Event Log.'
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
            Tags       = @('GoogleWorkspace', 'ActiveDirectory', 'EntraID', 'AzureAD', 'Intune', 'M365', 'Security', 'CompromiseAssessment', 'IncidentResponse', 'ThreatDetection', 'ADSecurity', 'CloudSecurity', 'NTLMRelay', 'TierZero', 'PSGuerrilla')
            LicenseUri = 'https://creativecommons.org/licenses/by/4.0/'
            ProjectUri = 'https://guerrilla.army'
            ReleaseNotes = 'v2.2.1 (metadata-only): ProjectUri now points at https://guerrilla.army (canonical project site + configuration wizard). Source remains at https://github.com/jimrtyler/PSGuerrilla. v2.2.0: 28 new AD checks across 4 new categories — Network (NTLM-relay preconditions: LDAP/SMB signing, LLMNR/NetBIOS/WPAD, IPv6 mitm6, Spooler/WebClient), TierZero (AAD Connect MSOL_ audit, tier-bleed by service-account name pattern for Veeam/vCenter/SCCM/SQL), Logging (Advanced Audit Policy, PowerShell Script Block/Module Logging, 4688 cmdline, Defender Tamper Protection, WEF, Sysmon), Tradecraft (GPP cpassword scan, DCShadow indicator, stale BitLocker keys, RODC PRP). Plus: cross-platform data paths via Get-PSGuerrillaDataRoot, Set-Safehouse asks ''which environments?'' first, banner suppressed in non-interactive sessions, SupportsShouldProcess on state-mutating cmdlets, theater-disambiguating aliases (Invoke-WorkspaceRecon/ADRecon/CloudRecon), score no longer inflates for missing categories, atomic state writes, 30+ bug fixes. Total checks: 459.'
        }
    }
}
