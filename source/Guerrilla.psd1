@{
    RootModule        = 'Guerrilla.psm1'
    ModuleVersion     = '2.48.0'
    GUID              = 'f7a3b2c1-4d5e-6f78-9a0b-1c2d3e4f5a6b'
    Author            = 'Jim Tyler, Microsoft MVP'
    CompanyName       = 'Jim Tyler'
    Copyright         = '(c) 2026 Jim Tyler. All rights reserved.'
    Description       = 'Agentless, read-only, point-in-time security assessment for PowerShell 7 across three platforms: on-premises Active Directory (211 checks across 15 categories including transitive Tier-0 attack-path analysis, certificate-services ESC1-ESC16, NTLM-relay preconditions, telemetry posture, and adversary tradecraft indicators), the Entra ID / Azure / Intune / M365 identity plane (257 checks including a full 44-control EIDSCA baseline, conditional access, PIM, application and OAuth governance, Exchange Online, SharePoint, Teams, Defender, and entitlement-management hygiene), and Google Workspace (168 checks aligned to the CISA SCuBA baselines, plus the first K12 candidate baseline checks with student-OU scoping). 636 checks total, each mapped to NIST 800-53, MITRE ATT&CK, CIS, EIDSCA, and CISA SCuBA where applicable and carrying a CISA Zero Trust pillar and weight, and each verdict validated by a golden-fixture test (1,829 fixtures). Every run is recorded locally and compared against your previous run: the report opens with what changed, including newly failing checks, confirmed remediations, and any check that went dark. Local history on your machine, no accounts, no telemetry.'
    PowerShellVersion = '7.0'
    FunctionsToExport = @(
        'Set-Safehouse'
        'Test-Safehouse'
        'Get-Safehouse'
        'Invoke-GWSAudit'
        'Invoke-ADAudit'
        'Invoke-EntraAudit'
        # Deprecated wrappers for the renamed audits; removed in the next major version.
        'Invoke-Fortification'
        'Invoke-Reconnaissance'
        'Invoke-Infiltration'
        'Invoke-Campaign'
        'Get-GuerrillaScore'
        'Get-GuerrillaMaturity'
        'Get-QuickWins'
        'Get-ComplianceCrosswalk'
        'Test-GuerrillaConditionalAccess'
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
        'Export-BloodHoundData'
        'Export-GuerrillaJUnit'
        'Get-GuerrillaCIGate'
        'Show-Guerrilla'
        'Get-ZeroTrustScore'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @(
        'Set-ReconConfig'
        'Get-ReconConfig'
        'Invoke-ADRecon'
        'Invoke-CloudRecon'
    )
    FormatsToProcess   = @('Guerrilla.format.ps1xml')
    PrivateData = @{
        PSData = @{
            Tags       = @('GoogleWorkspace', 'ActiveDirectory', 'EntraID', 'AzureAD', 'Intune', 'M365', 'Security', 'SecurityAssessment', 'ADSecurity', 'CloudSecurity', 'NTLMRelay', 'TierZero', 'GUI', 'WPF', 'Guerrilla')
            LicenseUri = 'https://creativecommons.org/licenses/by/4.0/'
            ProjectUri = 'https://guerrilla.army'
            ReleaseNotes = 'Guerrilla (formerly PSGuerrilla). v2.47.0: The platform audits are now named what they are. Invoke-ADAudit (Active Directory), Invoke-EntraAudit (Entra ID / Azure / Intune / M365), and Invoke-GWSAudit (Google Workspace) replace Invoke-Reconnaissance, Invoke-Infiltration, and Invoke-Fortification; the old names keep working as deprecated wrappers that warn once per session and will be removed in the next major version. The GitHub Action platform input takes AD, Entra, GWS, or Campaign, with the old values accepted and mapped. Report headings, the unified dashboard, and the machine-readable test-summary artifact now name platforms Active Directory, Entra ID / M365, and Google Workspace, and the artifact schema is v2 with a platform field per check. Delta state saved by earlier versions is still read via legacy-name fallbacks, so the first post-upgrade run keeps its baseline. The report now opens with what changed since your last run: every completed assessment is recorded to a local, per-user run history (verdicts, evidence hashes, and scores; never raw evidence values; no accounts, no telemetry, no network), and the next HTML report leads with newly failing checks, lost visibility (a check that was assessed before and is Not Assessed now is called out, never rendered as no change), confirmed remediations, and the score delta overall and per Zero Trust pillar. Invoke-Campaign gains its first all-platforms delta through the same single comparison mechanism, covered by golden fixtures. Score tier labels are now a plain risk ladder, Low Risk through Critical Risk, one label set everywhere in console output, HTML reports, and JSON exports; score thresholds and colors are unchanged. No check verdict logic changed. See CHANGELOG.md for earlier releases.'
        }
    }
}
