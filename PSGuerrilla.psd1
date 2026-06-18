@{
    RootModule        = 'PSGuerrilla.psm1'
    ModuleVersion     = '2.10.3'
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
            ReleaseNotes = 'v2.10.3 (patch): Fixes from the v2.10.1 attack-path validation + the v2.10.2 GUI re-check. (1) ADPATH-001 false positives eliminated — the attack-path engine was reporting default infrastructure/admin principals (Domain Controllers group, Enterprise Domain Controllers, RODCs, Enterprise Read-only DCs, Schema Admins) as Tier-0 escalation paths even though they hold replication/control rights by AD design. A centralized allowlist (Test-DefaultControlPrincipal, matched by forge-proof well-known SID/RID, not locale-dependent names) now excludes them; in the reporter''s live domain this drops the headline from "32 paths, all non-privileged" to the ~7 genuine ones. (2) SourceIsPrivileged is now correct (was always false, so the highest-risk sort/count was meaningless) — true for default privileged principals incl. operator groups and Tier-0 members. (3) Azure AD Connect MSOL_* sync accounts have real DCSync rights but by design (tracked by ADTIER-001); they''re now flagged Expected, kept out of the non-privileged count, and reported separately rather than as surprise escalations. (4) DCSync/ACL-delegation checks share the same allowlist — Test-SafeAdminSid (ADPRIV-028, ADACL-010/015/016) delegates to Test-DefaultControlPrincipal (a strict superset of its old list), closing the residual where Enterprise Read-only Domain Controllers (498) was reported as a non-default DCSync principal. (5) GUI-2 ComboBox selection box fixed for real — the closed box rendered with the system''s light button chrome (the nested ToggleButton''s TemplateBinding bound to its own unset Background, not the ComboBox''s), so near-white selection text read as blank/faint; the box fill is now hardcoded dark, verified by rendering the control off-screen to a bitmap and inspecting pixels. Regression tests added (Tests/verify-adpath-fix.ps1, 19/19). v2.10.2 (patch): GUI + safehouse audit fixes from the live GUI validation. (SH-1) Set-Safehouse -ConfigFile now also persists the Google Workspace delegated-admin email (and the Pushover/Twilio providers, previously dropped) into the vault — before this, a config-file setup followed by a vault-only scan (GUI / scheduled patrol, no -ConfigFile) failed with "AdminEmail is required." (SH-2) Get-Safehouse, Set-Safehouse -Status and the GUI Safehouse tab now reconcile vault metadata with the REAL secret store (Get-SecretInfo), so present-but-unregistered secrets (admin email, Pushover, legacy keys) are no longer hidden — a "are my creds loaded?" blind spot. (SH-3) Status now plainly discloses the no-master-password unattended mode instead of just labeling it "DPAPI". (GUI-1) The Safehouse "Test All" button now runs the real Test-Safehouse connectivity engine asynchronously and shows per-check results, instead of redirecting to the terminal. (GUI-2) ComboBoxes (Report style / Profile / Min alert level) now show their selected value when collapsed — a full dark control template themes the selection box. (GUI-4) A single-instance guard stops a second GUI window from clobbering shared config/state. (GUI-5) Rotate/Remove with no row selected now prompts to pick one. Regression tests added (Tests/verify-safehouse-fixes.ps1, 10/10). v2.10.1: Attack-path analysis now also flags GROUP-NESTING pivots — ADPATH-001 reports non-default groups nested inside a Tier-0 group (Domain/Enterprise/Schema Admins, Administrators, operator groups) as escalation pivots (controlling such a group, or being added to it, confers the Tier-0 group''s privileges). Uses the already-collected recursive privileged-group membership; well-known Tier-0 groups are excluded so only custom nesting is flagged. Each path now carries a PathType (Object control / Group nesting). v2.10.0: AD attack-path analysis. Invoke-Reconnaissance gains a new "AttackPath" category (check ADPATH-001) that turns the flat dangerous-ACL findings into named privilege-escalation PATHS to Tier-0, each annotated with the concrete takeover technique it enables. v1 models the highest-value edge class — non-default control (GenericAll/WriteDacl/WriteOwner/replication rights) over a Tier-0 object (the domain root, AdminSDHolder, the Domain Controllers OU, the GPO/Configuration/Schema containers), a one-hop path to Domain Admin equivalence — and surfaces paths from genuinely non-privileged principals first as the highest risk. Built on already-collected ACL + privileged-group data (no new collection); runs under -Categories All or ACLDelegation/AttackPath. AD coverage is now 204 checks across 15 categories. This is the first increment of the roadmap''s graph-based attack-path gap; full domain-wide TRANSITIVE path computation (low-priv user through nested-group control to Domain Admins) needs a full-domain ACL collector and is the next step. Regression tests added. v2.9.4 (patch): Fixes from the v2.9.3 live re-validation. (MON-4, regression) Continuous monitoring broke after the first run — Invoke-Surveillance/Invoke-Wiretap succeeded once then threw "Item has already been added" on every subsequent run (silently killing Register-Patrol scheduled monitoring). The scan-history append used `@($state.scanHistory) += @{...}`, which merged hashtable keys once a prior single-entry history reloaded from JSON. Both now build history via a new List-based Add-ScanHistoryEntry helper that always returns a clean array; two-run regression test added. (AD-1b) ADPRIV-028 (DCSync rights) reported instead of always SKIPping: with AD-1 collecting the domain-root DACL, the collector now derives DCSyncAccounts from the dangerous-ACE set (replication GUIDs 1131f6aa/1131f6ad/89e95b76, dropping default Tier-0 principals), completing the DCSync attack-path coverage. (GWS-3, partial) New Invoke-Fortification -Quick skips the slow per-user Gmail crawl (~1.4s/user; ~11min for 500 users) — directory/DNS/OAuth still run, Gmail-dependent EMAIL checks SKIP. Full parallelization deferred (needs live-tenant validation of runspace/token handling). v2.9.3 (patch): More live-validation backlog fixes. (REP-2) Get-ComplianceCrosswalk now exposes the technical frameworks already carried on every check — added NIST-800-53, MITRE-ATTACK and CIS to -Framework, built directly from each finding''s compliance map (previously only the education frameworks FERPA/COPPA/CIPA/NIST-171/STATE-EDTECH were surfaced). (GWS-2) Sampled Google Workspace Gmail checks (EMAIL-009/010/011/022) now append a "SAMPLED N of M active mailboxes" qualifier to a clean PASS so a partial scan can''t read as full coverage. (ENT-3) Invoke-GraphApi treats license-gated 400s (AadPremiumLicenseRequired, e.g. PIM schedule endpoints) as a quiet verbose note instead of an alarming warning on tenants without Entra ID P2. (ADTRADE-002) DCShadow indicator softened Critical->High — an unmatched server object under CN=Sites,CN=Configuration is usually lingering DC metadata, not an attack; the finding now says so and points at whenCreated. Remaining backlog tracked: GWS-1 (Cloud Identity Policy API — blocked until the SA gets the cloud-identity.policies.readonly DWD scope; adding it before delegation would break all Google auth), ENT-4/ENT-5, GWS-3, ADDOM-007. v2.9.2 (patch): Part-2 live-validation fixes (Google Workspace, monitoring, reporting). (1) Continuous monitoring couldn''t use the safehouse vault — Invoke-Surveillance/Invoke-Wiretap never read it, so a vault-only setup failed with "TenantId is required" (and broke Register-Patrol for vault installs). Both now have -VaultName and resolve TenantId/ClientId/ClientSecret from GUERRILLA_GRAPH_* as the last resort, like the audit cmdlets since v2.5.0. (2) Invoke-Surveillance aborted the whole run on the first Graph 403; each collector is now wrapped in try/catch and the risk-detection 403/AadPremiumLicenseRequired case degrades to a clear "requires IdentityRiskEvent.Read.All + IdentityRiskyUser.Read.All + Entra ID P2" skip while sign-in/audit signals still run. (3) Google Workspace Gmail sampling was non-random (Select-Object -First always inspected the same directory-order prefix, so a compromised mailbox later in the list was never seen) — now a random sample. (4) Export-RemediationScripts gained an -OutputPath alias (was the only Export-* using -OutputDirectory). (5) Invoke-Watchtower gained comment-based help. v2.9.1 (patch): Fixes from a live-environment validation pass (production AD domain + Entra tenant). (1) AD ACL/DCSync/GPO-delegation checks were silently dead: Resolve-ADSid referenced three module-scope caches ($script:SidCache/WellKnownSids/WellKnownRids) the .psm1 never initialized, so every ACL read threw and Get-ADObjectACLs swallowed it — turning ADACL-012/014, ADGPO-007/009 and the DCSync check ADPRIV-028 into false SKIPs. Caches now initialized at load (with well-known SID/RID tables) + a guard in Resolve-ADSid; domain-RID lookup gated on S-1-5-21-* SIDs. (2) Tier-0 tier-bleed checks ADTIER-002/003/004/005 ERRORed on CLEAN environments because New-TierBleedFinding''s [Parameter(Mandatory)][array]$Hits rejected an empty collection — the secure (zero-hit) state threw instead of PASS. Added [AllowEmptyCollection()]. (3) Entra password-protection checks EIDAUTH-013/014 falsely reported "settings not found": Get-EntraAuthMethodsData queried /settings (beta-only, 400s on v1.0); now uses v1.0 /groupSettings. (4) Removed a redundant always-400 Graph call (authenticationMethodConfigurations sourced from the parent policy object). (5) Invoke-LdapQuery now treats "no such object" (no AD CS / empty DNS partition) as verbose + empty instead of an alarming warning. Added Tests/verify-core-fixes.ps1. See CHANGELOG.md for v2.9.0 and earlier.'
        }
    }
}
