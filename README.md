# Guerrilla

**By [Jim Tyler](https://github.com/jimrtyler), Microsoft MVP**

Guerrilla is an agentless, read-only security assessment platform for PowerShell 7. It audits three platforms from one tool: on-premises Active Directory, the Entra ID / Azure / Microsoft 365 / Intune identity plane, and Google Workspace. It runs 636 checks, every verdict is backed by a golden-fixture test, and it never installs an agent or writes to the systems it assesses.

[![GitHub](https://img.shields.io/badge/GitHub-jimrtyler-181717?logo=github)](https://github.com/jimrtyler) [![LinkedIn](https://img.shields.io/badge/LinkedIn-jamestyler-0A66C2?logo=linkedin)](https://linkedin.com/in/jamestyler) [![YouTube](https://img.shields.io/badge/YouTube-PowerShellEngineer-FF0000?logo=youtube)](https://youtube.com/@powershellengineer)

```powershell
Install-Module Guerrilla -Scope CurrentUser
Import-Module Guerrilla
```

Full reference, the browsable check catalog, and the fixture framework live at **[guerrilla.army](https://guerrilla.army)**.

> **[View a sample report](./Guerrilla-Sample-Report.html)** to see the scope of what Guerrilla evaluates.

---

## What Guerrilla is

Guerrilla assesses identity security posture across three platforms in a single tool. It is agentless and read-only: it authenticates with the access you already grant it, reads configuration and directory state, and reports. It does not remediate, install software, or change the tenant.

| Platform | Scope | Checks |
|---------|-------|--------|
| **Active Directory** | On-premises Active Directory: privileged groups, delegation and ACLs, Kerberos, certificate services (ESC1 through ESC16), trusts, group policy, NTLM-relay preconditions, Tier-0 hygiene, logging posture, and adversary tradecraft indicators | 211 |
| **Entra ID / M365** | Entra ID, the Azure identity plane, Microsoft 365, and Intune: the full 44-control EIDSCA baseline, conditional access, PIM, application and OAuth governance, Exchange Online, SharePoint, Teams, Defender, hybrid identity, and endpoint compliance | 257 |
| **Google Workspace** | Google Workspace: Gmail, Drive, Chat, Meet, Calendar, Sites, Classroom, Groups, and admin controls, aligned to the CISA SCuBA secure configuration baselines, plus the Guerrilla K12 candidate baseline (student-OU scoped) | 168 |

**Total: 636 checks.** Each check maps to the standards it implements, where applicable, across NIST 800-53, MITRE ATT&CK, CIS Benchmarks, EIDSCA, and the CISA SCuBA baselines. Each carries a CISA Zero Trust Maturity Model pillar and weight, and each produces a `PASS`, `FAIL`, `WARN`, or an honest `Not Assessed`.

> A check that cannot collect its data (missing module, scope, license, or dataset) reports **Not Assessed**. Guerrilla never scores an uncollected control as a pass. Absence of evidence is not compliance.

## Every verdict is tested

The property that distinguishes Guerrilla is that its verdict logic is proven, not asserted. Every check that can be fixtured is validated by a golden fixture: a synthetic tenant state driven through the real check function, asserting the verdict the check must return.

Every fixtured check is held to three assertions:

- Clean input yields **PASS**.
- Known-bad input yields **FAIL** (or `WARN` where the control warns).
- Uncollectable input yields **Not Assessed**.

The suite currently stands at **1,829 golden fixtures across 636 checks, with 0 failures.** CI runs the fixtures, the collector query-contract tests, and the Zero Trust schema test before any release. A red suite blocks publish. The fixture framework, and a walkthrough of how to write one, is documented at [guerrilla.army/docs/validation](https://guerrilla.army/docs/validation).

## Requirements

- **PowerShell 7.0+** ([install guide](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell))
- **Operating system**: Windows (recommended, for DPAPI credential encryption), Linux, or macOS
- [PwshSpectreConsole](https://github.com/ShaunLawrie/PwshSpectreConsole) (optional, for rich terminal output; Guerrilla falls back gracefully without it)

### Per-platform access

| Platform | What you need |
|---------|---------------|
| **Active Directory** | Domain-joined machine or RSAT tools with domain read credentials |
| **Entra ID / Azure / M365** | App registration with read-only Microsoft Graph permissions |
| **Intune** | The same app registration with `DeviceManagementConfiguration.Read.All` |
| **Google Workspace** | Service account with domain-wide delegation plus an admin email |

> ### Endpoint protection (Microsoft Defender / EDR) may block the module
>
> Guerrilla is a security tool: several of its AD attack-detection files reference DCSync replication GUIDs, `GenericAll` / `WriteDacl`, and Tier-0 patterns. Antivirus heuristics, Microsoft Defender real-time protection in particular, can flag these as suspicious and block read access to the files, which makes `Import-Module Guerrilla` fail (often on a different AD file each attempt) with:
>
> ```
> Access to the path '…\Invoke-ADAclDelegationChecks.ps1' is denied
> ```
>
> This is a false positive. The files are inert PowerShell, not malware, but the block stops the module from loading. Fix it by adding a path exclusion from an **elevated** PowerShell:
>
> ```powershell
> Add-MpPreference -ExclusionPath "$HOME\Documents\PowerShell\Modules\Guerrilla"
> ```
>
> Alternatively, in **Windows Security > Virus and threat protection > Protection history**, choose **Allow** on the blocked item. On managed or EDR hosts, ask your security team to allowlist the module path. More detail under [Troubleshooting](#troubleshooting).

---

## Setup

### Step 1: Install the module

```powershell
# From the PowerShell Gallery (recommended)
Install-Module Guerrilla -Scope CurrentUser
Import-Module Guerrilla

# Or clone the repo
git clone https://github.com/jimrtyler/Guerrilla.git
Import-Module ./Guerrilla/Guerrilla.psd1
```

### Step 2: Open the Operations Console

`Show-Guerrilla` is the driver's seat. It opens a WPF window that runs the whole platform: Operations (run scans), Safehouse (manage credentials), Reports (browse and convert to PDF), and Settings (runtime config). Configure everything locally, in the module, from here.

```powershell
Show-Guerrilla
```

The console is Windows-only. On Linux and macOS the CLI cmdlets below do everything the console does.

### Step 3: Establish your Safehouse (credential vault)

`Set-Safehouse` creates an encrypted vault using Microsoft's SecretManagement framework and walks you through storing each credential.

```powershell
Set-Safehouse
```

**What happens during setup:**

1. **Dependency check** installs `Microsoft.PowerShell.SecretManagement` and `Microsoft.PowerShell.SecretStore` if missing (prompts for approval, or use `-Force` to auto-install).
2. **Vault creation** creates an encrypted vault named `Guerrilla` with no-password configuration applied up front.
   - **Windows**: DPAPI, encrypted with your Windows login, no extra password needed.
   - **Linux / macOS**: an encrypted file.
3. **Credential prompts** walk you through only the platforms you choose:
   - **Google Workspace**: paste your service account JSON key plus admin email.
   - **Entra ID / M365**: Tenant ID, Client ID, Client Secret (with GUID validation).
   - **Active Directory**: uses your current Kerberos session by default, so no credential is stored and no prompt is shown.
4. **Confirmation** displays a summary of stored credentials and your next command.

When you run `Set-Safehouse` without arguments, the first question is which platforms to set up. Pick only the ones you have. An Entra-only shop is never marched through Google Workspace prompts, and AD never asks for a stored credential.

```
  Which environments do you want to set up credentials for?
    [1] Google Workspace
    [2] Microsoft Entra / Graph / Azure / M365
    [3] Active Directory  (uses your current Kerberos session — no setup needed)
    [A] All of the above
  Selection (comma-separated, default: A):
```

### Step 4: Verify connectivity

Before your first scan, test that every credential works:

```powershell
Set-Safehouse -Test
```

This makes live read-only API calls to each platform and reports back with actionable guidance if anything fails (wrong scopes, expired secrets, missing permissions).

### Step 5: Run your first scan

```powershell
# Full campaign across all three platforms
Invoke-Campaign

# Or run individual platforms
Invoke-ADAudit      # Active Directory audit (211 checks)
Invoke-EntraAudit   # Entra / Azure / Intune / M365 audit (257 checks)
Invoke-GWSAudit     # Google Workspace audit (168 checks)
```

Results are saved to `$env:APPDATA/Guerrilla/` (Windows) or the equivalent per-user data directory on Linux and macOS, for report generation and trend tracking.

### Step 6: Generate reports

```powershell
# Board-ready one-pager
Export-ExecutiveSummary -OrganizationName 'Springfield USD'

# Full technical findings with remediation
Export-TechnicalReport -OrganizationName 'Springfield USD'

# Step-by-step remediation playbook
Export-RemediationPlaybook

# Auto-generated PowerShell fix scripts
Export-RemediationScripts

# Convert any HTML report to PDF
Export-ReportPdf -HtmlPath './Guerrilla-Technical-Report.html'
```

### Step 7: Run it on a cadence (optional)

Guerrilla does not run in the background. You run it, and every run is recorded locally and compared against your previous run: the report opens with what changed, including newly failing checks, confirmed remediations, and any check that went dark. To assess on a schedule, use your operating system's scheduler; see [docs/scheduled-runs.md](./docs/scheduled-runs.md) for Task Scheduler (Windows) and cron (macOS/Linux) examples.

---

## Managing your Safehouse

```powershell
# See what's stored (secrets are masked)
Get-Safehouse

# Detailed status with credential inventory
Set-Safehouse -Status

# Rotate specific credentials
Set-Safehouse -Rotate googleWorkspace
Set-Safehouse -Rotate microsoftGraph

# Remove credentials
Set-Safehouse -Remove googleWorkspace

# Change output directory or scoring profile
Set-Safehouse -OutputDirectory 'D:\Reports\Guerrilla'
Set-Safehouse -Profile K12

# Set minimum alert threshold
Set-Safehouse -MinimumAlertLevel HIGH

# Export credential metadata (NOT secrets) to JSON
Set-Safehouse -ExportMetadata
```

### Set-Safehouse quick reference

| Usage | Command |
|-------|---------|
| Initial setup (interactive) | `Set-Safehouse` |
| Auto-install dependencies | `Set-Safehouse -Force` |
| Test all connections | `Set-Safehouse -Test` |
| View vault status | `Set-Safehouse -Status` |
| Rotate credentials | `Set-Safehouse -Rotate googleWorkspace` |
| Remove credentials | `Set-Safehouse -Remove microsoftGraph` |
| Export metadata | `Set-Safehouse -ExportMetadata` |
| Custom vault name | `Set-Safehouse -VaultName 'MyVault'` |
| Set output directory | `Set-Safehouse -OutputDirectory './reports'` |
| Set scoring profile | `Set-Safehouse -Profile K12` |
| Set alert threshold | `Set-Safehouse -MinimumAlertLevel HIGH` |

---

## Preparing your platforms

### Active Directory

Guerrilla uses your current Kerberos session by default, so no stored credential is needed when you run from a domain-joined machine with a domain admin (or delegated read) account.

**Requirements:**
- Domain-joined machine, or RSAT tools installed
- Read access to AD objects (Domain Admins or delegated read permissions)
- For certificate services checks: Enterprise Admin or CA Admin access

### Microsoft Entra ID / Azure / M365

1. **Register an app** in the [Entra admin center](https://entra.microsoft.com) under App registrations > New registration.
2. **Add API permissions** (Application type, not Delegated), all read-only:
   - `Directory.Read.All`
   - `Policy.Read.All`
   - `AuditLog.Read.All`
   - `RoleManagement.Read.All`
   - `Application.Read.All`
   - `SecurityEvents.Read.All`
   - `DeviceManagementConfiguration.Read.All` (Intune)
   - `Mail.Read` (Exchange checks)
   - `Sites.Read.All` (SharePoint checks)
   - `AppCatalog.Read.All` (Teams app-catalog checks)
3. **Grant admin consent** for the permissions.
4. **Create a client secret** and note the expiration date.
5. During `Set-Safehouse`, provide the Tenant ID, Client ID, and Client Secret value.

### Google Workspace

1. **Create a GCP project** at [console.cloud.google.com](https://console.cloud.google.com).
2. **Enable APIs**: Admin SDK, Gmail API, Drive API, Groups Settings API.
3. **Create a service account** with domain-wide delegation.
4. **Grant read-only scopes** in the Google Admin Console:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.domain.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`
   - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
   - `https://www.googleapis.com/auth/admin.directory.orgunit.readonly`
   - `https://www.googleapis.com/auth/apps.groups.settings`
   - `https://www.googleapis.com/auth/admin.directory.device.mobile.readonly`
   - `https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly`
5. **Download the service account JSON key.**
6. During `Set-Safehouse`, paste the full JSON content when prompted and provide the admin email.

---

## Core functions

### Assessments

| Function | Alias | Description |
|----------|-------|-------------|
| `Invoke-ADAudit` | `Invoke-ADRecon` | Active Directory security audit (211 checks) |
| `Invoke-EntraAudit` | `Invoke-CloudRecon` | Entra ID, Azure, Intune, and M365 audit (257 checks) |
| `Invoke-GWSAudit` | (none) | Google Workspace security configuration audit (168 checks) |
| `Invoke-Campaign` | (none) | Unified audit across all three platforms in a single run |

Every run is recorded to a local, per-user history on your machine (no accounts, no telemetry), and the report opens with what changed since your last run.

### Credential and configuration

| Function | Description |
|----------|-------------|
| `Set-Safehouse` | Manage the encrypted vault, credentials, rotation, and module configuration |
| `Get-Safehouse` | View vault status, stored credentials, and current configuration |
| `Show-Guerrilla` | Open the WPF Operations Console (Windows only) |

### Scoring and analysis

| Function | Description |
|----------|-------------|
| `Get-GuerrillaScore` | Composite security score (0 to 100) with tier labels |
| `Get-ZeroTrustScore` | Zero Trust posture scored by CISA ZTMM pillar |
| `Get-QuickWins` | Highest impact, lowest effort fixes ranked by return |
| `Get-ComplianceCrosswalk` | Map findings to compliance frameworks |
| `Set-RiskAcceptance` | Accept risk on specific checks with justification and expiry |
| `Get-RiskAcceptance` | List active and expired risk acceptances |
| `Get-TrendReport` | Score-over-time trend analysis from scan history |

### Reports

| Function | Description |
|----------|-------------|
| `Export-ExecutiveSummary` | Board-ready one-pager (HTML) |
| `Export-TechnicalReport` | Full findings with current vs recommended values and remediation |
| `Export-RemediationPlaybook` | Step-by-step guide organized by phase and priority |
| `Export-RemediationScripts` | Generate runnable PowerShell fix scripts from findings |
| `Export-Dashboard` | Unified HTML dashboard across all platforms |
| `Export-ReportPdf` | Convert HTML reports to PDF via Edge or Chrome headless |
| `Export-BloodHoundData` | Export AD attack-path data for BloodHound ingestion |

---

## Security score tiers

The Guerrilla Score is a weighted composite of three components:

| Component | Weight | What it measures |
|-----------|--------|------------------|
| Posture | 70% | Audit findings weighted by severity |
| Coverage | 15% | Percentage of the three platforms assessed |
| Trend | 15% | Score change from the previous run |

| Score | Rating | Meaning |
|-------|--------|---------|
| 90 to 100 | Low Risk | Configuration closely aligned with the assessed baselines; keep assessing on a cadence |
| 75 to 89 | Moderate Risk | Minor gaps against the baselines; address remaining findings |
| 60 to 74 | Elevated Risk | Moderate gaps against the baselines; prioritize remediation |
| 40 to 59 | High Risk | Significant baseline gaps; needs immediate attention |
| 20 to 39 | Severe Risk | Widespread baseline gaps; urgent remediation |
| 0 to 19 | Critical Risk | Critical exposure across the assessed baselines; emergency response |

---

## AD audit categories

`Invoke-ADAudit -Categories <name(s)>` selects which AD categories run. The default is `All`.

| Category | What it audits |
|---|---|
| `DomainForest` | Domain and forest info, functional levels, FSMO holders, sites |
| `Trusts` | External and forest trusts, SID filtering, transitivity |
| `PrivilegedAccounts` | Domain / Enterprise / Schema Admins, krbtgt, AdminSDHolder, DCSync rights |
| `PasswordPolicy` | Default and fine-grained password policies, LAPS, and NT-hash quality via DSInternals when run on a DC with replication rights |
| `Kerberos` | Kerberoasting, AS-REP roasting, all delegation types, encryption types |
| `ACLDelegation` | Dangerous ACEs on critical objects, OU delegation, MachineAccountQuota |
| `GroupPolicy` | GPO inventory, link analysis, sensitive GPO permissions |
| `LogonScripts` | NETLOGON share contents, embedded credentials, dangerous patterns |
| `CertificateServices` | ESC1 through ESC9, ESC11, ESC13, ESC15, and ESC16 template misconfigurations |
| `StaleObjects` | Inactive users and computers, password-age outliers |
| `Network` | NTLM-relay preconditions: LDAP / SMB signing, LLMNR / NetBIOS / WPAD, IPv6 (mitm6), Spooler / WebClient |
| `TierZero` | Tier-bleed scanning by service-account name pattern, plus the Entra Connect MSOL_ account audit |
| `Logging` | Telemetry posture: Advanced Audit Policy, PowerShell script-block and module logging, process-creation auditing, WEF, Sysmon indicators |
| `Tradecraft` | Adversary indicators: GPP cpassword in SYSVOL, DCShadow surface, stale BitLocker keys, RODC PRP, shadow credentials, delegated-MSA escalation, Seamless SSO key rotation, gMSA exposure |

---

## Aliases and migration

### Renamed commands

The audits were renamed in v2.47.0 so platforms are named what they are. The old
names still work as deprecated wrappers that warn once per session; they will be
removed in the next major version.

| Old name (deprecated) | Use instead |
|-----------------------|-------------|
| `Invoke-Reconnaissance` | `Invoke-ADAudit` |
| `Invoke-Infiltration` | `Invoke-EntraAudit` |
| `Invoke-Fortification` | `Invoke-GWSAudit` |

### Deprecated aliases

These aliases carry retired names and are kept only for backward compatibility.
They are slated for removal in the next major version; use the canonical
commands instead.

| Deprecated alias | Use instead |
|------------------|-------------|
| `Invoke-ADRecon` | `Invoke-ADAudit` |
| `Invoke-CloudRecon` | `Invoke-EntraAudit` |

### Migrating from an earlier install

If you previously installed the module under its former name, Guerrilla migrates your data automatically and transparently on first load. The per-user data directory (reports and config) is carried forward one time, and safehouse credential resolution falls back to the legacy vault when the new `Guerrilla` vault has no value. No manual re-registration is required. See the [CHANGELOG](./CHANGELOG.md) for the version this took effect.

### Non-interactive imports

The startup banner is suppressed automatically when the module is imported from a scheduled task, CI runner, or any non-interactive session. You can also force-quiet it by setting `$env:GUERRILLA_QUIET = 1`.

---

## Troubleshooting

### `Import-Module` fails with "Access to the path '…Invoke-ADAclDelegationChecks.ps1' is denied"

Your endpoint protection is blocking Guerrilla's AD attack-detection files (a false positive, see the endpoint-protection callout under [Requirements](#requirements)). Tell-tale signs it is antivirus and not a permissions problem: your account has FullControl on the file yet even copying it is denied, and a different AD file is blocked on each import attempt.

```powershell
# Elevated PowerShell: exclude the module path, then re-import
Add-MpPreference -ExclusionPath "$HOME\Documents\PowerShell\Modules\Guerrilla"
Import-Module Guerrilla -Force
```

If you installed the module elsewhere, exclude that path instead (`(Get-Module Guerrilla -ListAvailable).ModuleBase`). On EDR-managed hosts, your security team adds the allowlist entry.

### A scan reports "No accessible Azure subscriptions"

The Entra app has no Azure Resource Manager access. Grant it the **Reader** role at the root management group to enable the `AZIAM-*` Azure resource checks. They report Not Assessed cleanly without it.

### Teams checks log a 403 for `/appCatalogs/teamsApps`

Add the `AppCatalog.Read.All` application permission to the app registration and grant admin consent. The scan continues without it; the Teams app-catalog portion stays empty.

### Google API returns 403

- Verify domain-wide delegation in Admin Console > Security > API Controls > Domain-wide Delegation.
- Confirm the correct scopes are granted to the service account client ID.
- Check that the admin email has Super Admin privileges.

### Graph API returns 401 or 403

- Verify admin consent was granted for the app permissions.
- Check the client secret has not expired: `Set-Safehouse -Status`.
- Rotate if needed: `Set-Safehouse -Rotate microsoftGraph`.

### PowerShell 5.1

Guerrilla requires PowerShell 7.0+. On Windows PowerShell 5.1:

```powershell
winget install Microsoft.PowerShell
pwsh
Import-Module ./Guerrilla.psd1
```

---

## Contributing

Guerrilla is an open, community-facing project, and its contributors are often practitioners who will never open a pull request. Reporting a wrong verdict, proposing a check with the incident that motivated it, and contributing fixture data from an unusual real tenant shape are all first-class contributions, and every rung is credited in release notes. See [CONTRIBUTING.md](./CONTRIBUTING.md) for the ladder, and [guerrilla.army/docs/validation](https://guerrilla.army/docs/validation) for how to write a fixture.

Every contributed check ships with fixtures. That requirement is what lets a maintainer accept a check from someone they have never met: the fixture proves the verdict logic is correct.

---

## Author

**Jim Tyler**, Microsoft MVP

- GitHub: [github.com/jimrtyler](https://github.com/jimrtyler)
- LinkedIn: [linkedin.com/in/jamestyler](https://linkedin.com/in/jamestyler)
- YouTube: [youtube.com/@powershellengineer](https://youtube.com/@powershellengineer)
- Newsletter: [powershell.news](https://powershell.news)

## License

[CC BY 4.0](LICENSE). Attribution required. Commercial use allowed.
</content>
</invoke>
