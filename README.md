# PSGuerrilla

**By [Jim Tyler](https://github.com/jimrtyler), Microsoft MVP**

Security assessment, threat detection, and continuous monitoring for Google Workspace, Active Directory, Entra ID, Azure, Intune, and Microsoft 365. PowerShell 7.0+.

[![GitHub](https://img.shields.io/badge/GitHub-jimrtyler-181717?logo=github)](https://github.com/jimrtyler) [![LinkedIn](https://img.shields.io/badge/LinkedIn-jamestyler-0A66C2?logo=linkedin)](https://linkedin.com/in/jamestyler) [![YouTube](https://img.shields.io/badge/YouTube-PowerShellEngineer-FF0000?logo=youtube)](https://youtube.com/@powershellengineer)

> **[View a sample report with all 431 checks](./PSGuerrilla-Sample-Report.html)** to see the full scope of what PSGuerrilla evaluates.

---

## Coverage

| Theater | Capability | Checks |
|---------|-----------|--------|
| Google Workspace | Compromise assessment, 23 detection signals, 8 audit categories | 98 |
| Active Directory | 14-category security reconnaissance | 203 |
| Entra ID / Azure / Intune / M365 | Infiltration audit across 14 categories | 159 |
| All theaters | Continuous monitoring with baseline drift detection | Real-time |

**Total: 459 security checks** across authentication, email security, drive/SharePoint, OAuth, admin management, conditional access, PIM, Kerberos, certificate services, group policy, Intune endpoint compliance, NTLM-relay preconditions, Tier-0 hygiene, logging/telemetry posture, adversary-tradecraft indicators (GPP cpassword, DCShadow, BitLocker hygiene, RODC PRP), and more.

## Requirements

- **PowerShell 7.0+** ([Install guide](https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell))
- **Operating System**: Windows (recommended — DPAPI encryption), Linux, or macOS
- [PwshSpectreConsole](https://github.com/ShaunLawrie/PwshSpectreConsole) (optional, for rich terminal output — PSGuerrilla falls back gracefully)

### Per-Environment Requirements

| Environment | What You Need |
|-------------|---------------|
| **Google Workspace** | Service account with domain-wide delegation + admin email |
| **Active Directory** | Domain-joined machine or RSAT tools with domain credentials |
| **Entra ID / Azure / M365** | App registration with appropriate Microsoft Graph API permissions |
| **Intune** | Same app registration — DeviceManagementConfiguration.Read.All scope |

---

## Setup Guide

### Step 1: Install the Module

```powershell
# Clone the repo
git clone https://github.com/jimrtyler/PSGuerrilla.git

# Import the module
Import-Module ./PSGuerrilla/PSGuerrilla.psd1
```

### Step 2: Generate Your Configuration (Recommended)

Visit **[guerrilla.army](https://guerrilla.army)** to use the interactive configuration builder. It walks you through selecting:
- Which environments to audit (Google Workspace, AD, Entra/Azure/M365, Intune)
- Mission mode (reporting only, or reporting + monitoring)
- Report formats and compliance frameworks
- Alerting channels (Teams, Slack, email, PagerDuty, etc.)

Download the generated `guerrilla-config.json` when finished.

> **Alternatively**, you can skip the config file entirely. PSGuerrilla will prompt you for credentials interactively and use sensible defaults.

### Step 3: Establish Your Safehouse (Credential Vault)

`Set-Safehouse` is the core setup command. It creates an encrypted vault using Microsoft's SecretManagement framework and walks you through storing each credential.

```powershell
# With a config file from guerrilla.army
Set-Safehouse -ConfigFile './guerrilla-config.json'

# Or without a config file (interactive, uses defaults)
Set-Safehouse
```

**What happens during setup:**

1. **Dependency check** — Installs `Microsoft.PowerShell.SecretManagement` and `Microsoft.PowerShell.SecretStore` if missing (prompts for approval, or use `-Force` to auto-install)
2. **Vault creation** — Creates an encrypted vault named `PSGuerrilla` with no-password configuration applied up front (no contradictory "enter a password / password not needed" prompts)
   - **Windows**: Uses DPAPI (encrypted with your Windows login — no extra password needed)
   - **Linux/macOS**: Uses an encrypted file
3. **Credential prompts** — Walks you through each credential your config requires:
   - **Google Workspace**: Paste your service account JSON key + admin email
   - **Entra ID / M365**: Tenant ID, Client ID, Client Secret (with GUID format validation)
   - **Active Directory**: Uses your current Kerberos session by default (no credential storage needed, no prompts shown)
   - **Alerting providers**: Webhook URLs, API keys, etc. for any configured alert channels
4. **Confirmation** — Displays a summary of stored credentials and your next command

**Without `-ConfigFile` (fully interactive):**

If you run `Set-Safehouse` without a config file, the first question is which environments you want to set up:

```
  Which environments do you want to set up credentials for?
    [1] Google Workspace
    [2] Microsoft Entra / Graph / Azure / M365
    [3] Active Directory  (uses your current Kerberos session — no setup needed)
    [A] All of the above
  Selection (comma-separated, default: A):
```

Pick only the ones you need. You won't be marched through Google Workspace prompts if you're an Entra-only shop, and AD never asks for stored credentials.

**Example output:**
```
╔══════════════════════════════════════════════╗
║         SAFEHOUSE ESTABLISHED                ║
╠══════════════════════════════════════════════╣
║  Vault: PSGuerrilla                          ║
║  Protection: DPAPI (User Scope)              ║
║  Credentials Stored: 5                       ║
╚══════════════════════════════════════════════╝

Next: Invoke-Campaign -ConfigFile './guerrilla-config.json'
```

### Step 4: Verify Connectivity

Before running your first scan, test that all credentials are working:

```powershell
# Test all configured environments
Set-Safehouse -Test

# Or with a config file
Set-Safehouse -Test -ConfigFile './guerrilla-config.json'
```

This makes live API calls to each environment and reports back with actionable guidance if anything fails (wrong scopes, expired secrets, missing permissions, etc.).

### Step 5: Run Your First Scan

```powershell
# Full campaign across all theaters
Invoke-Campaign -ConfigFile './guerrilla-config.json'

# Or run individual theaters
Invoke-Fortification                    # Google Workspace audit (98 checks)
Invoke-Reconnaissance                   # Active Directory audit (175 checks)
Invoke-Infiltration                     # Entra/Azure/M365 audit (159 checks)
```

Results are automatically saved to `$env:APPDATA/PSGuerrilla/` (Windows) for report generation and trend tracking.

### Step 6: Generate Reports

```powershell
# Board-ready one-pager
Export-ExecutiveSummary -OrganizationName 'Springfield USD'

# Full technical findings with remediation
Export-TechnicalReport -OrganizationName 'Springfield USD'

# Step-by-step remediation playbook
Export-RemediationPlaybook

# Auto-generated PowerShell fix scripts
Export-RemediationScripts

# Budget justification for leadership
Export-BudgetJustification

# Convert any HTML report to PDF
Export-ReportPdf -InputPath './PSGuerrilla-Technical-Report.html'
```

### Step 7: Set Up Continuous Monitoring (Optional)

```powershell
# Register a scheduled task that scans every 60 minutes and sends alerts
Register-Patrol -ConfigFile './guerrilla-config.json' `
    -Theaters Workspace, Entra, AD `
    -IntervalMinutes 60 `
    -SendAlerts

# View patrol status
Get-Patrol

# Remove a patrol
Unregister-Patrol -TaskName 'PSGuerrilla-Patrol'
```

---

## Managing Your Safehouse

### View Vault Status

```powershell
# See what's stored (secrets are masked)
Get-Safehouse

# Detailed status with credential inventory
Set-Safehouse -Status
```

### Rotate Credentials

```powershell
# Rotate specific environment credentials
Set-Safehouse -Rotate googleWorkspace
Set-Safehouse -Rotate microsoftGraph
```

### Remove Credentials

```powershell
Set-Safehouse -Remove googleWorkspace
```

### Update Runtime Settings

```powershell
# Change output directory
Set-Safehouse -OutputDirectory 'D:\Reports\PSGuerrilla'

# Switch scoring profile
Set-Safehouse -Profile K12

# Set minimum alert threshold
Set-Safehouse -MinimumAlertLevel HIGH
```

### Export Metadata (for Backup/Documentation)

```powershell
# Exports credential metadata (NOT secrets) to JSON
Set-Safehouse -ExportMetadata
```

---

## Set-Safehouse Quick Reference

| Usage | Command |
|-------|---------|
| Initial setup with config | `Set-Safehouse -ConfigFile './guerrilla-config.json'` |
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

## Preparing Your Environments

### Google Workspace Setup

1. **Create a GCP project** at [console.cloud.google.com](https://console.cloud.google.com)
2. **Enable APIs**: Admin SDK, Gmail API, Drive API, Groups Settings API
3. **Create a service account** with domain-wide delegation
4. **Grant scopes** in the Google Admin Console:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.domain.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`
   - `https://www.googleapis.com/auth/admin.reports.audit.readonly`
   - `https://www.googleapis.com/auth/admin.directory.orgunit.readonly`
   - `https://www.googleapis.com/auth/apps.groups.settings`
   - `https://www.googleapis.com/auth/admin.directory.device.mobile.readonly`
   - `https://www.googleapis.com/auth/admin.directory.device.chromeos.readonly`
5. **Download the service account JSON key**
6. During `Set-Safehouse`, paste the full JSON content when prompted and provide the admin email address

### Microsoft Entra ID / Azure / M365 Setup

1. **Register an app** in [Entra admin center](https://entra.microsoft.com) > App registrations > New registration
2. **Add API permissions** (Application type, not Delegated):
   - `Directory.Read.All`
   - `Policy.Read.All`
   - `AuditLog.Read.All`
   - `RoleManagement.Read.All`
   - `Application.Read.All`
   - `SecurityEvents.Read.All`
   - `DeviceManagementConfiguration.Read.All` (for Intune)
   - `Mail.Read` (for Exchange checks)
   - `Sites.Read.All` (for SharePoint checks)
3. **Grant admin consent** for the permissions
4. **Create a client secret** (note the expiration date)
5. During `Set-Safehouse`, provide:
   - **Tenant ID**: Found in Entra admin center > Overview
   - **Client ID**: Found in your app registration
   - **Client Secret**: The secret value (not the secret ID)

### Active Directory Setup

PSGuerrilla uses your **current Kerberos session** by default — no stored credentials needed if you're running from a domain-joined machine with a domain admin (or delegated read) account.

For environments where you need a service account:
```powershell
# Set-Safehouse will prompt for AD service account credentials if configured
Set-Safehouse -ConfigFile './guerrilla-config.json'
```

**Requirements:**
- Domain-joined machine, or RSAT tools installed
- Read access to AD objects (Domain Admins or delegated Read permissions)
- For certificate services checks: Enterprise Admin or CA Admin access

---

## Core Functions

### Assessments

| Function | Alias | Description |
|----------|-------|-------------|
| `Invoke-Recon` | `Invoke-WorkspaceRecon` | Google Workspace compromise assessment with 23 behavioral detection signals |
| `Invoke-Fortification` | — | Google Workspace security configuration audit (8 categories) |
| `Invoke-Reconnaissance` | `Invoke-ADRecon` | Active Directory security audit across 10 categories |
| `Invoke-Infiltration` | `Invoke-CloudRecon` | Entra ID, Azure, Intune, and M365 security assessment (159 checks) |
| `Invoke-Campaign` | — | Unified audit across all theaters in a single run |

> The theater-named aliases (`Invoke-WorkspaceRecon` / `Invoke-ADRecon` / `Invoke-CloudRecon`) are interchangeable with the canonical names — use whichever makes the intent clearer at the call site. `Invoke-Recon` (Workspace user behavior) and `Invoke-Reconnaissance` (AD configuration audit) look nearly identical but cover different theaters.

### Continuous Monitoring

| Function | Description |
|----------|-------------|
| `Invoke-Surveillance` | Entra ID sign-in risk and directory change monitoring via Graph API |
| `Invoke-Watchtower` | Active Directory baseline monitoring with drift detection |
| `Invoke-Wiretap` | M365 audit log monitoring (Exchange, SharePoint, Teams, Defender, Power Platform) |

### Credential & Configuration Management

| Function | Description |
|----------|-------------|
| `Set-Safehouse` | Manage encrypted vault, credentials, rotation, and module configuration |
| `Get-Safehouse` | View vault status, stored credentials, and current configuration |

### Alerting

Dispatch alerts through 9 providers. Each has a dedicated function or use `Send-Signal` to route automatically.

| Function | Provider |
|----------|----------|
| `Send-Signal` | Auto-route to configured provider(s) |
| `Send-SignalSendGrid` | SendGrid email |
| `Send-SignalMailgun` | Mailgun email |
| `Send-SignalTwilio` | Twilio SMS |
| `Send-SignalTeams` | Microsoft Teams (Adaptive Cards) |
| `Send-SignalSlack` | Slack (Block Kit) |
| `Send-SignalWebhook` | Generic webhook / SIEM ingestion |
| `Send-SignalPagerDuty` | PagerDuty with severity mapping |
| `Send-SignalSyslog` | Syslog in CEF or LEEF format |
| `Send-SignalEventLog` | Windows Event Log |
| `Send-SignalDigest` | Aggregated daily/weekly digest |

### Scoring & Analysis

| Function | Description |
|----------|-------------|
| `Get-GuerrillaScore` | Composite security score (0-100) with tier labels |
| `Get-QuickWins` | Highest impact, lowest effort fixes ranked by ROI |
| `Get-ComplianceCrosswalk` | Map findings to FERPA, COPPA, CIPA, NIST 800-171, state ed-tech |
| `Set-RiskAcceptance` | Accept risk on specific checks with justification and expiry |
| `Get-RiskAcceptance` | List active/expired risk acceptances |
| `Get-TrendReport` | Score-over-time trend analysis from scan history |

### Reports

| Function | Description |
|----------|-------------|
| `Export-ExecutiveSummary` | Board-ready one-pager (HTML) |
| `Export-TechnicalReport` | Full findings with current vs recommended values and remediation |
| `Export-RemediationPlaybook` | Step-by-step guide organized by phase and priority |
| `Export-RemediationScripts` | Generate runnable PowerShell fix scripts from findings |
| `Export-BudgetJustification` | Cost justification document for leadership |
| `Export-Dashboard` | Unified HTML dashboard across all theaters |
| `Export-ReportPdf` | Convert HTML reports to PDF via Edge/Chrome headless |

### Scheduling

| Function | Description |
|----------|-------------|
| `Register-Patrol` | Create scheduled scan tasks with interval and alert dispatch |
| `Unregister-Patrol` | Remove scheduled tasks |
| `Get-Patrol` | View task status, last run, next run |

---

## Security Score Tiers

The Guerrilla Score is a weighted composite of four components:

| Component | Weight | What It Measures |
|-----------|--------|-----------------|
| Posture | 40% | Audit findings weighted by severity |
| Threats | 30% | Active threat detections from monitoring |
| Coverage | 15% | Percentage of theaters actively scanned |
| Trend | 15% | Score change from previous scan |

| Score | Tier | Meaning |
|-------|------|---------|
| 90-100 | FORTRESS | Excellent posture — maintain monitoring |
| 75-89 | DEFENDED POSITION | Strong foundation — address remaining gaps |
| 60-74 | CONTESTED GROUND | Needs improvement — prioritize action |
| 40-59 | EXPOSED FLANK | Significant gaps — immediate attention |
| 20-39 | UNDER SIEGE | Critical weaknesses — urgent remediation |
| 0-19 | OVERRUN | Severe compromise risk — emergency response |

---

## Common Workflows

### Quick Assessment (No Config File)

```powershell
Import-Module ./PSGuerrilla.psd1
Set-Safehouse                # pick the environments you actually have when prompted
Invoke-Campaign
Export-TechnicalReport -OrganizationName 'Contoso'
```

### Full Mission with Reporting

```powershell
Import-Module ./PSGuerrilla.psd1
Set-Safehouse -ConfigFile './guerrilla-config.json'
Set-Safehouse -Test
Invoke-Campaign -ConfigFile './guerrilla-config.json'

Export-ExecutiveSummary -OrganizationName 'Springfield USD'
Export-TechnicalReport -OrganizationName 'Springfield USD'
Export-RemediationPlaybook
Export-RemediationScripts
Export-ReportPdf -InputPath './PSGuerrilla-Executive-Summary.html'
```

### Review High-Priority Findings

```powershell
$results = Invoke-Campaign -ConfigFile './guerrilla-config.json'
$results | Get-DeadDrop -MinimumThreatLevel HIGH
Get-QuickWins -Top 10
Get-ComplianceCrosswalk -FailOnly
```

### Ongoing Monitoring with Alerts

```powershell
Register-Patrol -ConfigFile './guerrilla-config.json' `
    -Theaters Workspace, Entra, AD, M365 `
    -IntervalMinutes 60 `
    -SendAlerts

# View results
Get-Patrol
Get-TrendReport
```

---

## Configuration

PSGuerrilla uses a JSON config file generated by the [PSGuerrilla Configuration Website](https://guerrilla.army) or manually created. The config controls which environments to audit, monitoring intervals, report formats, alerting channels, and compliance framework mappings.

```powershell
# All public functions accept -ConfigFile
Invoke-Campaign -ConfigFile './guerrilla-config.json'
Invoke-Reconnaissance -ConfigFile './guerrilla-config.json' -Category PrivilegedAccounts, Kerberos, Network
```

### AD Reconnaissance categories

`Invoke-Reconnaissance -Categories <name(s)>` selects which AD categories run. Default is `All`.

| Category | What it audits |
|---|---|
| `DomainForest` | Domain/forest info, functional levels, FSMO holders, sites |
| `Trusts` | External and forest trusts, SID filtering, transitivity |
| `PrivilegedAccounts` | Domain/Enterprise/Schema Admins, krbtgt, AdminSDHolder, DCSync rights |
| `PasswordPolicy` | Default Domain Password Policy + Fine-Grained Password Policies, LAPS |
| `Kerberos` | Kerberoasting, AS-REP roasting, all delegation types, encryption types |
| `ACLDelegation` | Dangerous ACEs on critical objects, OU delegation, MachineAccountQuota |
| `GroupPolicy` | GPO inventory, link analysis, sensitive GPO permissions |
| `LogonScripts` | NETLOGON share contents, embedded credentials, dangerous patterns |
| `CertificateServices` | ESC1–ESC16 + EKEUwu certificate template misconfigurations |
| `StaleObjects` | Inactive users/computers, password-age outliers |
| `Network` | NTLM-relay preconditions: LDAP/SMB signing, LLMNR/NetBIOS/WPAD, IPv6 (mitm6), Spooler/WebClient — the settings that turn an ESC8 finding from theoretical into one-shot domain compromise |
| `TierZero` | Tier-bleed scanning by service-account name pattern (Veeam / vCenter / SCCM / SQL in DA/EA/SA), plus the Azure AD Connect MSOL_ account audit (an account most enumeration tools never surface because it gets DCSync via ACL, not group membership) |
| `Logging` | Telemetry posture: Advanced Audit Policy adoption, PowerShell Script Block / Module Logging, Process Creation cmdline auditing, Defender Tamper Protection guidance, WEF SubscriptionManager, Sysmon deployment indicator — the events investigators need to actually catch the things the other categories warn about |
| `Tradecraft` | Adversary indicators that fall outside the standard category buckets: GPP cpassword leftovers in SYSVOL (still the #1 red-team find), DCShadow surface (rogue server objects in CN=Sites,CN=Configuration), stale BitLocker recovery keys, RODC Password Replication Policy hygiene |

Runtime configuration (detection thresholds, business hours, alert suppression, etc.) is managed separately:

```powershell
# Stored at $env:APPDATA/PSGuerrilla/config.json
Set-Safehouse -ConfigPath './my-runtime-config.json'
```

---

## Module Structure

```
PSGuerrilla/
  PSGuerrilla.psd1              # Module manifest (40 exported functions)
  PSGuerrilla.psm1              # Root module (loader)
  PSGuerrilla.format.ps1xml     # Custom table formatters
  Config/                        # JSON schema and defaults
  Data/                          # Threat intel, audit check definitions, compliance crosswalks
    AuditChecks/                 # 32 JSON files defining all 431 security checks
    Profiles/                    # Scoring profiles (Default, K12)
  Public/                        # 40 exported functions
  Private/                       # 222 internal functions
    AD/                          # Active Directory collection and checks
    ADMonitor/                   # AD continuous monitoring and detections
    Audit/                       # Shared audit framework
    Console/                     # Themed terminal output and Spectre integration
    Core/                        # Detection engine, IP classification, state management
    Entra/                       # Entra ID / Azure / Intune / M365 checks
    EntraMonitor/                # Entra ID continuous monitoring
    Export/                      # Report generation (HTML, CSV, JSON)
    Google/                      # Google Workspace API integration
    Graph/                       # Microsoft Graph API integration
    M365Monitor/                 # M365 audit log monitoring
    Vault/                       # SecretManagement vault integration
  Tests/                         # Pester 5 unit and integration tests
```

---

## Aliases & Migration

### Theater-named aliases

For readability at the call site — `Invoke-Recon` and `Invoke-Reconnaissance` look near-identical but cover different theaters. Use whichever name you prefer:

| Alias | Resolves to | Theater |
|-------|-------------|---------|
| `Invoke-WorkspaceRecon` | `Invoke-Recon` | Google Workspace user-behavior assessment |
| `Invoke-ADRecon` | `Invoke-Reconnaissance` | Active Directory configuration audit |
| `Invoke-CloudRecon` | `Invoke-Infiltration` | Entra ID / Azure / Intune / M365 audit |

### Migration from PSRecon

PSGuerrilla automatically migrates your PSRecon configuration on first load. All old command names (`Invoke-GoogleRecon`, `Get-ReconAlerts`, `Send-ReconAlert`, `Set-ReconConfig`, etc.) continue to work as aliases.

### Non-interactive imports

The startup banner is suppressed automatically when the module is imported from a scheduled task, CI runner, or any non-interactive session (when `[Environment]::UserInteractive` is false or stdout is redirected). You can also force-quiet it with `$env:PSGUERRILLA_QUIET = 1`.

---

## Troubleshooting

### "No audit findings available"

Run a scan first before generating reports:
```powershell
Invoke-Campaign -ConfigFile './guerrilla-config.json'
Export-TechnicalReport
```

### SecretManagement module won't install

```powershell
# Try installing manually
Install-Module Microsoft.PowerShell.SecretManagement -Scope CurrentUser
Install-Module Microsoft.PowerShell.SecretStore -Scope CurrentUser

# Then re-run setup
Set-Safehouse -ConfigFile './guerrilla-config.json'
```

### Google API returns 403

- Verify domain-wide delegation is configured in Admin Console > Security > API Controls > Domain-wide Delegation
- Confirm the correct scopes are granted to the service account client ID
- Check that the admin email has Super Admin privileges

### Graph API returns 401/403

- Verify admin consent was granted for the app permissions
- Check the client secret hasn't expired: `Set-Safehouse -Status`
- Rotate if needed: `Set-Safehouse -Rotate microsoftGraph`

### PowerShell 5.1 Compatibility

PSGuerrilla requires PowerShell 7.0+. If you're on Windows PowerShell 5.1:
```powershell
# Install PowerShell 7
winget install Microsoft.PowerShell
# Then run from pwsh
pwsh
Import-Module ./PSGuerrilla.psd1
```

---

## Author

**Jim Tyler** — Microsoft MVP

- GitHub: [github.com/jimrtyler](https://github.com/jimrtyler)
- LinkedIn: [linkedin.com/in/jamestyler](https://linkedin.com/in/jamestyler)
- YouTube: [youtube.com/@jimrtyler](https://youtube.com/@jimrtyler)
- Newsletter: [powershell.news](https://powershell.news)

## License

[CC BY 4.0](LICENSE) — Attribution required. Commercial use allowed.
