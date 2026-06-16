# Changelog

## [2.6.0] - 2026-06-16

### Added
- **The Google Workspace (Fortification) report is now far more actionable**, with the **Authentication** category built out as the first pass:
  - **Affected accounts are now listed.** When a check flags a problem against specific accounts — users without 2SV enforced/enrolled, super admins not enrolled in 2SV, stale super admins, super admins with personal recovery options — the HTML report now lists the **actual affected accounts** beneath the finding (capped at 25 with a "+N more" indicator) instead of showing only a count. The renderer also **auto-surfaces** affected-object lists that existing checks already capture (e.g. `ActiveSuperAdmins`), so other categories benefit immediately.
  - **"Fix in Admin Console" deep-links on every finding.** The Admin console deep-link previously appeared only in the Critical/High priority table; it now appears on **every actionable finding** in the per-category detail tables.
  - **"Why this is unsafe" reference articles.** Each Authentication check now links to an authoritative article explaining *why* the misconfiguration is dangerous — Google Workspace official documentation where available, supplemented by NIST/CIS/MITRE and reputable security research where they explain the attack better. New `referenceUrl` / `referenceTitle` fields on check definitions; all 13 URLs were verified to resolve (HTTP 200).

### Fixed
- **All three HTML report footers showed "v2.0.0" regardless of the installed version.** The version-detection logic walked `$PSScriptRoot` up one level too many (three `Split-Path -Parent` calls from `Private/Export/` overshot the module root), so the manifest was never found and every report fell back to the hardcoded default. All three exporters (Fortification, Reconnaissance, Infiltration) now read the version directly from the running module via `$ExecutionContext.SessionState.Module.Version`.

### Notes
- This is the first category in a rollout. The **rendering** improvements (affected-account lists, admin-console links on every finding) apply to **all** Google Workspace categories now. The curated **reference articles** currently cover the 13 Authentication checks and will be extended to the remaining seven categories in follow-up releases.
- New finding properties `ReferenceUrl` / `ReferenceTitle` flow through `New-AuditFinding`; the affected-account convention is `Details.AffectedItems` + `Details.AffectedLabel`. Both are backward compatible — all 64 existing HTML report validation checks still pass.

## [2.5.2] - 2026-06-16

### Fixed
- **The sample-report generator undercounted Active Directory checks as 175 instead of the real 203.** `Samples/Generate-SampleReports.ps1` built its AD report from a hardcoded `$adFiles` list of only **10 of the 14** AD check-definition files, silently omitting `ADLoggingChecks` (7), `ADNetworkChecks` (10), `ADTradecraftChecks` (4) and `TierZeroChecks` (7) — the 28 checks added in v2.2.0. The generator now **discovers every AD check file automatically** (a case-sensitive match on the `AD`/`TierZero` prefix, so the Google Workspace `AdminManagementChecks.json` — lowercase `d` — is never captured), so newly added categories can't silently drop out again.
- Regenerated the committed `Samples/Reconnaissance-AllFail.html`, which now reflects all **203** AD checks (GWS 98 + AD 203 + Entra 158 = **459** total).

### Notes
- This was purely a sample/count bug. **All 203 AD checks were always implemented and run** by `Invoke-Reconnaissance` — verified as a 1:1 mapping between the 203 JSON check IDs and the 203 `Test-Recon*` dispatch functions, with zero stubs. The module's advertised "203 AD checks / 459 total" was already correct.

## [2.5.1] - 2026-06-16

### Changed
- The Active Directory report's **"Findings by Priority" table now includes a Remediation column**. Previously it showed only ID / Severity / Status / Category / Check / Finding, and remediation guidance lived only in the per-category detail tables further down. It falls back to the recommended value when a check has no explicit remediation steps. (Google Workspace, Entra/M365, and Campaign reports already surfaced remediation in their findings tables / detail rows.)
- Regenerated the committed sample reports under `Samples/` to reflect the new column.

## [2.5.0] - 2026-06-16

### Added
- **Scans auto-resolve credentials from the safehouse vault.** Previously `Invoke-Fortification`, `Invoke-Infiltration`, and `Invoke-Campaign` only read the vault when handed a `-ConfigFile` (guerrilla-config.json) mission file — so an interactive `Set-Safehouse` setup (no config file) couldn't scan at all, failing with `ServiceAccountKeyPath is required` / `TenantId is required`, including from the `Show-Guerrilla` GUI. These cmdlets now fall back — as a last resort, after explicit parameters and `config.json` — to the default vault keys `Set-Safehouse` stores: `GUERRILLA_GWS_SA` (+ `_ADMIN_EMAIL`) for Google Workspace and `GUERRILLA_GRAPH_TENANT` / `GUERRILLA_GRAPH_CLIENTID` / `GUERRILLA_GRAPH_SECRET` for Entra/Azure/M365. A populated safehouse now "just works" for every theater from both the CLI and the GUI.
- `-VaultName` parameter (default `PSGuerrilla`) on `Invoke-Fortification` / `Invoke-Infiltration` / `Invoke-Campaign`, so non-default/custom vaults resolve correctly. `Show-Guerrilla` passes the active vault name automatically.
- `Get-SafehouseSecret` private helper — a graceful counterpart to `Get-GuerrillaCredential` that returns `$null` on a miss (vault/key absent, SecretManagement not installed) instead of throwing, for "fall back to the safehouse" resolution.

### Notes
- Active Directory was already covered: `Invoke-Reconnaissance` falls back to the current Kerberos session, so it needs no vault credentials.

## [2.4.4] - 2026-06-16

### Fixed
- **Show-Guerrilla scans failed for Google Workspace / Entra / Campaign with `A parameter cannot be found that matches parameter name 'ScanMode'`.** The GUI built its scan arguments from hardcoded per-cmdlet name lists that didn't match the cmdlets' real parameters: none of `Invoke-Fortification` / `Invoke-Infiltration` / `Invoke-Reconnaissance` declare `-ScanMode`, and `Invoke-Campaign` has neither `-Categories` nor `-NoReports`. The action now inspects the target cmdlet's actual parameter set via `(Get-Command $Cmdlet).Parameters` and only passes options the cmdlet declares, so every theater binds cleanly. (AD scans already worked because `Invoke-Reconnaissance` happened not to be on the `-ScanMode` list.)

## [2.4.3] - 2026-06-16

### Fixed
- **Show-Guerrilla scans failed instantly with `The term 'Invoke-Reconnaissance' is not recognized`.** Two bugs in the worker runspace that drives a scan:
  1. The module was never imported into the runspace — the code used `InitialSessionState.ImportPSModule()` with a full `.psd1` **path**, but that API expects a module **name** and silently does nothing with a path, so the runspace started with none of PSGuerrilla's commands. The worker now calls `Import-Module <manifest> -ErrorAction Stop` explicitly (with `-Verbose:$false` so the import's own load messages don't flood the scan log).
  2. The scan action was passed across the runspace boundary as a live scriptblock object, which retains affinity to the GUI runspace that created it — so it ran against the wrong runspace/thread and couldn't see the module even once imported (and could corrupt the engine). The action is now marshalled as source text and rehydrated inside the worker via `[scriptblock]::Create()`.

  No scan could be launched from the GUI before this fix. The CLI cmdlets were unaffected.
- `Tests/Manual/Test-GuiAsyncDrain.ps1` now resolves a real exported cmdlet (`Invoke-Reconnaissance`) inside the worker runspace, so this class of "module not loaded in the worker" regression is caught by the harness rather than only in the live GUI.

## [2.4.2] - 2026-06-16

### Fixed
- **GUI scan log looked hung / showed nothing useful during a scan.** The scan runspace's `Write-ProgressLine` output is emitted as several `Write-Host -NoNewline` fragments carrying ANSI colour codes. The GUI now strips the ANSI escapes and reassembles the fragments into clean whole lines (e.g. `[1750 UTC] RECON > Connecting to Active Directory`) instead of dropping or garbling them, so live per-phase progress actually appears.
- Footer version was hardcoded to `v2.3.0`; it now reads `ModuleVersion` from the manifest so it can't drift.

### Added
- GUI scan log now also surfaces the **Warning** stream and shows a **`... still working (Ns elapsed)` heartbeat** when a phase goes quiet for more than 5s, so long AD collection phases no longer look hung.
- `Tests/Manual/Test-GuiAsyncDrain.ps1` — a headless WPF-dispatcher harness that exercises the async drain (fragment reassembly, ANSI stripping, warnings, heartbeat, completion).

## [2.4.1] - 2026-06-15

### Fixed
- **GUI: "Run Scan" crashed when a scan finished.** The `OnLog`/`OnComplete`/`OnError` callbacks in `Show-GuerrillaWindow` were built via `GetNewClosure()` *inside* the Run-button click handler. `GetNewClosure()` snapshots only that handler's own locals — not the function-scope helpers it references (`$appendLog`, `$resetOperationsUI`, `$session`, `$brushes`), which are merely visible through the scope chain — so they resolved to `$null` when the DispatcherTimer fired the callbacks (`The expression after '&' in a pipeline element produced an object that was not valid`). The helpers are now localized into the handler scope before the closures are built. This bug was latent since the GUI shipped in 2.3.0 and only surfaced once 2.4.0 fixed the async path to actually fire completion callbacks.
- **GUI: a throwing callback could wedge the window.** `Invoke-GuerrillaGuiAsync` now guards every `OnComplete`/`OnError` invocation and downgrades a failure to a `Write-Warning` instead of letting it escape the timer tick as a raw console error.

## [2.4.0] - 2026-06-10

### Fixed
- **GUI: scan results never reached the window.** The `Invoke-GuerrillaGuiAsync` DispatcherTimer tick handler was not a closure, so `$state`/`$OnComplete`/`$OnError` were unresolvable when the timer fired; additionally, results were read from `EndInvoke` (always empty with the explicit-output `BeginInvoke` overload introduced in 2.3.1) instead of the output collection. Scans now complete, stream logs, and report results; a stray non-terminating error no longer discards a successful scan.
- **Vault-staged Google service-account key leaked to %TEMP%.** `Invoke-Recon`, `Invoke-Fortification`, and `Invoke-Campaign` staged the private key to a temp file and never deleted it. Scan bodies are now wrapped in `try/finally` cleanup.
- **Set-Safehouse could destroy the only copy of a key.** The "delete the original key file?" prompt ran before the vault write; deletion is now offered only after `Set-GuerrillaCredential` succeeds.
- `Save-TheaterState` now writes atomically (temp file + rename), matching `Save-OperationState` — a crash mid-write can no longer corrupt theater state.
- `Register-Patrol` escapes single quotes when embedding paths in the generated patrol-runner script (apostrophes in profile paths no longer break it).
- `Send-SignalSyslog` flattens CR/LF/tab and escapes CEF/LEEF metacharacters in threat-derived fields, preventing log-line forgery via crafted indicator text.
- `Get-Safehouse` again masks plaintext secrets found in config.json (lost in the 2.2.0 vault redesign), warns when no config exists, and no longer hard-fails when SecretManagement is not installed.
- `Show-Guerrilla` validates the thread is STA before loading WPF, replacing an opaque failure under `pwsh -MTA`.
- Renamed shadowed automatic variables: `$error` in `Invoke-IntuneChecks`, `$matches` in the threat-actor matcher (now `Find-ThreatActorProfile`, approved verb).

### Changed
- All `Invoke-RestMethod` calls now carry explicit timeouts: 30s for alert senders, token endpoints, geo/intel lookups; 120s for Graph/Azure RM/Google Admin API wrappers. A hung endpoint can no longer stall a patrol indefinitely.
- Removed ~30 dead variable assignments across check runners, exporters, and senders (PSScriptAnalyzer `PSUseDeclaredVarsMoreThanAssignments` is now clean for Public/Private).
- `Set-Safehouse`/`Get-Safehouse`/config-migration tests rewritten against the 2.2.0+ vault API (they still targeted the retired `-AdminEmail`/`-SendGridApiKey` surface).

## [2.0.0] - 2026-02-27

### Changed
- **Renamed module from PSRecon to PSGuerrilla** with guerrilla warfare-themed cmdlet names
- `Invoke-GoogleRecon` -> `Invoke-Recon`
- `Get-ReconAlerts` -> `Get-DeadDrop`
- `Send-ReconAlert` -> `Send-Signal`
- `Send-ReconAlertSendGrid` -> `Send-SignalSendGrid`
- `Send-ReconAlertMailgun` -> `Send-SignalMailgun`
- `Send-ReconAlertTwilio` -> `Send-SignalTwilio`
- `Set-ReconConfig` -> `Set-Safehouse`
- `Get-ReconConfig` -> `Get-Safehouse`
- `Register-ReconScheduledTask` -> `Register-Patrol`
- `Unregister-ReconScheduledTask` -> `Unregister-Patrol`
- `Get-ReconScheduledTask` -> `Get-Patrol`
- Reorganized Private functions into subdirectories: `Core/`, `Google/`, `Export/`, `Console/`
- Updated all type names: `PSRecon.*` -> `PSGuerrilla.*`
- Updated config/state paths: `$APPDATA/PSRecon` -> `$APPDATA/PSGuerrilla`
- Updated scheduled task name: `PSRecon-ScheduledScan` -> `PSGuerrilla-Patrol`
- Updated all branding strings and alert content

### Added
- Backward-compatible aliases for all 11 old PSRecon function names
- Automatic config migration from `$APPDATA/PSRecon` to `$APPDATA/PSGuerrilla`
- MIT License
- This changelog

## [1.0.0] - 2026-02-01

### Added
- Initial release as PSRecon
- Google Workspace compromise assessment via Admin Reports API
- 7 threat detection signals (known attacker IPs, cloud IP logins, reauth from cloud, risky actions, suspicious country logins, OAuth from cloud, cloud-only logins)
- Threat scoring engine with CRITICAL/HIGH/MEDIUM/LOW/Clean levels
- Incremental scanning with watermark-based state tracking
- HTML, CSV, and JSON report generation
- Alert dispatching via SendGrid, Mailgun, and Twilio SMS
- Scheduled task registration for automated scanning
- GeoIP enrichment via ip-api.com batch API
- CIDR-based cloud provider IP classification (AWS + general cloud/hosting)
- Known attacker IP database with exact-match detection
- Suspicious country login detection (19 countries)
- Config management with JSON persistence
