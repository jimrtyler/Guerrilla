# Changelog

## [2.10.1] - 2026-06-18

### Added
- **Attack-path analysis now flags group-nesting pivots.** Building on v2.10.0's object-control paths, `ADPATH-001` also reports **non-default groups nested inside a Tier-0 group** (Domain / Enterprise / Schema Admins, Administrators, the operator groups) as escalation pivots — controlling such a group, or being added to it, confers the Tier-0 group's privileges. Uses the already-collected recursive privileged-group membership (no new collection); the well-known Tier-0 groups themselves are excluded so only **custom** nesting is flagged. Each path now carries a `PathType` (`Object control` / `Group nesting`).

## [2.10.0] - 2026-06-18

### Added
- **AD attack-path analysis** (`ADPATH-001`, new **"AttackPath"** category). `Invoke-Reconnaissance` now turns the flat dangerous-ACL findings into named **privilege-escalation paths to Tier-0**, each annotated with the concrete takeover technique it enables (e.g. *"CORP\HelpDesk --[WriteDacl]--> Domain Root ⇒ can grant themselves DCSync replication rights and extract every domain hash — Domain Admin equivalent"*). v1 models the highest-value edge class — non-default control (GenericAll / WriteDacl / WriteOwner / replication rights) over a Tier-0 object (the domain root, AdminSDHolder, the Domain Controllers OU, the GPO / Configuration / Schema containers) — which is a **one-hop path to Domain Admin equivalence**. Paths from genuinely **non-privileged** principals are surfaced first as the highest risk. Built entirely on the already-collected ACL + privileged-group data (no new collection); runs under `-Categories All` or `ACLDelegation` / `AttackPath`. **AD coverage is now 204 checks across 15 categories** (460 total).

### Notes
- This is the first increment of the roadmap's headline gap (graph-based attack-path computation). Full **domain-wide transitive** path computation (low-priv user → nested-group control → Domain Admins) requires a full-domain ACL collector, which PSGuerrilla does not yet run (it reads ACLs on the 6 critical objects only); that deeper traversal is the next step, and the engine (`Get-ADAttackPath`) is structured to take additional edge sources directly.
- Regression tests added to `Tests/verify-core-fixes.ps1` (the engine derives paths, flags non-privileged sources, and the check returns FAIL/PASS/SKIP correctly).

## [2.9.4] - 2026-06-18

### Fixed
_From the v2.9.3 live re-validation._
- **MON-4 (regression) — continuous monitoring broke after the first run.** `Invoke-Surveillance` and `Invoke-Wiretap` succeeded once and then threw *"Item has already been added"* on every subsequent run, silently killing `Register-Patrol` scheduled monitoring. The scan-history append used `@($state.scanHistory) += @{...}`, which — once a prior single-entry history reloaded from JSON — performed a hashtable-key merge and threw. Both cmdlets now build history via a new `Add-ScanHistoryEntry` helper (List-based, tolerant of a collapsed single-object history) that always returns a clean array. A two-run regression test was added (the exact case that was missing). (MON-4)
- **`ADPRIV-028` (DCSync rights) now reports instead of always SKIPping.** With the AD-1 ACL fix in place the domain-root DACL is collected, but `ADPRIV-028` read a `DCSyncAccounts` field nothing ever populated. The collector now derives `DCSyncAccounts` from the dangerous-ACE set (filtering the replication extended-right GUIDs `1131f6aa` / `1131f6ad` / `89e95b76` and dropping default Tier-0 principals), so `ADPRIV-028` lights up — completing the DCSync attack-path coverage that AD-1 unblocked. (AD-1b)

### Added
- **`Invoke-Fortification -Quick`** — skips the slow per-user Gmail-settings crawl (which dominates wall-clock on large tenants: ~1.4 s/user, ~11 min for 500 users). Directory, DNS, and OAuth collection still run; the Gmail-dependent EMAIL checks SKIP cleanly. For fast iteration. (GWS-3, partial)

### Notes
- The **full GWS-3 fix** (parallelizing the per-user crawl with `ForEach-Object -Parallel`) is deferred: it needs care with module-function/token availability inside parallel runspaces and live-tenant validation, and getting it wrong would risk the core exfil-detection checks. The `-Quick` profile is the safe mitigation for now.
- **GWS-2b** (labeling sampled-clean results *"SAMPLED N of M"*) already shipped in v2.9.3 via `Get-GmailSampleNote`. Still open from the re-validation: **GWS-1** (Cloud Identity Policy API — blocked on the `cloud-identity.policies.readonly` DWD scope), **ENT-4** (M365 workload coverage), **ENT-5** (Azure IAM messaging).

## [2.9.3] - 2026-06-18

### Added
- **`Get-ComplianceCrosswalk` now surfaces the technical frameworks** already carried on every check. Added `NIST-800-53`, `MITRE-ATTACK`, and `CIS` to `-Framework`, built directly from each finding's `Compliance` map (NIST SP 800-53 controls, MITRE ATT&CK techniques, and CIS benchmarks including CIS-AD / CIS-M365 / CIS-Azure). Previously only the education frameworks (FERPA / COPPA / CIPA / NIST-171 / STATE-EDTECH) were exposed even though the richer mappings were already collected. (REP-2)

### Changed
- **Sampled Google Workspace Gmail checks no longer overstate coverage.** `EMAIL-009/010/011/022` (auto-forwarding, send-as, POP/IMAP, forwarding rules) now append a *"SAMPLED N of M active mailboxes"* qualifier to a clean PASS when only a subset of mailboxes was inspected — so a partial scan can't read as full coverage. Pairs with the random-sampling fix from v2.9.2. (GWS-2)
- **`ADTRADE-002` (DCShadow indicator) softened from Critical to High.** On long-lived domains an unmatched server object under `CN=Sites,CN=Configuration` is far more often **lingering DC metadata** (a DC removed without `ntdsutil` metadata cleanup) than an actual DCShadow attack; the finding now says so and points at the `whenCreated` timestamp to distinguish a recently created (suspicious) object from stale metadata. (ADTRADE-002)

### Fixed
- **Quieter Entra scans on tenants without P2.** `Invoke-GraphApi` now treats license-gated HTTP 400s (`AadPremiumLicenseRequired`, e.g. the PIM schedule-instance endpoints) as a `Write-Verbose` capability-gap note instead of an alarming red `Write-Warning`. (ENT-3)

### Notes
- **Remaining backlog (tracked, not yet done):** GWS-1 (convert the ~60 Google Workspace "verify in Admin Console" placeholders to real checks via the **Cloud Identity Policy API** — blocked until the service account's domain-wide delegation is granted `cloud-identity.policies.readonly`; **adding that scope to the requested set before it is delegated would break all Google auth** with `unauthorized_client`, so this must wait for the scope + live validation); ENT-4 (app-only Graph coverage for M365 workloads / opt-in EXO + Teams modules); ENT-5 (Azure IAM "no ARM access" vs "no resources" messaging — the safe approach is a zero-subscriptions guard that SKIPs with a "grant Reader at the root management group" message); GWS-3 (parallelize Fortification's per-user collection); and `ADDOM-007` replication health (needs a live DC + RSAT/`repadmin` to validate).

## [2.9.2] - 2026-06-18

### Fixed
_Part 2 of the live-environment validation pass — Google Workspace, continuous monitoring, and reporting._
- **Continuous monitoring couldn't use the safehouse vault.** `Invoke-Surveillance` and `Invoke-Wiretap` never read the vault, so a vault-only setup (interactive `Set-Safehouse`, no `guerrilla-config.json`) failed immediately with *"TenantId is required"* — even though `Invoke-Infiltration` handled the same vault fine, and this broke `Register-Patrol` scheduled monitoring for vault installs. Both cmdlets now have a `-VaultName` parameter and resolve `TenantId`/`ClientId`/`ClientSecret` from the vault (`GUERRILLA_GRAPH_*`) as the last resort after parameters and config — the same fallback the audit cmdlets got in v2.5.0.
- **`Invoke-Surveillance` aborted the entire run on the first Graph 403.** Its collectors had no isolation, so a missing Identity-Protection scope (or no Entra ID P2) killed all monitoring. Each collector is now wrapped in `try/catch`; the risk-detection `403` / `AadPremiumLicenseRequired` case degrades to a clear *"requires IdentityRiskEvent.Read.All + IdentityRiskyUser.Read.All scopes and an Entra ID P2 license"* skip, and the sign-in / audit-log signals still run.
- **Google Workspace Gmail sampling was non-random.** `Get-FortificationData` selected mailboxes with `Select-Object -First`, always inspecting the same directory-order prefix (often skewed to a single OU) — so a compromised mailbox later in the list was never examined and a "clean" sampled result gave false assurance. Now uses a **random** sample (`Get-Random`).
- **`Export-RemediationScripts -OutputPath` now works.** It was the only `Export-*` cmdlet using `-OutputDirectory`; added `-OutputPath` as an alias for parity with the other exporters.
- **`Invoke-Watchtower` gained comment-based help** (`.SYNOPSIS` / `.DESCRIPTION` / `.PARAMETER` / `.EXAMPLE`) — `Get-Help` previously returned only auto-generated syntax.

### Notes
- Larger improvements from the same report are tracked as follow-ups: converting the ~60 Google Workspace "verify in Admin Console" always-WARN placeholders into real checks via the **Cloud Identity Policy API** (GWS-1); parallelizing Fortification's per-user collection (GWS-3); and expanding `Get-ComplianceCrosswalk` to surface the NIST 800-53 / MITRE ATT&CK / CIS mappings already present in every check (REP-2).

## [2.9.1] - 2026-06-18

### Fixed
_Surfaced by a live-environment validation pass against a production Active Directory domain and Entra tenant._
- **AD ACL / DCSync / GPO-delegation checks were silently dead.** `Resolve-ADSid` referenced three module-scope caches (`$script:SidCache`, `$script:WellKnownSids`, `$script:WellKnownRids`) that the `.psm1` bootstrap never initialized — so every ACL read threw *"You cannot call a method on a null-valued expression"*, `Get-ADObjectACLs` swallowed it, and `ADACL-012`/`ADACL-014`, `ADGPO-007`/`ADGPO-009`, and the **DCSync-rights check `ADPRIV-028`** all became false SKIPs. The caches are now initialized at load (with the well-known SID/RID tables), with a belt-and-suspenders guard in `Resolve-ADSid`; the domain-RID lookup is gated on `S-1-5-21-*` SIDs to avoid collisions.
- **Tier-0 "tier bleed" checks ERRORed on clean environments.** `ADTIER-002/003/004/005` (Veeam/vCenter/SCCM/SQL service accounts in privileged groups) called `New-TierBleedFinding`, whose `[Parameter(Mandatory)][array]$Hits` **rejected an empty collection** — so the *secure* state (zero hits) threw instead of returning PASS. Added `[AllowEmptyCollection()]`.
- **Entra password-protection checks falsely reported "settings not found".** `Get-EntraAuthMethodsData` queried `/settings` (a beta-only segment that 400s on v1.0); it now uses the v1.0 `/groupSettings` resource, so `EIDAUTH-013`/`EIDAUTH-014` read the real Azure AD Password Protection posture.
- **Removed a redundant, always-400 Graph call.** The standalone `.../authenticationMethodsPolicy/authenticationMethodConfigurations` endpoint isn't directly addressable; the configurations are now sourced from the parent `authenticationMethodsPolicy` object (which already includes them).
- **Quieter logs on healthy domains.** `Invoke-LdapQuery` now treats *"no such object"* (e.g. a domain with no AD CS / Enterprise CA, or an empty DNS partition) as `Write-Verbose` + empty result instead of an alarming `Write-Warning`. The dependent check still SKIPs the same way.

### Notes
- Added `Tests/verify-core-fixes.ps1` covering the `Resolve-ADSid` and `New-TierBleedFinding` regressions.
- Larger improvements from the same validation report — license-gated PIM checks surfacing raw HTTP 400s instead of clean "requires Entra ID P2" SKIPs, app-only Graph coverage for M365 workloads (opt-in EXO/Teams/SharePoint), and Azure IAM "no access vs. no resources" messaging — are tracked as follow-ups.

## [2.9.0] - 2026-06-17

### Added
- **Test mode** — a `-TestMode` switch on `Invoke-Reconnaissance`, `Invoke-Fortification`, `Invoke-Infiltration`, and `Invoke-Campaign`, plus a **"Test mode" checkbox** in the `Show-Guerrilla` Operations tab. When enabled, the scan makes **no live connection** and instead synthesizes a complete **all-FAIL** report straight from the shipped check definitions. Everything downstream behaves exactly like a real scan: report **styles/themes**, **white-label branding**, affected-account lists, scoring, and CSV/JSON output. This lets a consultant preview a fully-populated report — and dial in branding/theme — without a tenant or domain. Works for all three theaters **and the big Campaign report** (which simulates all 459 checks across AD + Google Workspace + Entra/M365).

### Changed
- The **Campaign (big report)** now honours report **themes and white-label branding** too: `Invoke-Campaign` gains `-ReportStyle`, reads branding from config, and `Export-CampaignReportHtml` was moved onto the shared theming engine (Guerrilla / Professional / Slate), including plain **risk-based per-theater labels** in the plain themes. (Previously only the three single-theater reports were themed.)

### Notes
- In test mode the category selection is ignored — a full theater check set is always simulated (the point is a "fully failed report"). Real scans are unaffected.
- Backward compatible: default Guerrilla output is unchanged and all 64 HTML report validation checks still pass.

## [2.8.1] - 2026-06-17

### Fixed
- **Entra / Azure / M365 (Infiltration) scans launched from the GUI appeared to hang.** The scan actually completed, but the GUI's `OnComplete` callback called the module-**private** `Get-PSGuerrillaDataRoot`, which isn't resolvable inside a `GetNewClosure()` closure — so the callback threw *before* resetting the UI, leaving the progress bar spinning on "still working…". The AD and Google Workspace paths were unaffected because their result objects carry `HtmlReportPath` and skipped that branch. Two fixes: the callback now uses the already-captured `$session.ReportsDir` instead of the private function, and `Invoke-Infiltration` now returns `HtmlReportPath` (like the other theaters) so the GUI opens the exact report.
- **Poor contrast in the GUI dropdowns and left navigation.** The "Report style" (and Settings) dropdown popups used WPF's default light system theme, rendering the near-white item text invisible. `ComboBoxItem` now has an explicit dark control template (dark background + light text, with an amber highlight + dark text on hover). The left-nav button text was also dimmed and has been brightened for legibility.

## [2.8.0] - 2026-06-17

### Added
- **Report themes / styles.** Reports can be generated in three visual styles, selectable **per scan** from the Operations tab's new **"Report style"** dropdown (and via a new `-ReportStyle` parameter on `Invoke-Reconnaissance`, `Invoke-Fortification`, and `Invoke-Infiltration`):
  - **Guerrilla** (default, unchanged) — the original dark, tactical theme with FORTRESS / EXPOSED FLANK / OVERRUN posture labels.
  - **Professional** — a light, white-background corporate theme with a sans-serif body and plain **risk-based** labels (Secure / Hardened / Moderate Risk / Elevated Risk / High Risk / Critical Risk).
  - **Slate** — a modern dark dashboard theme, also with plain risk-based labels.

  A new theming engine (`Get-GuerrillaReportTheme`) drives a shared palette of CSS custom properties, so all three audit reports (AD / Google Workspace / Entra-M365) share one consistent look per style.
- **White-label branding.** A new **"Branding"** tab in `Show-Guerrilla` captures firm name, logo (file path or URL), consultant name + email, client / assessed-org name, and a confidentiality banner. These render in the report header (firm + logo, "Prepared by", "Prepared for") with the confidentiality banner across the top. Branding is saved to your config and applied to every subsequent scan. **The "Generated with PSGuerrilla by Jim Tyler, Microsoft MVP" footer attribution is always preserved** regardless of theme or branding.
- Showcase sample reports in the Professional theme with demo branding: `Samples/*-AllFail-Professional.html`.

### Notes
- The default look is unchanged — existing scans render identically (Guerrilla) unless a style is chosen. Backward compatible: all 64 HTML report validation checks still pass.
- Themes + branding currently apply to the three audit reports (Reconnaissance / Fortification / Infiltration). The Campaign roll-up and continuous-monitoring reports keep the Guerrilla styling for now.

## [2.7.0] - 2026-06-17

### Added
- **`Show-Guerrilla` GUI: new "Inspector" tab** — a built-in function & scan **source browser**. Lists every function in the module (801 today), filterable by **area** (Active Directory, Google Workspace, Entra / Azure / M365, Monitoring, Reporting & Export, Public cmdlets, Core & helpers, GUI) and searchable by name. Selecting a function shows its **full source**, the **file path and line number** it lives at, and a **Copy** button — so an operator can confirm exactly what any scan/check is doing without leaving the console or opening the repo. `Show-Guerrilla -StartOn Source` opens directly to it.

### Changed
- **Google Workspace scans now leave "Email Security" unchecked by default** in the GUI's category picker — it's opt-in (the noisier, slower set). Every other Workspace category stays checked, and the "All" toggle reflects the partial selection. Active Directory and Entra / M365 category defaults are unchanged (all checked).

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
