# Changelog

## [2.32.0] - 2026-06-25

_Operations Console redesign + console-hide._

### Changed
- **`Show-Guerrilla` GUI restyled to a light, modern, clean enterprise theme** — white cards, a blue accent (`#2563EB`), rounded corners, Segoe UI typography, subtle borders, and corrected ComboBox/DataGrid contrast (the dropdown/grid text now stays readable on light surfaces). Colors are centralized in `Get-GuerrillaGuiTheme.ps1`; layout, control names, and event logic are unchanged.

### Added
- **Console-hide:** the host PowerShell console is hidden while the GUI is open and restored when it closes. New `-KeepConsole` switch on `Show-Guerrilla` keeps the terminal visible (useful for debugging). Windows-only; the CLI is unchanged.

## [2.31.0] - 2026-06-24

_Three AD collectors that turn previously Not-Assessed checks into real verdicts on a domain controller. Each degrades to Not Assessed when its data/rights/module are unavailable — never a false pass._

### Added
- **NT-hash password quality** (`Get-ADPasswordHashQuality`) — replicates hashes via DSInternals (DCSync) and runs `Test-PasswordQuality`. Lights up **blank-password** (`ADPWD-010`) and **duplicate-password** (`ADPWD-011`) detection, and **privileged weak passwords** (`ADPRIV-016`). HIBP/dictionary/common (`ADPWD-012/013/014`) stay Not Assessed unless a dataset is supplied. **Security:** only account names + counts are kept; NT hashes/cleartext are analysed in memory and never written to the result, disk, or pipeline.
- **Replication health** (`Get-ADReplicationHealth`) — `Get-ADReplicationPartnerMetadata`/`Get-ADReplicationFailure` (or `repadmin`), feeding `ADDOM-007`; a single-DC forest is reported healthy.
- **DC user-rights assignment** (`Get-ADUserRightsAssignment`) — parses the Domain Controllers security template for `SeInteractiveLogonRight` / `SeRemoteInteractiveLogonRight` and flags non-Tier-0 principals, feeding `ADPRIV-026` (local logon) and `ADPRIV-027` (RDP).

## [2.30.3] - 2026-06-24

_Honesty fix — six AD checks could report PASS without actually performing the assessment._

### Fixed
- **DSInternals NT-hash password checks (`ADPWD-010`, `-011`, `-012`, `-013`, `-014`)** — these treated *DSInternals being installed* as *analysis performed* and returned **PASS** ("no blank/duplicate/HIBP/dictionary/common passwords") against a result field that no collector populates. They now return **Not Assessed** when the NT-hash analysis was not actually run (no hash dataset collected — requires replication / ntds.dit access), and still FAIL/PASS correctly once a real dataset is present.
- **AD CS ESC6 (`ADCS-009`)** — read the LDAP `pKIEnrollmentService` `flags` attribute, which cannot carry the `EDITF_ATTRIBUTESUBJECTALTNAME2` policy-module **registry** bit, so it returned a false **PASS** ("not set"). It now reports **Not Assessed** with guidance (`certutil -getreg policy\EditFlags` on each CA host), since the flag isn't determinable via agentless LDAP.

_Surfaced via live-domain Azure lab validation. Related coverage gaps that already SKIP honestly (`ADDOM-007` replication health, `ADPRIV-016` privileged-password strength, `ADPRIV-026/027` DC user-rights) remain Not Assessed and are tracked as planned collector features._

## [2.30.2] - 2026-06-24

_Live-domain reliability fix (validated on a domain controller)._

### Fixed
- **AD well-known group resolution (`ADTRADE-008`, `ADTRADE-009`, and any SID-based lookup)** — the SID→binary conversion called `SecurityIdentifier.GetSidBytes()`, **a method that does not exist**; it threw and was swallowed by the surrounding try/catch, so Cert Publishers / Key Admins / Enterprise Key Admins (and other RID-relative groups) reported *Not Assessed* even when present. Replaced with the correct `GetBinaryForm` in `Get-ADTradecraftSignals.ps1`, `Get-ADPrivilegedMembers.ps1`, and `Resolve-ADSid.ps1`. Confirmed against a live domain controller: the groups now resolve and the checks return real PASS/FAIL verdicts. (2.30.1 mis-attributed this to a byte[] objectSid issue — `objectSid` is already converted to a string upstream — so this is the actual root cause.)

## [2.30.1] - 2026-06-24

_Reliability fixes from live validation of the v2.30.0 checks. No check-count or public-surface change (580 checks)._

### Fixed
- **AD Tier-0 group resolution (`ADTRADE-008`, `ADTRADE-009`)** — the domain SID was read as a raw `System.Byte[]` and string-interpolated, producing a malformed SID so the RID-relative lookups for **Cert Publishers / Key Admins / Enterprise Key Admins** always failed and the checks reported *Not Assessed*. Now converted to the canonical SID string before use, so membership is evaluated correctly (an honesty-doctrine fix — a disguised SKIP could hide real members).
- **Entra Connect / hybrid identity (`EIDFED-013` and the federation family)** — hybrid detection no longer depends solely on `/directory/onPremisesSynchronization` (which requires `OnPremDirectorySynchronization.Read.All` and returns 403 without it). It now falls back to the authorized `organization.onPremisesSyncEnabled` signal and synced-user count, so a synchronized tenant is no longer misreported as cloud-only. The Azure AD Connect configuration review (`EIDFED-005`) no longer returns **PASS** when the sync configuration is unreadable — it reports **Not Assessed** and distinguishes a genuine cloud-only tenant from a hybrid tenant whose config is forbidden.

### Changed
- **Shadow-credential check (`ADTRADE-006`)** — distinguishes legitimate Windows Hello for Business / Entra hybrid device-registration keys on **member computers** (reported as **WARN**, review-only) from key credentials on **user/admin principals or domain controllers** (reported as **FAIL**, the real shadow-credential primitive). Eliminates the false positive on hybrid-joined estates while preserving detection of the actual attack.

## [2.30.0] - 2026-06-23

_+63 checks (580 total) — closing remaining framework-coverage gaps across all three theaters._

### Added
- **Exchange Online depth (+36)** — `M365EXO-013`…`M365EXO-048` implementing the CISA SCuBA EXO baseline: anti-spam / anti-phishing / malware depth, Safe Links & Safe Attachments, mail-flow and external-forwarding controls, SPF/DKIM/DMARC, connection filtering, mailbox auditing, and audit-log retention. Extended the Exchange collector accordingly (`Get-TransportConfig`, `Get-SharingPolicy`, `Get-HostedConnectionFilterPolicy`, `Get-HostedOutboundSpamFilterPolicy`, `Get-AcceptedDomain`, `Get-AtpPolicyForO365`, `Get-ExternalInOutlook`, DNS mail-security resolution).
- **Active Directory indicators (+6)** — `ADTRADE-005`…`ADTRADE-010`: Seamless SSO `AZUREADSSOACC` Kerberos key age (Silver-Ticket exposure), shadow credentials (`msDS-KeyCredentialLink`) on privileged objects, delegated-MSA migration escalation (BadSuccessor), Enterprise/Key Admins membership, Cert Publishers membership, and gMSA password-exposure posture.
- **Google Workspace SCuBA baselines (+15)** — new **Workspace Service Security** category (`GwsService`) covering Google Sites, Classroom, and Gemini, plus Assured Controls under Admin & User Management. Controls the Cloud Identity Policy API does not surface report as Not Assessed with Admin-console verification guidance.
- **Entra ID SCuBA completion (+5)** — `MS.AAD` controls for Authenticator number-matching context, password-never-expires, group-owner app consent, risky-user notification (manual/Not-Assessed), and managed-device MFA registration.
- **`EIDFED-013` — Entra Connect sync-client version currency** — flags an outdated Entra Connect (Tier-0 hybrid component) against a minimum-safe baseline. Server-side read (registry / `Get-ADSyncGlobalSettings`) yields a definitive PASS/FAIL; cloud-only runs report Not Assessed with the server-side path. Includes a pure version comparator with unit tests.

### Notes
- Counts: Active Directory 211, Entra ID / Azure / Intune / M365 244, Google Workspace 125 = **580 checks**; 49 public functions. Read-only.
- Honesty preserved: every control whose data cannot be collected returns **Not Assessed (SKIP/WARN)** — never a pass.

## [2.29.1] - 2026-06-21

_Documentation cleanup — no functional change._

### Changed
- Re-articulated the **EIDSCA checks** to describe each control by its Microsoft Graph setting and recommended value (functional remediation, no external links). Removed third-party product references from shipped help text, check descriptions, and this changelog — describing every feature on its own merits. No code, check logic, scoring, or count changes (517 checks, 49 public functions).

## [2.29.0] - 2026-06-21

_Turnkey CI/CD — a GitHub Action and a severity gate for security-config-as-code._

### Added
- **`Get-GuerrillaCIGate`** — decides whether a CI build should fail from findings + a `-FailOn` severity threshold (`Critical` / `High` / `Medium` / `Low` / `Any` / `None`). FAIL gates (plus WARN with `-WarningsAsFailures`); SKIP / "Not Assessed" never gates. Returns `{ShouldFail; GatingCount; GatingCheckIds}`.
- **`action.yml`** — a turnkey GitHub Action (composite) at the repo root: installs the module, runs a chosen theater (Infiltration / Reconnaissance / Fortification / Campaign), publishes JUnit results via `Export-GuerrillaJUnit`, and gates the build. The caller authenticates to the tenant/domain first; the Action does not handle auth.

### Notes
- Builds on the JUnit primitive. Gating logic is unit-tested (`Tests/verify-ci-gate.ps1`, 11/11); the Action itself wraps validated cmdlets — confirm end-to-end in a live runner. 49 public functions; 517 checks unchanged.

## [2.28.1] - 2026-06-21

_Release-notes maintenance — no functional change._

### Changed
- Refreshed the PSGallery release notes. No code, check, or scoring changes — module behavior is identical to 2.28.0 (517 checks, 48 public functions).

## [2.28.0] - 2026-06-21

_Interactive findings filter in the AD report — completes the interactive report experience._

### Added
- **Interactive findings filter** in the Reconnaissance report — a live filter bar (**status + severity buttons + text search**) over both findings tables, matching what the Campaign report already had. New shared helper `Get-GuerrillaFindingsFilterHtml`; finding rows are tagged `gg-row` / `data-status` / `data-sev` / `data-text` and filtered client-side (auto-opens collapsed categories so matches show, with a "no findings match" notice). Print-safe (the bar hides on print).

### Notes
- This completes the interactive report work (filter + Indicators of Exposure). Report/presentation only — no engine, check, or scoring changes (517 checks, 48 public functions). Samples regenerated. Test: `Tests/verify-report-sections.ps1` (39/39 — filter bar, tagged rows, and filter script present).
- Remaining roadmap: deeper Exchange Online coverage (needs a live tenant) and additional Entra ID governance checks.

## [2.27.0] - 2026-06-21

_Indicators of Exposure — a ranked, severity-scored exposure view in every report._

### Added
- **Indicators of Exposure** (`Get-GuerrillaIndicatorsOfExposureHtml`) — a ranked view of the estate's *actual* exposures, added to the **Reconnaissance, Google Workspace, Campaign, and Technical** reports. Each open (FAIL/WARN) finding becomes a named, severity-scored indicator with its **blast radius** (affected-object count); the list is ranked by severity → FAIL-before-WARN → impact, under a Critical/High/Medium/Low summary. It's the same data you already collect, presented the way a CISO expects to read it.

### Notes
- Report/presentation only — no engine, check, or scoring changes (517 checks, 48 public functions). Samples regenerated (the Infiltration/Campaign samples now also include the 44 EIDSCA checks). Test: `Tests/verify-report-sections.ps1` (36/36 — IOE ranking, severity ordering, empty-when-all-pass, plus presence in all four reports).
- Remaining roadmap: interactive findings filter, deeper Exchange Online coverage (+ SCuBA MS.EXO baseline refresh), and additional Entra ID governance checks.

## [2.26.0] - 2026-06-21

_Security config as code — JUnit output for CI/CD pipelines._

### Added
- **`Export-GuerrillaJUnit`** — converts any theater's findings (AD / Entra / M365 / Google Workspace) to **JUnit XML**, the format GitHub Actions, Azure DevOps, and GitLab render natively as pass/fail. One `<testsuite>` per category, one `<testcase>` per check: **FAIL → `<failure>`** (typed by severity), **SKIP/ERROR → `<skipped>`** ("Not Assessed", never a silent pass), WARN passes with output (or `-WarningsAsFailures` to gate on it too). Returns `{Tests; Failures; Skipped; Passed}` so a pipeline can `if ($r.Failures) { exit 1 }`.

### Notes
- PSGuerrilla results now render natively in CI/CD pipelines, across **all four theaters**. Copy-paste GitHub Actions / Azure DevOps / GitLab templates are available; a dedicated GitHub Action is a follow-on.
- 48 public functions; check counts unchanged (517). Test: `Tests/verify-junit.ps1` (14/14 — valid XML, per-category suites, FAIL/SKIP/WARN mapping, `-WarningsAsFailures`, XML escaping, gating counts).
- Remaining roadmap: the interactive report (filter + Indicators of Exposure), deeper Exchange Online coverage, and additional Entra ID governance checks.

## [2.25.0] - 2026-06-21

_Conditional Access what-if simulation — the live Graph evaluate API, with pre-built attack scenarios._

### Added
- **`Test-GuerrillaConditionalAccess`** — simulates a sign-in against the tenant's live CA policies via `POST /beta/identity/conditionalAccess/evaluate` (`signInIdentity` / `signInContext` / `signInConditions`) and **normalizes the applied policies into a single verdict** (Block / MfaRequired / CompliantDeviceRequired / PasswordChangeRequired / Grant / NotApplied / Unknown).
- **`Invoke-Infiltration -WhatIfUserId <guid>`** runs a **pre-built attack-scenario matrix** (legacy-auth, no-MFA cloud sign-in, high sign-in risk, high user risk, unmanaged device) against that user and grades each PASS/FAIL . Results land in `ConditionalAccess.WhatIf` and drive **`EIDCA-015`**, which was a placeholder/inference and is now a real, authoritative simulation when a user is supplied.

### Changed
- `EIDCA-015` now reports **live what-if** results when available; without `-WhatIfUserId` it falls back to the previous policy-config **inference, clearly labeled** as such (not a live simulation).

### Notes
- The CA evaluate API is **beta**: any empty/unrecognised response normalizes to `Unknown` → the scenario grader returns **SKIP = "Not Assessed"**, never a false PASS. (Same honesty rule; will need re-pinning if the API GAs with a changed shape.)
- 47 public functions; check counts unchanged (517). Test: `Tests/verify-ca-whatif.ps1` (19/19 — normalizer across response shapes, grader, scenario catalog, and EIDCA-015 live grading incl. no-data→SKIP). Live Graph POST validated separately on a tenant.
- Remaining roadmap: deeper Exchange Online coverage (+ SCuBA MS.EXO baseline refresh).

## [2.24.0] - 2026-06-21

_Full EIDSCA coverage — the 44-control Entra ID Security Config Analyzer baseline, evaluated for real._

### Added
- **Full EIDSCA baseline (44 controls)** as a new **`Eidsca`** category covering the EIDSCA control set (AF/AG/AM/AS/AT/AV authentication-method controls, AP authorization-policy, CP/CR consent, PR password-protection, ST guest-group settings). Each control is evaluated against its documented Microsoft Graph setting (Graph object + exact property path + operator + expected value), defined in `Data/AuditChecks/EidscaChecks.json`.
- A data-driven evaluator (`Resolve-EidscaControl`) runs the catalog against the raw Graph policy objects PSGuerrilla **already collects** (`authenticationMethodsPolicy`, `authorizationPolicy`, `adminConsentRequestPolicy`, directory `settings`) — no new collection needed. Surfaced via `Get-ComplianceCrosswalk -Framework EIDSCA` and the new category in `Invoke-Infiltration`.

### Changed
- EIDSCA coverage went from **10 approximate tags → 44 controls evaluated**. The interim `eidsca` tags on existing Entra checks (v2.22.0) were removed so the dedicated EIDSCA category owns the framework (no duplicate crosswalk rows).
- Check count: **473 → 517** (Entra/M365 158 → 202). AD 205, GWS 110 unchanged.

### Notes
- **Honest by design**: any control whose source policy/setting wasn't collected (scope/module not connected) returns **SKIP = "Not Assessed"**, never PASS. Verified.
- Test: `Tests/verify-eidsca.ps1` (18/18 — every source type + operator, FAIL on misconfig, SKIP on missing data, dispatcher + crosswalk). Offline-validated; live confirmation pending on a tenant.
- Next: Conditional Access what-if and deeper Exchange Online coverage (the SCuBA MS.EXO baseline mapping was undercounted and needs a refresh).

## [2.23.0] - 2026-06-21

_Fixes from the v2.22.0 live-validation pass — the attack-path visuals now render on real data, and "not assessed" stops reading as "compliant."_

### Fixed
- 🔴 **Attack-path visuals rendered empty on real domains.** The shared report code read `Details.Chains` (only `ADPATH-002` carries that) but `ADPATH-001` exposes its rich objects under **`Details.Paths`**, and the `@($null).Count == 1` gotcha defeated the `AffectedItems` fallback — so both the **Attack Paths to Tier-0** list and the **Attack-Path Cartography** SVG came up empty despite real escalation paths. A shared gather now reads **both** shapes, filters `$null` explicitly, excludes by-design `Expected` service-account paths, and derives hop count when `Length` is absent. Fixes all three reports (Reconnaissance / Campaign / Technical). Unit tests now exercise the `ADPATH-001` `Paths` shape and `Expected` exclusion.
- **Compliance crosswalk silently dropped SKIP'd checks**, making coverage read artificially low (e.g. ~24 surfaced vs ~72 tagged on a partial connection). SKIP findings now surface with `Status='SKIP'` ("Not Assessed") so the crosswalk distinguishes *passed* from *not looked at*; only `ERROR` is dropped. (`-FailOnly` behaviour unchanged.)
- **Maturity model rated all-SKIP categories as "Level 5 — Optimized"** (absence of evidence scored as success — same class as the old GTRADE-001 false-PASS). An estate or category with no PASS/FAIL/WARN now reports **Level 0 = "Not Assessed"**, never 5.

### Changed
- **BloodHound export** now resolves well-known privileged groups (Domain/Enterprise/Schema Admins, builtin operator aliases, etc.) to their **real SIDs** — domain SID derived from member SIDs + well-known RID/alias tables — so they overlay SharpHound's nodes instead of landing as parallel `NAME:<group>` nodes that break cross-tool pathfinding.
- **Full-domain ACL sweep now includes `organizationalUnit` objects**, so OU delegation (full-control / WriteDacl / WriteOwner on an OU) is no longer invisible to the sweep.

### Notes
- All report/honesty fixes — no check logic, scoring, or count changes (473 checks, 46 public functions). Credit: the live-validation pass on a ~19.5k-object domain + partial-connection tenant. Tests: report-sections 29/29, maturity 22/22, bloodhound 14/14, full-domain ACL 18/18, SCuBA 12/12.

## [2.22.0] - 2026-06-21

_CISA SCuBA baseline crosswalk — PSGuerrilla now produces a SCuBA secure-configuration mapping, not just prose references._

### Added
- **CISA SCuBA crosswalk**: 55 Entra/M365 checks now carry `scuba` compliance tags mapping to the published CISA SCuBA baseline policy IDs (MS.AAD / MS.EXO / MS.SHAREPOINT / MS.TEAMS / MS.DEFENDER / MS.POWERPLATFORM). `Get-ComplianceCrosswalk -Framework SCUBA` emits per-policy mapping rows, and the Executive Summary auto-surfaces a "SCUBA: N gap(s)" chip. **~76% of the assessable SCuBA baseline mapped** (72 of 95 policies; see the coverage matrix). Baseline IDs were taken from CISA's published SCuBA baselines, not fabricated.
- **EIDSCA tagging**: 8 checks tagged with `eidsca` control IDs; `Get-ComplianceCrosswalk -Framework EIDSCA`.

### Changed
- `New-AuditFinding` now carries `Scuba` and `Eidsca` compliance arrays through to finding objects — the one engine change required for the new tags to flow into the crosswalk.

### Notes
- **Honest by design**: only *tagged* checks produce SCuBA rows. 23 baseline policies and all of Microsoft Power BI are **not yet assessed** (no Power BI checks exist) — a report says "not assessed" rather than implying full compliance. The GAP list feeds a future net-new-check release (S1.4).
- Tag-only change: no check logic, scoring, or count changes (473 checks, 46 public functions unchanged). Clean additive JSON diffs. Test: `Tests/verify-scuba-crosswalk.ps1` (12/12 — tags survive finding construction, SCUBA/EIDSCA rows produced + filter, untagged checks emit none, no CIS/NIST regression).

## [2.21.0] - 2026-06-21

_Attack-Path Cartography — a native visual map of escalation routes to Tier-0._

### Added
- **Attack-Path Cartography** (`Get-GuerrillaCartographyHtml`) — a native, in-report **SVG node-link map** of the escalation routes to Tier-0, laid out left-to-right by longest-path rank. Non-privileged starting points are red (&#9873;), already-privileged amber, Tier-0 objectives gold (&#9733;); shared targets (e.g. Domain Admins reached from multiple sources) converge into one node. It's built entirely from the attack-path chain data already in findings — **no extra collection, no external tool** — so it renders self-contained in the HTML. Added to the **AD reconnaissance**, **Campaign**, and **Technical** reports (renders only when AD attack paths exist; capped at 25 paths with a shown notice).

### Notes
- Sits *alongside* the BloodHound export (a static picture in the report + the full interactive graph in BloodHound CE). The attack-path program is now complete — maturity model, transitive attack-path engine, full-domain ACL collection, BloodHound export, and cartography all shipped.
- Report/presentation only — no engine, check, or scoring changes. Check counts and 46 public functions unchanged. Samples regenerated to include the map. Test: `Tests/verify-report-sections.ps1` (24/24).

## [2.20.1] - 2026-06-21

_All four HTML report types now carry maturity + attack paths; sample reports regenerated to match._

### Changed
- **`Export-TechnicalReport`** (the README-linked "all checks" report) now also includes the **Security Maturity** and **Attack Paths to Tier-0** sections, so all four report types (Reconnaissance, Fortification, Campaign, Technical) are consistent.
- Shared section accent colour made theme-portable (`--deep-orange`, defined in every report theme) so the sections render correctly in the Technical report's standalone stylesheet.
- **Sample/showcase reports regenerated**: every sample now shows maturity; the AD, Campaign, and Technical samples show full attack-path chains; the AD sample shows the BloodHound callout. Added a **Campaign sample** (`Samples/Campaign-AllFail.html`) and a **sample BloodHound export** (`Samples/Reconnaissance-BloodHound.json`). `Generate-SampleReports.ps1` now also (re)generates the README root sample (`PSGuerrilla-Sample-Report.html`) so it can't fall behind the templates again.

### Notes
- Report/presentation only — no engine, check, or scoring changes. Check counts and 46 public functions unchanged. Test: `Tests/verify-report-sections.ps1` (18/18 — now covers all four report types).
- Remaining: cartography (the visual domain/trust/attack-path map).

## [2.20.0] - 2026-06-21

_Reports now showcase what PSGuerrilla actually does — maturity, attack paths, and the BloodHound export are no longer buried._

### Added
- **AD reconnaissance report** (`Export-ReconnaissanceReportHtml`) gains three sections:
  - **Security Maturity** (CMMI 1-5) — the maturity rating was previously only in the Executive Summary; a normal scan's HTML now shows it.
  - **Attack Paths to Tier-0** — renders the **full** transitive chains (`HelpDesk --GenericAll--> CORP-Helpdesk-Admins --MemberOf--> Domain Admins`), non-privileged sources first, instead of the single buried finding-row preview. When none are found it names the coverage lever (`-FullDomainAcl`).
  - **BloodHound Export callout** — when `-BloodHoundPath` was used, the report shows the written file path and BloodHound CE import steps.
- **GWS report** (`Export-FortificationReportHtml`) gains the **Security Maturity** section (GWS Adversary Tradecraft findings were already surfaced via the detailed-findings renderer).
- **Unified Campaign report** (`Export-CampaignReportHtml`) — the "one big report" — gains **Security Maturity** and **Attack Paths to Tier-0** across all theaters, so the aggregate view is no longer missing the marquee features.

### Changed
- `Invoke-Reconnaissance` now runs the BloodHound export **before** report generation so the HTML callout references a file that already exists.
- New shared helpers (`Get-GuerrillaMaturitySectionHtml`, `Get-GuerrillaAttackPathSectionHtml`) keep the three reports' sections identical and theme-agnostic.

### Notes
- Report/presentation only — no engine, check, or scoring changes. Check counts and 46 public functions unchanged.
- Test: `Tests/verify-report-sections.ps1` (15/15 — shared helpers in isolation, plus maturity/attack-path/BloodHound inclusion across the recon, GWS, and Campaign reports).
- Remaining: cartography (the visual domain/trust/attack-path map).

## [2.19.0] - 2026-06-20

_Full-domain ACL collector — shallow one-hop findings become deep low-priv → Domain Admins chains._

### Added
- **Full-domain ACL collector** (`Get-ADFullDomainAcl`, surfaced via **`Invoke-Reconnaissance -FullDomainAcl`**). Where the existing collector reads ACLs on the six critical Tier-0 objects, this sweeps **every group / user / computer / gMSA** in the domain, parsing each DACL from the binary `nTSecurityDescriptor` in one paged LDAP query (**no per-object DirectoryEntry bind** — the per-object path doesn't scale to a domain). Dangerous, non-default control ACEs are merged into `ACLs.DangerousACEs`, so the transitive attack-path engine **and** the BloodHound export consume them unchanged.

### Fixed
- **Chains now actually form.** ACE records previously carried no `ObjectClass` or `ObjectSID`, so the transitive engine could never classify an ACE target as a group node (`grp:`) and chains dead-ended regardless of coverage. Every ACE the full-domain collector emits now carries **`ObjectClass` + `ObjectSID` + `ObjectName`**, so a principal with `GenericAll`/`WriteDacl`/`WriteOwner` over a group anywhere in the Tier-0 membership closure produces a real transitive path (e.g. `HelpDesk --GenericAll--> CORP-Helpdesk-Admins --MemberOf--> Domain Admins`), and BloodHound keys the target node by SID.

### Notes
- **Opt-in** (off by default — it is the heaviest read PSGuerrilla performs). `MaxObjects` cap of 50000 with **explicit truncation reporting** (`FullDomainTruncated` + a log line — never a silent cap). SID→name resolution is cached. Read-only throughout.
- Detection vocabulary matches the critical-object pass (GenericAll/GenericWrite/WriteDacl/WriteOwner + dangerous extended rights + WriteProperty on dangerous GUIDs incl. `member`, `msDS-KeyCredentialLink`, DCSync, ForceChangePassword), with self-ACE / SELF / CREATOR OWNER skips on top of the existing default-principal ignores; the engine still applies its own default-principal exclusion downstream.
- 46 public functions. Test: `Tests/verify-fulldomain-acl.ps1` (18/18 — dangerous-ACE predicate, the `ObjectClass`/`ObjectSID` chain fix end-to-end through the engine, a regression guard proving no `ObjectClass` → no chain, and SID-keyed BloodHound nodes). Check counts unchanged.
- Remaining: cartography (the visual domain/trust/attack-path map). The next depth lever beyond this is full-domain *group membership* (control edges already land in the existing Tier-0 closure; all-group membership widens multi-control-hop chains through non-privileged groups).

## [2.18.0] - 2026-06-20

_BloodHound export — PSGuerrilla now feeds the best attack-path graph tool, free._

### Added
- **`Export-BloodHoundData`** — exports the collected AD graph (privileged-group membership + dangerous ACLs) to a **BloodHound CE OpenGraph** file. Nodes are **SID-keyed** (overlay cleanly with native SharpHound data) and edges use BloodHound's **native kinds** (`GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`, `AllExtendedRights`, `GetChanges`, `GetChangesAll`, `MemberOf`) so BloodHound's built-in pathfinding works over them directly. Unlike the in-report engine, the export includes the **full** graph (no default-principal exclusion) — BloodHound does its own reachability analysis. Import via BloodHound CE > Administration > File Ingest.
- **`Invoke-Reconnaissance -BloodHoundPath <file>`** writes the export as part of a normal scan; the result object gains `BloodHoundPath`.

### Notes
- This makes PSGuerrilla a **free BloodHound feeder** — the agentless, quiet collector that also hands you a graph (SharpHound gets flagged by EDR; this doesn't touch endpoints). Exported edge coverage tracks ACL collection (the six critical Tier-0 objects + privileged membership today); the full-domain ACL collector (roadmap) widens it and the exporter consumes it unchanged.
- Read-only. 46 public functions. Test: `Tests/verify-bloodhound-export.ps1` (12/12 — OpenGraph shape, SID-keyed nodes, native edge kinds incl. replication→GetChangesAll, MemberOf, provenance). Check counts unchanged.
- Remaining: the **full-domain ACL collector** (deepens both ADPATH-002 and this export) and **cartography**.

## [2.17.0] - 2026-06-20

_Transitive attack-path engine — chains control + group-membership edges to Tier-0._

### Added
- **Transitive attack-path engine** (`Resolve-AttackPathGraph` + `Get-ADTransitiveAttackPath`). A directed privilege graph where every edge points "toward more privilege" (control + group-membership), with a **BFS shortest-path** resolver that chains edges of **arbitrary length** to Tier-0 — e.g. `HelpDesk --[WriteDacl]--> CORP-Admins --[MemberOf]--> Domain Admins`. Cycle-safe and depth-bounded. Builds on the existing default-principal exclusion (no v2.10.x false positives).
- **New check `ADPATH-002` — Transitive Escalation Chains to Tier-0** (AttackPath category). Reports multi-hop chains (the single-hop case stays ADPATH-001's job), non-privileged sources first. **AD is now 205 checks (473 total).**

### Notes
- **Chain depth is bounded by ACL-collection coverage.** Today's six-critical-object collection yields mostly one-hop edges, so ADPATH-002 is typically clean on current data; the **full-domain ACL collector** (live-gated, next increment) populates control edges over arbitrary objects and unlocks deep low-privilege-to-Domain-Admin chains. The engine itself is validated for arbitrary depth: `Tests/verify-transitive-attackpath.ps1` (13/13) proves 3-hop chaining, shortest-path selection, cycle-safety, and depth bounding.
- **Still to come:** the full-domain ACL collector, the **BloodHound export**, and **cartography** (visual domain/trust/attack-path map).

## [2.16.0] - 2026-06-20

_Maturity rating now lands in the board-facing report._

### Added
- **`Export-ExecutiveSummary` now surfaces the Security Maturity rating.** A color-coded **Level X/5** badge in the stat row, plus a **"Security Maturity"** card with the overall level + label, the **next-level blockers** (what to fix to climb one level), and a **per-category maturity table** — computed via `Get-GuerrillaMaturity` from the report's findings. This is a board-facing maturity artifact, and it's strict (worst-unmet-control anchors the rating).

### Notes
- Report-only change; no new checks (counts unchanged). Validated: the section/badge/table render and are severity-color-coded (Level 1 = red through Level 5 = green); empty-findings path is safe.
- Remaining: **cartography** (visual domain/trust/attack-path map in the report) and the **full-domain transitive attack-path graph + BloodHound export**. Surfacing maturity in the per-theater Reconnaissance and Campaign reports is a small follow-on.

## [2.15.0] - 2026-06-20

_Maturity model — an executive-grade CMMI 1-5 maturity rating._

### Added
- **`Get-GuerrillaMaturity`** — a CMMI-style **1–5 security maturity** rating computed from audit findings (Active Directory, Google Workspace, or Entra/M365). Like a maturity model should, the **worst unmet control anchors the score**: a single open Critical caps the whole estate at **Level 1 (Initial)** regardless of how much else passes — stricter and more honest than an averaged 0–100 score, and the way an auditor/board reads posture.
  - Levels: 1 Initial → 2 Managed → 3 Defined → 4 Quantitatively Managed → 5 Optimized. Anchoring: FAIL caps by severity (Critical→1, High→2, Medium→3, Low→4), any WARN caps at 4; PASS/SKIP/ERROR never cap.
  - Returns the **overall level + label**, **per-category levels**, the exact **anchor findings** holding you at the current level, and the **next-level blockers** (so advancement is concrete). Accepts pipeline input: `(Invoke-Reconnaissance).Findings | Get-GuerrillaMaturity -Theater ActiveDirectory`.

### Notes
- Next: surface this in the AD/Campaign reports as a maturity section + **cartography** (visual domain/trust/attack-path map), then the **full-domain transitive attack-path graph + BloodHound export**.
- 45 public functions now (was 44). Regression test: `Tests/verify-maturity.ps1` (17/17). Check counts unchanged.

## [2.14.1] - 2026-06-20

_Live-validation fixes for the Adversary Tradecraft category._

### Fixed
- **GTRADE-001 (DeleFriend) no longer reports a false PASS.** There is no GA Directory API to *list* domain-wide-delegation grants (the legacy `/domainwidedelegation` path 404s on many tenants), so an empty collection means "could not enumerate," not "no grants." The check previously reported **PASS "no grants configured"** on emptiness — a false all-clear on the highest-value Google persistence vector. It now returns **WARN** with manual-verify guidance when grants can't be enumerated, and only PASS/FAIL when grants are actually present. (Also fixed the same empty→PASS masking in **OAUTH-008**.) Note: `@($null).Count` is 1, so the null case is now filtered explicitly.
- **GTRADE-005 (super-admin-equivalent custom roles) no longer over-matches read-only roles.** The privilege matcher used guessed names; it now uses the **real Google admin privilege vocabulary** (`USERS_ALL`/`USERS_CREATE`/`USERS_RESET_PASSWORD`/`GROUPS_ALL`/`DOMAIN_MANAGEMENT`/`ORGANIZATION_UNITS_*`/`APP_ADMIN`/`ROLE_MANAGEMENT`/`MANAGE_*`/`SECURITY`) and **excludes read-only (`_RETRIEVE`) privileges**, so a directory-reader role is no longer flagged as super-admin-equivalent.

### Changed
- **GTRADE-006** now labels OAuth grants with no friendly app name as `unnamed app (<client_id>)` instead of surfacing a bare numeric/platform string, keeping the finding actionable.

### Notes
- Live validation confirmed the v2.13.0 enum values (all booleans / a `"0s"` duration) — existing grading is correct, no change needed.
- GTRADE-002/003 (group exposure) remain pending live confirmation until the `apps.groups.settings` domain-wide-delegation scope is delegated on the assessing service account; graceful degradation (collector → `$null` → SKIP, scan completes) was confirmed live.
- Counts unchanged (GWS 110 / AD 204 / Entra 158). `Tests/verify-gws-tradecraft.ps1` now 24/24; test-mode dispatches 110 findings, 0 ERROR.

## [2.14.0] - 2026-06-20

_New Google Workspace **Adversary Tradecraft** category — detecting attack preconditions Google itself does not surface or alert on. GWS is now 110 checks across 9 categories (472 total)._

### Added
- **New GWS category: Adversary Tradecraft** (`GoogleTradecraftChecks`, 6 checks), the Google-Workspace analog of the AD Tier-0 / NTLM-relay-precondition checks. All read-only, weakest-OU/any-hit grading, graceful SKIP when data is unavailable:
  - **GTRADE-001 — Domain-Wide Delegation org-takeover exposure (DeleFriend).** Flags DWD grants holding org-impersonation scopes (full `mail.google.com`, full `drive`, `admin.directory` write, `cloud-platform`, `apps.groups`) — each is a DeleFriend takeover target if its service account gets a new key. (Full confirmation — a user-managed key on the SA — needs GCP IAM, a Phase-2 scope; flagged in the finding.)
  - **GTRADE-002 — Internet-readable Google Groups** (`whoCanViewGroup = ANYONE_CAN_VIEW`), the Kenna/UpGuard data-leak class Google doesn't alert on.
  - **GTRADE-003 — Open-join / external-member groups** (anyone-can-join or external members) — the open-group → IAM escalation precondition Google classifies "Won't Fix."
  - **GTRADE-004 — Super-admin sprawl** (count vs. the <5 best practice).
  - **GTRADE-005 — Super-admin-equivalent custom roles** (custom roles carrying user/security/role-management or data-export privileges).
  - **GTRADE-006 — Persistent / over-scoped OAuth grants** (full mail/drive/admin scopes that bypass MFA and survive a password reset — GhostToken-class).
- **New collector `Get-GoogleGroupSettings`** — enriches directory groups with exposure settings (`whoCanViewGroup` / `whoCanJoin` / `allowExternalMembers`) via the Groups Settings API on the **already-requested `apps.groups.settings` scope**. Isolated token (graceful SKIP if undelegated); per-group, gated by `-Quick` like the Gmail crawl; caps at 1000 groups and logs truncation (never silent). Wired into `Get-FortificationData` as `$data.GroupSettings`.

### Notes
- **Google Workspace is now 110 checks across 9 categories** (was 104 / 8); module total **472** (was 466). Counts updated in README; the new category runs under `Invoke-Fortification` (real + test mode) and `Invoke-Campaign`.
- **Phase-2 (deferred, needs a GCP IAM / `cloud-platform` read scope + new collector):** full DeleFriend confirmation (SA user-managed key × DWD), stale long-lived SA keys, and open-group→IAM-binding correlation. These can't be added without a new scope and live validation, so they're tracked, not shipped.
- Regression test: `Tests/verify-gws-tradecraft.ps1` (23/23). Test-mode Fortification dispatches all 110 findings with 0 ERROR.

## [2.13.0] - 2026-06-19

_Google Workspace coverage expansion — 6 net-new checks + ADMIN-008/009 converted. GWS is now 104 checks (466 total)._

### Added
- **6 net-new Google Workspace security checks** (all read live Cloud Identity policy, weakest-OU-wins, API-unavailable → SKIP):
  - **AUTH-014 (2SV Enrollment Allowed)** → `security.two_step_verification_enrollment.allowEnrollment` — WARN if users are blocked from enrolling in 2SV.
  - **AUTH-015 (2SV Enrollment Grace Period)** → `security.two_step_verification_grace_period.enrollmentGracePeriod` — PASS ≤ 7 days, WARN if longer (longest-OU).
  - **AUTH-016 (Advanced Protection Self-Enrollment)** → `security.advanced_protection_program.enableAdvancedProtectionSelfEnrollment` — PASS when high-risk users can self-enroll in APP.
  - **AUTH-017 (Super Admin Account Self-Recovery)** → `security.super_admin_account_recovery.enableAccountRecovery` — **FAIL** if super-admin self-service recovery is on (account-takeover path).
  - **COLLAB-011 (Meet External Participant Labeling)** → `meet.safety_external_participants.enableExternalLabel` — PASS when external participants are visibly labeled.
  - **COLLAB-012 (Meet Host Management)** → `meet.safety_host_management.enableHostManagement` — PASS when hosts have moderation controls (mute/remove/lock).

### Changed
- **ADMIN-008 / ADMIN-009 converted from placeholders to real checks** via `directory.workspace_resource_type_visibility` (the only `directory.*` policy type). ADMIN-008 (directory shared-contacts visibility) and ADMIN-009 (groups directory visibility) now read live config and WARN on broad directory exposure (audience-appropriate "review this," not FAIL), instead of an always-WARN "verify in Admin Console."

### Notes
- **Google Workspace is now 104 checks** (was 98); module total **466** (was 460). Counts updated in README. **39 of the 104 GWS checks now read live Cloud Identity policy** (33 conversions + 6 net-new).
- All net-new functions are dispatched and evaluate cleanly (test-mode Fortification: 104 findings, 0 ERROR). New regression suites: `Tests/verify-gws1-{auth,collab,admin}-p3.ps1`.

## [2.12.1] - 2026-06-19

_Live-validation fixes: the Lookout baseline-persistence bug + confirmed-enum tighten-ups._

### Fixed
- **`Invoke-Lookout` drift detection was non-functional — baseline never persisted.** `Get-TheaterState` / `Save-TheaterState` carried `[ValidateSet('entra','ad','m365')]`, which **rejected the `'workspace'` theater** Lookout uses — so every run silently failed to save/load its baseline and re-baselined instead of detecting drift. Added `'workspace'` to the ValidateSet on both. New regression `Tests/verify-lookout-state.ps1` exercises the **real** state helpers (not mocks) across two runs and asserts the 2nd run loads the baseline (`BaselineEstablished -eq $false`) — the gap that let this ship (the prior Lookout test mocked the state helpers).

### Changed
- **Confirmed-enum tighten-ups** (from live tenant values — closes WARNs that were grading unknown strings conservatively):
  - **COLLAB-008** (calendar external sharing): the real `maxAllowedExternalSharing` family is `EXTERNAL_*`. `EXTERNAL_ALL_INFO_*` (shares full event details externally) now → **FAIL**; `EXTERNAL_FREE_BUSY_ONLY` / `EXTERNAL_NO_SHARING` → **PASS**.
  - **OAUTH-006** (`api_controls.app_approval_requests.allowedForAll`): **corrected interpretation.** Per Google's Aug-2025 app-access-request-approval rollout, `ENABLED` means the *request-and-approve workflow* is on (users request unconfigured apps for **admin approval** — access is not auto-granted), a governance positive → **PASS** (was mis-graded as "allowed for all = insecure"). The real app gate remains OAUTH-001/007.
  - **OAUTH-001**: `UNSPECIFIED_UBER_BLOCK` confirmed as block-all → **PASS** (made explicit; a bare not-set value still falls through to WARN).
- **EMAIL-019** remediation reworded ("Security > Data protection > Manage rules: …") so the evaluated WARN's guidance text no longer contains the placeholder phrase that tripped validation greps.

### Notes
- `ADMIN-008` / `ADMIN-009` (directory contact / profile sharing) are convertible via `directory.workspace_resource_type_visibility` (confirmed present in the full schema dump) — deferred to a follow-up pending secure-direction confirmation, to avoid shipping questionable grading.
- Check counts unchanged (AD 204 / GWS 98 / Entra 158). All GWS-1 + Lookout suites green.

## [2.12.0] - 2026-06-19

_Google Workspace continuous monitoring — `Invoke-Lookout` closes the last gap in the GWS theater._

### Added
- **`Invoke-Lookout` — Google Workspace configuration-drift monitor.** The GWS theater finally has a continuous-monitoring cmdlet to sit alongside `Invoke-Surveillance` (Entra), `Invoke-Watchtower` (AD), and `Invoke-Wiretap` (M365). It runs the **read-only** Fortification posture audit, stores it as a baseline, and on each subsequent run diffs the current posture against the baseline — surfacing **newly-failing controls (drift)**, **resolved controls**, and the **posture-score change**. It complements `Invoke-Recon` (which watches user *behaviour* for compromise) by watching the tenant's *configuration* for regressions.
  - First run establishes the baseline (no drift reported); subsequent runs report the delta. `-Force` re-baselines. `-ScanMode Fast` (default) skips the slow per-user Gmail crawl (via Fortification `-Quick`); `Full` does the complete sweep.
  - New failures are surfaced on the result's `.NewThreats`, so it plugs straight into the alert wiring. Baseline state is stored under theater `workspace`. Built on the existing `Compare-FortificationState` engine — no new collection.
- **`Register-Patrol` now schedules `Invoke-Lookout` for the Workspace theater** (alongside `Invoke-Recon`), so a scheduled Workspace patrol covers both behavioural threats *and* configuration drift, each dispatching alerts when `SendAlerts` is set.

### Notes
- **Read-only.** Like the rest of the audit/monitor suite, Lookout makes no changes to Google Workspace — it only reads policy/config (the same collection `Invoke-Fortification` performs) and writes local state/reports. (Verified: the only POSTs in the codebase are read queries — Graph `$batch`, Azure Policy `summarize`, Chrome Policy `resolve` — and there are no AD/Google write cmdlets.)
- Exported cmdlet count is now 44 public functions (was 43). Check counts unchanged (AD 204 / GWS 98 / Entra 158).
- Regression test: `Tests/verify-lookout.ps1` (16/16 — baseline, drift, resolved, no-findings guard, read-only call shape, Fast/Full `-Quick` handling).

## [2.11.1] - 2026-06-19

_GWS-1 coverage extension — 7 more placeholders converted to real Cloud Identity policy checks (33 total)._

### Added
- **7 additional Fortification checks now read live Cloud Identity policy** instead of an always-WARN "verify in Admin Console":
  - **EMAIL-018 (Compliance Rules)** → `gmail.content_compliance` — PASS when ≥1 content-compliance rule is configured, else WARN.
  - **EMAIL-019 (DLP Rules)** → `rule.dlp` — counts **active, Gmail-scoped** DLP rules (state `ACTIVE` + `action.gmailAction`); PASS if ≥1, else WARN.
  - **DRIVE-010 (Drive DLP Rules)** → `rule.dlp` — counts active **Drive-scoped** rules (`action.driveAction`); PASS if ≥1, else WARN. (Gmail-only or inactive rules correctly don't count.)
  - **ADMIN-010 (Groups External Membership)** → `groups_for_business.groups_sharing.ownersCanAllowExternalMembers` — FAIL if external members allowed in any OU (weakest-OU-wins).
  - **ADMIN-011 (Group Creation Restrictions)** → `groups_for_business.groups_sharing.createGroupsAccessLevel` — FAIL on open creation, PASS on admin-restricted, WARN on unrecognized enum.
  - **COLLAB-004 (Chat External Communication)** → `chat.external_chat_restriction` (policy-primary, with the existing OrgUnitPolicies path kept as fallback).
  - **COLLAB-008 (Calendar External Sharing)** → `calendar.primary_calendar_max_allowed_external_sharing` (policy-primary, OrgUnitPolicies fallback retained).

### Notes
- **GWS-1 coverage is now 33 real policy-backed checks** (was 26 in v2.11.0). Check counts unchanged (AD 204 / GWS 98 / Entra 158) — logic changed, not the check set.
- Same safety rails as v2.11.0: weakest-OU-wins grading, API-unavailable→SKIP vs policy-absent→SKIP, and **unrecognized enums grade WARN, never PASS** (DLP/state matching is anchored so `INACTIVE` never counts as active). Enum strings for ADMIN-011, COLLAB-004/008 remain best-effort pending live confirmation.
- Remaining placeholders with **no Cloud Identity Policy API equivalent** stay documented manual-verify (TLS, inbound gateway, SSO, app passwords, unverified-apps, appointment slots, ownership transfer). The MDM/device family and directory/profile-sharing checks are pending the full 173-type schema dump.
- New regression suites (all green): `Tests/verify-gws1-{email,drive,admin,collab}-p2.ps1`; existing suites unchanged.

## [2.11.0] - 2026-06-19

_GWS-1 complete — the Cloud Identity policy data layer (v2.10.8) is now wired into real checks._

### Added
- **GWS-1: ~60 "verify in Admin Console" placeholders converted to real checks (26 now evaluate live policy).** Building on the v2.10.8 `Get-GoogleCloudIdentityPolicies` collector, the Fortification placeholder checks that map to a Cloud Identity policy setting now read it and return real PASS/FAIL/WARN instead of an always-WARN "verify manually". Converted:
  - **Authentication (6):** AUTH-003 (2SV method strength), AUTH-004 (password min length), AUTH-005 (password reuse), AUTH-006 (web session duration), AUTH-008 (less-secure apps), AUTH-011 (login challenges).
  - **Email Security (6):** EMAIL-013 (pre-delivery scanning), EMAIL-015 (attachment safety), EMAIL-016 (link/image scanning), EMAIL-017 (spoofing/authentication), EMAIL-020 (confidential mode), EMAIL-021 (S/MIME cert upload).
  - **Collaboration (5):** COLLAB-001 (Meet recording), COLLAB-002 (Meet audience), COLLAB-003 (Meet anonymous join), COLLAB-005 (Chat history), COLLAB-006 (Chat external spaces).
  - **Drive (3):** DRIVE-001 (external sharing mode), DRIVE-004 (shared-drive creation), DRIVE-008 (Drive for Desktop).
  - **OAuth (3):** OAUTH-001 (third-party app access), OAUTH-006 (API access control), OAUTH-007 (Marketplace app installs).
  - **Logging/Alerting (2):** LOG-004 (cloud data sharing/export), LOG-005 (admin alert rules active).
  - **Admin (1):** ADMIN-012 (Groups for Business service status).
- **New shape-immune helper** `Resolve-GooglePolicyValue` (+ `ConvertFrom-GoogleDurationSeconds`). It normalizes the policy lookup so checks are immune to whether `Get-GooglePolicySetting` hands back value objects or policy objects, returns per-OU field values, and distinguishes **API-unavailable** (→ SKIP) from **type-absent** (→ SKIP/PASS) — fixing a `return @()`→`$null` unwrap that would otherwise mislabel "policy absent" as "API unavailable". Grading is **weakest-OU-wins** (min length / longest session / any-insecure boolean).

### Notes
- **Checks with no Cloud Identity Policy API equivalent remain documented manual-verify** (honest coverage, not forced mappings): most Email routing/compliance (EMAIL-005/006/007/008/014/018/019), several Drive sub-settings, Calendar/Chat-app items, OAuth unverified-app/service-account-key, Admin directory/profile/group-creation, and **all** mobile-device/MDM checks (DEVICE-002..010) — the policy API doesn't expose them.
- **Enum caveats for live confirmation:** AUTH-003 (`allowedSignInFactorSet`), DRIVE-001 (`externalSharingMode`), COLLAB-002/003 (Meet audience enums), OAUTH-001/006/007 (access-level enums) grade known-insecure values as FAIL and **anything unrecognized as WARN — never PASS on an unknown enum**, so a different enum spelling degrades safely. Exact strings should be confirmed against the live `raw/gws-policy-schemas.txt`.
- Check counts unchanged (AD 204 / **GWS 98** / Entra 158 = 460) — conversions changed check *logic*, not the check set.
- Regression tests (all green): `Tests/verify-gws1-auth-checks.ps1` (20), `-email-` (15), `-collab-` (17), `-drive-` (11), `-oauth-` (16), `-admin-` (12), `-logging-` (10), `-device-` (4), plus the existing `-policy-collector` (8).

## [2.10.8] - 2026-06-19

### Added
- **GWS-1 enabling infrastructure — Cloud Identity Policy collector.** New `Get-GoogleCloudIdentityPolicies` collector pulls the full Workspace settings set from the Cloud Identity Policy API (`policies.list`, paginated) and indexes it by setting type, plus a `Get-GooglePolicySetting` lookup helper; wired into `Get-FortificationData` as `CloudIdentityPolicies`. This is the data layer that turns the ~60 "verify in Admin Console" placeholder checks (Gmail / Drive / Auth / Chat / Meet / Calendar / DLP / service-status) into real checks — the check conversions come next, once the live `setting.value` shapes are confirmed. The `cloud-identity.policies.readonly` scope is requested in an **isolated token** so a tenant that hasn't delegated it degrades gracefully (collector returns `$null`, dependent checks SKIP) instead of breaking the whole Google scan with `unauthorized_client`.

### Fixed
- **Chrome-policy collection no longer hardcodes a tenant-specific org-unit id.** `Get-FortificationData` resolved Chrome policies against a hardcoded `orgunits/<id>` — which only worked for one tenant (a bug for everyone else) and embedded a tenant identifier. It now resolves the customer's **root org-unit id dynamically** (from the directory API) and skips gracefully if it can't.

### Notes
- Teams `/appCatalogs/teamsApps` needs no change: the collector already queries with `$filter` (not `$top`), and `Invoke-GraphApi` paginates via `@odata.nextLink` — so the `$top`-rejection the validation flagged doesn't apply to our call path.
- Regression test: `Tests/verify-gws1-policy-collector.ps1` (8/8 — indexing, lookup, graceful degradation). Check counts unchanged.

## [2.10.7] - 2026-06-19

### Fixed
- **Spectre.Console console rendering restored (no more `AddItem`/`AddRow`/`BorderColor` errors).** When `PwshSpectreConsole` is installed, the bar charts and tables were calling Spectre.Console **C# extension methods** as instance methods (`$chart.AddItem(…)`, `$table.AddRow(…)`, `$table.BorderColor(…)`, `$tree.AddNode(…)`) — which PowerShell can't do, so every non-`-Quiet` scan spammed *"does not contain a method named …"* and the chart/table/tree came out blank. They now call the correct static extension classes (`BarChartExtensions::AddItem`, `TableExtensions::AddRow`, `HasTreeNodeExtensions::AddNode`) and set the border via `BorderStyle`, so the **category bar charts, "Findings by severity" chart, and the Priority-findings table now render** in the console. Each enhanced renderer is also wrapped in a try/catch that falls back to the text renderer, so a future Spectre.Console API change degrades gracefully instead of spamming.
- **Test mode now uses a zeroed report-filename timestamp.** With `-TestMode` the CSV/HTML/JSON reports are written as `…_report_00000000_000000.…` (Reconnaissance / Fortification) and `…-00000000-000000.…` (Infiltration / Campaign) instead of the live clock, so demo/sample output is fully deterministic — completing the test-mode determinism started in v2.10.5. (Real scans keep the real timestamp.)

## [2.10.6] - 2026-06-19

### Documentation
- **Defender / EDR false-positive guidance (the most common first-run failure).** PSGuerrilla's AD attack-detection files (DCSync GUIDs, `GenericAll`/`WriteDacl`, shadow-admin, Tier-0 patterns) can trip antivirus heuristics — Microsoft Defender real-time protection in particular blocks *read* access to them, so `Import-Module` fails with *"Access to the path '…Invoke-ADAclDelegationChecks.ps1' is denied"* (often a different AD file each attempt). README now documents this prominently in **Requirements** with the `Add-MpPreference -ExclusionPath` fix and a Protection-history "Allow" alternative, plus a dedicated **Troubleshooting** section. Surfaced by the v2.10.4 live validation.
- Added **`AppCatalog.Read.All`** to the documented Entra app-registration scopes (the Teams app-catalog collection calls `/appCatalogs/teamsApps`; without the scope that portion logs a handled 403 and stays empty). Added Troubleshooting entries for that 403 and for the "No accessible Azure subscriptions" SKIP.

## [2.10.5] - 2026-06-19

### Changed
- **Test mode now renders deterministic (zeroed) timestamps.** When a scan runs with `-TestMode` (or the GUI "Test mode" checkbox), all console timestamps read `00:00` / `00:00:00` instead of the live clock, so demo / sample / screenshot output is stable: the operation header shows `… 0000 UTC` (date kept real), `Write-ProgressLine` shows `[0000 UTC]`, and the GUI Operations log prefixes each line with `[00:00:00]`. Driven by a self-healing module flag (`$script:GuerrillaTestMode`) the audit cmdlets set per run; a real (non-test) run resets it. Report **filenames** still use the real timestamp (zeroing them would collide).

## [2.10.4] - 2026-06-18

_Backlog sweep — the code-only gaps that don't need a live tenant/DC to build and verify._

### Added
- **(GUI-1) Real "Add Credential" modal.** The Safehouse tab's "Add Credential" button now opens a dark-themed WPF dialog (not a redirect-to-terminal stub) that stores **Microsoft Entra / Graph** (tenant / client / secret + optional expiry) or **Google Workspace** (service-account JSON via file picker + delegated-admin email) credentials straight into the vault, then refreshes the grid. Field validation (GUID / email / valid SA JSON) runs before anything is written. Backed by a non-interactive `Save-SafehouseCredentialSet` helper; the dialog's builder/validator are pure and unit-tested, and the window was render-verified off-screen.

### Fixed
- **(ENT-5) Azure IAM now distinguishes "no ARM access" from "no resources."** Every `AZIAM-*` resource check shared one guard that emitted a misleading `WARN: No X found in scanned subscriptions` even when the real problem was zero Azure access. A shared `Get-AzureIAMUnavailableFinding` now returns a single clear **SKIP** — *"No accessible Azure subscriptions — grant the app the Reader role at the root management group"* (or surfaces the ARM authorization error) — so the WARN only fires when subscriptions exist but genuinely have no resources of that type.
- **(ENT-4, partial) Consolidated the M365 workload-skip noise.** Instead of ~40 individual `SKIP: <workload> not connected` lines, `Invoke-Infiltration` now prints **one** pre-flight banner summarizing which workload modules (EXO / Teams / SharePoint / Power Platform) are not connected and how many checks each skipped. (Net-new workload **checks** still need live Graph/admin-module validation and remain on the roadmap.)
- **(DSInternals) Single pre-flight note.** When DSInternals isn't installed, reconnaissance prints one note that the 5 password-hash checks (`ADPWD-010..014`) will SKIP, instead of five identical per-check skip lines.

### Notes
- Regression tests: `Tests/verify-ent5-azure-skip.ps1` (7/7), `Tests/verify-gui-credential-entry.ps1` (15/15). AD/GWS/Entra check counts unchanged (204 / 98 / 158).
- Still gated on a **live environment** (can't build+validate from a dev box), unchanged: full-domain transitive attack paths, GWS-1 Cloud Identity Policy API (blocked on the DWD scope), GWS-3 full parallelization, ENT-4 net-new workload checks, ADDOM-007 replication health, and the security-event-log behavioral ITDR layer.

## [2.10.3] - 2026-06-18

_Fixes from the v2.10.1 attack-path validation and the v2.10.2 GUI re-check._

### Fixed
- **ADPATH-001 false positives eliminated.** The attack-path engine was reporting **default infrastructure/admin principals** (the `Domain Controllers` group, `Enterprise Domain Controllers`, RODCs, `Enterprise Read-only Domain Controllers`, `Schema Admins`) as Tier-0 escalation paths — they legitimately hold replication/control rights **by AD design**. A new centralized allowlist (`Test-DefaultControlPrincipal`, matched by **forge-proof well-known SID/RID**, not locale-dependent names) excludes them. In the reporter's live domain this drops the headline from *"32 paths, 32 non-privileged"* to the ~7 genuine ones.
- **`SourceIsPrivileged` now correct.** Previously every path was flagged non-privileged (so the "highest-risk" sort/count was meaningless). It now returns true for default privileged principals (incl. the operator groups) and Tier-0 group members, so the non-privileged bucket contains only genuinely non-privileged custom principals.
- **Azure AD Connect sync accounts (`MSOL_*`) relabeled.** They hold real DCSync rights but **by design** (and are already tracked by `ADTIER-001`), so they're flagged `Expected`, kept **out** of the non-privileged count, and reported separately ("plus N expected service-account path(s) — see ADTIER-001") instead of as surprise escalations.
- **DCSync / ACL-delegation checks now share the same allowlist.** `Test-SafeAdminSid` (used by `ADPRIV-028`, `ADACL-010/015/016`, …) delegates to `Test-DefaultControlPrincipal` — a strict superset of its old list. This closes the v2.10.1 residual where **Enterprise Read-only Domain Controllers (498)** was reported as a non-default DCSync principal, and keeps the DCSync/ACL checks consistent with the attack-path engine. _(Re-validate the ADACL/ADPRIV non-default counts — they may drop slightly as more by-design infra principals are correctly excluded.)_
- **(GUI-2) ComboBox selection box actually fixed this time.** The closed box rendered with the **system's light button chrome** (because the nested `ToggleButton`'s `{TemplateBinding Background}` bound to the unset ToggleButton background, not the ComboBox's), so near-white selection text read as blank/faint. The box fill is now hardcoded dark — verified by rendering the control off-screen to a bitmap and inspecting the pixels (`Tests/tools/render-combo-probe.ps1`), not by eye.

### Notes
- Regression tests added: `Tests/verify-adpath-fix.ps1` (19/19 — default-principal exclusion incl. a localized-name-but-RID-516 case, MSOL relabeling, genuine-path retention, headline correctness).
- Roadmap unchanged: full domain-wide **transitive** path chaining still needs the full-domain ACL collector (next increment). The reporter also noted `ADPATH-001` object-control paths overlap `ADACL-016`; a future pass may cross-reference/dedupe them so the same ACE isn't counted by multiple checks.

## [2.10.2] - 2026-06-18

_GUI + Safehouse fixes from the live GUI/Safehouse validation pass._

### Fixed
- **(SH-1) Config-file setup now persists the Google Workspace admin email to the vault.** `Set-Safehouse -ConfigFile` migrated the service-account JSON but never stored `GUERRILLA_GWS_SA_ADMIN_EMAIL`, so a config-file setup followed by a **vault-only** scan (GUI / scheduled patrol, no `-ConfigFile`) failed with *"AdminEmail is required."* The migration now also stores the admin email (from `google.adminEmail`).
- **(SH-4) Config migration now also handles Pushover and Twilio/SMS providers** (previously silently dropped — only teams/slack/sendgrid/mailgun/pagerduty were migrated), using canonical keys `GUERRILLA_PUSHOVER_KEY` / `GUERRILLA_TWILIO_KEY`.
- **(SH-2) Status surfaces reconcile metadata with the real secret store.** `Get-Safehouse`, `Set-Safehouse -Status`, and the GUI Safehouse tab were metadata-driven (`GUERRILLA_VAULT_METADATA`), so secrets stored without a metadata entry (the interactive admin-email write, Pushover, a legacy bare key) were invisible — a *"are my creds loaded?"* blind spot. A new `Get-SafehouseCredentialView` helper reconciles metadata with `Get-SecretInfo`, surfacing present-but-unregistered keys (flagged `unregistered`).
- **(SH-3) Vault status discloses the no-master-password mode.** The store is configured with `Authentication None` for unattended runs; status now plainly states *"DPAPI at rest, no master password — any process running as this user can read these secrets"* instead of just labeling it `DPAPI`.
- **(GUI-1) The Safehouse "Test All" button now works.** It runs the real `Test-Safehouse` connectivity engine asynchronously (off the UI thread) and shows per-environment, per-check results, instead of redirecting to the terminal.
- **(GUI-2) ComboBoxes show their selected value when collapsed.** Report style / Profile / Minimum alert level rendered blank when closed because the stock WPF template themed the selection box via the system theme; a full dark `ControlTemplate` now themes the `SelectionBoxItem`.
- **(GUI-4) Single-instance guard.** A named mutex stops a second `Show-Guerrilla` window from opening and clobbering the shared `config.json` / `*-state.json` (last-writer-wins); the second launch warns and exits.
- **(GUI-5) Rotate/Remove give feedback when no row is selected** (previously a silent no-op).

### Notes
- GUI-3 (Safehouse tab under-reporting) is resolved by the SH-2 fix (the tab reads `Get-Safehouse`). GUI-6 (Patrol scheduling broken monitoring) was resolved by the v2.9.4 MON-4 fix.
- Full GUI-driven credential **entry** ("Add Credential") remains a roadmap item; the terminal `Set-Safehouse` flow is still the entry path.
- Regression tests added: `Tests/verify-safehouse-fixes.ps1` (10/10 — SH-1/SH-2/SH-4).

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
