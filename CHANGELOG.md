# Changelog

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
