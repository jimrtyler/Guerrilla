# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Get-ADPasswordHashQuality
# -------------------------------------------------------------------------------
# Replicates NT password hashes via DSInternals (Get-ADReplAccount, the DCSync
# protocol) and runs Test-PasswordQuality to surface blank passwords and
# password reuse (duplicate hashes). Feeds:
#   ADPWD-010 (blank passwords)         <- BlankPasswordUsers
#   ADPWD-011 (duplicate password hash) <- DuplicateHashGroups
#   ADPRIV-016 (privileged weak pwds)   <- PasswordAnalysis
#
# Honesty contract (project rule #1 — never PASS without assessing):
#   * Only runs when DSInternals is available AND replication succeeds.
#   * BlankPasswordUsers / DuplicateHashGroups need NO external dataset, so they
#     are ALWAYS set (even to @()) once replication succeeds — empty = "checked,
#     none found" → the check can PASS legitimately.
#   * HIBPCompromisedUsers / DictionaryMatchUsers / CommonPasswordUsers stay
#     $null UNLESS the caller supplies the corresponding dataset file. $null =
#     "not assessed" → ADPWD-012/013/014 SKIP honestly (we have no dataset).
#   * On ANY failure (no DCSync rights, not a DC, module load error) the whole
#     function returns $null and records an error → the dependent checks SKIP.
#
# SECURITY (mandatory): only SamAccountNames and counts are persisted in the
# result. NT hashes and any cleartext are NEVER written to the result, to disk,
# or to the pipeline. The replicated account objects ($replAccounts) and the
# Test-PasswordQuality report are discarded as soon as analysis completes.
#
# References: MITRE ATT&CK T1003.006 (OS Credential Dumping: DCSync),
# T1110 (Brute Force / credential reuse); ANSSI vuln_pwd_*; CIS Microsoft AD
# benchmarks (password policy).
# -------------------------------------------------------------------------------
function Get-ADPasswordHashQuality {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        # Optional DSInternals weak-password / pwned-hash dataset (a file of NT
        # hashes, one per line, e.g. an exported HIBP NTLM set). When supplied,
        # Test-PasswordQuality's WeakPasswordHashesSortedFile is used and
        # HIBPCompromisedUsers is populated. Absent => HIBP check stays SKIP.
        [string]$WeakPasswordHashesFile,

        # Optional cleartext dictionary file (one candidate password per line).
        # When supplied, DictionaryMatchUsers is populated. Absent => SKIP.
        [string]$DictionaryFile,

        [switch]$Quiet
    )

    $result = @{
        BlankPasswordUsers   = $null   # set to @() once replication succeeds
        DuplicateHashGroups  = $null   # set to @() once replication succeeds
        HIBPCompromisedUsers = $null   # stays $null unless dataset supplied
        DictionaryMatchUsers = $null   # stays $null unless dataset supplied
        CommonPasswordUsers  = $null   # stays $null (no built-in common list)
        PasswordAnalysis     = $null   # privileged-account weak-password subset
        Performed            = $false
        Error                = $null
    }

    # ── Gate 1: DSInternals must be importable ────────────────────────────────
    try {
        if (-not (Get-Module -ListAvailable -Name DSInternals -ErrorAction SilentlyContinue)) {
            $result.Error = 'DSInternals module not installed; NT-hash analysis not performed.'
            return $result
        }
        Import-Module DSInternals -ErrorAction Stop -Verbose:$false | Out-Null
    } catch {
        $result.Error = "DSInternals could not be loaded: $($_.Exception.Message)"
        return $result
    }

    if (-not (Get-Command -Name Get-ADReplAccount -ErrorAction SilentlyContinue) -or
        -not (Get-Command -Name Test-PasswordQuality -ErrorAction SilentlyContinue)) {
        $result.Error = 'DSInternals is present but Get-ADReplAccount / Test-PasswordQuality are unavailable.'
        return $result
    }

    # Determine the DC to replicate from and the naming context to pull.
    $domainDN = $Connection.DomainDN
    $server   = $Connection.Server
    if (-not $server) {
        # Fall back to the PDC-resolvable RootDSE host. DSInternals needs a
        # concrete server name for the DRSR bind.
        try { $server = $Connection.RootDSE.Properties['dnsHostName'][0].ToString() } catch { }
    }
    if (-not $server) {
        # Last resort: derive a DNS domain name from the DN so the DRSR locator
        # can find a DC. If this is empty too we bail honestly below.
        $server = ($domainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()
    }

    if ([string]::IsNullOrWhiteSpace($server) -or [string]::IsNullOrWhiteSpace($domainDN)) {
        $result.Error = 'Could not determine a domain controller / naming context for replication.'
        return $result
    }

    $replAccounts = $null
    try {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Replicating NT hashes via DSInternals from $server (DCSync)"
        }
        # The big read: pulls every account's secrets over the replication
        # protocol. Requires DCSync rights (Get-Changes + Get-Changes-All).
        $replAccounts = @(Get-ADReplAccount -All -Server $server -NamingContext $domainDN -ErrorAction Stop)
    } catch {
        # No DCSync rights, not a DC, RPC blocked, etc. — degrade honestly.
        $result.Error = "Replication failed (no DCSync rights / not a DC / RPC blocked): $($_.Exception.Message)"
        return $result
    }

    if ($null -eq $replAccounts -or @($replAccounts).Count -eq 0) {
        $result.Error = 'Replication returned no accounts; NT-hash analysis not performed.'
        return $result
    }

    # ── Run Test-PasswordQuality ──────────────────────────────────────────────
    $report = $null
    try {
        $tpqParams = @{ ErrorAction = 'Stop' }
        if ($WeakPasswordHashesFile -and (Test-Path -LiteralPath $WeakPasswordHashesFile)) {
            $tpqParams['WeakPasswordHashesSortedFile'] = $WeakPasswordHashesFile
        }
        if ($DictionaryFile -and (Test-Path -LiteralPath $DictionaryFile)) {
            $tpqParams['WeakPasswordsFile'] = $DictionaryFile
        }
        $report = $replAccounts | Test-PasswordQuality @tpqParams
    } catch {
        $result.Error = "Test-PasswordQuality failed: $($_.Exception.Message)"
        # Discard replicated secrets before returning (see SECURITY note).
        $replAccounts = $null
        [System.GC]::Collect()
        return $result
    } finally {
        # SECURITY: drop the replicated account objects (they carry NT hashes)
        # the instant we no longer need them. Nothing below touches $replAccounts.
        $replAccounts = $null
    }

    if ($null -eq $report) {
        $result.Error = 'Test-PasswordQuality produced no report.'
        [System.GC]::Collect()
        return $result
    }

    # Helper: coerce a DSInternals name list into SamAccountName-only hashtables.
    # We deliberately keep ONLY the account name — never the hash.
    $toUserList = {
        param($names)
        $list = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($n in @($names)) {
            if ([string]::IsNullOrWhiteSpace($n)) { continue }
            # DSInternals reports DOMAIN\sam — strip the domain prefix.
            $sam = ($n -split '\\')[-1]
            $list.Add(@{ SamAccountName = $sam })
        }
        return @($list)
    }

    # ── Blank passwords (no dataset required → always set) ────────────────────
    $blank = @()
    try { if ($null -ne $report.EmptyPassword) { $blank = & $toUserList $report.EmptyPassword } } catch { }
    $result.BlankPasswordUsers = @($blank)

    # ── Duplicate password hashes (no dataset required → always set) ──────────
    # DSInternals returns DuplicatePasswordGroups as a collection of arrays, each
    # array being the set of accounts that share one NT hash. We surface the
    # account NAMES and the group size only — never the hash itself.
    $dupeGroups = [System.Collections.Generic.List[hashtable]]::new()
    try {
        foreach ($grp in @($report.DuplicatePasswordGroups)) {
            $accts = @(& $toUserList $grp | ForEach-Object { $_.SamAccountName })
            if ($accts.Count -gt 1) {
                $dupeGroups.Add(@{
                    Accounts = @($accts)
                    Count    = $accts.Count
                })
            }
        }
    } catch { }
    $result.DuplicateHashGroups = @($dupeGroups)

    # ── Optional dataset-gated results (stay $null unless the dataset was given)
    if ($tpqParams.ContainsKey('WeakPasswordHashesSortedFile')) {
        $hibp = @()
        try { if ($null -ne $report.WeakPassword) { $hibp = & $toUserList $report.WeakPassword } } catch { }
        $result.HIBPCompromisedUsers = @($hibp)
    }
    if ($tpqParams.ContainsKey('WeakPasswordsFile')) {
        $dict = @()
        try { if ($null -ne $report.WeakPassword) { $dict = & $toUserList $report.WeakPassword } } catch { }
        $result.DictionaryMatchUsers = @($dict)
    }
    # CommonPasswordUsers: no built-in common-password corpus ships with the
    # module, so this stays $null (Not Assessed) — ADPWD-014 SKIPs honestly.

    # ── Privileged-account subset for ADPRIV-016 ──────────────────────────────
    # Accounts that are (a) members of a privileged group AND (b) appear in the
    # blank-password or duplicate-hash findings. Only NAMES are compared/stored.
    $privNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($Connection.ContainsKey('PrivilegedSamNames')) {
        foreach ($p in @($Connection.PrivilegedSamNames)) {
            if (-not [string]::IsNullOrWhiteSpace($p)) { [void]$privNames.Add(($p -split '\\')[-1]) }
        }
    }

    $weakPrivileged = [System.Collections.Generic.List[hashtable]]::new()
    if ($privNames.Count -gt 0) {
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($u in @($result.BlankPasswordUsers)) {
            if ($privNames.Contains($u.SamAccountName) -and -not $seen.Contains($u.SamAccountName)) {
                [void]$seen.Add($u.SamAccountName)
                $weakPrivileged.Add(@{ SamAccountName = $u.SamAccountName; Reason = 'BlankPassword' })
            }
        }
        foreach ($grp in @($result.DuplicateHashGroups)) {
            foreach ($acct in @($grp.Accounts)) {
                if ($privNames.Contains($acct) -and -not $seen.Contains($acct)) {
                    [void]$seen.Add($acct)
                    $weakPrivileged.Add(@{ SamAccountName = $acct; Reason = 'DuplicatePasswordHash' })
                }
            }
        }
        if ($result.HIBPCompromisedUsers) {
            foreach ($u in @($result.HIBPCompromisedUsers)) {
                if ($privNames.Contains($u.SamAccountName) -and -not $seen.Contains($u.SamAccountName)) {
                    [void]$seen.Add($u.SamAccountName)
                    $weakPrivileged.Add(@{ SamAccountName = $u.SamAccountName; Reason = 'KnownWeak/Compromised' })
                }
            }
        }
    }
    # PasswordAnalysis is the shape ADPRIV-016 reads: { WeakPasswords = @(...) }.
    # Set it (even empty) because replication succeeded — privileged accounts WERE
    # assessed, so an empty set is a legitimate PASS, not a false one.
    $result.PasswordAnalysis = @{
        WeakPasswords         = @($weakPrivileged)
        PrivilegedAssessed    = ($privNames.Count -gt 0)
        PrivilegedNameCount   = $privNames.Count
    }

    $result.Performed = $true

    # SECURITY: drop the report (it can hold hash-keyed structures) and prompt GC
    # so no secret material lingers longer than necessary.
    $report = $null
    [System.GC]::Collect()

    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message ("NT-hash analysis: {0} blank, {1} duplicate-hash group(s), {2} weak privileged" -f `
            @($result.BlankPasswordUsers).Count, @($result.DuplicateHashGroups).Count, @($weakPrivileged).Count)
    }

    return $result
}
