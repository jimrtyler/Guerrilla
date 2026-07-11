# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADTradecraftChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADTradecraftChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Recon$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# ── ADTRADE-001: GPP cpassword Leftovers ───────────────────────────────────
function Test-ReconADTRADE001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    if (-not $tc.SysvolReadable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not readable from this host (auth/network issue).'
    }
    $hits = @($tc.CpasswordHits)
    if ($hits.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No GPP cpassword fields found in SYSVOL Policies XML files (MS14-025 cleanup verified)' `
            -Details @{ FilesScanned = 'SYSVOL Policies recursive *.xml' }
    }
    $summary = @($hits | Select-Object -First 5 | ForEach-Object { "$($_.ExposedUser) in $($_.FilePath)" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "Found $($hits.Count) GPP cpassword leftover(s) in SYSVOL. Examples: $summary. Rotate every exposed credential — the cpassword AES key is public, anyone with SYSVOL read access can decrypt." `
        -Details @{ HitCount = $hits.Count; Hits = $hits }
}

# ── ADTRADE-002: DCShadow Indicator ────────────────────────────────────────
function Test-ReconADTRADE002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('TradecraftSignals','DomainControllers') -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    $dcs = $AuditData.DomainControllers
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    $configServers = @($tc.ConfigPartitionServers)
    if ($configServers.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No server objects found under CN=Sites,CN=Configuration. This is unusual for a real domain — verify the collector had read access to the configuration partition.' `
            -Details @{ ConfigServerCount = 0 }
    }

    # Build a set of known DC hostnames (lowercased) from the DomainControllers collection.
    # Get-ADDomainControllers returns a flat array of DC hashtables — keys are Name + FQDN.
    $knownDcHosts = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($dcs) {
        foreach ($d in @($dcs)) {
            if ($d.FQDN) { [void]$knownDcHosts.Add($d.FQDN) }
            if ($d.Name) { [void]$knownDcHosts.Add($d.Name) }
        }
    }
    if ($knownDcHosts.Count -eq 0) {
        # If we have no DC inventory we can't tell orphans from real DCs — SKIP rather
        # than flag every server in the config partition as a rogue.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DomainControllers data not available to cross-reference. Re-run with DomainForest category enabled to populate the DC inventory.'
    }

    $orphans = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($s in $configServers) {
        $sHost = $s.DNSHostName ?? $s.CN ?? ''
        if (-not $sHost) { continue }
        # The configuration partition may include short-name servers; also try just the CN.
        $isKnown = $knownDcHosts.Contains($sHost) -or $knownDcHosts.Contains($s.CN)
        if (-not $isKnown) {
            $orphans.Add(@{
                Server     = $sHost
                DN         = $s.DistinguishedName
                Created    = $s.WhenCreated
            })
        }
    }

    if ($orphans.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($configServers.Count) server objects in CN=Sites,CN=Configuration match known domain controllers — no DCShadow indicator." `
            -Details @{ ConfigServerCount = $configServers.Count; DcCount = $knownDcHosts.Count }
    }

    $summary = @($orphans | ForEach-Object { "$($_.Server) (created $($_.Created))" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($orphans.Count) server object(s) under CN=Sites,CN=Configuration that do NOT match a known DC: $summary. Investigate immediately — DCShadow registers fake DCs here, but legitimate causes also exist (replicated objects from a removed DC, legacy site setup)." `
        -Details @{ OrphanCount = $orphans.Count; Orphans = @($orphans) }
}

# ── ADTRADE-003: Stale BitLocker Recovery Keys ─────────────────────────────
function Test-ReconADTRADE003 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    $keys = @($tc.BitLockerKeys)
    if ($keys.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No BitLocker recovery information found in AD. Either BitLocker is not deployed, or the recovery keys are stored elsewhere (Intune, MBAM, etc.).' `
            -Details @{ KeyCount = 0 }
    }

    $thresholdDays = 365
    $cutoff = [datetime]::UtcNow.AddDays(-$thresholdDays)
    $staleKeys = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($k in $keys) {
        $created = $k.WhenCreated
        if ($created -is [datetime] -and $created -lt $cutoff) {
            $staleKeys.Add(@{
                DN            = $k.DistinguishedName
                ParentComputer = $k.ParentComputer
                AgeDays        = [int]([datetime]::UtcNow - $created).TotalDays
            })
        }
    }

    if ($staleKeys.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "$($keys.Count) BitLocker recovery key(s) found, all within $thresholdDays days" `
            -Details @{ KeyCount = $keys.Count }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($staleKeys.Count) BitLocker recovery key(s) older than $thresholdDays days (of $($keys.Count) total). Review their parent computer accounts — confirm the drives have been destroyed or wiped, then prune the AD computer objects to cascade-delete the orphan keys." `
        -Details @{ StaleCount = $staleKeys.Count; TotalCount = $keys.Count; ThresholdDays = $thresholdDays; Sample = @($staleKeys | Select-Object -First 10) }
}

# ── ADTRADE-004: RODC Password Replication Policy Hygiene ──────────────────
function Test-ReconADTRADE004 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    $rodcs = @($tc.Rodcs)
    if ($rodcs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No RODCs in this domain — PRP hygiene N/A.' `
            -Details @{ RodcCount = 0 }
    }
    # The PRP itself isn't a simple LDAP attribute — it's expressed via msDS-RevealOnDemandGroup
    # and msDS-NeverRevealGroup on each RODC computer object, plus the canonical Deny / Allow
    # groups. Surfacing the inventory + the manual verification command is the right call here
    # rather than half-checking with incomplete logic.
    $summary = @($rodcs | ForEach-Object { $_.DNSHostName }) -join ', '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Domain has $($rodcs.Count) RODC(s): $summary. Verify each RODC's Password Replication Policy out-of-band: Get-ADDomainControllerPasswordReplicationPolicy -Identity <rodc> -Denied. Domain Admins, Enterprise Admins, Schema Admins, Account Operators, and krbtgt must be in the Denied list (typically via the 'Denied RODC Password Replication Group' builtin)." `
        -Details @{ RodcCount = $rodcs.Count; Rodcs = @($rodcs) }
}

# ── ADTRADE-005: Seamless SSO (AZUREADSSOACC$) Key Rotation ────────────────
function Test-ReconADTRADE005 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    $sso = $tc.SeamlessSsoAccount
    if (-not $sso) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'AZUREADSSOACC$ account not present — Entra Seamless SSO is not configured in this domain, so there is no key to rotate.'
    }

    $pwdLastSet = $sso.PwdLastSet
    if ($pwdLastSet -isnot [datetime]) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'AZUREADSSOACC$ exists but pwdLastSet could not be read (attribute not collected or never set).' `
            -Details @{ DistinguishedName = $sso.DistinguishedName }
    }

    $ageDays = [int]([datetime]::UtcNow - $pwdLastSet).TotalDays
    $threshold = 90
    if ($ageDays -le $threshold) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "AZUREADSSOACC`$ Kerberos key was rotated $ageDays day(s) ago (within the $threshold-day target)." `
            -Details @{ PwdAgeDays = $ageDays; ThresholdDays = $threshold; PwdLastSet = $pwdLastSet }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "AZUREADSSOACC`$ Kerberos key has not been rotated in $ageDays day(s) (target: every $threshold days). A stale key lets an attacker who has captured it forge Silver Tickets for any hybrid user indefinitely. Roll it twice with Update-AzureADSSOForest." `
        -Details @{ PwdAgeDays = $ageDays; ThresholdDays = $threshold; PwdLastSet = $pwdLastSet; DistinguishedName = $sso.DistinguishedName }
}

# ── ADTRADE-006: Shadow Credentials on Privileged Principals ───────────────
function Test-ReconADTRADE006 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    if (-not $tc.ShadowCredCollected) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'msDS-KeyCredentialLink enumeration did not complete (read access to the attribute requires DC/privileged rights). Absence of data is not evidence of cleanliness — re-run with sufficient privilege.'
    }
    $hits = @($tc.ShadowCredentials)
    if ($hits.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No msDS-KeyCredentialLink (shadow credential) values found on privileged/Tier-0 principals (admins, domain controllers, adminCount=1 objects).' `
            -Details @{ ScannedScope = 'adminCount=1 + domain controllers' }
    }

    # A member computer carrying its own msDS-KeyCredentialLink is the normal signature of a
    # Windows Hello for Business / Entra hybrid device-registration key — NOT the shadow-credential
    # primitive. Failing on those screams on every hybrid-joined estate. Score key credentials on
    # user/admin principals or domain controllers as high-signal (FAIL); treat member-computer
    # device keys as review-only (WARN) — never silently PASS, but never a false FAIL either.
    $highSignal = @($hits | Where-Object { -not $_.IsComputer -or $_.IsDomainController })
    $deviceKeys = @($hits | Where-Object { $_.IsComputer -and -not $_.IsDomainController })

    if ($highSignal.Count -gt 0) {
        $summary = @($highSignal | Select-Object -First 8 | ForEach-Object {
            "$($_.SamAccountName) [$($_.ObjectClass)$(if ($_.IsDomainController) { '/DC' })] ($($_.KeyCredentialCount) key(s))" }) -join '; '
        $tail = if ($deviceKeys.Count) { " ($($deviceKeys.Count) member-computer device key(s) excluded as likely-legitimate.)" } else { '' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($highSignal.Count) privileged principal(s) (user/admin/domain controller) carry msDS-KeyCredentialLink values: $summary. A key credential on an admin account or a domain controller is the shadow-credential backdoor (Whisker/pyWhisker, T1556) allowing PKINIT logon as that account. Verify every key against a legitimate enrollment and remove unrecognised entries.$tail" `
            -Details @{ HitCount = $highSignal.Count; Principals = @($highSignal); DeviceKeyComputers = $deviceKeys.Count }
    }

    # Only member-computer device keys remain — overwhelmingly legitimate WHfB / Entra-hybrid registrations.
    $summary = @($deviceKeys | Select-Object -First 8 | ForEach-Object { "$($_.SamAccountName) ($($_.KeyCredentialCount) key(s))" }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($deviceKeys.Count) member-computer account(s) carry msDS-KeyCredentialLink values: $summary. These are typically legitimate Windows Hello for Business / Entra hybrid device-registration keys, not shadow credentials. Confirm each key's owner matches the computer object — a key whose owner differs from the object is the actual shadow-credential primitive. Not failing on expected device keys." `
        -Details @{ DeviceKeyComputers = $deviceKeys.Count; Principals = @($deviceKeys) }
}

# ── ADTRADE-007: BadSuccessor dMSA Escalation Surface ──────────────────────
function Test-ReconADTRADE007 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    if ($tc.DmsaClassPresent -eq $false) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Schema does not contain the msDS-DelegatedManagedServiceAccount class — this forest predates Windows Server 2025, so the BadSuccessor dMSA migration abuse is not applicable.'
    }
    if ($null -eq $tc.DmsaClassPresent) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Could not determine whether the dMSA class exists (schema partition unreadable). Absence of data is not a PASS — re-run with read access to the schema NC.'
    }
    if (-not $tc.DmsaAclCollected) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'dMSA class exists but the OU ACL sweep did not complete (ntSecurityDescriptor read failed). Re-run with rights to read OU DACLs.'
    }
    $ous = @($tc.BadSuccessorOus)
    if ($ous.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No OU grants a non-Tier-0 principal the ability to create or write a delegated Managed Service Account (dMSA). BadSuccessor escalation surface not present.' `
            -Details @{ DmsaClassPresent = $true }
    }
    $summary = @($ous | Select-Object -First 6 | ForEach-Object {
        $aces = @($_.RiskyAces | ForEach-Object { "$($_.Principal) [$($_.Scope)]" }) -join ', '
        "$($_.Name): $aces"
    }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($ous.Count) OU(s) let a non-Tier-0 principal create/write a dMSA (BadSuccessor). Examples: $summary. Such a principal can create a dMSA, mark it as superseding a privileged account, and inherit that account's Kerberos keys. Remove CreateChild/GenericAll on these OUs from non-admin principals." `
        -Details @{ OuCount = $ous.Count; OUs = @($ous) }
}

# ── ADTRADE-008: Enterprise Key Admins / Key Admins Membership ─────────────
function Test-ReconADTRADE008 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    if (-not $tc.KeyAdminGroupsFound) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Neither the Key Admins (RID 526) nor Enterprise Key Admins (RID 527) group could be resolved in this domain. Cannot assess membership.'
    }
    $ek = @($tc.EnterpriseKeyAdmins | Where-Object { $_.ObjectClass -ne 'group' })
    $ka = @($tc.KeyAdmins | Where-Object { $_.ObjectClass -ne 'group' })
    $total = $ek.Count + $ka.Count
    if ($total -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Key Admins and Enterprise Key Admins groups are empty (recommended). These groups hold domain-wide msDS-KeyCredentialLink write rights.' `
            -Details @{ KeyAdminsCount = 0; EnterpriseKeyAdminsCount = 0 }
    }
    $names = @(@($ek | ForEach-Object { "$($_.SamAccountName) (Enterprise Key Admins)" }) +
               @($ka | ForEach-Object { "$($_.SamAccountName) (Key Admins)" })) -join ', '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$total member(s) in Key Admins / Enterprise Key Admins: $names. Members can write msDS-KeyCredentialLink on objects domain-wide, a one-step shadow-credential primitive over any account. These groups should be empty unless WHfB key provisioning explicitly requires them." `
        -Details @{
            EnterpriseKeyAdminsCount = $ek.Count
            KeyAdminsCount           = $ka.Count
            EnterpriseKeyAdmins      = @($ek | ForEach-Object { @{ SamAccountName = $_.SamAccountName; ObjectClass = $_.ObjectClass } })
            KeyAdmins                = @($ka | ForEach-Object { @{ SamAccountName = $_.SamAccountName; ObjectClass = $_.ObjectClass } })
        }
}

# ── ADTRADE-009: Cert Publishers Membership ────────────────────────────────
function Test-ReconADTRADE009 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    if (-not $tc.CertPublishersFound) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cert Publishers group (RID 517) could not be resolved in this domain. Cannot assess membership.'
    }
    $members = @($tc.CertPublishers | Where-Object { $_.ObjectClass -ne 'group' })
    # Default membership is the Enterprise CA computer account(s). Member computers are expected;
    # user/service-account members are the concern.
    $nonComputer = @($members | Where-Object { $_.ObjectClass -ne 'computer' })
    if ($members.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Cert Publishers group is empty (no AD CS Enterprise CA, or membership is clean).' `
            -Details @{ MemberCount = 0 }
    }
    if ($nonComputer.Count -eq 0) {
        $names = @($members | ForEach-Object { $_.SamAccountName }) -join ', '
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Cert Publishers contains only computer account(s) (expected: Enterprise CA hosts): $names." `
            -Details @{ MemberCount = $members.Count; ComputerOnly = $true }
    }
    $names = @($nonComputer | ForEach-Object { "$($_.SamAccountName) [$($_.ObjectClass)]" }) -join ', '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($nonComputer.Count) non-computer member(s) in Cert Publishers: $names. Members can publish certificates into the NTAuth store, enabling certificate-based authentication abuse (ESC). Only Enterprise CA computer accounts belong here." `
        -Details @{
            MemberCount       = $members.Count
            NonComputerCount  = $nonComputer.Count
            NonComputerMembers = @($nonComputer | ForEach-Object { @{ SamAccountName = $_.SamAccountName; ObjectClass = $_.ObjectClass } })
        }
}

# ── ADTRADE-010: gMSA Posture & Password Exposure ──────────────────────────
function Test-ReconADTRADE010 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'TradecraftSignals' -Subject 'tradecraft signals'
    if ($na) { return $na }
    $tc = $AuditData.Tradecraft
    if (-not $tc) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Tradecraft data not collected.'
    }
    if (-not $tc.GmsaCollected) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'gMSA enumeration did not complete (LDAP query failed). Cannot assess managed-account posture.'
    }
    $gmsas = @($tc.GmsaAccounts)
    if ($gmsas.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No group Managed Service Accounts (gMSA) found. If service accounts run under static-password user accounts they are exposed to Kerberoasting and manual password rotation — migrate service identities to gMSAs (auto-rotated 240-bit passwords).' `
            -Details @{ GmsaCount = 0 }
    }
    $exposed = @($gmsas | Where-Object { $_.BroadlyRetrievable -or $_.NonTier0Retrievable })
    if ($exposed.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "$($gmsas.Count) gMSA(s) in use; none expose their managed password to a broad or non-Tier-0 principal via PrincipalsAllowedToRetrieveManagedPassword." `
            -Details @{ GmsaCount = $gmsas.Count }
    }
    $summary = @($exposed | Select-Object -First 6 | ForEach-Object {
        $why = if ($_.BroadlyRetrievable) { 'broad principal (Everyone/Authenticated Users/Domain Users)' } else { 'non-privileged principal' }
        "$($_.SamAccountName) -> $why"
    }) -join '; '
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($exposed.Count) of $($gmsas.Count) gMSA(s) expose their managed password to a broad/non-privileged principal: $summary. Any such principal can recover the cleartext gMSA password (e.g. GMSAPasswordReader) and impersonate the service. Restrict msDS-GroupMSAMembership to the specific hosts that must run the service." `
        -Details @{ GmsaCount = $gmsas.Count; ExposedCount = $exposed.Count; Exposed = @($exposed) }
}
