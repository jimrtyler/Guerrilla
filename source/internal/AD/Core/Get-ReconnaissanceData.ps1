# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ReconnaissanceData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [string[]]$Categories = @('All'),

        [int]$InactiveDays = 90,

        [int]$PasswordAgeDays = 365,

        [string]$NtdsPath,

        [string]$WeakPasswordList,

        # Opt-in: sweep ACLs across every domain object (not just the six critical Tier-0 objects).
        # Heaviest read Guerrilla performs; unlocks deep transitive chains + a richer BloodHound export.
        [switch]$FullDomainAcl,

        [switch]$Quiet
    )

    # ── Category-to-data-source mapping ──────────────────────────────────
    $categoryDataNeeds = @{
        DomainForest        = @('DomainInfo', 'DomainControllers')
        Trusts              = @('TrustRelationships')
        PrivilegedAccounts  = @('PrivilegedMembers', 'DomainInfo')
        PasswordPolicy      = @('PasswordPolicies', 'DomainInfo')
        Kerberos            = @('KerberosConfig')
        ACLDelegation       = @('ObjectACLs', 'PrivilegedMembers')
        GroupPolicy         = @('GroupPolicyObjects')
        LogonScripts        = @('LogonScripts')
        CertificateServices = @('CertificateServices')
        StaleObjects        = @('StaleObjects')
        Network             = @('NetworkConfig')
        TierZero            = @('PrivilegedMembers', 'TierZeroSignals')
        Logging             = @('NetworkConfig')
        Tradecraft          = @('DomainControllers', 'TradecraftSignals')
        AttackPath          = @('ObjectACLs', 'PrivilegedMembers')
    }

    # Resolve which data sources are required
    $requiredSources = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase
    )

    if ($Categories -contains 'All') {
        foreach ($sources in $categoryDataNeeds.Values) {
            foreach ($s in $sources) { [void]$requiredSources.Add($s) }
        }
    } else {
        foreach ($cat in $Categories) {
            if ($categoryDataNeeds.ContainsKey($cat)) {
                foreach ($s in $categoryDataNeeds[$cat]) {
                    [void]$requiredSources.Add($s)
                }
            }
        }
    }

    # Always collect module availability
    [void]$requiredSources.Add('ModuleAvailability')

    # ── Initialize result hashtable ──────────────────────────────────────
    $data = @{
        Domain              = $null
        DomainControllers   = $null
        Trusts              = $null
        PrivilegedAccounts  = $null
        PasswordPolicies    = $null
        Kerberos            = $null
        ACLs                = $null
        GroupPolicies       = $null
        LogonScripts        = $null
        CertificateServices = $null
        StaleObjects        = $null
        Network             = $null
        TierZero            = $null
        Tradecraft          = $null
        ModuleAvailability  = $null
        Connection          = $Connection
        Errors              = @{}
    }

    # Helper: determine whether a data source is needed
    $needsSource = { param([string]$Name) $requiredSources.Contains($Name) }

    # ── 1. Module Availability ───────────────────────────────────────────
    if (& $needsSource 'ModuleAvailability') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Checking module availability'
        }
        try {
            $data.ModuleAvailability = Test-ADModuleAvailability
        } catch {
            $data.Errors['ModuleAvailability'] = $_.Exception.Message
            $data.ModuleAvailability = @{
                ActiveDirectory = $false
                GroupPolicy     = $false
                DSInternals     = $false
                PSPKI           = $false
            }
        }
        # Single pre-flight note for the DSInternals-gated password-hash checks
        # (ADPWD-010..014), instead of five identical per-check SKIP lines in the report run.
        if (-not $Quiet -and $data.ModuleAvailability -and -not $data.ModuleAvailability.DSInternals) {
            Write-ProgressLine -Phase INFO -Message 'DSInternals not installed — the 5 password-hash checks (ADPWD-010..014) will SKIP. Install-Module DSInternals (and run on a DC / with replication rights) to enable NT-hash analysis.'
        }
    }

    # ── 2. Domain Information ────────────────────────────────────────────
    if (& $needsSource 'DomainInfo') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting domain information'
        }
        try {
            $data.Domain = Get-ADDomainInfo -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect domain information: $_"
            $data.Errors['DomainInfo'] = $_.Exception.Message
        }
    }

    # ── 3. Domain Controllers ────────────────────────────────────────────
    if (& $needsSource 'DomainControllers') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Enumerating domain controllers'
        }
        try {
            $data.DomainControllers = Get-ADDomainControllers -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to enumerate domain controllers: $_"
            $data.Errors['DomainControllers'] = $_.Exception.Message
        }
    }

    # ── 4. Trust Relationships ───────────────────────────────────────────
    if (& $needsSource 'TrustRelationships') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting trust relationships'
        }
        try {
            $data.Trusts = Get-ADTrustRelationships -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect trust relationships: $_"
            $data.Errors['TrustRelationships'] = $_.Exception.Message
        }
    }

    # ── 5. Privileged Members ────────────────────────────────────────────
    if (& $needsSource 'PrivilegedMembers') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Enumerating privileged group members'
        }
        try {
            $data.PrivilegedAccounts = Get-ADPrivilegedMembers -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to enumerate privileged members: $_"
            $data.Errors['PrivilegedMembers'] = $_.Exception.Message
        }
    }

    # ── 6. Password Policies ────────────────────────────────────────────
    if (& $needsSource 'PasswordPolicies') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting password policies'
        }
        try {
            $data.PasswordPolicies = Get-ADPasswordPolicies -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect password policies: $_"
            $data.Errors['PasswordPolicies'] = $_.Exception.Message
        }
    }

    # ── 7. Kerberos Configuration ────────────────────────────────────────
    if (& $needsSource 'KerberosConfig') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Analyzing Kerberos configuration'
        }
        try {
            $data.Kerberos = Get-ADKerberosConfig -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to analyze Kerberos configuration: $_"
            $data.Errors['KerberosConfig'] = $_.Exception.Message
        }
    }

    # ── 8. Object ACLs / Delegation ──────────────────────────────────────
    if (& $needsSource 'ObjectACLs') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Auditing object ACLs and delegation'
        }
        try {
            $data.ACLs = Get-ADObjectACLs -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to audit object ACLs: $_"
            $data.Errors['ObjectACLs'] = $_.Exception.Message
        }

        # ── Full-domain ACL sweep (opt-in) — merges domain-wide control ACEs into DangerousACEs ──
        # so the transitive engine and BloodHound export see the whole control graph, not just the
        # six critical objects. Only runs when ACL collection succeeded.
        if ($FullDomainAcl -and $data.ACLs -and $null -ne $data.ACLs.DangerousACEs) {
            if (-not $Quiet) {
                Write-ProgressLine -Phase RECON -Message 'Full-domain ACL sweep (this can take a while on large domains)'
            }
            try {
                $fd = Get-ADFullDomainAcl -Connection $Connection -Quiet:$Quiet
                if ($fd.Error) {
                    $data.Errors['FullDomainAcl'] = $fd.Error
                } else {
                    $data.ACLs.DangerousACEs            = @($data.ACLs.DangerousACEs) + @($fd.DangerousACEs)
                    $data.ACLs.FullDomainScanned        = $true
                    $data.ACLs.FullDomainObjectsScanned = $fd.ObjectsScanned
                    $data.ACLs.FullDomainTruncated      = $fd.Truncated
                    if (-not $Quiet) {
                        $detail = "$($fd.ObjectsScanned) objects, $(@($fd.DangerousACEs).Count) dangerous ACE(s)$(if ($fd.Truncated) { ' (TRUNCATED at cap — coverage incomplete)' })"
                        Write-ProgressLine -Phase RECON -Message 'Full-domain ACL sweep complete' -Detail $detail
                    }
                }
            } catch {
                Write-Warning "Full-domain ACL sweep failed: $_"
                $data.Errors['FullDomainAcl'] = $_.Exception.Message
            }
        }

        # Derive DCSync principals from the domain-root DACL so ADPRIV-028 (DCSync rights)
        # lights up — the data is in ACLs.DangerousACEs but ADPRIV-028 reads a top-level
        # DCSyncAccounts field. Only set it when ACL data was actually collected, so a
        # failed ACL collection leaves it unset and ADPRIV-028 SKIPs (not a false PASS).
        if ($data.ACLs -and $null -ne $data.ACLs.DangerousACEs) {
            $dcSyncGuids = @(
                '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes
                '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'  # DS-Replication-Get-Changes-All
                '89e95b76-444d-4c62-991a-0facbeda640c'  # DS-Replication-Get-Changes-In-Filtered-Set
            )
            $dcSyncAces = @($data.ACLs.DangerousACEs | Where-Object {
                    ($_.ObjectTypeGUID -and $_.ObjectTypeGUID -in $dcSyncGuids) -or
                    ($_.ObjectType -and $_.ObjectType -match 'DS-Replication-Get-Changes')
                } | Where-Object {
                    -not (Test-SafeAdminSid -Sid $_.IdentitySID -IdentityReference $_.IdentityReference)
                })
            $byIdentity = @{}
            foreach ($ace in $dcSyncAces) {
                $id = $ace.IdentityReference ?? $ace.IdentitySID
                if (-not $id) { continue }
                if (-not $byIdentity.ContainsKey($id)) {
                    $byIdentity[$id] = [System.Collections.Generic.List[string]]::new()
                }
                $rn = $ace.ObjectType ?? $ace.ObjectTypeGUID ?? 'ExtendedRight'
                if (-not $byIdentity[$id].Contains($rn)) { [void]$byIdentity[$id].Add($rn) }
            }
            $data.DCSyncAccounts = @($byIdentity.Keys | ForEach-Object {
                    @{ SamAccountName = $_; Rights = @($byIdentity[$_]) }
                })
        }
    }

    # ── 9. Group Policy Objects ──────────────────────────────────────────
    if (& $needsSource 'GroupPolicyObjects') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Collecting Group Policy Objects'
        }
        try {
            $data.GroupPolicies = Get-ADGroupPolicyObjects -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to collect Group Policy Objects: $_"
            $data.Errors['GroupPolicyObjects'] = $_.Exception.Message
        }
    }

    # ── 10. Logon Scripts ────────────────────────────────────────────────
    if (& $needsSource 'LogonScripts') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Analyzing logon scripts'
        }
        try {
            $data.LogonScripts = Get-ADLogonScripts -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to analyze logon scripts: $_"
            $data.Errors['LogonScripts'] = $_.Exception.Message
        }
    }

    # ── 11. Certificate Services (AD CS) ─────────────────────────────────
    if (& $needsSource 'CertificateServices') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Enumerating AD Certificate Services'
        }
        try {
            $data.CertificateServices = Get-ADCertificateServices -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to enumerate Certificate Services: $_"
            $data.Errors['CertificateServices'] = $_.Exception.Message
        }
    }

    # ── 12. Network policy (relay-precondition surface) ──────────────────
    if (& $needsSource 'NetworkConfig') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Reading network-layer policy from SYSVOL'
        }
        try {
            $data.Network = Get-ADNetworkConfig -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to read network policy from SYSVOL: $_"
            $data.Errors['NetworkConfig'] = $_.Exception.Message
        }
    }

    # ── 13. Tier-Zero signals (MSOL_ accounts, hybrid identity surface) ──
    if (& $needsSource 'TierZeroSignals') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Scanning for Tier-0 hybrid-identity signals'
        }
        try {
            $data.TierZero = Get-ADTierZeroSignals -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Tier-Zero signal collection failed: $_"
            $data.Errors['TierZeroSignals'] = $_.Exception.Message
        }
    }

    # ── 14. Tradecraft signals (cpassword, DCShadow, BitLocker, RODC) ────
    if (& $needsSource 'TradecraftSignals') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Scanning for adversary-tradecraft signals'
        }
        try {
            $data.Tradecraft = Get-ADTradecraftSignals -Connection $Connection -Quiet:$Quiet
        } catch {
            Write-Warning "Tradecraft signal collection failed: $_"
            $data.Errors['TradecraftSignals'] = $_.Exception.Message
        }
    }

    # ── 15. Stale Objects ────────────────────────────────────────────────
    if (& $needsSource 'StaleObjects') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Identifying stale and abandoned objects'
        }
        try {
            $data.StaleObjects = Get-ADStaleObjects `
                -Connection $Connection `
                -InactiveDays $InactiveDays `
                -PasswordAgeDays $PasswordAgeDays `
                -Quiet:$Quiet
        } catch {
            Write-Warning "Failed to identify stale objects: $_"
            $data.Errors['StaleObjects'] = $_.Exception.Message
        }
    }

    # ── 16. Replication health (ADDOM-007) ───────────────────────────────
    # Only attempt if domain info was collected (we merge into $data.Domain).
    if ((& $needsSource 'DomainInfo') -and $data.Domain) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Assessing AD replication health'
        }
        try {
            $dcCount = if ($null -ne $data.DomainControllers) { @($data.DomainControllers).Count } else { 0 }
            $replHealth = Get-ADReplicationHealth -Connection $Connection -DomainControllerCount $dcCount -Quiet:$Quiet
            # $null means "not assessable" — leave it so ADDOM-007 SKIPs honestly.
            if ($null -ne $replHealth) {
                $data.Domain.ReplicationHealth = $replHealth
            }
        } catch {
            Write-Warning "Replication health collection failed: $_"
            $data.Errors['ReplicationHealth'] = $_.Exception.Message
        }
    }

    # ── 17. User Rights Assignment on DCs (ADPRIV-026/027) ────────────────
    # Parses the Domain Controllers OU GPO security template (GptTmpl.inf).
    if (& $needsSource 'PrivilegedMembers') {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Parsing DC-OU User Rights Assignment from SYSVOL'
        }
        try {
            # If the GroupPolicies collector found GPOs linked to the DC OU,
            # pass their GUIDs so additional templates get parsed.
            $uraConn = $Connection.Clone()
            if ($data.GroupPolicies -and $data.GroupPolicies.ContainsKey('DCOULinkedGpoGuids')) {
                $uraConn['DCOULinkedGpoGuids'] = @($data.GroupPolicies.DCOULinkedGpoGuids)
            }
            $ura = Get-ADUserRightsAssignment -Connection $uraConn -Quiet:$Quiet
            if ($null -ne $ura) {
                if (-not $data.PrivilegedAccounts) { $data.PrivilegedAccounts = @{} }
                $data.PrivilegedAccounts['UserRightsAssignment'] = $ura
            }
        } catch {
            Write-Warning "User Rights Assignment collection failed: $_"
            $data.Errors['UserRightsAssignment'] = $_.Exception.Message
        }
    }

    # ── 18. NT-hash quality via DSInternals (ADPWD-010/011, ADPRIV-016) ───
    # Only when the password-hash analysis is in scope (PasswordPolicies or
    # PrivilegedMembers) AND DSInternals is available. On any failure the
    # collector returns null fields so the dependent checks SKIP.
    $hashScope = (& $needsSource 'PasswordPolicies') -or (& $needsSource 'PrivilegedMembers')
    if ($hashScope -and $data.ModuleAvailability -and $data.ModuleAvailability.DSInternals) {
        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message 'Analyzing NT password-hash quality (DSInternals)'
        }
        try {
            # Build the privileged SamAccountName allow-set so the collector can
            # compute the ADPRIV-016 privileged subset (names only — no hashes).
            $privSamNames = @()
            if ($data.PrivilegedAccounts -and $data.PrivilegedAccounts.AllPrivilegedUsers) {
                $privSamNames = @($data.PrivilegedAccounts.AllPrivilegedUsers |
                    ForEach-Object { $_.SamAccountName } |
                    Where-Object { $_ })
            }
            $hashConn = $Connection.Clone()
            $hashConn['PrivilegedSamNames'] = $privSamNames

            $hashParams = @{ Connection = $hashConn; Quiet = $Quiet }
            if ($WeakPasswordList) { $hashParams['WeakPasswordHashesFile'] = $WeakPasswordList }

            $hq = Get-ADPasswordHashQuality @hashParams

            if ($null -ne $hq -and $hq.Performed) {
                if (-not $data.PasswordPolicies) { $data.PasswordPolicies = @{} }
                # Only the no-dataset-required fields are always set; the rest stay
                # $null (Not Assessed) unless a dataset was supplied.
                $data.PasswordPolicies['BlankPasswordUsers']   = $hq.BlankPasswordUsers
                $data.PasswordPolicies['DuplicateHashGroups']  = $hq.DuplicateHashGroups
                if ($null -ne $hq.HIBPCompromisedUsers) { $data.PasswordPolicies['HIBPCompromisedUsers'] = $hq.HIBPCompromisedUsers }
                if ($null -ne $hq.DictionaryMatchUsers) { $data.PasswordPolicies['DictionaryMatchUsers'] = $hq.DictionaryMatchUsers }
                if ($null -ne $hq.CommonPasswordUsers)  { $data.PasswordPolicies['CommonPasswordUsers']  = $hq.CommonPasswordUsers }

                # Privileged weak-password subset for ADPRIV-016.
                if ($null -ne $hq.PasswordAnalysis) {
                    if (-not $data.PrivilegedAccounts) { $data.PrivilegedAccounts = @{} }
                    $data.PrivilegedAccounts['PasswordAnalysis'] = $hq.PasswordAnalysis
                    $data.PasswordAnalysis = $hq.PasswordAnalysis
                }
            } elseif ($null -ne $hq -and $hq.Error) {
                # Record why analysis did not run; fields stay $null → checks SKIP.
                $data.Errors['PasswordHashQuality'] = $hq.Error
            }
        } catch {
            Write-Warning "NT password-hash analysis failed: $_"
            $data.Errors['PasswordHashQuality'] = $_.Exception.Message
        }
    }

    # ── Summary ──────────────────────────────────────────────────────────
    if (-not $Quiet) {
        $collectedCount = 0
        $nullKeys = [System.Collections.Generic.List[string]]::new()

        foreach ($key in @('Domain', 'DomainControllers', 'Trusts', 'PrivilegedAccounts',
                           'PasswordPolicies', 'Kerberos', 'ACLs', 'GroupPolicies',
                           'LogonScripts', 'CertificateServices', 'StaleObjects', 'Network', 'TierZero', 'Tradecraft')) {
            if ($null -ne $data[$key]) {
                $collectedCount++
            } elseif ($requiredSources.Count -gt 0) {
                # Only track as missing if it was actually requested
                $sourceMapping = @{
                    Domain             = 'DomainInfo'
                    DomainControllers  = 'DomainControllers'
                    Trusts             = 'TrustRelationships'
                    PrivilegedAccounts = 'PrivilegedMembers'
                    PasswordPolicies   = 'PasswordPolicies'
                    Kerberos           = 'KerberosConfig'
                    ACLs               = 'ObjectACLs'
                    GroupPolicies      = 'GroupPolicyObjects'
                    LogonScripts       = 'LogonScripts'
                    CertificateServices = 'CertificateServices'
                    StaleObjects       = 'StaleObjects'
                    Network            = 'NetworkConfig'
                    TierZero           = 'TierZeroSignals'
                    Tradecraft         = 'TradecraftSignals'
                }
                if ($sourceMapping.ContainsKey($key) -and $requiredSources.Contains($sourceMapping[$key])) {
                    $nullKeys.Add($key)
                }
            }
        }

        $errorCount = $data.Errors.Count
        $domainName = if ($data.Domain) { $data.Domain.DomainName } else { 'unknown' }

        $summary = "Reconnaissance complete for $domainName`: $collectedCount data source(s) collected"
        if ($errorCount -gt 0) {
            $summary += ", $errorCount error(s)"
        }
        if ($nullKeys.Count -gt 0) {
            $summary += " (missing: $($nullKeys -join ', '))"
        }
        Write-ProgressLine -Phase RECON -Message $summary
    }

    return $data
}
