# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADTradecraftSignals {
    <#
    .SYNOPSIS
        Collects signals for advanced-adversary tradecraft detection.
    .DESCRIPTION
        Gathers:
          * GPP cpassword matches across SYSVOL Policies\**\*.xml
          * Server objects under CN=Sites,CN=Configuration (DCShadow surface)
          * msFVE-RecoveryInformation objects + parent computer staleness
          * RODC inventory (so the PRP check can short-circuit if none)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        CpasswordHits        = @()
        ConfigPartitionServers = @()
        BitLockerKeys        = @()
        Rodcs                = @()
        SysvolReadable       = $false
        # ── Modern adversary tradecraft (ADTRADE-005..010) ────────────────
        SeamlessSsoAccount   = $null   # AZUREADSSOACC$ computer account (pwdLastSet)
        ShadowCredentials    = @()     # privileged principals carrying msDS-KeyCredentialLink
        ShadowCredCollected  = $false  # did the privileged-principal enumeration run cleanly?
        DmsaClassPresent     = $null   # schema has msDS-DelegatedManagedServiceAccount class?
        BadSuccessorOus      = @()     # OUs where a non-Tier0 principal can create/write dMSA
        DmsaAclCollected     = $false  # did the OU ACL sweep run cleanly?
        EnterpriseKeyAdmins  = @()     # members of Enterprise Key Admins
        KeyAdmins            = @()     # members of Key Admins
        KeyAdminGroupsFound  = $false  # were the Key Admins / Enterprise Key Admins groups resolvable?
        CertPublishers       = @()     # members of Cert Publishers
        CertPublishersFound  = $false  # was the Cert Publishers group resolvable?
        GmsaAccounts         = @()     # gMSA inventory + PrincipalsAllowedToRetrieveManagedPassword
        GmsaCollected        = $false  # did the gMSA enumeration run cleanly?
        Errors               = @{}
    }

    $domainDns = ($Connection.DomainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

    # Well-known SIDs / RID suffixes that are legitimately privileged (Tier-0). A principal whose
    # SID matches one of these is NOT an escalation when it can read a gMSA password or write a
    # KeyCredentialLink — these are the accounts that are SUPPOSED to hold that power.
    $tier0RidSuffixes = @('-512', '-516', '-518', '-519', '-521', '-526', '-527')  # DA, DCs, Schema, EA, RODC, Key Admins, Enterprise Key Admins
    $tier0WellKnown   = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9')                    # SYSTEM, Administrators, Enterprise DCs
    $isTier0Sid = {
        param([string]$Sid)
        if (-not $Sid) { return $false }
        if ($tier0WellKnown -contains $Sid) { return $true }
        foreach ($suffix in $tier0RidSuffixes) { if ($Sid.EndsWith($suffix)) { return $true } }
        return $false
    }

    # Helper: resolve a group by domain-relative RID (or well-known SID) and return its recursive
    # non-group members as lightweight hashtables. Reuses the LDAP_MATCHING_RULE_IN_CHAIN pattern.
    $resolveGroupMembers = {
        param([string]$GroupSid, [string]$SearchBase)
        $out = @{ Found = $false; Members = @() }
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($GroupSid)
            # SecurityIdentifier has no GetSidBytes(); use GetBinaryForm. The previous call threw and
            # was swallowed here, making every RID-relative group lookup SKIP ("could not be resolved").
            $sidBytes = New-Object byte[] $sidObj.BinaryLength
            $sidObj.GetBinaryForm($sidBytes, 0)
            $escapedSid = ($sidBytes | ForEach-Object { '\' + $_.ToString('x2') }) -join ''
            $root = New-LdapSearchRoot -Connection $Connection -SearchBase $SearchBase
            $grp = @(Invoke-LdapQuery -SearchRoot $root `
                -Filter "(objectSid=$escapedSid)" `
                -Properties @('distinguishedName', 'sAMAccountName') -SizeLimit 1)
            if ($grp.Count -eq 0) { return $out }
            $out.Found = $true
            $groupDN = $grp[0]['distinguishedname']
            $memberRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
            $members = @(Invoke-LdapQuery -SearchRoot $memberRoot `
                -Filter "(memberOf:1.2.840.113556.1.4.1941:=$groupDN)" `
                -Properties @('sAMAccountName', 'objectClass', 'objectSid', 'distinguishedName', 'userAccountControl'))
            $out.Members = @($members | ForEach-Object {
                $oc = $_['objectclass']
                $leaf = if ($oc -is [System.Array]) { "$($oc[-1])" } else { "$oc" }
                @{
                    SamAccountName    = "$($_['samaccountname'])"
                    ObjectClass       = $leaf
                    ObjectSid         = if ($_['objectsid']) { try { ([System.Security.Principal.SecurityIdentifier]::new([byte[]]$_['objectsid'], 0)).Value } catch { '' } } else { '' }
                    DistinguishedName = "$($_['distinguishedname'])"
                }
            })
        } catch {
            $out.Error = $_.Exception.Message
        }
        return $out
    }

    # Domain SID (needed for the RID-relative Cert Publishers group).
    $domainSidString = ''
    try {
        $dRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $dObj = @(Invoke-LdapQuery -SearchRoot $dRoot -Filter '(objectClass=domainDNS)' `
            -Properties @('objectSid') -Scope Base)
        if ($dObj.Count -gt 0 -and $dObj[0].ContainsKey('objectsid')) {
            # objectSid is returned as a System.Byte[]. String-interpolating it yields the
            # space-joined decimal bytes (a malformed SID), so every RID-relative group lookup
            # (Cert Publishers / Key Admins / Enterprise Key Admins) silently failed and the
            # checks SKIP'd. Convert to the canonical S-1-5-21-… string before appending RIDs;
            # resolveGroupMembers then re-parses and binary-escapes it correctly.
            $rawSid = $dObj[0]['objectsid']
            if ($rawSid -is [byte[]]) {
                $domainSidString = ([System.Security.Principal.SecurityIdentifier]::new($rawSid, 0)).Value
            } elseif ("$rawSid" -match '^S-\d') {
                $domainSidString = "$rawSid"
            }
        }
    } catch {
        $result.Errors['DomainSID'] = $_.Exception.Message
    }

    # ── 1. GPP cpassword scan ────────────────────────────────────────────
    $policiesRoot = "\\$domainDns\SYSVOL\$domainDns\Policies"
    try {
        if (Test-Path -LiteralPath $policiesRoot -ErrorAction Stop) {
            $result.SysvolReadable = $true
            $xmlFiles = @(Get-ChildItem -LiteralPath $policiesRoot -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue)
            foreach ($f in $xmlFiles) {
                try {
                    $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                    if ($content -match 'cpassword="([^"]+)"') {
                        # Capture surrounding userName/runAs if present for human-readable output
                        $userMatch = if ($content -match 'userName="([^"]+)"') { $Matches[1] }
                                     elseif ($content -match 'runAs="([^"]+)"') { $Matches[1] }
                                     else { '(unknown)' }
                        $result.CpasswordHits += [PSCustomObject]@{
                            FilePath = $f.FullName
                            ExposedUser = $userMatch
                            CpasswordLength = $Matches[1].Length
                        }
                    }
                } catch {
                    # Don't fail the whole scan on a single unreadable XML
                }
            }
        }
    } catch {
        $result.Errors['CpasswordScan'] = $_.Exception.Message
    }

    # ── 2. Configuration-partition server objects ───────────────────────
    try {
        $configDN = $Connection.ConfigDN
        if ($configDN) {
            $sitesDN = "CN=Sites,$configDN"
            $sitesRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $sitesDN
            $servers = @(Invoke-LdapQuery -SearchRoot $sitesRoot `
                -Filter '(objectClass=server)' `
                -Properties @('cn', 'dNSHostName', 'distinguishedName', 'whenCreated', 'serverReference'))
            foreach ($s in $servers) {
                $result.ConfigPartitionServers += [PSCustomObject]@{
                    CN                = $s['cn'] ?? ''
                    DNSHostName       = $s['dnshostname'] ?? ''
                    DistinguishedName = $s['distinguishedname'] ?? ''
                    WhenCreated       = $s['whencreated']
                    ServerReference   = $s['serverreference'] ?? ''
                }
            }
        }
    } catch {
        $result.Errors['ConfigPartitionServers'] = $_.Exception.Message
    }

    # ── 3. BitLocker recovery information ───────────────────────────────
    try {
        $blRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $blKeys = @(Invoke-LdapQuery -SearchRoot $blRoot `
            -Filter '(objectClass=msFVE-RecoveryInformation)' `
            -Properties @('distinguishedName', 'whenCreated'))
        foreach ($k in $blKeys) {
            # Parent computer DN = drop the leftmost CN= component
            $dn = $k['distinguishedname']
            $parentDN = if ($dn -match '^[^,]+,(.+)$') { $Matches[1] } else { $null }
            $result.BitLockerKeys += [PSCustomObject]@{
                DistinguishedName = $dn
                ParentComputer    = $parentDN
                WhenCreated       = $k['whencreated']
            }
        }
    } catch {
        $result.Errors['BitLockerKeys'] = $_.Exception.Message
    }

    # ── 4. RODC inventory ───────────────────────────────────────────────
    try {
        $rodcRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        # RODCs have userAccountControl bit 0x4000000 (PARTIAL_SECRETS_ACCOUNT, 67108864) set on their computer object.
        $rodcs = @(Invoke-LdapQuery -SearchRoot $rodcRoot `
            -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864))' `
            -Properties @('cn', 'dNSHostName', 'distinguishedName'))
        foreach ($r in $rodcs) {
            $result.Rodcs += [PSCustomObject]@{
                CN                = $r['cn'] ?? ''
                DNSHostName       = $r['dnshostname'] ?? ''
                DistinguishedName = $r['distinguishedname'] ?? ''
            }
        }
    } catch {
        $result.Errors['Rodcs'] = $_.Exception.Message
    }

    # ── 5. Seamless SSO computer account (AZUREADSSOACC$) — ADTRADE-005 ───
    # If its Kerberos key (pwdLastSet) is stale (>90d), an attacker who has obtained the key
    # can forge Silver Tickets for any Azure AD / Entra hybrid user indefinitely (T1558.002).
    try {
        $ssoRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $sso = @(Invoke-LdapQuery -SearchRoot $ssoRoot `
            -Filter '(&(objectCategory=computer)(sAMAccountName=AZUREADSSOACC$))' `
            -Properties @('sAMAccountName', 'distinguishedName', 'pwdLastSet', 'whenCreated') -SizeLimit 1)
        if ($sso.Count -gt 0) {
            $result.SeamlessSsoAccount = @{
                SamAccountName    = "$($sso[0]['samaccountname'])"
                DistinguishedName = "$($sso[0]['distinguishedname'])"
                PwdLastSet        = $sso[0]['pwdlastset']   # already converted to [datetime] (or $null) by Convert-LdapValue
                WhenCreated       = $sso[0]['whencreated']
            }
        }
        # absent account => Seamless SSO not configured; leave SeamlessSsoAccount $null => check SKIPs
    } catch {
        $result.Errors['SeamlessSso'] = $_.Exception.Message
    }

    # ── 6. Shadow credentials on privileged principals — ADTRADE-006 ─────
    # msDS-KeyCredentialLink lets a principal authenticate with an attacker-supplied key pair
    # (Whisker / pyWhisker, T1556). Enumerate the attribute on Tier-0-relevant objects: privileged
    # group members, all domain controllers, and any object whose adminCount=1.
    try {
        $scRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        # adminCount=1 captures users/computers protected by AdminSDHolder (current + historical Tier-0);
        # the DC filter captures domain controllers, which are Tier-0 by definition.
        $scFilter = '(&(|(objectCategory=person)(objectCategory=computer))(msDS-KeyCredentialLink=*)(|(adminCount=1)(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))'
        $scHits = @(Invoke-LdapQuery -SearchRoot $scRoot -Filter $scFilter `
            -Properties @('sAMAccountName', 'distinguishedName', 'objectClass', 'adminCount', 'userAccountControl', 'msDS-KeyCredentialLink'))
        $result.ShadowCredCollected = $true
        foreach ($h in $scHits) {
            $oc = $h['objectclass']
            $leaf = if ($oc -is [System.Array]) { "$($oc[-1])" } else { "$oc" }
            $kcl = $h['msds-keycredentiallink']
            $kclCount = if ($kcl -is [System.Array]) { $kcl.Count } elseif ($kcl) { 1 } else { 0 }
            $uac = 0; [void][int]::TryParse("$($h['useraccountcontrol'])", [ref]$uac)
            # SERVER_TRUST_ACCOUNT (0x2000) or PARTIAL_SECRETS_ACCOUNT/RODC (0x4000000) => domain controller.
            $isDc = (($uac -band 8192) -ne 0) -or (($uac -band 67108864) -ne 0)
            $result.ShadowCredentials += @{
                SamAccountName     = "$($h['samaccountname'])"
                DistinguishedName  = "$($h['distinguishedname'])"
                ObjectClass        = $leaf
                AdminCount         = "$($h['admincount'])"
                KeyCredentialCount = $kclCount
                IsComputer         = ($leaf -eq 'computer')
                IsDomainController = $isDc
            }
        }
    } catch {
        # A directory that simply has no key credentials returns zero rows (still "collected").
        # Only a genuine query failure should leave ShadowCredCollected = $false so the check SKIPs.
        $result.Errors['ShadowCredentials'] = $_.Exception.Message
    }

    # ── 7. BadSuccessor dMSA escalation surface — ADTRADE-007 ────────────
    # dMSA (msDS-DelegatedManagedServiceAccount) shipped with Server 2025. If a non-Tier-0 principal
    # can create a dMSA in an OU (CreateChild on the dMSA class) it can be migrated onto a privileged
    # account, inheriting its Kerberos keys (T1098). First confirm the schema actually has the class —
    # pre-2025 forests will not, and the check must SKIP gracefully rather than PASS.
    $dmsaSchemaGuid = $null
    try {
        $schemaRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.SchemaDN
        $dmsaClass = @(Invoke-LdapQuery -SearchRoot $schemaRoot `
            -Filter '(&(objectClass=classSchema)(lDAPDisplayName=msDS-DelegatedManagedServiceAccount))' `
            -Properties @('schemaIDGUID', 'lDAPDisplayName') -SizeLimit 1)
        if ($dmsaClass.Count -gt 0) {
            $result.DmsaClassPresent = $true
            $rawGuid = $dmsaClass[0]['schemaidguid']
            if ($rawGuid -is [byte[]]) { $dmsaSchemaGuid = ([guid]$rawGuid) }
        } else {
            $result.DmsaClassPresent = $false
        }
    } catch {
        $result.Errors['DmsaSchema'] = $_.Exception.Message
        # leave DmsaClassPresent $null => check SKIPs (schema unreadable, not "absent")
    }

    if ($result.DmsaClassPresent -eq $true) {
        try {
            $ouRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
            $ous = @(Invoke-LdapQuery -SearchRoot $ouRoot -Filter '(objectCategory=organizationalUnit)' `
                -Properties @('distinguishedName', 'name', 'ntsecuritydescriptor'))
            $result.DmsaAclCollected = $true
            # CreateChild = 0x1; GenericAll/WriteDacl/WriteOwner also grant the ability to set it up.
            $createChild = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
            $dangerousRights = @('GenericAll', 'WriteDacl', 'WriteOwner')
            foreach ($ou in $ous) {
                $sdBytes = $ou['ntsecuritydescriptor']
                if (-not ($sdBytes -is [byte[]])) { continue }
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                try {
                    $sd.SetSecurityDescriptorBinaryForm($sdBytes)
                    $rules = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                } catch { continue }
                $risky = [System.Collections.Generic.List[hashtable]]::new()
                foreach ($rule in $rules) {
                    if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }
                    $pSid = $rule.IdentityReference.Value
                    if (& $isTier0Sid $pSid) { continue }
                    $rights = $rule.ActiveDirectoryRights
                    $otGuid = $rule.ObjectType.ToString()
                    $grantsCreate = (($rights -band $createChild) -ne 0) -and
                        ($otGuid -eq '00000000-0000-0000-0000-000000000000' -or ($dmsaSchemaGuid -and $otGuid -eq $dmsaSchemaGuid.ToString()))
                    $grantsBroad = $false
                    foreach ($dr in $dangerousRights) { if ($rights.ToString() -match $dr) { $grantsBroad = $true; break } }
                    if ($grantsCreate -or $grantsBroad) {
                        $risky.Add(@{
                            Principal = $pSid
                            Rights    = $rights.ToString()
                            Scope     = if ($grantsCreate -and $otGuid -eq $dmsaSchemaGuid.ToString()) { 'dMSA-class CreateChild' }
                                        elseif ($grantsCreate) { 'CreateChild (all classes)' }
                                        else { 'Broad write (GenericAll/WriteDacl/WriteOwner)' }
                        })
                    }
                }
                if ($risky.Count -gt 0) {
                    $result.BadSuccessorOus += @{
                        OU       = "$($ou['distinguishedname'])"
                        Name     = "$($ou['name'])"
                        RiskyAces = @($risky)
                    }
                }
            }
        } catch {
            $result.Errors['BadSuccessorAcl'] = $_.Exception.Message
        }
    }

    # ── 8. Enterprise Key Admins / Key Admins membership — ADTRADE-008 ───
    # These groups hold msDS-KeyCredentialLink write rights domain-wide (a domain-wide shadow-cred
    # primitive). They ship EMPTY; any member is an escalation path (T1556).
    if ($domainSidString) {
        $ek = & $resolveGroupMembers "$domainSidString-527" $Connection.DomainDN   # Enterprise Key Admins
        $ka = & $resolveGroupMembers "$domainSidString-526" $Connection.DomainDN   # Key Admins
        if ($ek.Found -or $ka.Found) { $result.KeyAdminGroupsFound = $true }
        if ($ek.Found) { $result.EnterpriseKeyAdmins = @($ek.Members) }
        if ($ka.Found) { $result.KeyAdmins = @($ka.Members) }
        if ($ek.Error) { $result.Errors['EnterpriseKeyAdmins'] = $ek.Error }
        if ($ka.Error) { $result.Errors['KeyAdmins'] = $ka.Error }
    }

    # ── 9. Cert Publishers membership — ADTRADE-009 ──────────────────────
    # Members can publish certificates to the NTAuth store; an attacker-controlled member can enable
    # certificate-based authentication abuse (ESC, T1649). Domain RID 517.
    if ($domainSidString) {
        $cp = & $resolveGroupMembers "$domainSidString-517" $Connection.DomainDN
        if ($cp.Found) {
            $result.CertPublishersFound = $true
            $result.CertPublishers = @($cp.Members)
        }
        if ($cp.Error) { $result.Errors['CertPublishers'] = $cp.Error }
    }

    # ── 10. gMSA posture — ADTRADE-010 ───────────────────────────────────
    # Group Managed Service Accounts: who can retrieve the managed password
    # (msDS-GroupMSAMembership / PrincipalsAllowedToRetrieveManagedPassword). If that SD grants a
    # broad or non-privileged principal, the gMSA password is recoverable (GMSAPasswordReader, T1552).
    try {
        $gmsaRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $gmsas = @(Invoke-LdapQuery -SearchRoot $gmsaRoot `
            -Filter '(objectClass=msDS-GroupManagedServiceAccount)' `
            -Properties @('sAMAccountName', 'distinguishedName', 'msDS-GroupMSAMembership'))
        $result.GmsaCollected = $true
        # SIDs that make a gMSA password "broadly" retrievable (everyone / authenticated users / domain users).
        $broadSids = @('S-1-1-0', 'S-1-5-11', 'S-1-5-7')
        foreach ($g in $gmsas) {
            $retrievers = [System.Collections.Generic.List[hashtable]]::new()
            $broad = $false
            $nonTier0 = $false
            $sdBytes = $g['msds-groupmsamembership']
            if ($sdBytes -is [byte[]]) {
                $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                try {
                    $sd.SetSecurityDescriptorBinaryForm($sdBytes)
                    $rules = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                    foreach ($rule in $rules) {
                        if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }
                        $pSid = $rule.IdentityReference.Value
                        $isBroad = $broadSids -contains $pSid -or ($pSid -match '-513$')  # -513 = Domain Users
                        $isT0 = & $isTier0Sid $pSid
                        if ($isBroad) { $broad = $true }
                        if (-not $isT0 -and -not $isBroad) { $nonTier0 = $true }
                        $retrievers.Add(@{ Principal = $pSid; Broad = $isBroad; Tier0 = $isT0 })
                    }
                } catch { }
            }
            $result.GmsaAccounts += @{
                SamAccountName    = "$($g['samaccountname'])"
                DistinguishedName = "$($g['distinguishedname'])"
                Retrievers        = @($retrievers)
                BroadlyRetrievable = $broad
                NonTier0Retrievable = $nonTier0
            }
        }
    } catch {
        $result.Errors['Gmsa'] = $_.Exception.Message
    }

    return $result
}
