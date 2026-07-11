# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADPrivilegedMembers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $domainDN = $Connection.DomainDN

    $result = @{
        PrivilegedGroups      = @{}
        AllPrivilegedUsers    = @()
        AdminSDHolderACL      = $null
        AdminCountOrphans     = @()
        KrbtgtAccount         = $null
        ProtectedUsersMembers = @()
        Errors                = @{}
    }

    # ── Member properties to retrieve ─────────────────────────────────
    $memberProperties = @(
        'sAMAccountName', 'distinguishedName', 'objectClass', 'objectSid',
        'userAccountControl', 'pwdLastSet', 'lastLogonTimestamp',
        'adminCount', 'memberOf', 'servicePrincipalName',
        'whenCreated', 'displayName', 'description'
    )

    # ── Helper: Get the DN of a group by its well-known SID/RID ───────
    $domainSidString = ''
    try {
        $domainRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $domainObj = Invoke-LdapQuery -SearchRoot $domainRoot `
            -Filter '(objectClass=domainDNS)' `
            -Properties @('objectSid') `
            -Scope Base
        if ($domainObj.Count -gt 0 -and $domainObj[0].ContainsKey('objectsid')) {
            $domainSidString = $domainObj[0]['objectsid']
        }
    } catch {
        Write-Verbose "Failed to retrieve domain SID: $_"
        $result.Errors['DomainSID'] = $_.Exception.Message
    }

    # Helper function to find a group DN by SID
    $findGroupBySid = {
        param([string]$SidString, [System.DirectoryServices.DirectoryEntry]$SearchRoot)
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($SidString)
            # SecurityIdentifier has no GetSidBytes(); use GetBinaryForm (the old call threw silently).
            $sidBytes = New-Object byte[] $sidObj.BinaryLength
            $sidObj.GetBinaryForm($sidBytes, 0)
            $escapedSid = ($sidBytes | ForEach-Object { '\' + $_.ToString('x2') }) -join ''
            $results = @(Invoke-LdapQuery -SearchRoot $SearchRoot `
                -Filter "(objectSid=$escapedSid)" `
                -Properties @('distinguishedName', 'cn', 'sAMAccountName') `
                -SizeLimit 1)
            if ($results.Count -gt 0) {
                return $results[0]
            }
        } catch {
            Write-Verbose "Failed to find group by SID $SidString`: $_"
        }
        return $null
    }

    # Helper function to find a group DN by name
    $findGroupByName = {
        param([string]$GroupName, [System.DirectoryServices.DirectoryEntry]$SearchRoot)
        try {
            $results = @(Invoke-LdapQuery -SearchRoot $SearchRoot `
                -Filter "(&(objectClass=group)(sAMAccountName=$GroupName))" `
                -Properties @('distinguishedName', 'cn', 'sAMAccountName') `
                -SizeLimit 1)
            if ($results.Count -gt 0) {
                return $results[0]
            }
        } catch {
            Write-Verbose "Failed to find group by name $GroupName`: $_"
        }
        return $null
    }

    # ── Define privileged groups to enumerate ─────────────────────────
    # Domain-relative groups use the domain SID + RID
    # Builtin groups use well-known SIDs
    $privilegedGroupDefs = [ordered]@{}

    if ($domainSidString) {
        $privilegedGroupDefs['Domain Admins']     = @{ SID = "$domainSidString-512"; RID = 512 }
        $privilegedGroupDefs['Enterprise Admins']  = @{ SID = "$domainSidString-519"; RID = 519 }
        $privilegedGroupDefs['Schema Admins']      = @{ SID = "$domainSidString-518"; RID = 518 }
    } else {
        # Fallback: search by name if we cannot construct SID
        $privilegedGroupDefs['Domain Admins']     = @{ Name = 'Domain Admins' }
        $privilegedGroupDefs['Enterprise Admins']  = @{ Name = 'Enterprise Admins' }
        $privilegedGroupDefs['Schema Admins']      = @{ Name = 'Schema Admins' }
    }

    # Builtin groups (well-known SIDs)
    $privilegedGroupDefs['Administrators']     = @{ SID = 'S-1-5-32-544'; Builtin = $true }
    $privilegedGroupDefs['Account Operators']  = @{ SID = 'S-1-5-32-548'; Builtin = $true }
    $privilegedGroupDefs['Server Operators']   = @{ SID = 'S-1-5-32-549'; Builtin = $true }
    $privilegedGroupDefs['Print Operators']    = @{ SID = 'S-1-5-32-550'; Builtin = $true }
    $privilegedGroupDefs['Backup Operators']   = @{ SID = 'S-1-5-32-551'; Builtin = $true }

    # DnsAdmins: no well-known builtin SID; RID is typically 1101 but not guaranteed
    if ($domainSidString) {
        $privilegedGroupDefs['DnsAdmins'] = @{ SID = "$domainSidString-1101"; RID = 1101; FallbackName = 'DnsAdmins' }
    } else {
        $privilegedGroupDefs['DnsAdmins'] = @{ Name = 'DnsAdmins' }
    }

    # ── 1. Resolve group DNs and enumerate recursive members ──────────
    $allPrivilegedUsersDN = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $allPrivilegedUsersMap = @{}  # DN -> member object

    foreach ($groupEntry in $privilegedGroupDefs.GetEnumerator()) {
        $groupLabel = $groupEntry.Key
        $groupDef = $groupEntry.Value

        if (-not $Quiet) {
            Write-ProgressLine -Phase AUDITING -Message 'Enumerating privileged group' -Detail $groupLabel
        }

        # Resolve the group DN
        $groupObj = $null
        $groupDN = ''

        # Determine search root based on whether this is a builtin group
        $searchRootDN = if ($groupDef.ContainsKey('Builtin') -and $groupDef.Builtin) {
            "CN=Builtin,$domainDN"
        } else {
            $domainDN
        }

        try {
            $groupSearchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $searchRootDN

            if ($groupDef.ContainsKey('SID') -and $groupDef.SID) {
                $groupObj = & $findGroupBySid $groupDef.SID $groupSearchRoot
            }

            # Fallback to name search if SID lookup failed
            if (-not $groupObj) {
                $fallbackName = if ($groupDef.ContainsKey('FallbackName')) { $groupDef.FallbackName }
                                elseif ($groupDef.ContainsKey('Name')) { $groupDef.Name }
                                else { $groupLabel }
                # Search from domain root for name-based lookups
                $domainSearchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
                $groupObj = & $findGroupByName $fallbackName $domainSearchRoot
            }
        } catch {
            Write-Verbose "Failed to resolve group $groupLabel`: $_"
            $result.Errors["Group_$groupLabel"] = $_.Exception.Message
        }

        if (-not $groupObj) {
            Write-Verbose "Group '$groupLabel' not found in this domain"
            $result.PrivilegedGroups[$groupLabel] = @()
            continue
        }

        $groupDN = $groupObj['distinguishedname']
        Write-Verbose "Resolved group '$groupLabel' to DN: $groupDN"

        # Use LDAP_MATCHING_RULE_IN_CHAIN for recursive membership
        # This returns all objects that are transitively a member of the group
        $memberFilter = "(memberOf:1.2.840.113556.1.4.1941:=$groupDN)"

        $members = @()
        try {
            $memberSearchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
            $members = Invoke-LdapQuery -SearchRoot $memberSearchRoot `
                -Filter $memberFilter `
                -Properties $memberProperties
        } catch {
            Write-Verbose "Failed to enumerate members of $groupLabel`: $_"
            $result.Errors["Members_$groupLabel"] = $_.Exception.Message
        }

        # Also check builtin container for nested builtin group members
        if ($groupDef.ContainsKey('Builtin') -and $groupDef.Builtin) {
            try {
                $builtinSearchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase "CN=Builtin,$domainDN"
                $builtinMembers = Invoke-LdapQuery -SearchRoot $builtinSearchRoot `
                    -Filter $memberFilter `
                    -Properties $memberProperties
                if ($builtinMembers.Count -gt 0) {
                    $members = @($members) + @($builtinMembers)
                }
            } catch {
                Write-Verbose "Failed to enumerate builtin members of $groupLabel`: $_"
            }
        }

        Write-Verbose "Group '$groupLabel' has $($members.Count) recursive member(s)"

        # Build normalized member objects
        $groupMembers = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($member in $members) {
            $memberDN = if ($member.ContainsKey('distinguishedname')) { $member['distinguishedname'] } else { '' }

            # Skip duplicates within this group
            $existingInGroup = $groupMembers | Where-Object { $_.DistinguishedName -eq $memberDN }
            if ($existingInGroup) { continue }

            $sam = if ($member.ContainsKey('samaccountname')) { $member['samaccountname'] } else { '' }
            $uac = if ($member.ContainsKey('useraccountcontrol')) { [int]$member['useraccountcontrol'] } else { 0 }
            $objectClasses = if ($member.ContainsKey('objectclass')) {
                $oc = $member['objectclass']
                if ($oc -is [array]) { $oc } else { @($oc) }
            } else { @() }

            # Determine the primary object class
            $primaryClass = if ($objectClasses -contains 'computer') { 'computer' }
                           elseif ($objectClasses -contains 'group') { 'group' }
                           elseif ($objectClasses -contains 'user') { 'user' }
                           elseif ($objectClasses -contains 'msDS-GroupManagedServiceAccount') { 'msDS-GroupManagedServiceAccount' }
                           elseif ($objectClasses -contains 'msDS-ManagedServiceAccount') { 'msDS-ManagedServiceAccount' }
                           else { ($objectClasses | Select-Object -Last 1) }

            $uacFlags = Get-UACFlags -UserAccountControl $uac

            # Service principal names
            $spns = @()
            if ($member.ContainsKey('serviceprincipalname')) {
                $spnVal = $member['serviceprincipalname']
                $spns = if ($spnVal -is [array]) { @($spnVal) } else { @($spnVal) }
            }

            # MemberOf
            $memberOfList = @()
            if ($member.ContainsKey('memberof')) {
                $moVal = $member['memberof']
                $memberOfList = if ($moVal -is [array]) { @($moVal) } else { @($moVal) }
            }

            $memberObj = @{
                SamAccountName      = $sam
                DistinguishedName   = $memberDN
                DisplayName         = if ($member.ContainsKey('displayname')) { $member['displayname'] } else { '' }
                ObjectClass         = $primaryClass
                UserAccountControl  = $uac
                UACFlags            = $uacFlags
                Enabled             = -not $uacFlags.ACCOUNTDISABLE
                PwdLastSet          = if ($member.ContainsKey('pwdlastset')) { $member['pwdlastset'] } else { $null }
                LastLogonTimestamp   = if ($member.ContainsKey('lastlogontimestamp')) { $member['lastlogontimestamp'] } else { $null }
                AdminCount          = if ($member.ContainsKey('admincount')) { [int]$member['admincount'] } else { 0 }
                MemberOf            = $memberOfList
                SID                 = if ($member.ContainsKey('objectsid')) { $member['objectsid'] } else { '' }
                ServicePrincipalName = $spns
                IsServiceAccount    = ($spns.Count -gt 0 -or $sam -match '^svc[_-]' -or $sam -match '_svc$' -or
                                       $primaryClass -eq 'msDS-GroupManagedServiceAccount' -or
                                       $primaryClass -eq 'msDS-ManagedServiceAccount')
                IsComputer          = ($primaryClass -eq 'computer')
                IsGroup             = ($primaryClass -eq 'group')
                WhenCreated         = if ($member.ContainsKey('whencreated')) { $member['whencreated'] } else { $null }
                Description         = if ($member.ContainsKey('description')) { $member['description'] } else { '' }
            }

            $groupMembers.Add($memberObj)

            # Track across all groups for deduplication
            if ($primaryClass -ne 'group' -and $memberDN -and -not $allPrivilegedUsersDN.Contains($memberDN)) {
                [void]$allPrivilegedUsersDN.Add($memberDN)
                $allPrivilegedUsersMap[$memberDN] = $memberObj
            }
        }

        $result.PrivilegedGroups[$groupLabel] = @($groupMembers)
    }

    # ── 2. Build deduplicated list of all privileged users ────────────
    $result.AllPrivilegedUsers = @($allPrivilegedUsersMap.Values)

    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message "Total unique privileged accounts: $($result.AllPrivilegedUsers.Count)"
    }

    # ── 3. AdminSDHolder ACL ──────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Reading AdminSDHolder security descriptor'
    }

    try {
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
        $adminSDRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $adminSDHolderDN
        $adminSDResults = @(Invoke-LdapQuery -SearchRoot $adminSDRoot `
            -Filter '(objectClass=container)' `
            -Properties @('ntSecurityDescriptor') `
            -Scope Base)

        if ($adminSDResults.Count -gt 0 -and $adminSDResults[0].ContainsKey('ntsecuritydescriptor')) {
            $sdBytes = $adminSDResults[0]['ntsecuritydescriptor']
            if ($sdBytes -is [byte[]]) {
                try {
                    $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $sd.SetSecurityDescriptorBinaryForm($sdBytes)
                    $result.AdminSDHolderACL = $sd
                } catch {
                    Write-Verbose "Failed to parse AdminSDHolder security descriptor: $_"
                    $result.AdminSDHolderACL = $sdBytes  # Return raw bytes as fallback
                }
            } else {
                $result.AdminSDHolderACL = $sdBytes
            }
        }
    } catch {
        Write-Verbose "Failed to read AdminSDHolder: $_"
        $result.Errors['AdminSDHolder'] = $_.Exception.Message
    }

    # ── 4. AdminCount orphans ─────────────────────────────────────────
    # Users with adminCount=1 who are NOT in any protected/privileged group
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Identifying adminCount orphans'
    }

    try {
        $adminCountFilter = '(&(objectCategory=person)(objectClass=user)(adminCount=1))'
        $adminCountRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $adminCountResults = Invoke-LdapQuery -SearchRoot $adminCountRoot `
            -Filter $adminCountFilter `
            -Properties $memberProperties

        $orphans = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($acUser in $adminCountResults) {
            $acDN = if ($acUser.ContainsKey('distinguishedname')) { $acUser['distinguishedname'] } else { '' }

            # If this user is in our privileged users set, they are not an orphan
            if ($allPrivilegedUsersDN.Contains($acDN)) { continue }

            $sam = if ($acUser.ContainsKey('samaccountname')) { $acUser['samaccountname'] } else { '' }
            $uac = if ($acUser.ContainsKey('useraccountcontrol')) { [int]$acUser['useraccountcontrol'] } else { 0 }
            $uacFlags = Get-UACFlags -UserAccountControl $uac

            $spns = @()
            if ($acUser.ContainsKey('serviceprincipalname')) {
                $spnVal = $acUser['serviceprincipalname']
                $spns = if ($spnVal -is [array]) { @($spnVal) } else { @($spnVal) }
            }

            $memberOfList = @()
            if ($acUser.ContainsKey('memberof')) {
                $moVal = $acUser['memberof']
                $memberOfList = if ($moVal -is [array]) { @($moVal) } else { @($moVal) }
            }

            $orphanObj = @{
                SamAccountName      = $sam
                DistinguishedName   = $acDN
                DisplayName         = if ($acUser.ContainsKey('displayname')) { $acUser['displayname'] } else { '' }
                ObjectClass         = 'user'
                UserAccountControl  = $uac
                UACFlags            = $uacFlags
                Enabled             = -not $uacFlags.ACCOUNTDISABLE
                PwdLastSet          = if ($acUser.ContainsKey('pwdlastset')) { $acUser['pwdlastset'] } else { $null }
                LastLogonTimestamp   = if ($acUser.ContainsKey('lastlogontimestamp')) { $acUser['lastlogontimestamp'] } else { $null }
                AdminCount          = 1
                MemberOf            = $memberOfList
                SID                 = if ($acUser.ContainsKey('objectsid')) { $acUser['objectsid'] } else { '' }
                ServicePrincipalName = $spns
                WhenCreated         = if ($acUser.ContainsKey('whencreated')) { $acUser['whencreated'] } else { $null }
                Description         = if ($acUser.ContainsKey('description')) { $acUser['description'] } else { '' }
            }

            $orphans.Add($orphanObj)
        }

        $result.AdminCountOrphans = @($orphans)
        Write-Verbose "Found $($orphans.Count) adminCount orphan(s)"
    } catch {
        Write-Verbose "Failed to identify adminCount orphans: $_"
        $result.Errors['AdminCountOrphans'] = $_.Exception.Message
    }

    # ── 5. krbtgt account ─────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Retrieving krbtgt account info'
    }

    try {
        $krbtgtRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $krbtgtResults = @(Invoke-LdapQuery -SearchRoot $krbtgtRoot `
            -Filter '(&(objectClass=user)(sAMAccountName=krbtgt))' `
            -Properties @(
                'sAMAccountName', 'distinguishedName', 'objectSid',
                'pwdLastSet', 'whenCreated', 'whenChanged',
                'userAccountControl', 'msDS-KeyVersionNumber'
            ) `
            -SizeLimit 1)

        if ($krbtgtResults.Count -gt 0) {
            $k = $krbtgtResults[0]
            $kUac = if ($k.ContainsKey('useraccountcontrol')) { [int]$k['useraccountcontrol'] } else { 0 }

            $result.KrbtgtAccount = @{
                SamAccountName     = if ($k.ContainsKey('samaccountname')) { $k['samaccountname'] } else { 'krbtgt' }
                DistinguishedName  = if ($k.ContainsKey('distinguishedname')) { $k['distinguishedname'] } else { '' }
                SID                = if ($k.ContainsKey('objectsid')) { $k['objectsid'] } else { '' }
                PwdLastSet         = if ($k.ContainsKey('pwdlastset')) { $k['pwdlastset'] } else { $null }
                WhenCreated        = if ($k.ContainsKey('whencreated')) { $k['whencreated'] } else { $null }
                WhenChanged        = if ($k.ContainsKey('whenchanged')) { $k['whenchanged'] } else { $null }
                UserAccountControl = $kUac
                UACFlags           = Get-UACFlags -UserAccountControl $kUac
                KeyVersionNumber   = if ($k.ContainsKey('msds-keyversionnumber')) { [int]$k['msds-keyversionnumber'] } else { 0 }
            }

            # Calculate password age in days
            if ($result.KrbtgtAccount.PwdLastSet) {
                $pwdAge = ([datetime]::UtcNow - $result.KrbtgtAccount.PwdLastSet).TotalDays
                $result.KrbtgtAccount['PwdAgeDays'] = [math]::Round($pwdAge, 1)
            } else {
                $result.KrbtgtAccount['PwdAgeDays'] = -1
            }
        }
    } catch {
        Write-Verbose "Failed to retrieve krbtgt account: $_"
        $result.Errors['KrbtgtAccount'] = $_.Exception.Message
    }

    # ── 6. Protected Users group members ──────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Enumerating Protected Users group'
    }

    try {
        # Protected Users group has well-known RID 525
        $protectedUsersDN = ''

        if ($domainSidString) {
            $puSid = "$domainSidString-525"
            $puSearchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
            $puGroup = & $findGroupBySid $puSid $puSearchRoot
            if ($puGroup) {
                $protectedUsersDN = $puGroup['distinguishedname']
            }
        }

        # Fallback to name search
        if (-not $protectedUsersDN) {
            $puNameRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
            $puByName = & $findGroupByName 'Protected Users' $puNameRoot
            if ($puByName) {
                $protectedUsersDN = $puByName['distinguishedname']
            }
        }

        if ($protectedUsersDN) {
            Write-Verbose "Protected Users group DN: $protectedUsersDN"

            $puMemberFilter = "(memberOf:1.2.840.113556.1.4.1941:=$protectedUsersDN)"
            $puMemberRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
            $puMembers = Invoke-LdapQuery -SearchRoot $puMemberRoot `
                -Filter $puMemberFilter `
                -Properties $memberProperties

            $puMemberList = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($pu in $puMembers) {
                $puSam = if ($pu.ContainsKey('samaccountname')) { $pu['samaccountname'] } else { '' }
                $puUac = if ($pu.ContainsKey('useraccountcontrol')) { [int]$pu['useraccountcontrol'] } else { 0 }
                $puFlags = Get-UACFlags -UserAccountControl $puUac

                $puObj = @{
                    SamAccountName     = $puSam
                    DistinguishedName  = if ($pu.ContainsKey('distinguishedname')) { $pu['distinguishedname'] } else { '' }
                    ObjectClass        = 'user'
                    UserAccountControl = $puUac
                    UACFlags           = $puFlags
                    Enabled            = -not $puFlags.ACCOUNTDISABLE
                    SID                = if ($pu.ContainsKey('objectsid')) { $pu['objectsid'] } else { '' }
                }
                $puMemberList.Add($puObj)
            }

            $result.ProtectedUsersMembers = @($puMemberList)
            Write-Verbose "Protected Users group has $($puMemberList.Count) member(s)"
        } else {
            Write-Verbose 'Protected Users group not found (may not exist at this domain functional level)'
        }
    } catch {
        Write-Verbose "Failed to enumerate Protected Users: $_"
        $result.Errors['ProtectedUsers'] = $_.Exception.Message
    }

    # ── Summary ───────────────────────────────────────────────────────
    if (-not $Quiet) {
        $totalPriv = $result.AllPrivilegedUsers.Count
        $orphanCount = $result.AdminCountOrphans.Count
        $serviceAccts = @($result.AllPrivilegedUsers | Where-Object { $_.IsServiceAccount }).Count
        $computerAccts = @($result.AllPrivilegedUsers | Where-Object { $_.IsComputer }).Count
        $disabledAccts = @($result.AllPrivilegedUsers | Where-Object { -not $_.Enabled }).Count
        $puCount = $result.ProtectedUsersMembers.Count

        $summary = "Privileged accounts: $totalPriv total, $disabledAccts disabled, $orphanCount orphaned adminCount"
        if ($serviceAccts -gt 0) { $summary += ", $serviceAccts service" }
        if ($computerAccts -gt 0) { $summary += ", $computerAccts computer" }
        $summary += ", $puCount in Protected Users"

        if ($result.KrbtgtAccount -and $result.KrbtgtAccount.PwdAgeDays -ge 0) {
            $summary += " | krbtgt pwd age: $($result.KrbtgtAccount.PwdAgeDays)d"
        }

        if ($result.Errors.Count -gt 0) {
            $summary += " ($($result.Errors.Count) error(s))"
        }

        Write-ProgressLine -Phase AUDITING -Message $summary
    }

    return $result
}
