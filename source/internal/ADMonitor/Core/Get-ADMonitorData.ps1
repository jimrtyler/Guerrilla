# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADMonitorData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$LdapConnection,

        [ValidateSet('Fast', 'Full')]
        [string]$ScanMode = 'Fast',

        [switch]$Quiet
    )

    $result = @{
        privilegedGroups = @{}
        adminSDHolderACL = @()
        krbtgtPwdLastSet = $null
        krbtgtKeyVersion = 0
        trusts           = @()
        gpoObjects       = @{}
        sensitiveAcls    = @{}
        certTemplates    = @{}
        delegations      = @{}
        dnsRecords       = @()
        schemaVersion    = 0
        recentlyChanged  = @()
        domainName       = ''
        collectedAt      = [datetime]::UtcNow.ToString('o')
        scanMode         = $ScanMode
        errors           = @{}
    }

    $domainDN = $LdapConnection.DomainDN
    $schemaDN = $LdapConnection.SchemaDN
    $result.domainName = ($domainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

    # ── 1. Privileged group membership (Fast + Full) ───────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase SCANNING -Message 'Collecting privileged group membership'
    }

    try {
        $privData = Get-ADPrivilegedMembers -Connection $LdapConnection -Quiet:$Quiet

        foreach ($groupName in $privData.PrivilegedGroups.Keys) {
            $members = $privData.PrivilegedGroups[$groupName]
            $memberNames = @($members | Where-Object { -not $_.IsGroup } | ForEach-Object { $_.SamAccountName }) | Sort-Object
            $result.privilegedGroups[$groupName] = $memberNames
        }

        # AdminSDHolder ACL entries
        if ($privData.AdminSDHolderACL -and $privData.AdminSDHolderACL -is [System.DirectoryServices.ActiveDirectorySecurity]) {
            $sd = $privData.AdminSDHolderACL
            $aclEntries = [System.Collections.Generic.List[hashtable]]::new()
            try {
                $rules = $sd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                foreach ($rule in $rules) {
                    $aclEntries.Add(@{
                        identity = $rule.IdentityReference.Value
                        rights   = $rule.ActiveDirectoryRights.ToString()
                        type     = $rule.AccessControlType.ToString()
                    })
                }
            } catch {
                Write-Verbose "Failed to parse AdminSDHolder ACL rules: $_"
            }
            $result.adminSDHolderACL = @($aclEntries)
        }

        # krbtgt info
        if ($privData.KrbtgtAccount) {
            $result.krbtgtPwdLastSet = if ($privData.KrbtgtAccount.PwdLastSet) {
                $privData.KrbtgtAccount.PwdLastSet.ToString('o')
            } else { $null }
            $result.krbtgtKeyVersion = $privData.KrbtgtAccount.KeyVersionNumber
        }
    } catch {
        Write-Warning "Failed to collect privileged group data: $_"
        $result.errors['privilegedGroups'] = $_.Exception.Message
    }

    # ── 2. Trust relationships (Fast + Full) ───────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase SCANNING -Message 'Collecting trust relationships'
    }

    try {
        $trustData = Get-ADTrustRelationships -Connection $LdapConnection -Quiet:$Quiet
        $trusts = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($t in $trustData) {
            $trusts.Add(@{
                name               = $t.TrustPartner
                flatName           = $t.FlatName
                direction          = $t.TrustDirection
                type               = $t.TrustType
                isTransitive       = $t.IsTransitive
                sidFiltering       = $t.SIDFilteringEnabled
                forestTransitive   = $t.ForestTransitive
                withinForest       = $t.WithinForest
                whenCreated        = if ($t.WhenCreated) { $t.WhenCreated.ToString('o') } else { $null }
                whenChanged        = if ($t.WhenChanged) { $t.WhenChanged.ToString('o') } else { $null }
                trustAttributes    = $t.TrustAttributes
                trustSID           = $t.TrustSID
            })
        }
        $result.trusts = @($trusts)
    } catch {
        Write-Warning "Failed to collect trust relationships: $_"
        $result.errors['trusts'] = $_.Exception.Message
    }

    # ── 3. Recently changed objects (Fast + Full) ──────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase SCANNING -Message 'Querying recently changed objects'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $LdapConnection -SearchBase $domainDN
        $recentDate = [datetime]::UtcNow.AddDays(-7)
        $recentFilter = "(&(whenChanged>=$($recentDate.ToString('yyyyMMddHHmmss.0Z')))(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)))"

        $recentResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter $recentFilter `
            -Properties @('distinguishedName', 'objectClass', 'whenChanged', 'sAMAccountName', 'whenCreated')

        $recentList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($obj in $recentResults) {
            $objClasses = if ($obj.ContainsKey('objectclass')) {
                $oc = $obj['objectclass']
                if ($oc -is [array]) { $oc } else { @($oc) }
            } else { @() }

            $primaryClass = if ($objClasses -contains 'computer') { 'computer' }
                           elseif ($objClasses -contains 'group') { 'group' }
                           elseif ($objClasses -contains 'user') { 'user' }
                           elseif ($objClasses -contains 'organizationalUnit') { 'organizationalUnit' }
                           else { ($objClasses | Select-Object -Last 1) }

            $recentList.Add(@{
                dn          = if ($obj.ContainsKey('distinguishedname')) { $obj['distinguishedname'] } else { '' }
                objectClass = $primaryClass
                sam         = if ($obj.ContainsKey('samaccountname')) { $obj['samaccountname'] } else { '' }
                whenChanged = if ($obj.ContainsKey('whenchanged') -and $obj['whenchanged']) { $obj['whenchanged'].ToString('o') } else { $null }
                whenCreated = if ($obj.ContainsKey('whencreated') -and $obj['whencreated']) { $obj['whencreated'].ToString('o') } else { $null }
            })
        }
        $result.recentlyChanged = @($recentList)

        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message "Found $($recentList.Count) recently changed objects"
        }
    } catch {
        Write-Verbose "Failed to query recently changed objects: $_"
        $result.errors['recentlyChanged'] = $_.Exception.Message
    }

    # ── Full mode: additional data collection ──────────────────────────
    if ($ScanMode -eq 'Full') {

        # ── 4. GPO Objects ─────────────────────────────────────────────
        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'Collecting Group Policy Objects'
        }

        try {
            $gpoData = Get-ADGroupPolicyObjects -Connection $LdapConnection -Quiet:$Quiet
            $gpoMap = @{}
            foreach ($gpo in $gpoData.GPOs) {
                $gpoMap[$gpo.GUID] = @{
                    name          = $gpo.DisplayName
                    guid          = $gpo.GUID
                    whenChanged   = if ($gpo.WhenChanged) { $gpo.WhenChanged.ToString('o') } else { $null }
                    versionNumber = $gpo.VersionNumber
                    flags         = $gpo.Flags
                    isLinked      = $gpo.IsLinked
                    linkedTo      = @($gpo.LinkedTo | ForEach-Object {
                        @{
                            containerDN = $_.ContainerDN
                            isEnabled   = $_.IsEnabled
                            isEnforced  = $_.IsEnforced
                        }
                    })
                }
            }
            $result.gpoObjects = $gpoMap
        } catch {
            Write-Warning "Failed to collect GPO data: $_"
            $result.errors['gpoObjects'] = $_.Exception.Message
        }

        # ── 5. Sensitive ACLs ──────────────────────────────────────────
        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'Collecting sensitive object ACLs'
        }

        try {
            $aclData = Get-ADObjectACLs -Connection $LdapConnection -Quiet:$Quiet
            $aclMap = @{}

            foreach ($objName in $aclData.CriticalObjectACLs.Keys) {
                $objInfo = $aclData.CriticalObjectACLs[$objName]
                $aceEntries = [System.Collections.Generic.List[hashtable]]::new()
                if ($objInfo.ACEs) {
                    foreach ($ace in $objInfo.ACEs) {
                        if ($ace.AccessControlType -ne 'Allow') { continue }
                        $aceEntries.Add(@{
                            identity = $ace.IdentityReference
                            rights   = $ace.ActiveDirectoryRights
                            objectType = $ace.ObjectType
                            isInherited = $ace.IsInherited
                        })
                    }
                }
                $aclMap[$objName] = @{
                    objectDN = $objInfo.ObjectDN
                    aces     = @($aceEntries)
                }
            }

            # Also include dangerous ACEs for comparison
            $aclMap['_dangerousACEs'] = @{
                objectDN = ''
                aces     = @($aclData.DangerousACEs | ForEach-Object {
                    @{
                        identity   = $_.IdentityReference
                        rights     = $_.ActiveDirectoryRights
                        objectType = $_.ObjectType
                        objectDN   = $_.ObjectDN
                        objectName = $_.ObjectName
                    }
                })
            }

            $result.sensitiveAcls = $aclMap
        } catch {
            Write-Warning "Failed to collect ACL data: $_"
            $result.errors['sensitiveAcls'] = $_.Exception.Message
        }

        # ── 6. Certificate templates ───────────────────────────────────
        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'Collecting certificate template data'
        }

        try {
            $certData = Get-ADCertificateServices -Connection $LdapConnection -Quiet:$Quiet
            $certMap = @{}
            foreach ($tmpl in $certData.CertificateTemplates) {
                $certMap[$tmpl.Name] = @{
                    displayName             = $tmpl.DisplayName
                    dn                      = $tmpl.DN
                    schemaVersion           = $tmpl.SchemaVersion
                    enrolleeSuppliesSubject = $tmpl.EnrolleeSuppliesSubject
                    allowsAuthentication    = $tmpl.AllowsAuthentication
                    isPublished             = $tmpl.IsPublished
                    whenChanged             = if ($tmpl.WhenChanged) { $tmpl.WhenChanged.ToString('o') } else { $null }
                    enrollmentPermissions   = @($tmpl.EnrollmentPermissions | ForEach-Object {
                        @{ identity = $_.Identity; right = $_.Right }
                    })
                }
            }
            $result.certTemplates = $certMap
        } catch {
            Write-Warning "Failed to collect certificate template data: $_"
            $result.errors['certTemplates'] = $_.Exception.Message
        }

        # ── 7. OU Delegations ──────────────────────────────────────────
        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'Collecting OU delegation data'
        }

        try {
            # Reuse ACL data if already collected
            if (-not $aclData) {
                $aclData = Get-ADObjectACLs -Connection $LdapConnection -Quiet:$Quiet
            }

            $delegationMap = @{}
            foreach ($delegation in $aclData.OUDelegation) {
                $ouDN = $delegation.OUDN
                if (-not $delegationMap.ContainsKey($ouDN)) {
                    $delegationMap[$ouDN] = [System.Collections.Generic.List[hashtable]]::new()
                }
                $delegationMap[$ouDN].Add(@{
                    identity    = $delegation.IdentityReference
                    rights      = $delegation.ActiveDirectoryRights
                    objectType  = $delegation.ObjectType
                    isInherited = $delegation.IsInherited
                })
            }
            $result.delegations = $delegationMap
        } catch {
            Write-Warning "Failed to collect delegation data: $_"
            $result.errors['delegations'] = $_.Exception.Message
        }

        # ── 8. DNS Records ─────────────────────────────────────────────
        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'Collecting DNS records'
        }

        try {
            $dnsContainers = @(
                "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"
                "CN=MicrosoftDNS,CN=System,$domainDN"
            )

            $dnsRecords = [System.Collections.Generic.List[hashtable]]::new()
            foreach ($dnsContainer in $dnsContainers) {
                try {
                    $dnsRoot = New-LdapSearchRoot -Connection $LdapConnection -SearchBase $dnsContainer
                    $zoneResults = Invoke-LdapQuery -SearchRoot $dnsRoot `
                        -Filter '(objectClass=dnsZone)' `
                        -Properties @('dc', 'distinguishedName') `
                        -Scope OneLevel

                    foreach ($zone in $zoneResults) {
                        $zoneName = if ($zone.ContainsKey('dc')) { $zone['dc'] } else { '' }
                        if ($zoneName -eq '..Cache' -or $zoneName -eq 'RootDNSServers') { continue }

                        $zoneDN = $zone['distinguishedname']
                        try {
                            $zoneRoot = New-LdapSearchRoot -Connection $LdapConnection -SearchBase $zoneDN
                            $recordResults = Invoke-LdapQuery -SearchRoot $zoneRoot `
                                -Filter '(objectClass=dnsNode)' `
                                -Properties @('dc', 'dnsRecord', 'whenChanged') `
                                -Scope OneLevel

                            foreach ($record in $recordResults) {
                                $recName = if ($record.ContainsKey('dc')) { $record['dc'] } else { '' }
                                $dnsRecords.Add(@{
                                    name        = $recName
                                    zone        = $zoneName
                                    whenChanged = if ($record.ContainsKey('whenchanged') -and $record['whenchanged']) {
                                        $record['whenchanged'].ToString('o')
                                    } else { $null }
                                })
                            }
                        } catch {
                            Write-Verbose "Failed to enumerate DNS records in zone $zoneName`: $_"
                        }
                    }
                } catch {
                    Write-Verbose "DNS container not accessible: $dnsContainer"
                }
            }
            $result.dnsRecords = @($dnsRecords)
        } catch {
            Write-Verbose "Failed to collect DNS data: $_"
            $result.errors['dnsRecords'] = $_.Exception.Message
        }

        # ── 9. Schema version ──────────────────────────────────────────
        if (-not $Quiet) {
            Write-ProgressLine -Phase SCANNING -Message 'Reading schema version'
        }

        try {
            $schemaRoot = New-LdapSearchRoot -Connection $LdapConnection -SearchBase $schemaDN
            $schemaResults = @(Invoke-LdapQuery -SearchRoot $schemaRoot `
                -Filter '(objectClass=dMD)' `
                -Properties @('objectVersion') `
                -Scope Base)

            if ($schemaResults.Count -gt 0 -and $schemaResults[0].ContainsKey('objectversion')) {
                $result.schemaVersion = [int]$schemaResults[0]['objectversion']
            }
        } catch {
            Write-Verbose "Failed to read schema version: $_"
            $result.errors['schemaVersion'] = $_.Exception.Message
        }
    }

    # ── Summary ────────────────────────────────────────────────────────
    if (-not $Quiet) {
        $groupCount = $result.privilegedGroups.Keys.Count
        $totalMembers = ($result.privilegedGroups.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        $summary = "Data collection complete: $groupCount privileged groups, $totalMembers members, $($result.trusts.Count) trusts"
        if ($ScanMode -eq 'Full') {
            $summary += ", $($result.gpoObjects.Keys.Count) GPOs, $($result.certTemplates.Keys.Count) cert templates"
        }
        if ($result.errors.Count -gt 0) {
            $summary += " ($($result.errors.Count) error(s))"
        }
        Write-ProgressLine -Phase SCANNING -Message $summary
    }

    return $result
}
