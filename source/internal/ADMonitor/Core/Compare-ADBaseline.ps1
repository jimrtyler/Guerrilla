# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Compare-ADBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$PreviousBaseline,

        [Parameter(Mandatory)]
        [hashtable]$CurrentData
    )

    $changes = @{
        GroupChanges        = @()
        GPOChanges          = @()
        GPOLinkChanges      = @()
        TrustChanges        = @()
        ACLChanges          = @()
        AdminSDHolderChanged = $false
        KrbtgtChanged       = $false
        CertTemplateChanges = @()
        DelegationChanges   = @()
        DNSChanges          = @()
        SchemaChanges       = @()
        NewComputers        = @()
        NewServiceAccounts  = @()
        PasswordChanges     = @()
    }

    # ── 1. Privileged group membership changes ─────────────────────────
    $prevGroups = if ($PreviousBaseline.ContainsKey('privilegedGroups')) { $PreviousBaseline['privilegedGroups'] } else { @{} }

    $groupChanges = [System.Collections.Generic.List[hashtable]]::new()

    # Check current groups against baseline
    foreach ($groupName in $CurrentData.privilegedGroups.Keys) {
        $currentMembers = @($CurrentData.privilegedGroups[$groupName] | Sort-Object)
        $prevGroupInfo = if ($prevGroups.ContainsKey($groupName)) { $prevGroups[$groupName] } else { $null }

        if (-not $prevGroupInfo) {
            # Entire group is new to monitoring
            if ($currentMembers.Count -gt 0) {
                $groupChanges.Add(@{
                    Group      = $groupName
                    ChangeType = 'NewGroup'
                    Added      = $currentMembers
                    Removed    = @()
                })
            }
            continue
        }

        $prevMembers = @($prevGroupInfo.members | Sort-Object)

        # Compare member lists
        $added = @($currentMembers | Where-Object { $_ -notin $prevMembers })
        $removed = @($prevMembers | Where-Object { $_ -notin $currentMembers })

        if ($added.Count -gt 0 -or $removed.Count -gt 0) {
            $groupChanges.Add(@{
                Group      = $groupName
                ChangeType = 'MembershipChanged'
                Added      = $added
                Removed    = $removed
            })
        }
    }

    # Check for groups that disappeared
    foreach ($groupName in $prevGroups.Keys) {
        if (-not $CurrentData.privilegedGroups.ContainsKey($groupName)) {
            $prevMembers = @($prevGroups[$groupName].members)
            if ($prevMembers.Count -gt 0) {
                $groupChanges.Add(@{
                    Group      = $groupName
                    ChangeType = 'GroupRemoved'
                    Added      = @()
                    Removed    = $prevMembers
                })
            }
        }
    }

    $changes.GroupChanges = @($groupChanges)

    # ── 2. AdminSDHolder ACL changes ───────────────────────────────────
    $prevACLHash = if ($PreviousBaseline.ContainsKey('adminSDHolderACL') -and $PreviousBaseline['adminSDHolderACL'].ContainsKey('aclHash')) {
        $PreviousBaseline['adminSDHolderACL']['aclHash']
    } else { 'EMPTY' }

    $currentACLEntries = @($CurrentData.adminSDHolderACL | ForEach-Object {
        "$($_.identity)|$($_.rights)|$($_.type)"
    } | Sort-Object)

    $currentACLHash = if ($currentACLEntries.Count -gt 0) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $joined = $currentACLEntries -join '||'
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
        $hashBytes = $sha.ComputeHash($bytes)
        [BitConverter]::ToString($hashBytes) -replace '-', ''
    } else { 'EMPTY' }

    if ($prevACLHash -ne $currentACLHash) {
        $changes.AdminSDHolderChanged = $true

        # Determine specific ACL differences
        $prevACEs = @()
        if ($PreviousBaseline.ContainsKey('adminSDHolderACL') -and $PreviousBaseline['adminSDHolderACL'].ContainsKey('entries')) {
            $prevACEs = @($PreviousBaseline['adminSDHolderACL']['entries'])
        }
        $currentACEs = @($CurrentData.adminSDHolderACL)

        $prevAceKeys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ace in $prevACEs) {
            [void]$prevAceKeys.Add("$($ace.identity)|$($ace.rights)|$($ace.type)")
        }

        $currentAceKeys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ace in $currentACEs) {
            [void]$currentAceKeys.Add("$($ace.identity)|$($ace.rights)|$($ace.type)")
        }

        $aclChanges = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($ace in $currentACEs) {
            $key = "$($ace.identity)|$($ace.rights)|$($ace.type)"
            if (-not $prevAceKeys.Contains($key)) {
                $aclChanges.Add(@{
                    ObjectDN   = 'AdminSDHolder'
                    ChangeType = 'Added'
                    Identity   = $ace.identity
                    Rights     = $ace.rights
                })
            }
        }
        foreach ($ace in $prevACEs) {
            $key = "$($ace.identity)|$($ace.rights)|$($ace.type)"
            if (-not $currentAceKeys.Contains($key)) {
                $aclChanges.Add(@{
                    ObjectDN   = 'AdminSDHolder'
                    ChangeType = 'Removed'
                    Identity   = $ace.identity
                    Rights     = $ace.rights
                })
            }
        }
        $changes.ACLChanges = @($aclChanges)
    }

    # ── 3. krbtgt password change ──────────────────────────────────────
    $prevKrbtgt = if ($PreviousBaseline.ContainsKey('krbtgt')) { $PreviousBaseline['krbtgt'] } else { @{} }

    if ($prevKrbtgt.ContainsKey('pwdLastSet') -and $prevKrbtgt['pwdLastSet']) {
        if ($CurrentData.krbtgtPwdLastSet -and $CurrentData.krbtgtPwdLastSet -ne $prevKrbtgt['pwdLastSet']) {
            $changes.KrbtgtChanged = $true
        }
        if ($CurrentData.krbtgtKeyVersion -ne 0 -and $prevKrbtgt.ContainsKey('keyVersion') -and
            $CurrentData.krbtgtKeyVersion -ne $prevKrbtgt['keyVersion']) {
            $changes.KrbtgtChanged = $true
        }
    }

    # ── 4. Trust relationship changes ──────────────────────────────────
    $prevTrusts = if ($PreviousBaseline.ContainsKey('trusts')) { $PreviousBaseline['trusts'] } else { @{} }

    $trustChanges = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($trust in $CurrentData.trusts) {
        $trustKey = $trust.name.ToLower()

        if (-not $prevTrusts.ContainsKey($trustKey)) {
            $trustChanges.Add(@{
                Name       = $trust.name
                ChangeType = 'Added'
                Direction  = $trust.direction
                Type       = $trust.type
                Details    = "New trust: $($trust.name) ($($trust.direction), $($trust.type))"
            })
            continue
        }

        $prevTrust = $prevTrusts[$trustKey]

        # Check for property changes
        $trustDiffs = [System.Collections.Generic.List[string]]::new()
        if ($trust.direction -ne $prevTrust.direction) { $trustDiffs.Add("direction: $($prevTrust.direction) -> $($trust.direction)") }
        if ($trust.type -ne $prevTrust.type) { $trustDiffs.Add("type: $($prevTrust.type) -> $($trust.type)") }
        if ($trust.isTransitive -ne $prevTrust.isTransitive) { $trustDiffs.Add("transitive: $($prevTrust.isTransitive) -> $($trust.isTransitive)") }
        if ($trust.sidFiltering -ne $prevTrust.sidFiltering) { $trustDiffs.Add("sidFiltering: $($prevTrust.sidFiltering) -> $($trust.sidFiltering)") }
        if ($trust.trustAttributes -ne $prevTrust.trustAttributes) { $trustDiffs.Add("attributes: $($prevTrust.trustAttributes) -> $($trust.trustAttributes)") }

        if ($trustDiffs.Count -gt 0) {
            $trustChanges.Add(@{
                Name       = $trust.name
                ChangeType = 'Modified'
                Direction  = $trust.direction
                Type       = $trust.type
                Details    = "Trust modified: $($trustDiffs -join '; ')"
            })
        }
    }

    # Removed trusts
    foreach ($trustKey in $prevTrusts.Keys) {
        $found = $CurrentData.trusts | Where-Object { $_.name.ToLower() -eq $trustKey }
        if (-not $found) {
            $trustChanges.Add(@{
                Name       = $prevTrusts[$trustKey].name
                ChangeType = 'Removed'
                Direction  = $prevTrusts[$trustKey].direction
                Type       = $prevTrusts[$trustKey].type
                Details    = "Trust removed: $($prevTrusts[$trustKey].name)"
            })
        }
    }

    $changes.TrustChanges = @($trustChanges)

    # ── 5. GPO changes (Full mode) ────────────────────────────────────
    $prevGPOs = if ($PreviousBaseline.ContainsKey('gpoObjects')) { $PreviousBaseline['gpoObjects'] } else { @{} }

    $gpoChanges = [System.Collections.Generic.List[hashtable]]::new()
    $gpoLinkChanges = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoGuid in $CurrentData.gpoObjects.Keys) {
        $currentGPO = $CurrentData.gpoObjects[$gpoGuid]

        if (-not $prevGPOs.ContainsKey($gpoGuid)) {
            $gpoChanges.Add(@{
                GUID       = $gpoGuid
                Name       = $currentGPO.name
                ChangeType = 'Added'
                Details    = "New GPO: $($currentGPO.name)"
            })
            continue
        }

        $prevGPO = $prevGPOs[$gpoGuid]

        # Version change means content modification
        if ($currentGPO.versionNumber -ne $prevGPO.versionNumber) {
            $gpoChanges.Add(@{
                GUID            = $gpoGuid
                Name            = $currentGPO.name
                ChangeType      = 'Modified'
                PreviousVersion = $prevGPO.versionNumber
                CurrentVersion  = $currentGPO.versionNumber
                Details         = "GPO modified: $($currentGPO.name) (v$($prevGPO.versionNumber) -> v$($currentGPO.versionNumber))"
            })
        }

        # Link changes
        $currentLinkHash = ($currentGPO.linkedTo | ForEach-Object {
            "$($_.containerDN)|$($_.isEnabled)|$($_.isEnforced)"
        } | Sort-Object) -join '||'
        $currentLinkHashVal = if ($currentLinkHash) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($currentLinkHash)
            $hashBytes = $sha.ComputeHash($bytes)
            [BitConverter]::ToString($hashBytes) -replace '-', ''
        } else { 'EMPTY' }

        $prevLinkHash = if ($prevGPO.ContainsKey('linkHash')) { $prevGPO['linkHash'] } else { 'EMPTY' }

        if ($currentLinkHashVal -ne $prevLinkHash) {
            $gpoLinkChanges.Add(@{
                GUID       = $gpoGuid
                Name       = $currentGPO.name
                ChangeType = 'LinkChanged'
                Details    = "GPO link changed: $($currentGPO.name)"
            })
        }
    }

    # Removed GPOs
    foreach ($gpoGuid in $prevGPOs.Keys) {
        if (-not $CurrentData.gpoObjects.ContainsKey($gpoGuid)) {
            $gpoChanges.Add(@{
                GUID       = $gpoGuid
                Name       = $prevGPOs[$gpoGuid].name
                ChangeType = 'Removed'
                Details    = "GPO removed: $($prevGPOs[$gpoGuid].name)"
            })
        }
    }

    $changes.GPOChanges = @($gpoChanges)
    $changes.GPOLinkChanges = @($gpoLinkChanges)

    # ── 6. Sensitive ACL changes (Full mode) ───────────────────────────
    $prevAcls = if ($PreviousBaseline.ContainsKey('sensitiveAcls')) { $PreviousBaseline['sensitiveAcls'] } else { @{} }

    if (-not $changes.AdminSDHolderChanged) {
        # Only process non-AdminSDHolder ACL changes if AdminSDHolder wasn't already flagged
        $additionalAclChanges = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($objName in $CurrentData.sensitiveAcls.Keys) {
            if ($objName -eq '_dangerousACEs') { continue }

            $currentObj = $CurrentData.sensitiveAcls[$objName]
            $currentAceStrings = @($currentObj.aces | ForEach-Object {
                "$($_.identity)|$($_.rights)|$($_.objectType)"
            } | Sort-Object)
            $currentHash = if ($currentAceStrings.Count -gt 0) {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                $joined = $currentAceStrings -join '||'
                $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
                $hashBytes = $sha.ComputeHash($bytes)
                [BitConverter]::ToString($hashBytes) -replace '-', ''
            } else { 'EMPTY' }

            $prevHash = if ($prevAcls.ContainsKey($objName) -and $prevAcls[$objName].ContainsKey('aceHash')) {
                $prevAcls[$objName]['aceHash']
            } else { 'EMPTY' }

            if ($currentHash -ne $prevHash) {
                $additionalAclChanges.Add(@{
                    ObjectDN   = $currentObj.objectDN
                    ObjectName = $objName
                    ChangeType = 'Modified'
                    Identity   = ''
                    Rights     = ''
                    Details    = "ACL changed on: $objName"
                })
            }
        }

        if ($additionalAclChanges.Count -gt 0) {
            $changes.ACLChanges = @($changes.ACLChanges) + @($additionalAclChanges)
        }
    }

    # ── 7. Certificate template changes (Full mode) ────────────────────
    $prevCerts = if ($PreviousBaseline.ContainsKey('certTemplates')) { $PreviousBaseline['certTemplates'] } else { @{} }

    $certChanges = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($tmplName in $CurrentData.certTemplates.Keys) {
        $currentTmpl = $CurrentData.certTemplates[$tmplName]

        if (-not $prevCerts.ContainsKey($tmplName)) {
            $certChanges.Add(@{
                Name       = $tmplName
                ChangeType = 'Added'
                Details    = "New certificate template: $tmplName"
                EnrolleeSuppliesSubject = $currentTmpl.enrolleeSuppliesSubject
                AllowsAuthentication    = $currentTmpl.allowsAuthentication
            })
            continue
        }

        $prevTmpl = $prevCerts[$tmplName]
        $certDiffs = [System.Collections.Generic.List[string]]::new()

        if ($currentTmpl.whenChanged -ne $prevTmpl.whenChanged) { $certDiffs.Add('timestamp changed') }
        if ($currentTmpl.enrolleeSuppliesSubject -ne $prevTmpl.enrolleeSuppliesSubject) {
            $certDiffs.Add("enrolleeSuppliesSubject: $($prevTmpl.enrolleeSuppliesSubject) -> $($currentTmpl.enrolleeSuppliesSubject)")
        }
        if ($currentTmpl.allowsAuthentication -ne $prevTmpl.allowsAuthentication) {
            $certDiffs.Add("allowsAuthentication: $($prevTmpl.allowsAuthentication) -> $($currentTmpl.allowsAuthentication)")
        }
        if ($currentTmpl.isPublished -ne $prevTmpl.isPublished) {
            $certDiffs.Add("isPublished: $($prevTmpl.isPublished) -> $($currentTmpl.isPublished)")
        }

        if ($certDiffs.Count -gt 0) {
            $certChanges.Add(@{
                Name       = $tmplName
                ChangeType = 'Modified'
                Details    = "Template modified: $($certDiffs -join '; ')"
                EnrolleeSuppliesSubject = $currentTmpl.enrolleeSuppliesSubject
                AllowsAuthentication    = $currentTmpl.allowsAuthentication
            })
        }
    }

    foreach ($tmplName in $prevCerts.Keys) {
        if (-not $CurrentData.certTemplates.ContainsKey($tmplName)) {
            $certChanges.Add(@{
                Name       = $tmplName
                ChangeType = 'Removed'
                Details    = "Certificate template removed: $tmplName"
            })
        }
    }

    $changes.CertTemplateChanges = @($certChanges)

    # ── 8. Delegation changes (Full mode) ──────────────────────────────
    $prevDelegations = if ($PreviousBaseline.ContainsKey('delegations')) { $PreviousBaseline['delegations'] } else { @{} }

    $delegationChanges = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ouDN in $CurrentData.delegations.Keys) {
        $currentEntries = $CurrentData.delegations[$ouDN]
        $currentStrings = @($currentEntries | ForEach-Object {
            "$($_.identity)|$($_.rights)|$($_.objectType)"
        } | Sort-Object)
        $currentHash = if ($currentStrings.Count -gt 0) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $joined = $currentStrings -join '||'
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($joined)
            $hashBytes = $sha.ComputeHash($bytes)
            [BitConverter]::ToString($hashBytes) -replace '-', ''
        } else { 'EMPTY' }

        if (-not $prevDelegations.ContainsKey($ouDN)) {
            if ($currentEntries.Count -gt 0) {
                $delegationChanges.Add(@{
                    OUDN       = $ouDN
                    ChangeType = 'Added'
                    Details    = "New delegations on: $ouDN ($($currentEntries.Count) entries)"
                    Entries    = @($currentEntries)
                })
            }
            continue
        }

        $prevHash = if ($prevDelegations[$ouDN].ContainsKey('hash')) { $prevDelegations[$ouDN]['hash'] } else { 'EMPTY' }

        if ($currentHash -ne $prevHash) {
            $delegationChanges.Add(@{
                OUDN       = $ouDN
                ChangeType = 'Modified'
                Details    = "Delegations modified on: $ouDN"
                Entries    = @($currentEntries)
            })
        }
    }

    $changes.DelegationChanges = @($delegationChanges)

    # ── 9. DNS record changes (Full mode) ──────────────────────────────
    $prevDNS = if ($PreviousBaseline.ContainsKey('dnsRecords') -and $PreviousBaseline['dnsRecords'].ContainsKey('recordSet')) {
        [System.Collections.Generic.HashSet[string]]::new(
            [string[]]$PreviousBaseline['dnsRecords']['recordSet'],
            [StringComparer]::OrdinalIgnoreCase
        )
    } else {
        [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }

    $currentDNSSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($rec in $CurrentData.dnsRecords) {
        [void]$currentDNSSet.Add("$($rec.zone)|$($rec.name)")
    }

    $dnsChanges = [System.Collections.Generic.List[hashtable]]::new()

    # New DNS records
    foreach ($key in $currentDNSSet) {
        if (-not $prevDNS.Contains($key)) {
            $parts = $key -split '\|', 2
            $dnsChanges.Add(@{
                Name       = $parts[1]
                Zone       = $parts[0]
                ChangeType = 'Added'
                Details    = "New DNS record: $($parts[1]) in zone $($parts[0])"
            })
        }
    }

    # Removed DNS records
    foreach ($key in $prevDNS) {
        if (-not $currentDNSSet.Contains($key)) {
            $parts = $key -split '\|', 2
            $dnsChanges.Add(@{
                Name       = $parts[1]
                Zone       = $parts[0]
                ChangeType = 'Removed'
                Details    = "DNS record removed: $($parts[1]) from zone $($parts[0])"
            })
        }
    }

    $changes.DNSChanges = @($dnsChanges)

    # ── 10. Schema changes (Full mode) ─────────────────────────────────
    $prevSchemaVersion = if ($PreviousBaseline.ContainsKey('schemaVersion')) { $PreviousBaseline['schemaVersion'] } else { 0 }

    if ($CurrentData.schemaVersion -ne 0 -and $prevSchemaVersion -ne 0 -and $CurrentData.schemaVersion -ne $prevSchemaVersion) {
        $changes.SchemaChanges = @(@{
            ChangeType      = 'VersionChanged'
            PreviousVersion = $prevSchemaVersion
            CurrentVersion  = $CurrentData.schemaVersion
            Details         = "Schema version changed: $prevSchemaVersion -> $($CurrentData.schemaVersion)"
        })
    }

    # ── 11. New computer accounts and service accounts from recentlyChanged ─
    $recentComputers = [System.Collections.Generic.List[hashtable]]::new()
    $recentServiceAccounts = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($obj in $CurrentData.recentlyChanged) {
        # Check if recently created (within last 7 days, created == changed for new objects)
        $isRecentCreation = $false
        if ($obj.whenCreated -and $obj.whenChanged) {
            try {
                $created = [datetime]::Parse($obj.whenCreated)
                $changed = [datetime]::Parse($obj.whenChanged)
                $timeDiff = [Math]::Abs(($changed - $created).TotalMinutes)
                $isRecentCreation = $timeDiff -lt 60 -and $created -gt [datetime]::UtcNow.AddDays(-7)
            } catch { }
        }

        if ($isRecentCreation) {
            if ($obj.objectClass -eq 'computer') {
                $recentComputers.Add(@{
                    DN          = $obj.dn
                    SAM         = $obj.sam
                    WhenCreated = $obj.whenCreated
                })
            }

            if ($obj.objectClass -eq 'user' -and ($obj.sam -match '^svc[_-]' -or $obj.sam -match '_svc$' -or $obj.dn -match 'OU=Service')) {
                $recentServiceAccounts.Add(@{
                    DN          = $obj.dn
                    SAM         = $obj.sam
                    WhenCreated = $obj.whenCreated
                })
            }
        }
    }

    $changes.NewComputers = @($recentComputers)
    $changes.NewServiceAccounts = @($recentServiceAccounts)
    $changes.RecentlyChanged = @($CurrentData.recentlyChanged)

    # ── 12. Password changes for privileged group members ────────────────
    $passwordChanges = [System.Collections.Generic.List[hashtable]]::new()

    # Detect recently-changed user objects that are members of privileged groups
    $privilegedMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($groupName in $CurrentData.privilegedGroups.Keys) {
        foreach ($member in @($CurrentData.privilegedGroups[$groupName])) {
            [void]$privilegedMembers.Add($member)
        }
    }

    foreach ($obj in $CurrentData.recentlyChanged) {
        if ($obj.objectClass -eq 'user' -and $privilegedMembers.Contains($obj.sam)) {
            $passwordChanges.Add(@{
                SAM         = $obj.sam
                DN          = $obj.dn
                WhenChanged = $obj.whenChanged
                Group       = ($CurrentData.privilegedGroups.Keys | Where-Object {
                    $obj.sam -in @($CurrentData.privilegedGroups[$_])
                }) -join ', '
            })
        }
    }

    $changes.PasswordChanges = @($passwordChanges)

    return $changes
}
