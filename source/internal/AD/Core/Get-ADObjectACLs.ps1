# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADObjectACLs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        CriticalObjectACLs  = @{}
        DangerousACEs       = @()
        MachineAccountQuota = 0
        DomainRootOwner     = ''
        GPOPermissions      = @{}
        OUDelegation        = @()
    }

    $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN

    # ── Well-known GUIDs for dangerous extended rights and properties ──────────
    $dangerousGuids = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
        '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
        'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'Self-Membership'
        'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'Validated-SPN'
    }

    # Dangerous rights to flag
    $dangerousRights = @(
        'GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner'
    )

    # Default groups to ignore in ACL analysis
    $defaultIgnorePatterns = @(
        'Domain Admins', 'Enterprise Admins', 'SYSTEM',
        'BUILTIN\Administrators', 'Administrators',
        'S-1-5-18'  # SYSTEM SID
    )

    # ── Critical objects to audit ─────────────────────────────────────────────
    $criticalObjects = @{
        'Domain Root'           = $Connection.DomainDN
        'AdminSDHolder'         = "CN=AdminSDHolder,CN=System,$($Connection.DomainDN)"
        'Domain Controllers OU' = "OU=Domain Controllers,$($Connection.DomainDN)"
        'Schema Container'      = $Connection.SchemaDN
        'Configuration Container' = $Connection.ConfigDN
        'GPO Container'         = "CN=Policies,CN=System,$($Connection.DomainDN)"
    }

    $allDangerousACEs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($objName in $criticalObjects.Keys) {
        $objDN = $criticalObjects[$objName]
        Write-Verbose "Analyzing ACLs on critical object: $objName ($objDN)..."

        try {
            $entry = New-LdapSearchRoot -Connection $Connection -SearchBase $objDN
            $sd = $entry.ObjectSecurity

            if ($null -eq $sd) {
                Write-Verbose "Could not read security descriptor for $objDN"
                $result.CriticalObjectACLs[$objName] = @{
                    ObjectDN = $objDN
                    Error    = 'Could not read security descriptor'
                    ACEs     = @()
                }
                continue
            }

            $accessRules = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            $aceList = [System.Collections.Generic.List[hashtable]]::new()

            foreach ($rule in $accessRules) {
                $sidStr = $rule.IdentityReference.Value
                $resolved = Resolve-ADSid -SidString $sidStr -SearchRoot $searchRoot

                $objectTypeGuid = if ($rule.ObjectType -and $rule.ObjectType.ToString() -ne '00000000-0000-0000-0000-000000000000') {
                    $rule.ObjectType.ToString()
                } else { $null }

                $objectTypeName = if ($objectTypeGuid -and $dangerousGuids.ContainsKey($objectTypeGuid)) {
                    $dangerousGuids[$objectTypeGuid]
                } elseif ($objectTypeGuid) {
                    $objectTypeGuid
                } else { $null }

                $inheritedTypeGuid = if ($rule.InheritedObjectType -and $rule.InheritedObjectType.ToString() -ne '00000000-0000-0000-0000-000000000000') {
                    $rule.InheritedObjectType.ToString()
                } else { $null }

                $ace = @{
                    IdentityReference     = $resolved
                    IdentitySID           = $sidStr
                    ActiveDirectoryRights = $rule.ActiveDirectoryRights.ToString()
                    AccessControlType     = $rule.AccessControlType.ToString()
                    ObjectType            = $objectTypeName
                    ObjectTypeGUID        = $objectTypeGuid
                    InheritedObjectType   = $inheritedTypeGuid
                    IsInherited           = $rule.IsInherited
                    ObjectDN              = $objDN
                    ObjectName            = $objName
                }
                $aceList.Add($ace)

                # ── Check if this is a dangerous non-default ACE ──────────
                if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }

                # Skip default/expected groups
                $isDefault = $false
                foreach ($pattern in $defaultIgnorePatterns) {
                    if ($resolved -eq $pattern -or $resolved -like "*\$pattern" -or $sidStr -eq $pattern) {
                        $isDefault = $true
                        break
                    }
                }
                # Also skip if it ends with the well-known domain admin/EA RIDs
                if (-not $isDefault -and $sidStr -match '-512$|-519$') {
                    $isDefault = $true
                }
                if ($isDefault) { continue }

                $rights = $rule.ActiveDirectoryRights.ToString()
                $isDangerous = $false

                # Check for dangerous broad rights
                foreach ($dr in $dangerousRights) {
                    if ($rights -match $dr) {
                        $isDangerous = $true
                        break
                    }
                }

                # Check for dangerous WriteProperty on specific attributes
                if (-not $isDangerous -and $rights -match 'WriteProperty' -and $objectTypeGuid) {
                    if ($dangerousGuids.ContainsKey($objectTypeGuid)) {
                        $isDangerous = $true
                    }
                }

                # Check for dangerous ExtendedRight (DCSync, password reset, etc.)
                if (-not $isDangerous -and $rights -match 'ExtendedRight') {
                    if ($objectTypeGuid -and $dangerousGuids.ContainsKey($objectTypeGuid)) {
                        $isDangerous = $true
                    } elseif (-not $objectTypeGuid) {
                        # All extended rights granted (no specific GUID means all)
                        $isDangerous = $true
                    }
                }

                if ($isDangerous) {
                    $allDangerousACEs.Add($ace)
                }
            }

            # Store the owner for domain root
            if ($objName -eq 'Domain Root') {
                try {
                    $ownerSid = $sd.GetOwner([System.Security.Principal.SecurityIdentifier])
                    $result.DomainRootOwner = Resolve-ADSid -SidString $ownerSid.Value -SearchRoot $searchRoot
                } catch {
                    Write-Verbose "Could not resolve domain root owner: $_"
                    $result.DomainRootOwner = 'Unknown'
                }
            }

            $result.CriticalObjectACLs[$objName] = @{
                ObjectDN = $objDN
                ACECount = $aceList.Count
                ACEs     = @($aceList)
            }

            Write-Verbose "  $objName`: $($aceList.Count) ACEs analyzed."
        } catch {
            Write-Warning "Failed to read ACLs for $objName ($objDN): $_"
            $result.CriticalObjectACLs[$objName] = @{
                ObjectDN = $objDN
                Error    = "Failed: $_"
                ACEs     = @()
            }
        }
    }

    $result.DangerousACEs = @($allDangerousACEs)
    Write-Verbose "Total dangerous non-default ACEs found: $($allDangerousACEs.Count)."

    # ── ms-DS-MachineAccountQuota ─────────────────────────────────────────────
    Write-Verbose 'Reading ms-DS-MachineAccountQuota from domain root...'
    try {
        $domainRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
        $maqResults = @(Invoke-LdapQuery -SearchRoot $domainRoot `
            -Filter '(objectClass=domainDNS)' `
            -Properties @('ms-DS-MachineAccountQuota') `
            -Scope Base)

        if ($maqResults.Count -gt 0) {
            $result.MachineAccountQuota = [int]($maqResults[0]['ms-ds-machineaccountquota'] ?? 10)
            Write-Verbose "MachineAccountQuota: $($result.MachineAccountQuota)"
        }
    } catch {
        Write-Warning "Failed to read MachineAccountQuota: $_"
    }

    # ── GPO Permissions ───────────────────────────────────────────────────────
    Write-Verbose 'Analyzing GPO permissions...'
    try {
        $gpoPoliciesDN = "CN=Policies,CN=System,$($Connection.DomainDN)"
        $gpoRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $gpoPoliciesDN

        $gpoObjects = Invoke-LdapQuery -SearchRoot $gpoRoot `
            -Filter '(objectClass=groupPolicyContainer)' `
            -Properties @('displayname', 'distinguishedname', 'name')

        $gpoPerms = @{}
        foreach ($gpo in $gpoObjects) {
            $gpoDN = $gpo['distinguishedname'] ?? ''
            $gpoDisplayName = $gpo['displayname'] ?? $gpo['name'] ?? $gpoDN

            try {
                $gpoEntry = New-LdapSearchRoot -Connection $Connection -SearchBase $gpoDN
                $gpoSd = $gpoEntry.ObjectSecurity
                if ($null -eq $gpoSd) { continue }

                $rules = $gpoSd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
                $editPrincipals = [System.Collections.Generic.List[string]]::new()
                $applyPrincipals = [System.Collections.Generic.List[string]]::new()

                foreach ($rule in $rules) {
                    if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }

                    $sidStr = $rule.IdentityReference.Value
                    $resolved = Resolve-ADSid -SidString $sidStr -SearchRoot $searchRoot
                    $rights = $rule.ActiveDirectoryRights.ToString()

                    # Edit = WriteDacl, WriteOwner, WriteProperty, GenericWrite, GenericAll
                    if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') {
                        if (-not $editPrincipals.Contains($resolved)) {
                            $editPrincipals.Add($resolved)
                        }
                    }

                    # Apply = GenericRead + GenericExecute (roughly)
                    if ($rights -match 'GenericRead|GenericExecute|ReadProperty') {
                        if (-not $applyPrincipals.Contains($resolved)) {
                            $applyPrincipals.Add($resolved)
                        }
                    }
                }

                $gpoPerms[$gpoDisplayName] = @{
                    DN             = $gpoDN
                    CanEdit        = @($editPrincipals)
                    AppliesTo      = @($applyPrincipals)
                }
            } catch {
                Write-Verbose "Failed to read ACL for GPO $gpoDisplayName`: $_"
            }
        }

        $result.GPOPermissions = $gpoPerms
        Write-Verbose "Analyzed permissions on $($gpoPerms.Count) GPO(s)."
    } catch {
        Write-Warning "Failed to analyze GPO permissions: $_"
    }

    # ── OU Delegation (object creation/deletion) ──────────────────────────────
    Write-Verbose 'Scanning OUs for delegated creation/deletion ACEs...'
    try {
        $ouResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(objectClass=organizationalUnit)' `
            -Properties @('distinguishedname')

        $ouDelegations = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($ou in $ouResults) {
            $ouDN = $ou['distinguishedname'] ?? ''
            if (-not $ouDN) { continue }

            try {
                $ouEntry = New-LdapSearchRoot -Connection $Connection -SearchBase $ouDN
                $ouSd = $ouEntry.ObjectSecurity
                if ($null -eq $ouSd) { continue }

                $rules = $ouSd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

                foreach ($rule in $rules) {
                    if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }
                    $rights = $rule.ActiveDirectoryRights.ToString()

                    # CreateChild or DeleteChild indicate delegation
                    if ($rights -notmatch 'CreateChild|DeleteChild|GenericAll') { continue }

                    $sidStr = $rule.IdentityReference.Value
                    $resolved = Resolve-ADSid -SidString $sidStr -SearchRoot $searchRoot

                    # Skip default groups
                    $isDefault = $false
                    foreach ($pattern in $defaultIgnorePatterns) {
                        if ($resolved -eq $pattern -or $resolved -like "*\$pattern" -or $sidStr -eq $pattern) {
                            $isDefault = $true
                            break
                        }
                    }
                    if (-not $isDefault -and $sidStr -match '-512$|-519$') {
                        $isDefault = $true
                    }
                    if ($isDefault) { continue }

                    $inheritedTypeGuid = if ($rule.InheritedObjectType -and $rule.InheritedObjectType.ToString() -ne '00000000-0000-0000-0000-000000000000') {
                        $rule.InheritedObjectType.ToString()
                    } else { $null }

                    $objectTypeGuid = if ($rule.ObjectType -and $rule.ObjectType.ToString() -ne '00000000-0000-0000-0000-000000000000') {
                        $rule.ObjectType.ToString()
                    } else { $null }

                    $ouDelegations.Add(@{
                        OUDN                  = $ouDN
                        IdentityReference     = $resolved
                        IdentitySID           = $sidStr
                        ActiveDirectoryRights = $rights
                        ObjectType            = $objectTypeGuid
                        InheritedObjectType   = $inheritedTypeGuid
                        IsInherited           = $rule.IsInherited
                    })
                }
            } catch {
                Write-Verbose "Failed to read ACL for OU $ouDN`: $_"
            }
        }

        $result.OUDelegation = @($ouDelegations)
        Write-Verbose "Found $($ouDelegations.Count) OU delegation ACE(s)."
    } catch {
        Write-Warning "Failed to scan OU delegations: $_"
    }

    return $result
}
