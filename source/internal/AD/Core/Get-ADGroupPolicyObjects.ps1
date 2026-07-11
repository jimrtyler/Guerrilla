# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADGroupPolicyObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    $result = @{
        GPOs                = @()
        GPOLinks            = @{}
        SYSVOLContent       = @{}
        GPOVersionMismatch  = @()
        WMIFilters          = @()
        GPOPermissions      = @{}
    }

    $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.DomainDN
    $domainFqdn = ($Connection.DomainDN -replace ',DC=', '.' -replace '^DC=', '')

    # ── Query all GPOs ────────────────────────────────────────────────────────
    Write-Verbose 'Querying all Group Policy Objects from AD...'
    try {
        $gpoPoliciesDN = "CN=Policies,CN=System,$($Connection.DomainDN)"
        $gpoRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $gpoPoliciesDN

        $gpoResults = Invoke-LdapQuery -SearchRoot $gpoRoot `
            -Filter '(objectClass=groupPolicyContainer)' `
            -Properties @(
                'displayname', 'distinguishedname', 'name', 'whencreated', 'whenchanged',
                'versionnumber', 'gpcfilesyspath', 'flags', 'gpcmachineextensionnames',
                'gpcuserextensionnames'
            )

        Write-Verbose "Found $($gpoResults.Count) GPO(s) in AD."
    } catch {
        Write-Warning "Failed to query GPOs: $_"
        return $result
    }

    # ── Collect gPLink from all containers (OUs, domain root, sites) ──────────
    Write-Verbose 'Collecting gPLink attributes from OUs, domain root, and sites...'
    $gpoLinksMap = @{}

    # gPLink from OUs and domain root
    try {
        $linkContainers = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(|(objectClass=organizationalUnit)(objectClass=domainDNS))' `
            -Properties @('distinguishedname', 'gplink')

        foreach ($container in $linkContainers) {
            $containerDN = $container['distinguishedname'] ?? ''
            $gpLink = $container['gplink']
            if ($containerDN -and $gpLink) {
                $gpoLinksMap[$containerDN] = $gpLink
            }
        }
    } catch {
        Write-Warning "Failed to read gPLink from OUs: $_"
    }

    # gPLink from sites
    try {
        $sitesDN = "CN=Sites,$($Connection.ConfigDN)"
        $sitesRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $sitesDN
        $siteContainers = Invoke-LdapQuery -SearchRoot $sitesRoot `
            -Filter '(objectClass=site)' `
            -Properties @('distinguishedname', 'gplink')

        foreach ($site in $siteContainers) {
            $siteDN = $site['distinguishedname'] ?? ''
            $gpLink = $site['gplink']
            if ($siteDN -and $gpLink) {
                $gpoLinksMap[$siteDN] = $gpLink
            }
        }
    } catch {
        Write-Verbose "Failed to read gPLink from sites (may not have permissions): $_"
    }

    # ── Parse gPLink values ───────────────────────────────────────────────────
    # gPLink format: [LDAP://CN={GUID},CN=Policies,CN=System,DC=...;flags][LDAP://...;flags]
    # flags: 0=enabled, 1=disabled, 2=enforced, 3=disabled+enforced
    $parsedLinks = @{}
    $gpoDNToLinkedContainers = @{}

    foreach ($containerDN in $gpoLinksMap.Keys) {
        $linkStr = $gpoLinksMap[$containerDN]
        $parsed = [System.Collections.Generic.List[hashtable]]::new()

        $linkMatches = [regex]::Matches($linkStr, '\[LDAP://([^;]+);(\d+)\]')
        foreach ($match in $linkMatches) {
            $gpoDN = $match.Groups[1].Value
            $linkFlags = [int]$match.Groups[2].Value

            $linkEntry = @{
                GPODN       = $gpoDN
                Flags       = $linkFlags
                IsEnabled   = ($linkFlags -band 1) -eq 0
                IsEnforced  = ($linkFlags -band 2) -ne 0
            }
            $parsed.Add($linkEntry)

            # Build reverse mapping: GPO DN -> containers where it is linked
            $gpoDNLower = $gpoDN.ToLower()
            if (-not $gpoDNToLinkedContainers.ContainsKey($gpoDNLower)) {
                $gpoDNToLinkedContainers[$gpoDNLower] = [System.Collections.Generic.List[hashtable]]::new()
            }
            $gpoDNToLinkedContainers[$gpoDNLower].Add(@{
                ContainerDN = $containerDN
                IsEnabled   = $linkEntry.IsEnabled
                IsEnforced  = $linkEntry.IsEnforced
            })
        }

        $parsedLinks[$containerDN] = @($parsed)
    }

    $result.GPOLinks = $parsedLinks

    # ── Build GPO list with link information ──────────────────────────────────
    $gpoList = [System.Collections.Generic.List[hashtable]]::new()
    $versionMismatches = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpo in $gpoResults) {
        $gpoDN = $gpo['distinguishedname'] ?? ''
        $displayName = $gpo['displayname'] ?? $gpo['name'] ?? ''
        $gpoGuid = $gpo['name'] ?? ''  # 'name' is the {GUID} form

        $versionNumber = [int]($gpo['versionnumber'] ?? 0)
        # Version: high 16 bits = user version, low 16 bits = computer version
        $versionUser     = ($versionNumber -shr 16) -band 0xFFFF
        $versionComputer = $versionNumber -band 0xFFFF

        $flags = [int]($gpo['flags'] ?? 0)
        $gpcFileSysPath = $gpo['gpcfilesyspath'] ?? ''

        # Get linked containers from reverse map
        $linkedTo = @()
        $gpoDNLower = $gpoDN.ToLower()
        if ($gpoDNToLinkedContainers.ContainsKey($gpoDNLower)) {
            $linkedTo = @($gpoDNToLinkedContainers[$gpoDNLower])
        }

        $gpoEntry = @{
            DisplayName     = $displayName
            DN              = $gpoDN
            GUID            = $gpoGuid
            WhenCreated     = $gpo['whencreated']
            WhenChanged     = $gpo['whenchanged']
            VersionUser     = $versionUser
            VersionComputer = $versionComputer
            VersionNumber   = $versionNumber
            GPCFileSysPath  = $gpcFileSysPath
            Flags           = $flags
            FlagDescription = switch ($flags) {
                0 { 'All settings enabled' }
                1 { 'User configuration disabled' }
                2 { 'Computer configuration disabled' }
                3 { 'All settings disabled' }
                default { "Unknown ($flags)" }
            }
            LinkedTo        = $linkedTo
            IsLinked        = $linkedTo.Count -gt 0
            IsEmpty         = $false  # Will be updated during SYSVOL scan
        }

        $gpoList.Add($gpoEntry)
    }

    $result.GPOs = @($gpoList)
    Write-Verbose "Processed $($gpoList.Count) GPO(s) with link analysis."

    # ── SYSVOL Content Analysis ───────────────────────────────────────────────
    Write-Verbose 'Analyzing SYSVOL content for GPOs...'
    $sysvolBase = "\\$domainFqdn\SYSVOL\$domainFqdn\Policies"
    $sysvolAccessible = Test-Path -LiteralPath $sysvolBase -ErrorAction SilentlyContinue

    if (-not $sysvolAccessible) {
        Write-Verbose "SYSVOL not accessible at $sysvolBase. Skipping SYSVOL analysis."
    }

    foreach ($gpoEntry in $gpoList) {
        $gpoGuid = $gpoEntry.GUID
        $displayName = $gpoEntry.DisplayName

        if (-not $sysvolAccessible -or -not $gpoGuid) {
            $result.SYSVOLContent[$displayName] = @{
                Error = 'SYSVOL not accessible'
            }
            continue
        }

        $gpoSysvolPath = Join-Path $sysvolBase $gpoGuid
        $sysvolInfo = @{
            HasScripts         = $false
            HasPreferences     = $false
            HasRegistryPol     = $false
            ScriptFiles        = @()
            PreferenceFiles    = @()
            CPasswordFound     = $false
            CPasswordLocations = @()
            GptIniVersion      = $null
        }

        try {
            if (-not (Test-Path -LiteralPath $gpoSysvolPath -ErrorAction SilentlyContinue)) {
                $gpoEntry.IsEmpty = $true
                $result.SYSVOLContent[$displayName] = $sysvolInfo
                continue
            }

            # Check for scripts
            $scriptDirs = @(
                (Join-Path $gpoSysvolPath 'Machine\Scripts'),
                (Join-Path $gpoSysvolPath 'User\Scripts')
            )
            $scriptFiles = [System.Collections.Generic.List[string]]::new()
            foreach ($scriptDir in $scriptDirs) {
                if (Test-Path -LiteralPath $scriptDir -ErrorAction SilentlyContinue) {
                    $found = Get-ChildItem -LiteralPath $scriptDir -Recurse -File -ErrorAction SilentlyContinue
                    foreach ($f in $found) {
                        $scriptFiles.Add($f.FullName)
                    }
                }
            }
            $sysvolInfo.HasScripts = $scriptFiles.Count -gt 0
            $sysvolInfo.ScriptFiles = @($scriptFiles)

            # Check for Preferences
            $prefDirs = @(
                (Join-Path $gpoSysvolPath 'Machine\Preferences'),
                (Join-Path $gpoSysvolPath 'User\Preferences')
            )
            $prefFiles = [System.Collections.Generic.List[string]]::new()
            $cpassLocations = [System.Collections.Generic.List[string]]::new()

            foreach ($prefDir in $prefDirs) {
                if (Test-Path -LiteralPath $prefDir -ErrorAction SilentlyContinue) {
                    $found = Get-ChildItem -LiteralPath $prefDir -Recurse -File -ErrorAction SilentlyContinue
                    foreach ($f in $found) {
                        $prefFiles.Add($f.FullName)

                        # Scan XML files for cpassword
                        if ($f.Extension -eq '.xml') {
                            try {
                                $xmlContent = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                                if ($xmlContent -match 'cpassword') {
                                    $cpassLocations.Add($f.FullName)
                                }
                            } catch {
                                Write-Verbose "Could not read $($f.FullName): $_"
                            }
                        }
                    }
                }
            }
            $sysvolInfo.HasPreferences = $prefFiles.Count -gt 0
            $sysvolInfo.PreferenceFiles = @($prefFiles)
            $sysvolInfo.CPasswordFound = $cpassLocations.Count -gt 0
            $sysvolInfo.CPasswordLocations = @($cpassLocations)

            # Check for Registry.pol
            $regPolPaths = @(
                (Join-Path $gpoSysvolPath 'Machine\Registry.pol'),
                (Join-Path $gpoSysvolPath 'User\Registry.pol')
            )
            foreach ($regPolPath in $regPolPaths) {
                if (Test-Path -LiteralPath $regPolPath -ErrorAction SilentlyContinue) {
                    $sysvolInfo.HasRegistryPol = $true
                    break
                }
            }

            # Check if GPO is effectively empty (only GPT.INI exists)
            $allFiles = @(Get-ChildItem -LiteralPath $gpoSysvolPath -Recurse -File -ErrorAction SilentlyContinue)
            $nonDefaultFiles = @($allFiles | Where-Object { $_.Name -ne 'GPT.INI' })
            $gpoEntry.IsEmpty = $nonDefaultFiles.Count -eq 0

            # ── GPT.INI version check ─────────────────────────────────────
            $gptIniPath = Join-Path $gpoSysvolPath 'GPT.INI'
            if (Test-Path -LiteralPath $gptIniPath -ErrorAction SilentlyContinue) {
                try {
                    $gptContent = Get-Content -LiteralPath $gptIniPath -ErrorAction Stop
                    foreach ($line in $gptContent) {
                        if ($line -match '^\s*Version\s*=\s*(\d+)') {
                            $sysvolVersion = [int]$Matches[1]
                            $sysvolInfo.GptIniVersion = $sysvolVersion

                            $sysvolUserVer     = ($sysvolVersion -shr 16) -band 0xFFFF
                            $sysvolComputerVer = $sysvolVersion -band 0xFFFF

                            if ($sysvolUserVer -ne $gpoEntry.VersionUser -or $sysvolComputerVer -ne $gpoEntry.VersionComputer) {
                                $mismatch = @{
                                    DisplayName        = $displayName
                                    GUID               = $gpoGuid
                                    ADVersionUser      = $gpoEntry.VersionUser
                                    ADVersionComputer  = $gpoEntry.VersionComputer
                                    SYSVOLVersionUser  = $sysvolUserVer
                                    SYSVOLVersionComputer = $sysvolComputerVer
                                }
                                $versionMismatches.Add($mismatch)
                            }
                            break
                        }
                    }
                } catch {
                    Write-Verbose "Could not parse GPT.INI for $displayName`: $_"
                }
            }
        } catch {
            Write-Verbose "SYSVOL analysis failed for GPO $displayName`: $_"
            $sysvolInfo['Error'] = "Failed: $_"
        }

        $result.SYSVOLContent[$displayName] = $sysvolInfo
    }

    $result.GPOVersionMismatch = @($versionMismatches)
    if ($versionMismatches.Count -gt 0) {
        Write-Verbose "Found $($versionMismatches.Count) GPO(s) with AD/SYSVOL version mismatch."
    }

    # ── WMI Filters ───────────────────────────────────────────────────────────
    Write-Verbose 'Querying WMI filters...'
    try {
        $wmiContainerDN = "CN=SOM,CN=WMIPolicy,CN=System,$($Connection.DomainDN)"
        $wmiRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $wmiContainerDN
        $wmiResults = Invoke-LdapQuery -SearchRoot $wmiRoot `
            -Filter '(objectClass=msWMI-Som)' `
            -Properties @('msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2', 'distinguishedname', 'msWMI-ID', 'whencreated')

        $wmiList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($wmi in $wmiResults) {
            $wmiList.Add(@{
                Name        = $wmi['mswmi-name'] ?? ''
                Description = $wmi['mswmi-parm1'] ?? ''
                Query       = $wmi['mswmi-parm2'] ?? ''
                DN          = $wmi['distinguishedname'] ?? ''
                ID          = $wmi['mswmi-id'] ?? ''
                WhenCreated = $wmi['whencreated']
            })
        }

        $result.WMIFilters = @($wmiList)
        Write-Verbose "Found $($wmiList.Count) WMI filter(s)."
    } catch {
        Write-Verbose "Failed to query WMI filters (container may not exist): $_"
    }

    # ── GPO Permissions (edit vs apply) ───────────────────────────────────────
    Write-Verbose 'Analyzing GPO DACL permissions (edit vs apply)...'
    $gpoPerms = @{}

    foreach ($gpoEntry in $gpoList) {
        $gpoDN = $gpoEntry.DN
        $displayName = $gpoEntry.DisplayName

        try {
            $gpoAdEntry = New-LdapSearchRoot -Connection $Connection -SearchBase $gpoDN
            $gpoSd = $gpoAdEntry.ObjectSecurity
            if ($null -eq $gpoSd) { continue }

            $rules = $gpoSd.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])
            $canEdit = [System.Collections.Generic.List[string]]::new()
            $canApply = [System.Collections.Generic.List[string]]::new()

            foreach ($rule in $rules) {
                if ($rule.AccessControlType.ToString() -ne 'Allow') { continue }

                $sidStr = $rule.IdentityReference.Value
                $resolved = Resolve-ADSid -SidString $sidStr -SearchRoot $searchRoot
                $rights = $rule.ActiveDirectoryRights.ToString()

                # Edit permissions: write access to GPO object
                if ($rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') {
                    if (-not $canEdit.Contains($resolved)) {
                        $canEdit.Add($resolved)
                    }
                }

                # Apply permissions: read + apply (GenericRead or ReadProperty with GenericExecute)
                if ($rights -match 'GenericRead|GenericExecute|ReadProperty') {
                    if (-not $canApply.Contains($resolved)) {
                        $canApply.Add($resolved)
                    }
                }
            }

            $gpoPerms[$displayName] = @{
                DN       = $gpoDN
                CanEdit  = @($canEdit)
                CanApply = @($canApply)
            }
        } catch {
            Write-Verbose "Failed to read DACL for GPO $displayName`: $_"
        }
    }

    # Check who can link GPOs (write gPLink on containers)
    try {
        $ouResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(|(objectClass=organizationalUnit)(objectClass=domainDNS))' `
            -Properties @('distinguishedname')

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

                    # Writing gPLink requires WriteProperty on the specific attribute
                    # gPLink attribute GUID: f30e3bbe-9ff0-11d1-b603-0000f80367c1
                    $objectTypeGuid = if ($rule.ObjectType) { $rule.ObjectType.ToString() } else { $null }
                    $isGPLinkWrite = ($rights -match 'WriteProperty') -and
                                    ($objectTypeGuid -eq 'f30e3bbe-9ff0-11d1-b603-0000f80367c1' -or
                                     $rights -match 'GenericAll|GenericWrite')

                    if ($isGPLinkWrite) {
                        $sidStr = $rule.IdentityReference.Value
                        $resolved = Resolve-ADSid -SidString $sidStr -SearchRoot $searchRoot

                        # Add linking info to all GPOs (linking ability is per-container, not per-GPO)
                        foreach ($gpoDisplayName in $gpoPerms.Keys) {
                            if (-not $gpoPerms[$gpoDisplayName].ContainsKey('CanLinkAt')) {
                                $gpoPerms[$gpoDisplayName]['CanLinkAt'] = @{}
                            }
                            if (-not $gpoPerms[$gpoDisplayName]['CanLinkAt'].ContainsKey($resolved)) {
                                $gpoPerms[$gpoDisplayName]['CanLinkAt'][$resolved] = [System.Collections.Generic.List[string]]::new()
                            }
                            if (-not $gpoPerms[$gpoDisplayName]['CanLinkAt'][$resolved].Contains($ouDN)) {
                                $gpoPerms[$gpoDisplayName]['CanLinkAt'][$resolved].Add($ouDN)
                            }
                        }
                    }
                }
            } catch {
                Write-Verbose "Failed to check link permissions on $ouDN`: $_"
            }
        }
    } catch {
        Write-Verbose "Failed to analyze GPO link permissions: $_"
    }

    $result.GPOPermissions = $gpoPerms
    Write-Verbose "Completed GPO permission analysis for $($gpoPerms.Count) GPO(s)."

    return $result
}
