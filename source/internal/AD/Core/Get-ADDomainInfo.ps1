# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADDomainInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    # ── Functional level mapping ──────────────────────────────────────
    $functionalLevelMap = @{
        0  = '2000'
        1  = '2003Interim'
        2  = '2003'
        3  = '2008'
        4  = '2008R2'
        5  = '2012'
        6  = '2012R2'
        7  = '2016'
        10 = '2025'
    }

    # ── Schema version mapping ────────────────────────────────────────
    $schemaVersionMap = @{
        13 = '2000'
        30 = '2003'
        31 = '2003R2'
        44 = '2008'
        47 = '2008R2'
        56 = '2012'
        69 = '2012R2'
        87 = '2016'
        88 = '2019'
        90 = '2022'
        91 = '2025'
    }

    $result = @{
        ForestFunctionalLevel       = 0
        ForestFunctionalLevelName   = 'Unknown'
        DomainFunctionalLevel       = 0
        DomainFunctionalLevelName   = 'Unknown'
        SchemaVersion               = 0
        SchemaVersionName           = 'Unknown'
        DomainName                  = ''
        ForestName                  = ''
        DomainDN                    = ''
        ForestDN                    = ''
        DomainSID                   = ''
        Sites                       = @()
        RecycleBinEnabled           = $false
        TombstoneLifetime           = 0
        FSMORoles                   = @{
            SchemaMaster        = ''
            DomainNamingMaster  = ''
            PDCEmulator         = ''
            RIDMaster           = ''
            InfrastructureMaster = ''
        }
        DnsZones                    = @()
        Errors                      = @{}
    }

    $domainDN = $Connection.DomainDN
    $configDN = $Connection.ConfigDN
    $schemaDN = $Connection.SchemaDN
    $forestDN = $Connection.ForestDN

    # ── 1. Functional levels ──────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Collecting domain functional levels'
    }

    $result.ForestFunctionalLevel = $Connection.ForestFunctionality
    $result.DomainFunctionalLevel = $Connection.DomainFunctionality

    if ($functionalLevelMap.ContainsKey($Connection.ForestFunctionality)) {
        $result.ForestFunctionalLevelName = $functionalLevelMap[$Connection.ForestFunctionality]
    }
    if ($functionalLevelMap.ContainsKey($Connection.DomainFunctionality)) {
        $result.DomainFunctionalLevelName = $functionalLevelMap[$Connection.DomainFunctionality]
    }

    # ── 2. Schema version ─────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Reading schema version'
    }

    try {
        $schemaRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $schemaDN
        $schemaResults = @(Invoke-LdapQuery -SearchRoot $schemaRoot `
            -Filter '(objectClass=dMD)' `
            -Properties @('objectVersion') `
            -Scope Base)

        if ($schemaResults.Count -gt 0 -and $schemaResults[0].ContainsKey('objectversion')) {
            $result.SchemaVersion = [int]$schemaResults[0]['objectversion']
            if ($schemaVersionMap.ContainsKey($result.SchemaVersion)) {
                $result.SchemaVersionName = $schemaVersionMap[$result.SchemaVersion]
            }
        }
    } catch {
        Write-Verbose "Failed to read schema version: $_"
        $result.Errors['SchemaVersion'] = $_.Exception.Message
    }

    # ── 3. Domain and forest names ────────────────────────────────────
    $result.DomainDN = $domainDN
    $result.ForestDN = $forestDN

    # Convert DN to DNS-style name: DC=contoso,DC=com -> contoso.com
    $result.DomainName = ($domainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()
    $result.ForestName = ($forestDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

    # ── 4. Domain SID ─────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Retrieving domain SID'
    }

    try {
        $domainRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $domainObj = @(Invoke-LdapQuery -SearchRoot $domainRoot `
            -Filter '(objectClass=domainDNS)' `
            -Properties @('objectSid') `
            -Scope Base)

        if ($domainObj.Count -gt 0 -and $domainObj[0].ContainsKey('objectsid')) {
            $result.DomainSID = $domainObj[0]['objectsid']
        }
    } catch {
        Write-Verbose "Failed to retrieve domain SID: $_"
        $result.Errors['DomainSID'] = $_.Exception.Message
    }

    # ── 5. Sites, subnets, site links, and servers ────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Enumerating AD sites and subnets'
    }

    try {
        $sitesContainerDN = "CN=Sites,$configDN"
        $sitesRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $sitesContainerDN

        # Get all site objects
        $siteResults = Invoke-LdapQuery -SearchRoot $sitesRoot `
            -Filter '(objectClass=site)' `
            -Properties @('cn', 'distinguishedName', 'description', 'whenCreated') `
            -Scope OneLevel

        Write-Verbose "Found $($siteResults.Count) site(s)"

        # Get all subnet objects
        $subnetsContainerDN = "CN=Subnets,CN=Sites,$configDN"
        $subnetResults = @()
        try {
            $subnetsRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $subnetsContainerDN
            $subnetResults = Invoke-LdapQuery -SearchRoot $subnetsRoot `
                -Filter '(objectClass=subnet)' `
                -Properties @('cn', 'siteObject', 'description') `
                -Scope OneLevel
        } catch {
            Write-Verbose "Failed to enumerate subnets: $_"
        }

        # Build subnet-to-site lookup
        $subnetsBySite = @{}
        foreach ($subnet in $subnetResults) {
            $siteRef = if ($subnet.ContainsKey('siteobject')) { $subnet['siteobject'] } else { '' }
            if ($siteRef) {
                if (-not $subnetsBySite.ContainsKey($siteRef)) {
                    $subnetsBySite[$siteRef] = [System.Collections.Generic.List[string]]::new()
                }
                $subnetsBySite[$siteRef].Add($subnet['cn'])
            }
        }

        # Get all site link objects
        $siteLinksContainerDN = "CN=IP,CN=Inter-Site Transports,CN=Sites,$configDN"
        $siteLinkResults = @()
        try {
            $siteLinksRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $siteLinksContainerDN
            $siteLinkResults = Invoke-LdapQuery -SearchRoot $siteLinksRoot `
                -Filter '(objectClass=siteLink)' `
                -Properties @('cn', 'siteList', 'cost', 'replInterval', 'description') `
                -Scope OneLevel
        } catch {
            Write-Verbose "Failed to enumerate site links: $_"
        }

        # Build site link lookup: site DN -> list of site link names
        $siteLinksBySite = @{}
        foreach ($link in $siteLinkResults) {
            $linkedSites = @()
            if ($link.ContainsKey('sitelist')) {
                $linkedSites = if ($link['sitelist'] -is [array]) { $link['sitelist'] } else { @($link['sitelist']) }
            }
            foreach ($linkedSiteDN in $linkedSites) {
                if (-not $siteLinksBySite.ContainsKey($linkedSiteDN)) {
                    $siteLinksBySite[$linkedSiteDN] = [System.Collections.Generic.List[string]]::new()
                }
                $siteLinksBySite[$linkedSiteDN].Add($link['cn'])
            }
        }

        # Build sites array with servers
        $sites = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($site in $siteResults) {
            $siteDN = $site['distinguishedname']
            $siteName = $site['cn']

            # Get servers (DCs) in this site
            $siteServers = @()
            try {
                $serversContainerDN = "CN=Servers,$siteDN"
                $serversRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $serversContainerDN
                $serverResults = Invoke-LdapQuery -SearchRoot $serversRoot `
                    -Filter '(objectClass=server)' `
                    -Properties @('cn', 'dNSHostName') `
                    -Scope OneLevel
                $siteServers = @($serverResults | ForEach-Object {
                    @{
                        Name = $_['cn']
                        FQDN = if ($_.ContainsKey('dnshostname')) { $_['dnshostname'] } else { $_['cn'] }
                    }
                })
            } catch {
                Write-Verbose "Failed to enumerate servers in site $siteName`: $_"
            }

            $siteObj = @{
                Name        = $siteName
                Description = if ($site.ContainsKey('description')) { $site['description'] } else { '' }
                Subnets     = @(if ($subnetsBySite.ContainsKey($siteDN)) { $subnetsBySite[$siteDN] } else { @() })
                SiteLinks   = @(if ($siteLinksBySite.ContainsKey($siteDN)) { $siteLinksBySite[$siteDN] } else { @() })
                Servers     = $siteServers
            }
            $sites.Add($siteObj)
        }

        $result.Sites = @($sites)
    } catch {
        Write-Verbose "Failed to enumerate sites: $_"
        $result.Errors['Sites'] = $_.Exception.Message
    }

    # ── 6. Recycle Bin feature ────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Checking AD Recycle Bin status'
    }

    try {
        $recycleBinDN = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,$configDN"
        $recycleBinRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $recycleBinDN
        $recycleBinResults = Invoke-LdapQuery -SearchRoot $recycleBinRoot `
            -Filter '(objectClass=msDS-OptionalFeature)' `
            -Properties @('msDS-EnabledFeatureBL') `
            -Scope Base

        if ($recycleBinResults.Count -gt 0 -and $recycleBinResults[0].ContainsKey('msds-enabledfeaturebl')) {
            $enabledBL = $recycleBinResults[0]['msds-enabledfeaturebl']
            $result.RecycleBinEnabled = ($null -ne $enabledBL -and @($enabledBL).Count -gt 0)
        }
    } catch {
        Write-Verbose "AD Recycle Bin feature not found or not accessible: $_"
        # Not an error condition — feature may not exist on older schemas
    }

    # ── 7. Tombstone lifetime ─────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Reading tombstone lifetime'
    }

    try {
        $dirServiceDN = "CN=Directory Service,CN=Windows NT,CN=Services,$configDN"
        $dirServiceRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $dirServiceDN
        $dirServiceResults = Invoke-LdapQuery -SearchRoot $dirServiceRoot `
            -Filter '(objectClass=nTDSService)' `
            -Properties @('tombstoneLifetime') `
            -Scope Base

        if ($dirServiceResults.Count -gt 0 -and $dirServiceResults[0].ContainsKey('tombstonelifetime')) {
            $result.TombstoneLifetime = [int]$dirServiceResults[0]['tombstonelifetime']
        } else {
            # Default tombstone lifetime is 60 days for forests upgraded from 2000/2003, 180 for newer
            $result.TombstoneLifetime = 180
            Write-Verbose 'tombstoneLifetime attribute not set; defaulting to 180 days'
        }
    } catch {
        Write-Verbose "Failed to read tombstone lifetime: $_"
        $result.Errors['TombstoneLifetime'] = $_.Exception.Message
    }

    # ── 8. FSMO roles ─────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Locating FSMO role holders'
    }

    # Helper to extract server name from NTDS Settings DN
    # CN=NTDS Settings,CN=SERVERNAME,CN=Servers,CN=SiteName,CN=Sites,...
    $extractServerFromNtds = {
        param([string]$NtdsDN)
        if ([string]::IsNullOrWhiteSpace($NtdsDN)) { return '' }
        # Remove "CN=NTDS Settings," prefix, then take the first CN value
        $remainder = $NtdsDN -replace '^CN=NTDS Settings,', ''
        if ($remainder -match '^CN=([^,]+)') {
            return $Matches[1]
        }
        return $NtdsDN
    }

    # Schema Master — fSMORoleOwner on the Schema container
    try {
        $schemaRoot2 = New-LdapSearchRoot -Connection $Connection -SearchBase $schemaDN
        $schemaFsmo = @(Invoke-LdapQuery -SearchRoot $schemaRoot2 `
            -Filter '(objectClass=dMD)' `
            -Properties @('fSMORoleOwner') `
            -Scope Base)

        if ($schemaFsmo.Count -gt 0 -and $schemaFsmo[0].ContainsKey('fsmoroleowner')) {
            $result.FSMORoles.SchemaMaster = & $extractServerFromNtds $schemaFsmo[0]['fsmoroleowner']
        }
    } catch {
        Write-Verbose "Failed to determine Schema Master: $_"
        $result.Errors['FSMO_SchemaMaster'] = $_.Exception.Message
    }

    # Domain Naming Master — fSMORoleOwner on CN=Partitions,<ConfigDN>
    try {
        $partitionsDN = "CN=Partitions,$configDN"
        $partitionsRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $partitionsDN
        $partitionsFsmo = @(Invoke-LdapQuery -SearchRoot $partitionsRoot `
            -Filter '(objectClass=crossRefContainer)' `
            -Properties @('fSMORoleOwner') `
            -Scope Base)

        if ($partitionsFsmo.Count -gt 0 -and $partitionsFsmo[0].ContainsKey('fsmoroleowner')) {
            $result.FSMORoles.DomainNamingMaster = & $extractServerFromNtds $partitionsFsmo[0]['fsmoroleowner']
        }
    } catch {
        Write-Verbose "Failed to determine Domain Naming Master: $_"
        $result.Errors['FSMO_DomainNamingMaster'] = $_.Exception.Message
    }

    # PDC Emulator, RID Master, Infrastructure Master — fSMORoleOwner on the domain head
    try {
        $domainHeadRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $domainHeadFsmo = @(Invoke-LdapQuery -SearchRoot $domainHeadRoot `
            -Filter '(objectClass=domainDNS)' `
            -Properties @('fSMORoleOwner') `
            -Scope Base)

        if ($domainHeadFsmo.Count -gt 0 -and $domainHeadFsmo[0].ContainsKey('fsmoroleowner')) {
            $result.FSMORoles.PDCEmulator = & $extractServerFromNtds $domainHeadFsmo[0]['fsmoroleowner']
        }
    } catch {
        Write-Verbose "Failed to determine PDC Emulator: $_"
        $result.Errors['FSMO_PDCEmulator'] = $_.Exception.Message
    }

    # RID Master — fSMORoleOwner on CN=RID Manager$,CN=System,<DomainDN>
    try {
        $ridManagerDN = "CN=RID Manager`$,CN=System,$domainDN"
        $ridRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $ridManagerDN
        $ridFsmo = @(Invoke-LdapQuery -SearchRoot $ridRoot `
            -Filter '(objectClass=rIDManager)' `
            -Properties @('fSMORoleOwner') `
            -Scope Base)

        if ($ridFsmo.Count -gt 0 -and $ridFsmo[0].ContainsKey('fsmoroleowner')) {
            $result.FSMORoles.RIDMaster = & $extractServerFromNtds $ridFsmo[0]['fsmoroleowner']
        }
    } catch {
        Write-Verbose "Failed to determine RID Master: $_"
        $result.Errors['FSMO_RIDMaster'] = $_.Exception.Message
    }

    # Infrastructure Master — fSMORoleOwner on CN=Infrastructure,<DomainDN>
    try {
        $infraDN = "CN=Infrastructure,$domainDN"
        $infraRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $infraDN
        $infraFsmo = @(Invoke-LdapQuery -SearchRoot $infraRoot `
            -Filter '(objectClass=infrastructureUpdate)' `
            -Properties @('fSMORoleOwner') `
            -Scope Base)

        if ($infraFsmo.Count -gt 0 -and $infraFsmo[0].ContainsKey('fsmoroleowner')) {
            $result.FSMORoles.InfrastructureMaster = & $extractServerFromNtds $infraFsmo[0]['fsmoroleowner']
        }
    } catch {
        Write-Verbose "Failed to determine Infrastructure Master: $_"
        $result.Errors['FSMO_InfrastructureMaster'] = $_.Exception.Message
    }

    # ── 9. DNS zones ──────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Enumerating DNS zones'
    }

    $dnsZones = [System.Collections.Generic.List[hashtable]]::new()

    # Try Application Directory Partition first (DC=DomainDnsZones), then fallback to CN=System
    $dnsContainers = @(
        "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"
        "CN=MicrosoftDNS,DC=ForestDnsZones,$forestDN"
        "CN=MicrosoftDNS,CN=System,$domainDN"
    )

    foreach ($dnsContainer in $dnsContainers) {
        try {
            $dnsRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $dnsContainer
            $zoneResults = Invoke-LdapQuery -SearchRoot $dnsRoot `
                -Filter '(objectClass=dnsZone)' `
                -Properties @(
                    'dc', 'name', 'dnsProperty',
                    'whenCreated', 'whenChanged',
                    'distinguishedName'
                ) `
                -Scope OneLevel

            foreach ($zone in $zoneResults) {
                $zoneName = if ($zone.ContainsKey('dc')) { $zone['dc'] }
                            elseif ($zone.ContainsKey('name')) { $zone['name'] }
                            else { '' }

                # Skip the cache zone and RootDNSServers
                if ($zoneName -eq '..Cache' -or $zoneName -eq 'RootDNSServers') { continue }

                # Determine zone type from the container
                $zoneType = if ($dnsContainer -match 'DC=DomainDnsZones') {
                    'AD-Domain'
                } elseif ($dnsContainer -match 'DC=ForestDnsZones') {
                    'AD-Forest'
                } else {
                    'AD-Legacy'
                }

                $zoneObj = @{
                    Name           = $zoneName
                    ZoneType       = $zoneType
                    Container      = $dnsContainer
                    WhenCreated    = if ($zone.ContainsKey('whencreated')) { $zone['whencreated'] } else { $null }
                    WhenChanged    = if ($zone.ContainsKey('whenchanged')) { $zone['whenchanged'] } else { $null }
                }

                # Check for duplicate zone names already collected
                $existing = $dnsZones | Where-Object { $_.Name -eq $zoneName -and $_.ZoneType -eq $zoneType }
                if (-not $existing) {
                    $dnsZones.Add($zoneObj)
                }
            }
        } catch {
            Write-Verbose "DNS zone container not accessible: $dnsContainer - $_"
            # Not an error — container may not exist in this environment
        }
    }

    $result.DnsZones = @($dnsZones)

    # ── Summary ───────────────────────────────────────────────────────
    if (-not $Quiet) {
        $summary = "Domain info collected: $($result.DomainName) " +
                   "(FL $($result.DomainFunctionalLevelName)), " +
                   "$($result.Sites.Count) site(s), " +
                   "$($result.DnsZones.Count) DNS zone(s)"
        if ($result.Errors.Count -gt 0) {
            $summary += " ($($result.Errors.Count) error(s))"
        }
        Write-ProgressLine -Phase AUDITING -Message $summary
    }

    return $result
}
