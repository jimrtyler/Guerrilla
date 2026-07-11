# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADDomainForestChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADDomainForestChecks'
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

# ── ADDOM-001: Forest Functional Level ─────────────────────────────────────
function Test-ReconADDOM001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $level = [int]$domain.ForestFunctionalLevel
    $levelName = $domain.ForestFunctionalLevelName

    $status = if ($level -ge 7) { 'PASS' }
              elseif ($level -ge 6) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "Forest functional level: $levelName (level $level)"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            ForestFunctionalLevel     = $level
            ForestFunctionalLevelName = $levelName
        }
}

# ── ADDOM-002: Domain Functional Level ─────────────────────────────────────
function Test-ReconADDOM002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $level = [int]$domain.DomainFunctionalLevel
    $levelName = $domain.DomainFunctionalLevelName

    $status = if ($level -ge 7) { 'PASS' }
              elseif ($level -ge 6) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "Domain functional level: $levelName (level $level)"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            DomainFunctionalLevel     = $level
            DomainFunctionalLevelName = $levelName
        }
}

# ── ADDOM-003: Schema Version ──────────────────────────────────────────────
function Test-ReconADDOM003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $schemaVersion = [int]$domain.SchemaVersion
    $schemaName = $domain.SchemaVersionName

    if ($schemaVersion -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Schema version could not be determined'
    }

    $status = if ($schemaVersion -ge 88) { 'PASS' }
              elseif ($schemaVersion -eq 87) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "Schema version: $schemaVersion ($schemaName)"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            SchemaVersion     = $schemaVersion
            SchemaVersionName = $schemaName
        }
}

# ── ADDOM-004: DC Inventory ────────────────────────────────────────────────
function Test-ReconADDOM004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainControllers' -Subject 'domain controllers'
    if ($na) { return $na }

    $dcs = @($AuditData.DomainControllers)
    if ($dcs.Count -eq 0 -or ($dcs.Count -eq 1 -and $null -eq $dcs[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain controller data not available'
    }

    $gcCount = @($dcs | Where-Object { $_.IsGlobalCatalog }).Count
    $rodcCount = @($dcs | Where-Object { $_.IsRODC }).Count
    $obsoleteCount = @($dcs | Where-Object { $_.ObsoleteOS }).Count

    $status = if ($dcs.Count -eq 1) { 'WARN' } else { 'PASS' }

    $currentValue = "$($dcs.Count) domain controller(s): $gcCount GC, $rodcCount RODC"
    if ($obsoleteCount -gt 0) {
        $currentValue += ", $obsoleteCount running obsolete OS"
    }
    if ($dcs.Count -eq 1) {
        $currentValue += ' (single DC - no redundancy)'
    }

    $dcSummary = @($dcs | ForEach-Object {
        @{
            Name            = $_.Name
            FQDN            = $_.FQDN
            OperatingSystem = $_.OperatingSystem
            IsGlobalCatalog = $_.IsGlobalCatalog
            IsRODC          = $_.IsRODC
            ObsoleteOS      = $_.ObsoleteOS
        }
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            TotalDCs      = $dcs.Count
            GCCount       = $gcCount
            RODCCount     = $rodcCount
            ObsoleteCount = $obsoleteCount
            DCSummary     = $dcSummary
        }
}

# ── ADDOM-005: Obsolete OS on DCs ──────────────────────────────────────────
function Test-ReconADDOM005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainControllers' -Subject 'domain controllers'
    if ($na) { return $na }

    $dcs = @($AuditData.DomainControllers)
    if ($dcs.Count -eq 0 -or ($dcs.Count -eq 1 -and $null -eq $dcs[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain controller data not available'
    }

    $obsoleteDCs = @($dcs | Where-Object { $_.ObsoleteOS -eq $true })

    if ($obsoleteDCs.Count -gt 0) {
        $dcNames = @($obsoleteDCs | ForEach-Object { "$($_.Name) ($($_.OperatingSystem))" })
        $currentValue = "$($obsoleteDCs.Count) DC(s) running obsolete OS: $($dcNames -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                ObsoleteDCs = @($obsoleteDCs | ForEach-Object {
                    @{ Name = $_.Name; FQDN = $_.FQDN; OperatingSystem = $_.OperatingSystem }
                })
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($dcs.Count) DC(s) running supported operating systems" `
        -Details @{ TotalDCs = $dcs.Count }
}

# ── ADDOM-006: FSMO Role Identification ────────────────────────────────────
function Test-ReconADDOM006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain -or -not $domain.FSMORoles) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'FSMO role data not available'
    }

    $roles = $domain.FSMORoles
    # Check if all roles are on the same DC
    $uniqueHolders = @($roles.Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique)

    $status = 'PASS'
    $currentValue = "FSMO roles distributed across $($uniqueHolders.Count) DC(s)"

    if ($uniqueHolders.Count -eq 1 -and $uniqueHolders[0]) {
        $status = 'WARN'
        $currentValue = "All 5 FSMO roles held by single DC: $($uniqueHolders[0])"
    } elseif ($uniqueHolders.Count -eq 0) {
        $status = 'WARN'
        $currentValue = 'Unable to determine FSMO role holders'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            SchemaMaster        = $roles.SchemaMaster
            DomainNamingMaster  = $roles.DomainNamingMaster
            PDCEmulator         = $roles.PDCEmulator
            RIDMaster           = $roles.RIDMaster
            InfrastructureMaster = $roles.InfrastructureMaster
            UniqueHolders       = @($uniqueHolders)
        }
}

# ── ADDOM-007: AD Replication Health ───────────────────────────────────────
function Test-ReconADDOM007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    # ReplicationHealth may not be collected depending on access level
    if (-not $domain.ContainsKey('ReplicationHealth') -or $null -eq $domain.ReplicationHealth) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Replication health data not collected. Run repadmin /replsummary for manual verification'
    }

    $replHealth = $domain.ReplicationHealth

    # If replication health data is available, evaluate it
    $failures = @()
    if ($replHealth -is [array]) {
        $failures = @($replHealth | Where-Object {
            $_.Status -and $_.Status -ne 'Success' -and $_.Status -ne 'OK'
        })
    } elseif ($replHealth -is [hashtable]) {
        if ($replHealth.ContainsKey('Failures')) {
            $failures = @($replHealth.Failures)
        }
    }

    if ($failures.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($failures.Count) replication failure(s) detected" `
            -Details @{ Failures = $failures }
    }

    # Single-DC forest: there is no replication topology to fail. Report this
    # explicitly so the PASS reads as an assessed result, not an empty default.
    if ($replHealth -is [hashtable] -and $replHealth.SingleDC -eq $true) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Single domain controller, no replication topology to assess (healthy)' `
            -Details @{ ReplicationHealth = $replHealth }
    }

    $partnerCount = if ($replHealth -is [hashtable] -and $null -ne $replHealth.Partners) { @($replHealth.Partners).Count } else { 0 }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "AD replication is healthy ($partnerCount partner link(s), no failures)" `
        -Details @{ ReplicationHealth = $replHealth }
}

# ── ADDOM-008: Tombstone Lifetime ──────────────────────────────────────────
function Test-ReconADDOM008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $tombstone = [int]$domain.TombstoneLifetime

    if ($tombstone -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Tombstone lifetime could not be determined' `
            -Details @{ TombstoneLifetime = 0 }
    }

    $status = if ($tombstone -ge 180) { 'PASS' }
              elseif ($tombstone -ge 60) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "Tombstone lifetime: $tombstone days"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{ TombstoneLifetime = $tombstone }
}

# ── ADDOM-009: AD Recycle Bin ──────────────────────────────────────────────
function Test-ReconADDOM009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $enabled = $domain.RecycleBinEnabled

    if ($enabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'AD Recycle Bin is enabled' `
            -Details @{ RecycleBinEnabled = $true }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue 'AD Recycle Bin is not enabled. Deleted objects cannot be fully recovered without authoritative restore' `
        -Details @{ RecycleBinEnabled = $false }
}

# ── ADDOM-010: Sites and Subnets ───────────────────────────────────────────
function Test-ReconADDOM010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $sites = @($domain.Sites)
    if ($sites.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No site data available'
    }

    $sitesWithNoSubnets = @($sites | Where-Object {
        $null -eq $_.Subnets -or @($_.Subnets).Count -eq 0
    })

    $totalSubnets = 0
    foreach ($site in $sites) {
        $totalSubnets += @($site.Subnets).Count
    }

    if ($sitesWithNoSubnets.Count -gt 0) {
        $emptyNames = @($sitesWithNoSubnets | ForEach-Object { $_.Name })
        $currentValue = "$($sitesWithNoSubnets.Count) of $($sites.Count) site(s) have no subnets assigned: $($emptyNames -join ', ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                TotalSites         = $sites.Count
                TotalSubnets       = $totalSubnets
                SitesWithNoSubnets = $emptyNames
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($sites.Count) site(s) have subnets assigned ($totalSubnets total subnets)" `
        -Details @{
            TotalSites   = $sites.Count
            TotalSubnets = $totalSubnets
        }
}

# ── ADDOM-011: Site Link Configuration ─────────────────────────────────────
function Test-ReconADDOM011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $sites = @($domain.Sites)
    if ($sites.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No site data available'
    }

    # Collect unique site link names across all sites
    $allSiteLinks = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($site in $sites) {
        if ($site.SiteLinks) {
            foreach ($link in $site.SiteLinks) {
                [void]$allSiteLinks.Add($link)
            }
        }
    }

    # Sites with no site links are isolated
    $isolatedSites = @($sites | Where-Object {
        $null -eq $_.SiteLinks -or @($_.SiteLinks).Count -eq 0
    })

    $status = 'PASS'
    $currentValue = "$($allSiteLinks.Count) site link(s) connecting $($sites.Count) site(s)"

    if ($isolatedSites.Count -gt 0) {
        $status = 'WARN'
        $isolatedNames = @($isolatedSites | ForEach-Object { $_.Name })
        $currentValue += ". $($isolatedSites.Count) site(s) have no site links: $($isolatedNames -join ', ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            TotalSiteLinks = $allSiteLinks.Count
            TotalSites     = $sites.Count
            SiteLinks      = @($allSiteLinks)
            IsolatedSites  = @(if ($isolatedSites.Count -gt 0) { $isolatedSites | ForEach-Object { $_.Name } } else { @() })
        }
}

# ── ADDOM-012: DNS Zone Security ───────────────────────────────────────────
function Test-ReconADDOM012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainInfo' -Subject 'domain information'
    if ($na) { return $na }

    $domain = $AuditData.Domain
    if (-not $domain) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Domain information not available'
    }

    $dnsZones = @($domain.DnsZones)
    if ($dnsZones.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No DNS zone data available'
    }

    # Check for zones that might have insecure dynamic update settings.
    # The LDAP query for dnsZone objects doesn't always expose the DynamicUpdate setting
    # directly. We check if the zone data includes a DynamicUpdate property.
    $insecureZones = [System.Collections.Generic.List[string]]::new()
    $checkedZones = 0

    foreach ($zone in $dnsZones) {
        # Only check AD-integrated zones (which should use secure-only updates)
        if ($zone.ZoneType -match '^AD-') {
            $checkedZones++

            if ($zone.ContainsKey('DynamicUpdate')) {
                # DynamicUpdate values: 0=None, 1=Nonsecure+Secure, 2=SecureOnly
                if ($zone.DynamicUpdate -eq 1 -or $zone.DynamicUpdate -eq 'NonsecureAndSecure') {
                    $insecureZones.Add($zone.Name)
                }
            }
        }
    }

    # If no DynamicUpdate property was available, provide guidance
    if ($checkedZones -gt 0 -and $insecureZones.Count -eq 0) {
        $hasDynamicUpdateData = $false
        foreach ($zone in $dnsZones) {
            if ($zone.ContainsKey('DynamicUpdate')) {
                $hasDynamicUpdateData = $true
                break
            }
        }

        if (-not $hasDynamicUpdateData) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue "$checkedZones AD-integrated DNS zone(s) found. Dynamic update settings could not be verified programmatically. Verify all zones use Secure Only dynamic updates in DNS Manager" `
                -Details @{
                    TotalDnsZones  = $dnsZones.Count
                    ADIntegrated   = $checkedZones
                    ZoneNames      = @($dnsZones | ForEach-Object { $_.Name })
                }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $checkedZones AD-integrated DNS zone(s) use secure dynamic updates" `
            -Details @{
                TotalDnsZones = $dnsZones.Count
                ADIntegrated  = $checkedZones
            }
    }

    if ($insecureZones.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($insecureZones.Count) DNS zone(s) allow nonsecure dynamic updates: $($insecureZones -join ', ')" `
            -Details @{
                InsecureZones = @($insecureZones)
                TotalDnsZones = $dnsZones.Count
            }
    }

    # Fallback: no AD-integrated zones found at all
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($dnsZones.Count) DNS zone(s) found but none are AD-integrated. Verify DNS zone configuration manually" `
        -Details @{ TotalDnsZones = $dnsZones.Count }
}

# ── ADDOM-013: LDAP Signing ───────────────────────────────────────────────
function Test-ReconADDOM013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    # Attempt to find LDAP signing configuration from GPO SYSVOL content
    $gpoData = $AuditData.GroupPolicies
    $ldapSigningValue = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            # Check for registry-based policy: LDAPServerIntegrity
            # Value 2 = Require signing
            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('SecuritySettings')) {
                $secSettings = $gpoContent.SecuritySettings

                if ($secSettings -is [hashtable] -and $secSettings.ContainsKey('LDAPServerIntegrity')) {
                    $ldapSigningValue = [int]$secSettings.LDAPServerIntegrity
                }
            }

            # Also check the raw registry policy data
            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'LDAPServerIntegrity' -or
                        $regPolicy.ValueName -eq 'ldapserverintegrity') {
                        $ldapSigningValue = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    if ($null -ne $ldapSigningValue) {
        # 0 = None, 1 = Require signing (for server), 2 = Require signing (alternate encoding)
        $status = if ($ldapSigningValue -ge 2) { 'PASS' }
                  elseif ($ldapSigningValue -eq 1) { 'WARN' }
                  else { 'FAIL' }

        $valueLabel = switch ($ldapSigningValue) {
            0 { 'None' }
            1 { 'Negotiate signing' }
            2 { 'Require signing' }
            default { "Unknown ($ldapSigningValue)" }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "LDAP server signing requirement: $valueLabel" `
            -Details @{ LDAPServerIntegrity = $ldapSigningValue }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'LDAP signing configuration could not be verified from GPO data. Verify Domain controller: LDAP server signing requirements is set to Require signing in Group Policy applied to the Domain Controllers OU' `
        -Details @{ Note = 'GPO SYSVOL content not available or LDAPServerIntegrity setting not found' }
}

# ── ADDOM-014: LDAP Channel Binding ───────────────────────────────────────
function Test-ReconADDOM014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    # Check for LdapEnforceChannelBinding registry setting in GPO data
    $gpoData = $AuditData.GroupPolicies
    $channelBindingValue = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'LdapEnforceChannelBinding' -or
                        $regPolicy.ValueName -eq 'ldapenforcechannelbinding') {
                        $channelBindingValue = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    if ($null -ne $channelBindingValue) {
        # 0 = Never, 1 = When Supported, 2 = Always
        $status = if ($channelBindingValue -eq 2) { 'PASS' }
                  elseif ($channelBindingValue -eq 1) { 'WARN' }
                  else { 'FAIL' }

        $valueLabel = switch ($channelBindingValue) {
            0 { 'Never' }
            1 { 'When Supported' }
            2 { 'Always' }
            default { "Unknown ($channelBindingValue)" }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "LDAP channel binding: $valueLabel" `
            -Details @{ LdapEnforceChannelBinding = $channelBindingValue }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'LDAP channel binding configuration could not be verified from GPO data. Check the LdapEnforceChannelBinding registry value (HKLM\System\CurrentControlSet\Services\NTDS\Parameters) on all DCs. Value should be 2 (Always)' `
        -Details @{ Note = 'GPO SYSVOL content not available or LdapEnforceChannelBinding setting not found' }
}

# ── ADDOM-015: SMB Signing ─────────────────────────────────────────────────
function Test-ReconADDOM015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    # Check for SMB signing settings in GPO data
    # Policy: "Microsoft network server: Digitally sign communications (always)"
    # Registry: HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature
    $gpoData = $AuditData.GroupPolicies
    $smbSigningRequired = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('SecuritySettings')) {
                $secSettings = $gpoContent.SecuritySettings

                # Check for the security option directly
                if ($secSettings -is [hashtable]) {
                    if ($secSettings.ContainsKey('RequireSecuritySignature')) {
                        $smbSigningRequired = [int]$secSettings.RequireSecuritySignature
                    }
                    if ($secSettings.ContainsKey('LanmanServerRequireSecuritySignature')) {
                        $smbSigningRequired = [int]$secSettings.LanmanServerRequireSecuritySignature
                    }
                }
            }

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'RequireSecuritySignature' -and
                        $regPolicy.Key -match 'LanmanServer') {
                        $smbSigningRequired = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    if ($null -ne $smbSigningRequired) {
        $status = if ($smbSigningRequired -eq 1) { 'PASS' } else { 'FAIL' }
        $valueLabel = if ($smbSigningRequired -eq 1) { 'Required (Enabled)' } else { 'Not Required (Disabled)' }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "SMB signing on domain controllers: $valueLabel" `
            -Details @{ RequireSecuritySignature = $smbSigningRequired }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'SMB signing configuration could not be verified from GPO data. Verify Microsoft network server: Digitally sign communications (always) is Enabled in Group Policy applied to the Domain Controllers OU' `
        -Details @{ Note = 'GPO SYSVOL content not available or SMB signing setting not found' }
}

# ── ADDOM-016: NTLMv1 Detection ────────────────────────────────────────────
function Test-ReconADDOM016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    # Check LAN Manager authentication level in GPO data
    # Registry: HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel
    $gpoData = $AuditData.GroupPolicies
    $lmLevel = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('SecuritySettings')) {
                $secSettings = $gpoContent.SecuritySettings
                if ($secSettings -is [hashtable] -and $secSettings.ContainsKey('LmCompatibilityLevel')) {
                    $lmLevel = [int]$secSettings.LmCompatibilityLevel
                }
            }

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'LmCompatibilityLevel' -or
                        $regPolicy.ValueName -eq 'lmcompatibilitylevel') {
                        $lmLevel = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    if ($null -ne $lmLevel) {
        # Level 0-2: NTLMv1 is allowed; Level 3-5: NTLMv1 is refused
        $status = if ($lmLevel -ge 3) { 'PASS' } else { 'FAIL' }

        $levelDescription = switch ($lmLevel) {
            0 { 'Send LM & NTLM responses' }
            1 { 'Send LM & NTLM - use NTLMv2 session security if negotiated' }
            2 { 'Send NTLM response only' }
            3 { 'Send NTLMv2 response only' }
            4 { 'Send NTLMv2 response only. Refuse LM' }
            5 { 'Send NTLMv2 response only. Refuse LM & NTLM' }
            default { "Unknown ($lmLevel)" }
        }

        $currentValue = "LAN Manager authentication level: $lmLevel ($levelDescription)"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue `
            -Details @{
                LmCompatibilityLevel = $lmLevel
                Description          = $levelDescription
                NTLMv1Allowed        = ($lmLevel -lt 3)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'LAN Manager authentication level could not be verified from GPO data. Check Network security: LAN Manager authentication level in Group Policy. FAIL if level is below 3 (NTLMv1 would be allowed)' `
        -Details @{ Note = 'GPO SYSVOL content not available or LmCompatibilityLevel setting not found' }
}

# ── ADDOM-017: NTLMv2 Enforcement ──────────────────────────────────────────
function Test-ReconADDOM017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    # Reuses the same LmCompatibilityLevel data but with stricter thresholds
    $gpoData = $AuditData.GroupPolicies
    $lmLevel = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('SecuritySettings')) {
                $secSettings = $gpoContent.SecuritySettings
                if ($secSettings -is [hashtable] -and $secSettings.ContainsKey('LmCompatibilityLevel')) {
                    $lmLevel = [int]$secSettings.LmCompatibilityLevel
                }
            }

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'LmCompatibilityLevel' -or
                        $regPolicy.ValueName -eq 'lmcompatibilitylevel') {
                        $lmLevel = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    if ($null -ne $lmLevel) {
        # Level 5 = PASS (refuse LM & NTLM), Level 3-4 = WARN (NTLMv2 only but not refusing legacy), < 3 = FAIL
        $status = if ($lmLevel -eq 5) { 'PASS' }
                  elseif ($lmLevel -ge 3) { 'WARN' }
                  else { 'FAIL' }

        $levelDescription = switch ($lmLevel) {
            0 { 'Send LM & NTLM responses' }
            1 { 'Send LM & NTLM - use NTLMv2 session security if negotiated' }
            2 { 'Send NTLM response only' }
            3 { 'Send NTLMv2 response only' }
            4 { 'Send NTLMv2 response only. Refuse LM' }
            5 { 'Send NTLMv2 response only. Refuse LM & NTLM' }
            default { "Unknown ($lmLevel)" }
        }

        $currentValue = "LAN Manager authentication level: $lmLevel ($levelDescription)"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue `
            -Details @{
                LmCompatibilityLevel = $lmLevel
                Description          = $levelDescription
                FullyEnforced        = ($lmLevel -eq 5)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'NTLMv2 enforcement level could not be verified from GPO data. Verify Network security: LAN Manager authentication level is set to level 5 (Send NTLMv2 response only. Refuse LM & NTLM)' `
        -Details @{ Note = 'GPO SYSVOL content not available or LmCompatibilityLevel setting not found' }
}

# ── ADDOM-018: Null Session Enumeration ────────────────────────────────────
function Test-ReconADDOM018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    # Check RestrictAnonymous / RestrictAnonymousSAM settings in GPO data
    $gpoData = $AuditData.GroupPolicies
    $restrictAnonymous = $null
    $restrictAnonymousSAM = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('SecuritySettings')) {
                $secSettings = $gpoContent.SecuritySettings
                if ($secSettings -is [hashtable]) {
                    if ($secSettings.ContainsKey('RestrictAnonymous')) {
                        $restrictAnonymous = [int]$secSettings.RestrictAnonymous
                    }
                    if ($secSettings.ContainsKey('RestrictAnonymousSAM')) {
                        $restrictAnonymousSAM = [int]$secSettings.RestrictAnonymousSAM
                    }
                }
            }

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'RestrictAnonymous' -or
                        $regPolicy.ValueName -eq 'restrictanonymous') {
                        $restrictAnonymous = [int]$regPolicy.Value
                    }
                    if ($regPolicy.ValueName -eq 'RestrictAnonymousSAM' -or
                        $regPolicy.ValueName -eq 'restrictanonymoussam') {
                        $restrictAnonymousSAM = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    if ($null -ne $restrictAnonymous -or $null -ne $restrictAnonymousSAM) {
        $issues = [System.Collections.Generic.List[string]]::new()

        # RestrictAnonymous: 0 = allow, 1 = restrict enumeration of shares, 2 = no access without explicit permission
        if ($null -ne $restrictAnonymous -and $restrictAnonymous -lt 1) {
            $issues.Add('RestrictAnonymous not set (anonymous enumeration of SAM accounts and shares allowed)')
        }

        # RestrictAnonymousSAM: 0 = disabled, 1 = enabled
        if ($null -ne $restrictAnonymousSAM -and $restrictAnonymousSAM -ne 1) {
            $issues.Add('RestrictAnonymousSAM not enabled (anonymous enumeration of SAM accounts allowed)')
        }

        if ($issues.Count -gt 0) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                -CurrentValue "Null session restrictions insufficient: $($issues -join '; ')" `
                -Details @{
                    RestrictAnonymous    = $restrictAnonymous
                    RestrictAnonymousSAM = $restrictAnonymousSAM
                    Issues               = @($issues)
                }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Null session enumeration is restricted (RestrictAnonymous=$restrictAnonymous, RestrictAnonymousSAM=$restrictAnonymousSAM)" `
            -Details @{
                RestrictAnonymous    = $restrictAnonymous
                RestrictAnonymousSAM = $restrictAnonymousSAM
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Null session settings could not be verified from GPO data. Verify RestrictAnonymous and RestrictAnonymousSAM are configured in Group Policy to prevent anonymous enumeration' `
        -Details @{ Note = 'GPO SYSVOL content not available or RestrictAnonymous settings not found' }
}

# ── ADDOM-019: Print Spooler on DCs ───────────────────────────────────────
function Test-ReconADDOM019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    # Check GPO data for Print Spooler service configuration on DCs
    $gpoData = $AuditData.GroupPolicies
    $spoolerDisabled = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            # Check for system service policies
            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('SystemServices')) {
                $services = $gpoContent.SystemServices
                if ($services -is [hashtable] -and $services.ContainsKey('Spooler')) {
                    # StartupMode: 2=Automatic, 3=Manual, 4=Disabled
                    $spoolerDisabled = ($services.Spooler.StartupMode -eq 4)
                }
                if ($services -is [array]) {
                    $spoolerEntry = $services | Where-Object { $_.ServiceName -eq 'Spooler' }
                    if ($spoolerEntry) {
                        $spoolerDisabled = ($spoolerEntry.StartupMode -eq 4)
                    }
                }
            }

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('SecuritySettings')) {
                $secSettings = $gpoContent.SecuritySettings
                if ($secSettings -is [hashtable] -and $secSettings.ContainsKey('SystemServices')) {
                    $svcSettings = $secSettings.SystemServices
                    if ($svcSettings -is [hashtable] -and $svcSettings.ContainsKey('Spooler')) {
                        $spoolerDisabled = ($svcSettings.Spooler -eq 4 -or $svcSettings.Spooler -eq 'Disabled')
                    }
                }
            }
        }
    }

    if ($null -ne $spoolerDisabled) {
        if ($spoolerDisabled) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'Print Spooler service is disabled on domain controllers via Group Policy' `
                -Details @{ SpoolerDisabledByGPO = $true }
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Print Spooler service is NOT disabled on domain controllers. This exposes DCs to PrintNightmare and SpoolSample attacks' `
            -Details @{ SpoolerDisabledByGPO = $false }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Print Spooler service status on DCs could not be verified from GPO data. Manually confirm the Spooler service is disabled on all domain controllers to mitigate PrintNightmare (CVE-2021-34527) and coercion attacks' `
        -Details @{ Note = 'GPO SYSVOL content not available or Spooler service configuration not found. Remote service query requires direct DC access.' }
}

# ── ADDOM-020: DSRM Password ──────────────────────────────────────────────
function Test-ReconADDOM020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('GroupPolicyObjects','DomainControllers') -Subject 'Group Policy objects'
    if ($na) { return $na }

    # DSRM password cannot be verified remotely via LDAP. We can check:
    # 1. DsrmAdminLogonBehavior registry value from GPO data (should be 0)
    # 2. Number of DCs to inform the auditor how many need manual verification
    $gpoData = $AuditData.GroupPolicies
    $dsrmLogonBehavior = $null

    if ($gpoData -and $gpoData.ContainsKey('SYSVOLContent')) {
        $sysvolContent = $gpoData.SYSVOLContent

        foreach ($gpoId in $sysvolContent.Keys) {
            $gpoContent = $sysvolContent[$gpoId]

            if ($gpoContent -is [hashtable] -and $gpoContent.ContainsKey('RegistryPolicies')) {
                foreach ($regPolicy in $gpoContent.RegistryPolicies) {
                    if ($regPolicy.ValueName -eq 'DsrmAdminLogonBehavior' -or
                        $regPolicy.ValueName -eq 'dsrmadminlogonbehavior') {
                        $dsrmLogonBehavior = [int]$regPolicy.Value
                    }
                }
            }
        }
    }

    $dcCount = 0
    if ($AuditData.DomainControllers) {
        $dcCount = @($AuditData.DomainControllers).Count
    }

    $details = @{
        DCCount = $dcCount
        Note    = 'DSRM password age and uniqueness cannot be verified remotely. Use ntdsutil on each DC to reset and document DSRM passwords.'
    }

    if ($null -ne $dsrmLogonBehavior) {
        $details['DsrmAdminLogonBehavior'] = $dsrmLogonBehavior

        if ($dsrmLogonBehavior -ne 0) {
            # Value 1 or 2 allows DSRM account to be used for network logon, which is dangerous
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                -CurrentValue "DsrmAdminLogonBehavior is set to $dsrmLogonBehavior (allows network DSRM logon). This should be 0 to prevent DSRM account from being used remotely. DSRM password rotation on $dcCount DC(s) requires manual verification" `
                -Details $details
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "DsrmAdminLogonBehavior is correctly set to 0 (network DSRM logon prevented). DSRM password rotation and uniqueness across $dcCount DC(s) requires manual verification" `
            -Details $details
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "DSRM password configuration requires manual verification on $dcCount DC(s). Verify DsrmAdminLogonBehavior is set to 0 (HKLM\System\CurrentControlSet\Control\Lsa) and DSRM passwords are unique per DC and rotated regularly" `
        -Details $details
}
