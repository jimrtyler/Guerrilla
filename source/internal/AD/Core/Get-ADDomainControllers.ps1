# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADDomainControllers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [switch]$Quiet
    )

    # ── Obsolete/unsupported OS patterns ──────────────────────────────
    # OS names that indicate end-of-support or obsolete Windows Server versions.
    # Windows Server 2012 R2 extended support ended Oct 2023.
    # Windows Server 2012 (non-R2) ended Oct 2023.
    # Anything older is long out of support.
    $obsoleteOsPatterns = @(
        'Windows Server 2012 R2'
        'Windows Server 2012'
        'Windows Server 2008 R2'
        'Windows Server 2008'
        'Windows Server 2003'
        'Windows 2000'
    )

    $domainDN = $Connection.DomainDN
    $configDN = $Connection.ConfigDN

    if (-not $Quiet) {
        Write-ProgressLine -Phase AUDITING -Message 'Enumerating domain controllers'
    }

    # ── 1. Query DC computer objects ──────────────────────────────────
    # SERVER_TRUST_ACCOUNT (0x2000 = 8192) identifies domain controller computer accounts
    $dcFilter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'

    $dcProperties = @(
        'cn', 'dNSHostName', 'distinguishedName', 'objectSid',
        'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack',
        'userAccountControl', 'lastLogonTimestamp', 'whenCreated',
        'msDS-isRODC', 'primaryGroupID'
    )

    $dcResults = @()
    try {
        $domainRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $dcResults = Invoke-LdapQuery -SearchRoot $domainRoot `
            -Filter $dcFilter `
            -Properties $dcProperties
    } catch {
        Write-Warning "Failed to enumerate domain controllers: $_"
        return @()
    }

    Write-Verbose "Found $($dcResults.Count) domain controller(s)"

    # ── 2. Determine FSMO role holders for cross-reference ────────────
    $fsmoHolders = @{
        SchemaMaster        = ''
        DomainNamingMaster  = ''
        PDCEmulator         = ''
        RIDMaster           = ''
        InfrastructureMaster = ''
    }

    $extractServerFromNtds = {
        param([string]$NtdsDN)
        if ([string]::IsNullOrWhiteSpace($NtdsDN)) { return '' }
        $remainder = $NtdsDN -replace '^CN=NTDS Settings,', ''
        if ($remainder -match '^CN=([^,]+)') { return $Matches[1] }
        return ''
    }

    # Schema Master
    try {
        $schemaRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $Connection.SchemaDN
        $r = @(Invoke-LdapQuery -SearchRoot $schemaRoot -Filter '(objectClass=dMD)' -Properties @('fSMORoleOwner') -Scope Base)
        if ($r.Count -gt 0 -and $r[0].ContainsKey('fsmoroleowner')) {
            $fsmoHolders.SchemaMaster = & $extractServerFromNtds $r[0]['fsmoroleowner']
        }
    } catch { Write-Verbose "Could not resolve Schema Master: $_" }

    # Domain Naming Master
    try {
        $partRoot = New-LdapSearchRoot -Connection $Connection -SearchBase "CN=Partitions,$configDN"
        $r = @(Invoke-LdapQuery -SearchRoot $partRoot -Filter '(objectClass=crossRefContainer)' -Properties @('fSMORoleOwner') -Scope Base)
        if ($r.Count -gt 0 -and $r[0].ContainsKey('fsmoroleowner')) {
            $fsmoHolders.DomainNamingMaster = & $extractServerFromNtds $r[0]['fsmoroleowner']
        }
    } catch { Write-Verbose "Could not resolve Domain Naming Master: $_" }

    # PDC Emulator
    try {
        $domHead = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $r = @(Invoke-LdapQuery -SearchRoot $domHead -Filter '(objectClass=domainDNS)' -Properties @('fSMORoleOwner') -Scope Base)
        if ($r.Count -gt 0 -and $r[0].ContainsKey('fsmoroleowner')) {
            $fsmoHolders.PDCEmulator = & $extractServerFromNtds $r[0]['fsmoroleowner']
        }
    } catch { Write-Verbose "Could not resolve PDC Emulator: $_" }

    # RID Master
    try {
        $ridRoot = New-LdapSearchRoot -Connection $Connection -SearchBase "CN=RID Manager`$,CN=System,$domainDN"
        $r = @(Invoke-LdapQuery -SearchRoot $ridRoot -Filter '(objectClass=rIDManager)' -Properties @('fSMORoleOwner') -Scope Base)
        if ($r.Count -gt 0 -and $r[0].ContainsKey('fsmoroleowner')) {
            $fsmoHolders.RIDMaster = & $extractServerFromNtds $r[0]['fsmoroleowner']
        }
    } catch { Write-Verbose "Could not resolve RID Master: $_" }

    # Infrastructure Master
    try {
        $infraRoot = New-LdapSearchRoot -Connection $Connection -SearchBase "CN=Infrastructure,$domainDN"
        $r = @(Invoke-LdapQuery -SearchRoot $infraRoot -Filter '(objectClass=infrastructureUpdate)' -Properties @('fSMORoleOwner') -Scope Base)
        if ($r.Count -gt 0 -and $r[0].ContainsKey('fsmoroleowner')) {
            $fsmoHolders.InfrastructureMaster = & $extractServerFromNtds $r[0]['fsmoroleowner']
        }
    } catch { Write-Verbose "Could not resolve Infrastructure Master: $_" }

    # ── 3. Determine Global Catalog servers from NTDS Settings ────────
    $gcServers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    try {
        $sitesRoot = New-LdapSearchRoot -Connection $Connection -SearchBase "CN=Sites,$configDN"
        $ntdsResults = Invoke-LdapQuery -SearchRoot $sitesRoot `
            -Filter '(&(objectClass=nTDSDSA)(options:1.2.840.113556.1.4.803:=1))' `
            -Properties @('distinguishedName')

        foreach ($ntds in $ntdsResults) {
            $dn = $ntds['distinguishedname']
            $serverName = & $extractServerFromNtds $dn
            if ($serverName) {
                [void]$gcServers.Add($serverName)
            }
        }
        Write-Verbose "Found $($gcServers.Count) Global Catalog server(s)"
    } catch {
        Write-Verbose "Failed to enumerate GC servers via NTDS Settings: $_"
    }

    # ── 4. Build DC result objects ────────────────────────────────────
    $domainControllers = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($dc in $dcResults) {
        $dcName = if ($dc.ContainsKey('cn')) { $dc['cn'] } else { '' }
        $dcFQDN = if ($dc.ContainsKey('dnshostname')) { $dc['dnshostname'] } else { '' }
        $os     = if ($dc.ContainsKey('operatingsystem')) { $dc['operatingsystem'] } else { '' }
        $osVer  = if ($dc.ContainsKey('operatingsystemversion')) { $dc['operatingsystemversion'] } else { '' }
        $osSP   = if ($dc.ContainsKey('operatingsystemservicepack')) { $dc['operatingsystemservicepack'] } else { '' }
        $uac    = if ($dc.ContainsKey('useraccountcontrol')) { [int]$dc['useraccountcontrol'] } else { 0 }

        # Determine if this is an RODC
        # Method 1: msDS-isRODC attribute (Server 2008+)
        # Method 2: PARTIAL_SECRETS_ACCOUNT UAC flag (0x04000000)
        # Method 3: primaryGroupID = 521 (Read-only Domain Controllers group)
        $isRODC = $false
        if ($dc.ContainsKey('msds-isrodc')) {
            $isRODC = [bool]$dc['msds-isrodc']
        }
        if (-not $isRODC) {
            $isRODC = ($uac -band 0x04000000) -ne 0
        }
        if (-not $isRODC -and $dc.ContainsKey('primarygroupid')) {
            $isRODC = ([int]$dc['primarygroupid'] -eq 521)
        }

        # Determine if this is a Global Catalog
        $isGC = $gcServers.Contains($dcName)

        # Resolve IPv4 address from DNS hostname
        $ipv4 = ''
        if ($dcFQDN) {
            try {
                $dnsEntry = [System.Net.Dns]::GetHostAddresses($dcFQDN)
                $ipv4Addr = $dnsEntry | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                if ($ipv4Addr) {
                    $ipv4 = $ipv4Addr.ToString()
                }
            } catch {
                Write-Verbose "DNS resolution failed for $dcFQDN`: $_"
            }
        }

        # Determine FSMO roles held by this DC
        $dcFsmoRoles = [System.Collections.Generic.List[string]]::new()
        foreach ($role in $fsmoHolders.GetEnumerator()) {
            if ($role.Value -and $role.Value -eq $dcName) {
                $dcFsmoRoles.Add($role.Key)
            }
        }

        # Determine obsolete/unsupported OS
        $isObsoleteOS = $false
        $isUnsupportedOS = $false

        if ($os) {
            foreach ($pattern in $obsoleteOsPatterns) {
                if ($os -like "*$pattern*") {
                    $isObsoleteOS = $true
                    break
                }
            }

            # For unsupported check, we need to be careful: "Windows Server 2012" should not
            # match "Windows Server 2012 R2". Check 2012 R2 first, then plain 2012.
            if ($os -like '*Windows Server 2012 R2*') {
                $isUnsupportedOS = $true  # 2012 R2 is also out of support
            } elseif ($os -like '*Windows Server 2012*') {
                $isUnsupportedOS = $true
            } elseif ($os -like '*Windows Server 2008 R2*' -or
                      $os -like '*Windows Server 2008*' -or
                      $os -like '*Windows Server 2003*' -or
                      $os -like '*Windows 2000*') {
                $isUnsupportedOS = $true
            }
        }

        $dcObj = @{
            Name                      = $dcName
            FQDN                      = $dcFQDN
            DistinguishedName         = if ($dc.ContainsKey('distinguishedname')) { $dc['distinguishedname'] } else { '' }
            OperatingSystem           = $os
            OperatingSystemVersion    = $osVer
            OperatingSystemServicePack = $osSP
            IsGlobalCatalog           = $isGC
            IsRODC                    = $isRODC
            IPv4Address               = $ipv4
            LastLogon                 = if ($dc.ContainsKey('lastlogontimestamp')) { $dc['lastlogontimestamp'] } else { $null }
            WhenCreated               = if ($dc.ContainsKey('whencreated')) { $dc['whencreated'] } else { $null }
            SID                       = if ($dc.ContainsKey('objectsid')) { $dc['objectsid'] } else { '' }
            UserAccountControl        = $uac
            FSMORoles                 = @($dcFsmoRoles)
            ObsoleteOS                = $isObsoleteOS
            UnsupportedOS             = $isUnsupportedOS
        }

        $domainControllers.Add($dcObj)
    }

    # ── Summary ───────────────────────────────────────────────────────
    if (-not $Quiet) {
        $gcCount = @($domainControllers | Where-Object { $_.IsGlobalCatalog }).Count
        $rodcCount = @($domainControllers | Where-Object { $_.IsRODC }).Count
        $obsoleteCount = @($domainControllers | Where-Object { $_.ObsoleteOS }).Count

        $summary = "Found $($domainControllers.Count) DC(s): $gcCount GC, $rodcCount RODC"
        if ($obsoleteCount -gt 0) {
            $summary += ", $obsoleteCount obsolete OS"
        }
        Write-ProgressLine -Phase AUDITING -Message $summary
    }

    return @($domainControllers)
}
