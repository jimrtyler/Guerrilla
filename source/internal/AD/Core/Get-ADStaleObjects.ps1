# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADStaleObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Connection,

        [int]$InactiveDays = 90,

        [int]$PasswordAgeDays = 365,

        [switch]$Quiet
    )

    $result = @{
        InactiveUsers          = @()
        InactiveComputers      = @()
        DisabledWithGroups     = @()
        ExpiredNotDisabled     = @()
        ObsoleteOSComputers    = @()
        UnsupportedOSComputers = @()
        OrphanedFSPs           = @()
        OrphanedSIDHistory     = @()
        AbandonedOUs           = @()
        PrinterObjects         = @()
        StaleDNSRecords        = @()
        TotalUsers             = 0
        TotalComputers         = 0
        TotalDisabled          = 0
        Errors                 = @{}
    }

    $domainDN = $Connection.DomainDN
    $now = [datetime]::UtcNow
    $inactiveThreshold = $now.AddDays(-$InactiveDays)
    $passwordAgeThreshold = $now.AddDays(-$PasswordAgeDays)

    # Convert thresholds to Windows FileTime for LDAP comparison
    $inactiveFileTime = $inactiveThreshold.ToFileTimeUtc()
    $passwordFileTime = $passwordAgeThreshold.ToFileTimeUtc()

    # Common properties for user queries
    $userProperties = @(
        'samaccountname', 'distinguishedname', 'useraccountcontrol',
        'lastlogontimestamp', 'pwdlastset', 'whencreated',
        'memberof', 'description'
    )

    # Common properties for computer queries
    $computerProperties = @(
        'samaccountname', 'distinguishedname', 'useraccountcontrol',
        'lastlogontimestamp', 'pwdlastset', 'whencreated',
        'operatingsystem', 'operatingsystemversion', 'description',
        'dnshostname'
    )

    # ── Helper: Convert LDAP user result to output hashtable ────────────
    function ConvertTo-UserObject {
        param([hashtable]$Obj)

        $uac = [int]($Obj['useraccountcontrol'] ?? 0)
        $memberOf = @()
        if ($Obj.ContainsKey('memberof')) {
            $raw = $Obj['memberof']
            $memberOf = if ($raw -is [array]) { @($raw) } else { @($raw) }
        }

        @{
            SamAccountName = $Obj['samaccountname'] ?? ''
            DN             = $Obj['distinguishedname'] ?? ''
            LastLogon      = $Obj['lastlogontimestamp']
            PwdLastSet     = $Obj['pwdlastset']
            WhenCreated    = if ($Obj.ContainsKey('whencreated')) { $Obj['whencreated'] } else { $null }
            MemberOf       = $memberOf
            Enabled        = ($uac -band 0x0002) -eq 0
            Description    = if ($Obj.ContainsKey('description')) { $Obj['description'] } else { '' }
        }
    }

    function ConvertTo-ComputerObject {
        param([hashtable]$Obj)

        $uac = [int]($Obj['useraccountcontrol'] ?? 0)

        @{
            SamAccountName   = $Obj['samaccountname'] ?? ''
            DN               = $Obj['distinguishedname'] ?? ''
            LastLogon        = $Obj['lastlogontimestamp']
            PwdLastSet       = $Obj['pwdlastset']
            WhenCreated      = if ($Obj.ContainsKey('whencreated')) { $Obj['whencreated'] } else { $null }
            OperatingSystem  = if ($Obj.ContainsKey('operatingsystem')) { $Obj['operatingsystem'] } else { '' }
            OSVersion        = if ($Obj.ContainsKey('operatingsystemversion')) { $Obj['operatingsystemversion'] } else { '' }
            DNSHostName      = if ($Obj.ContainsKey('dnshostname')) { $Obj['dnshostname'] } else { '' }
            Enabled          = ($uac -band 0x0002) -eq 0
            Description      = if ($Obj.ContainsKey('description')) { $Obj['description'] } else { '' }
        }
    }

    # ── 1. Total counts ─────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Counting domain objects'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        # Total users
        $totalUsers = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=person)(objectClass=user))' `
            -Properties @('distinguishedname')
        $result.TotalUsers = $totalUsers.Count

        # Total computers
        $totalComputers = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(objectCategory=computer)' `
            -Properties @('distinguishedname')
        $result.TotalComputers = $totalComputers.Count

        # Total disabled
        $totalDisabled = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(|(objectCategory=person)(objectCategory=computer))(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))' `
            -Properties @('distinguishedname')
        $result.TotalDisabled = $totalDisabled.Count

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Domain totals: $($result.TotalUsers) users, $($result.TotalComputers) computers, $($result.TotalDisabled) disabled"
        }
    } catch {
        Write-Warning "Failed to count domain objects: $_"
        $result.Errors['TotalCounts'] = $_.Exception.Message
    }

    # ── 2. Inactive users ───────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message "Finding users inactive for $InactiveDays+ days"
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        # Enabled users with lastLogonTimestamp older than threshold
        # The LDAP filter excludes disabled accounts (bit 0x2 NOT set)
        $inactiveUserResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$inactiveFileTime))" `
            -Properties $userProperties

        $inactiveUsers = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($user in $inactiveUserResults) {
            $inactiveUsers.Add((ConvertTo-UserObject -Obj $user))
        }

        # Also catch users who have NEVER logged in (no lastLogonTimestamp)
        $neverLoggedIn = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))' `
            -Properties $userProperties

        foreach ($user in $neverLoggedIn) {
            # Only include if account was created before the threshold
            $created = if ($user.ContainsKey('whencreated')) { $user['whencreated'] } else { $null }
            if ($null -ne $created -and $created -is [datetime] -and $created -lt $inactiveThreshold) {
                $inactiveUsers.Add((ConvertTo-UserObject -Obj $user))
            }
        }

        $result.InactiveUsers = @($inactiveUsers)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($inactiveUsers.Count) inactive user(s)"
        }
    } catch {
        Write-Warning "Failed to query inactive users: $_"
        $result.Errors['InactiveUsers'] = $_.Exception.Message
    }

    # ── 3. Inactive computers ───────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message "Finding computers inactive for $InactiveDays+ days"
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        $inactiveComputerResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(lastLogonTimestamp<=$inactiveFileTime))" `
            -Properties $computerProperties

        $inactiveComputers = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($comp in $inactiveComputerResults) {
            $inactiveComputers.Add((ConvertTo-ComputerObject -Obj $comp))
        }

        # Computers that have never checked in
        $neverCheckedIn = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))' `
            -Properties $computerProperties

        foreach ($comp in $neverCheckedIn) {
            $created = if ($comp.ContainsKey('whencreated')) { $comp['whencreated'] } else { $null }
            if ($null -ne $created -and $created -is [datetime] -and $created -lt $inactiveThreshold) {
                $inactiveComputers.Add((ConvertTo-ComputerObject -Obj $comp))
            }
        }

        $result.InactiveComputers = @($inactiveComputers)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($inactiveComputers.Count) inactive computer(s)"
        }
    } catch {
        Write-Warning "Failed to query inactive computers: $_"
        $result.Errors['InactiveComputers'] = $_.Exception.Message
    }

    # ── 4. Disabled accounts with group memberships ─────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Finding disabled accounts with group memberships'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        $disabledWithMemberships = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(|(objectCategory=person)(objectCategory=computer))(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(memberOf=*))' `
            -Properties @('samaccountname', 'distinguishedname', 'useraccountcontrol', 'memberof', 'objectcategory')

        $disabledWithGroups = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($obj in $disabledWithMemberships) {
            $memberOf = @()
            if ($obj.ContainsKey('memberof')) {
                $raw = $obj['memberof']
                $memberOf = if ($raw -is [array]) { @($raw) } else { @($raw) }
            }

            # Filter out Domain Users (everyone is a member) — check by CN
            $significantGroups = @($memberOf | Where-Object {
                $_ -notmatch '^CN=Domain Users,' -and
                $_ -notmatch '^CN=Domain Computers,'
            })

            if ($significantGroups.Count -gt 0) {
                $disabledWithGroups.Add(@{
                    SamAccountName = $obj['samaccountname'] ?? ''
                    DN             = $obj['distinguishedname'] ?? ''
                    GroupCount     = $significantGroups.Count
                    Groups         = $significantGroups
                    ObjectCategory = if ($obj.ContainsKey('objectcategory')) { $obj['objectcategory'] } else { '' }
                })
            }
        }

        $result.DisabledWithGroups = @($disabledWithGroups)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($disabledWithGroups.Count) disabled account(s) with group memberships"
        }
    } catch {
        Write-Warning "Failed to query disabled accounts with groups: $_"
        $result.Errors['DisabledWithGroups'] = $_.Exception.Message
    }

    # ── 5. Expired passwords (not disabled) ─────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message "Finding accounts with passwords older than $PasswordAgeDays days"
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        # Enabled users whose password was last set before the threshold
        # Exclude accounts with password-never-expires (0x10000)
        $oldPasswordResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(userAccountControl:1.2.840.113556.1.4.803:=65536))(pwdLastSet<=$passwordFileTime)(pwdLastSet>=1))" `
            -Properties $userProperties

        $expiredNotDisabled = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($user in $oldPasswordResults) {
            $expiredNotDisabled.Add((ConvertTo-UserObject -Obj $user))
        }

        $result.ExpiredNotDisabled = @($expiredNotDisabled)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($expiredNotDisabled.Count) account(s) with passwords older than $PasswordAgeDays days"
        }
    } catch {
        Write-Warning "Failed to query expired password accounts: $_"
        $result.Errors['ExpiredNotDisabled'] = $_.Exception.Message
    }

    # ── 6. Obsolete and unsupported OS computers ────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Identifying computers with obsolete operating systems'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        # Query all computers with an operatingSystem attribute
        $allOSComputers = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(&(objectCategory=computer)(operatingSystem=*))' `
            -Properties $computerProperties

        # Obsolete OS patterns (severely outdated - pre-2012 R2)
        $obsoletePatterns = @(
            'Windows XP'
            'Windows Vista'
            'Windows 7'
            'Windows 8'
            'Windows Server 2000'
            'Windows Server 2003'
            'Windows Server 2008'
            'Windows 2000'
            'Windows 2003'
        )

        # Unsupported OS patterns (end of extended support - 2012 R2 and older, includes all obsolete)
        $unsupportedPatterns = $obsoletePatterns + @(
            'Windows Server 2012'
            'Windows 8\.1'
        )

        $obsoleteComputers = [System.Collections.Generic.List[hashtable]]::new()
        $unsupportedComputers = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($comp in $allOSComputers) {
            $os = if ($comp.ContainsKey('operatingsystem')) { $comp['operatingsystem'] } else { '' }
            if ([string]::IsNullOrWhiteSpace($os)) { continue }

            $compObj = ConvertTo-ComputerObject -Obj $comp

            # Check obsolete (worst offenders)
            $isObsolete = $false
            foreach ($pattern in $obsoletePatterns) {
                if ($os -match $pattern) {
                    $isObsolete = $true
                    break
                }
            }

            # Check unsupported (includes obsolete + 2012/2012R2 + Windows 8.1)
            $isUnsupported = $false
            foreach ($pattern in $unsupportedPatterns) {
                if ($os -match $pattern) {
                    $isUnsupported = $true
                    break
                }
            }

            if ($isObsolete) {
                $obsoleteComputers.Add($compObj)
            }
            if ($isUnsupported) {
                $unsupportedComputers.Add($compObj)
            }
        }

        $result.ObsoleteOSComputers = @($obsoleteComputers)
        $result.UnsupportedOSComputers = @($unsupportedComputers)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($obsoleteComputers.Count) obsolete OS, $($unsupportedComputers.Count) unsupported OS computer(s)"
        }
    } catch {
        Write-Warning "Failed to query OS information: $_"
        $result.Errors['OSComputers'] = $_.Exception.Message
    }

    # ── 7. Orphaned Foreign Security Principals ─────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Checking for orphaned foreign security principals'
    }

    try {
        $fspDN = "CN=ForeignSecurityPrincipals,$domainDN"
        $fspRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $fspDN
        $lookupRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        $fspResults = Invoke-LdapQuery -SearchRoot $fspRoot `
            -Filter '(objectClass=foreignSecurityPrincipal)' `
            -Properties @('cn', 'distinguishedName', 'objectSid') `
            -Scope OneLevel

        $orphanedFSPs = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($fsp in $fspResults) {
            $sid = $fsp['cn'] ?? ''
            if ([string]::IsNullOrWhiteSpace($sid)) { continue }

            # Try to resolve the SID
            $resolved = Resolve-ADSid -SidString $sid -SearchRoot $lookupRoot

            # If the resolved name is still the SID string, it is orphaned
            if ($resolved -eq $sid) {
                $orphanedFSPs.Add(@{
                    SID  = $sid
                    DN   = $fsp['distinguishedname'] ?? ''
                })
            }
        }

        $result.OrphanedFSPs = @($orphanedFSPs)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($orphanedFSPs.Count) orphaned FSP(s) out of $($fspResults.Count) total"
        }
    } catch {
        Write-Verbose "Failed to check foreign security principals: $_"
        $result.Errors['OrphanedFSPs'] = $_.Exception.Message
    }

    # ── 8. Orphaned SID History ─────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Checking for orphaned SID history entries'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN
        $lookupRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        $sidHistoryResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(sIDHistory=*)' `
            -Properties @('samaccountname', 'distinguishedname', 'sidhistory', 'objectclass')

        $orphanedSIDHistory = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($obj in $sidHistoryResults) {
            $sidHistoryValues = @()
            if ($obj.ContainsKey('sidhistory')) {
                $raw = $obj['sidhistory']
                $sidHistoryValues = if ($raw -is [array]) { @($raw) } else { @($raw) }
            }

            $orphanedEntries = [System.Collections.Generic.List[string]]::new()
            foreach ($sidValue in $sidHistoryValues) {
                # SID may already be a string from Convert-LdapValue
                $sidString = if ($sidValue -is [string]) { $sidValue } else { $sidValue.ToString() }

                $resolved = Resolve-ADSid -SidString $sidString -SearchRoot $lookupRoot
                if ($resolved -eq $sidString) {
                    $orphanedEntries.Add($sidString)
                }
            }

            if ($orphanedEntries.Count -gt 0) {
                $orphanedSIDHistory.Add(@{
                    SamAccountName  = $obj['samaccountname'] ?? ''
                    DN              = $obj['distinguishedname'] ?? ''
                    OrphanedSIDs    = @($orphanedEntries)
                    TotalSIDHistory = $sidHistoryValues.Count
                })
            }
        }

        $result.OrphanedSIDHistory = @($orphanedSIDHistory)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($orphanedSIDHistory.Count) object(s) with orphaned SID history"
        }
    } catch {
        Write-Warning "Failed to check SID history: $_"
        $result.Errors['OrphanedSIDHistory'] = $_.Exception.Message
    }

    # ── 9. Abandoned OUs ────────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Checking for abandoned (empty) OUs'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        $allOUs = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(objectClass=organizationalUnit)' `
            -Properties @('distinguishedName', 'ou', 'description', 'whenCreated')

        $abandonedOUs = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($ou in $allOUs) {
            $ouDN = $ou['distinguishedname'] ?? ''
            if ([string]::IsNullOrWhiteSpace($ouDN)) { continue }

            try {
                $ouRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $ouDN
                $childResults = Invoke-LdapQuery -SearchRoot $ouRoot `
                    -Filter '(objectClass=*)' `
                    -Properties @('distinguishedname') `
                    -Scope OneLevel `
                    -SizeLimit 1

                if ($childResults.Count -eq 0) {
                    $abandonedOUs.Add(@{
                        DN          = $ouDN
                        Name        = if ($ou.ContainsKey('ou')) { $ou['ou'] } else { '' }
                        Description = if ($ou.ContainsKey('description')) { $ou['description'] } else { '' }
                        WhenCreated = if ($ou.ContainsKey('whencreated')) { $ou['whencreated'] } else { $null }
                    })
                }
            } catch {
                Write-Verbose "Failed to check children of OU $ouDN`: $_"
            }
        }

        $result.AbandonedOUs = @($abandonedOUs)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($abandonedOUs.Count) abandoned OU(s) out of $($allOUs.Count) total"
        }
    } catch {
        Write-Warning "Failed to query OUs: $_"
        $result.Errors['AbandonedOUs'] = $_.Exception.Message
    }

    # ── 10. Printer objects ─────────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Enumerating printer objects in AD'
    }

    try {
        $searchRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $domainDN

        $printerResults = Invoke-LdapQuery -SearchRoot $searchRoot `
            -Filter '(objectClass=printQueue)' `
            -Properties @(
                'cn', 'distinguishedName', 'printerName',
                'serverName', 'uNCName', 'portName',
                'driverName', 'whenCreated'
            )

        $printerObjects = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($printer in $printerResults) {
            $printerObjects.Add(@{
                Name        = $printer['cn'] ?? ''
                DN          = $printer['distinguishedname'] ?? ''
                PrinterName = if ($printer.ContainsKey('printername')) { $printer['printername'] } else { '' }
                ServerName  = if ($printer.ContainsKey('servername')) { $printer['servername'] } else { '' }
                UNCName     = if ($printer.ContainsKey('uncname')) { $printer['uncname'] } else { '' }
                PortName    = if ($printer.ContainsKey('portname')) { $printer['portname'] } else { '' }
                DriverName  = if ($printer.ContainsKey('drivername')) { $printer['drivername'] } else { '' }
                WhenCreated = if ($printer.ContainsKey('whencreated')) { $printer['whencreated'] } else { $null }
            })
        }

        $result.PrinterObjects = @($printerObjects)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($printerObjects.Count) printer object(s)"
        }
    } catch {
        Write-Warning "Failed to enumerate printer objects: $_"
        $result.Errors['PrinterObjects'] = $_.Exception.Message
    }

    # ── 11. Stale DNS records ───────────────────────────────────────────
    if (-not $Quiet) {
        Write-ProgressLine -Phase RECON -Message 'Checking for stale DNS records'
    }

    try {
        $domainName = ($domainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()

        # Try AD-integrated DNS zone containers
        $dnsContainers = @(
            "DC=$domainName,CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"
            "CN=MicrosoftDNS,DC=DomainDnsZones,$domainDN"
        )

        $staleDNSRecords = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($dnsContainer in $dnsContainers) {
            try {
                $dnsRoot = New-LdapSearchRoot -Connection $Connection -SearchBase $dnsContainer

                $dnsRecords = Invoke-LdapQuery -SearchRoot $dnsRoot `
                    -Filter '(&(objectClass=dnsNode)(!(dc=@))(!(dc=_*)))' `
                    -Properties @('dc', 'distinguishedName', 'dnsRecord', 'whenChanged', 'dNSTombstoned') `
                    -Scope Subtree

                foreach ($record in $dnsRecords) {
                    $recordName = if ($record.ContainsKey('dc')) { $record['dc'] } else { '' }
                    $whenChanged = if ($record.ContainsKey('whenchanged')) { $record['whenchanged'] } else { $null }
                    $tombstoned = if ($record.ContainsKey('dnstombstoned')) { $record['dnstombstoned'] } else { $false }

                    # Stale if not changed within InactiveDays or tombstoned
                    $isStale = $false
                    if ($tombstoned -eq $true) {
                        $isStale = $true
                    } elseif ($null -ne $whenChanged -and $whenChanged -is [datetime]) {
                        $isStale = $whenChanged -lt $inactiveThreshold
                    }

                    if ($isStale) {
                        $staleDNSRecords.Add(@{
                            Name        = $recordName
                            DN          = $record['distinguishedname'] ?? ''
                            WhenChanged = $whenChanged
                            Tombstoned  = [bool]$tombstoned
                            Container   = $dnsContainer
                        })
                    }
                }

                # If we successfully queried one container, break out
                if ($dnsRecords.Count -ge 0) { break }
            } catch {
                Write-Verbose "DNS container not accessible: $dnsContainer - $_"
                continue
            }
        }

        $result.StaleDNSRecords = @($staleDNSRecords)

        if (-not $Quiet) {
            Write-ProgressLine -Phase RECON -Message "Found $($staleDNSRecords.Count) stale DNS record(s)"
        }
    } catch {
        Write-Verbose "Failed to check stale DNS records: $_"
        $result.Errors['StaleDNSRecords'] = $_.Exception.Message
    }

    # ── Summary ─────────────────────────────────────────────────────────
    if (-not $Quiet) {
        $summary = "Stale object analysis complete: " +
                   "$($result.InactiveUsers.Count) inactive users, " +
                   "$($result.InactiveComputers.Count) inactive computers, " +
                   "$($result.ObsoleteOSComputers.Count) obsolete OS, " +
                   "$($result.AbandonedOUs.Count) empty OUs"
        if ($result.Errors.Count -gt 0) {
            $summary += " ($($result.Errors.Count) error(s))"
        }
        Write-ProgressLine -Phase RECON -Message $summary
    }

    return $result
}
