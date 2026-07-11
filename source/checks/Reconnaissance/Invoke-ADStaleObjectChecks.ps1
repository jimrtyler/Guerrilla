# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADStaleObjectChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = $null
    try {
        $checkDefs = Get-AuditCategoryDefinitions -Category 'ADStaleObjectChecks'
    } catch {
        Write-Verbose "ADStaleObjectChecks definitions not found: $_"
        return @()
    }

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

# -- ADSTALE-001: Inactive User Accounts -------------------------------------
function Test-ReconADSTALE001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $inactiveUsers = @($stale.InactiveUsers)
    if ($inactiveUsers.Count -eq 0 -or ($inactiveUsers.Count -eq 1 -and $null -eq $inactiveUsers[0])) {
        $totalUsers = if ($stale.ContainsKey('TotalUsers')) { $stale.TotalUsers } else { 'unknown' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "No inactive user accounts found ($totalUsers total user(s))" `
            -Details @{ TotalUsers = $totalUsers }
    }

    # Build sample list (first 10)
    $sampleList = @($inactiveUsers | Select-Object -First 10 | ForEach-Object {
        $_.SamAccountName
    })
    $sampleText = $sampleList -join ', '
    if ($inactiveUsers.Count -gt 10) { $sampleText += '...' }

    $totalUsers = if ($stale.ContainsKey('TotalUsers')) { $stale.TotalUsers } else { 0 }
    $currentValue = "$($inactiveUsers.Count) inactive user account(s) found: $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            InactiveCount = $inactiveUsers.Count
            TotalUsers    = $totalUsers
            SampleAccounts = @($inactiveUsers | Select-Object -First 20 | ForEach-Object {
                @{
                    SamAccountName = $_.SamAccountName
                    DN             = $_.DN
                    LastLogon      = $_.LastLogon
                    Enabled        = $_.Enabled
                    MemberOf       = @($_.MemberOf).Count
                }
            })
        }
}

# -- ADSTALE-002: Inactive Computer Accounts ---------------------------------
function Test-ReconADSTALE002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $inactiveComputers = @($stale.InactiveComputers)
    if ($inactiveComputers.Count -eq 0 -or ($inactiveComputers.Count -eq 1 -and $null -eq $inactiveComputers[0])) {
        $totalComputers = if ($stale.ContainsKey('TotalComputers')) { $stale.TotalComputers } else { 'unknown' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "No inactive computer accounts found ($totalComputers total computer(s))" `
            -Details @{ TotalComputers = $totalComputers }
    }

    $sampleList = @($inactiveComputers | Select-Object -First 10 | ForEach-Object {
        $name = if ($_.SamAccountName) { $_.SamAccountName } else { $_.Name }
        $os = if ($_.OperatingSystem) { " ($($_.OperatingSystem))" } else { '' }
        "$name$os"
    })
    $sampleText = $sampleList -join ', '
    if ($inactiveComputers.Count -gt 10) { $sampleText += '...' }

    $totalComputers = if ($stale.ContainsKey('TotalComputers')) { $stale.TotalComputers } else { 0 }
    $currentValue = "$($inactiveComputers.Count) inactive computer account(s) found: $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            InactiveCount  = $inactiveComputers.Count
            TotalComputers = $totalComputers
            SampleAccounts = @($inactiveComputers | Select-Object -First 20 | ForEach-Object {
                @{
                    SamAccountName  = if ($_.SamAccountName) { $_.SamAccountName } else { $_.Name }
                    DN              = $_.DN
                    LastLogon       = $_.LastLogon
                    OperatingSystem = $_.OperatingSystem
                    Enabled         = $_.Enabled
                }
            })
        }
}

# -- ADSTALE-003: Disabled Accounts with Group Memberships -------------------
function Test-ReconADSTALE003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $disabledWithGroups = @($stale.DisabledWithGroups)
    if ($disabledWithGroups.Count -eq 0 -or ($disabledWithGroups.Count -eq 1 -and $null -eq $disabledWithGroups[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No disabled accounts with residual group memberships found' `
            -Details @{ TotalDisabled = if ($stale.ContainsKey('TotalDisabled')) { $stale.TotalDisabled } else { 0 } }
    }

    # Identify accounts with the most group memberships
    $sorted = @($disabledWithGroups | Sort-Object { $_.GroupCount } -Descending)
    $sampleList = @($sorted | Select-Object -First 10 | ForEach-Object {
        "$($_.SamAccountName) ($($_.GroupCount) group(s))"
    })
    $sampleText = $sampleList -join ', '
    if ($disabledWithGroups.Count -gt 10) { $sampleText += '...' }

    $totalGroups = 0
    foreach ($acct in $disabledWithGroups) { $totalGroups += [int]$acct.GroupCount }

    $currentValue = "$($disabledWithGroups.Count) disabled account(s) retain $totalGroups group membership(s): $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            AffectedCount    = $disabledWithGroups.Count
            TotalMemberships = $totalGroups
            SampleAccounts   = @($sorted | Select-Object -First 20 | ForEach-Object {
                @{
                    SamAccountName = $_.SamAccountName
                    DN             = $_.DN
                    GroupCount     = $_.GroupCount
                    Groups         = @($_.Groups | Select-Object -First 5)
                }
            })
        }
}

# -- ADSTALE-004: Expired Passwords Not Disabled -----------------------------
function Test-ReconADSTALE004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $expiredNotDisabled = @($stale.ExpiredNotDisabled)
    if ($expiredNotDisabled.Count -eq 0 -or ($expiredNotDisabled.Count -eq 1 -and $null -eq $expiredNotDisabled[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No enabled accounts with expired passwords found' `
            -Details @{ TotalUsers = if ($stale.ContainsKey('TotalUsers')) { $stale.TotalUsers } else { 0 } }
    }

    $sampleList = @($expiredNotDisabled | Select-Object -First 10 | ForEach-Object {
        $_.SamAccountName
    })
    $sampleText = $sampleList -join ', '
    if ($expiredNotDisabled.Count -gt 10) { $sampleText += '...' }

    $currentValue = "$($expiredNotDisabled.Count) enabled account(s) have expired passwords: $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            AffectedCount  = $expiredNotDisabled.Count
            TotalUsers     = if ($stale.ContainsKey('TotalUsers')) { $stale.TotalUsers } else { 0 }
            SampleAccounts = @($expiredNotDisabled | Select-Object -First 20 | ForEach-Object {
                @{
                    SamAccountName = $_.SamAccountName
                    DN             = $_.DN
                    PwdLastSet     = $_.PwdLastSet
                    Enabled        = $_.Enabled
                }
            })
        }
}

# -- ADSTALE-005: Obsolete OS Computers -------------------------------------
function Test-ReconADSTALE005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $obsoleteComputers = @($stale.ObsoleteOSComputers)
    if ($obsoleteComputers.Count -eq 0 -or ($obsoleteComputers.Count -eq 1 -and $null -eq $obsoleteComputers[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No computers running obsolete operating systems found' `
            -Details @{ TotalComputers = if ($stale.ContainsKey('TotalComputers')) { $stale.TotalComputers } else { 0 } }
    }

    # Group by OS
    $osCounts = @{}
    foreach ($comp in $obsoleteComputers) {
        $os = if ($comp.OperatingSystem) { $comp.OperatingSystem } else { 'Unknown' }
        if (-not $osCounts.ContainsKey($os)) { $osCounts[$os] = 0 }
        $osCounts[$os]++
    }

    $osBreakdown = @($osCounts.GetEnumerator() | Sort-Object Value -Descending |
        ForEach-Object { "$($_.Value) x $($_.Key)" })

    $currentValue = "$($obsoleteComputers.Count) computer(s) running obsolete operating systems: $($osBreakdown -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            ObsoleteCount  = $obsoleteComputers.Count
            TotalComputers = if ($stale.ContainsKey('TotalComputers')) { $stale.TotalComputers } else { 0 }
            OSBreakdown    = $osCounts
            SampleComputers = @($obsoleteComputers | Select-Object -First 20 | ForEach-Object {
                @{
                    SamAccountName  = if ($_.SamAccountName) { $_.SamAccountName } else { $_.Name }
                    DN              = $_.DN
                    OperatingSystem = $_.OperatingSystem
                    OSVersion       = $_.OSVersion
                    LastLogon       = $_.LastLogon
                    Enabled         = $_.Enabled
                }
            })
        }
}

# -- ADSTALE-006: Unsupported OS Versions ------------------------------------
function Test-ReconADSTALE006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $unsupportedComputers = @($stale.UnsupportedOSComputers)
    if ($unsupportedComputers.Count -eq 0 -or ($unsupportedComputers.Count -eq 1 -and $null -eq $unsupportedComputers[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No computers running unsupported operating systems found' `
            -Details @{ TotalComputers = if ($stale.ContainsKey('TotalComputers')) { $stale.TotalComputers } else { 0 } }
    }

    # Group by OS
    $osCounts = @{}
    foreach ($comp in $unsupportedComputers) {
        $os = if ($comp.OperatingSystem) { $comp.OperatingSystem } else { 'Unknown' }
        if (-not $osCounts.ContainsKey($os)) { $osCounts[$os] = 0 }
        $osCounts[$os]++
    }

    $osBreakdown = @($osCounts.GetEnumerator() | Sort-Object Value -Descending |
        ForEach-Object { "$($_.Value) x $($_.Key)" })

    $currentValue = "$($unsupportedComputers.Count) computer(s) running unsupported operating systems: $($osBreakdown -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            UnsupportedCount = $unsupportedComputers.Count
            TotalComputers   = if ($stale.ContainsKey('TotalComputers')) { $stale.TotalComputers } else { 0 }
            OSBreakdown      = $osCounts
            SampleComputers  = @($unsupportedComputers | Select-Object -First 20 | ForEach-Object {
                @{
                    SamAccountName  = if ($_.SamAccountName) { $_.SamAccountName } else { $_.Name }
                    DN              = $_.DN
                    OperatingSystem = $_.OperatingSystem
                    OSVersion       = $_.OSVersion
                    LastLogon       = $_.LastLogon
                    Enabled         = $_.Enabled
                }
            })
        }
}

# -- ADSTALE-007: Orphaned Foreign Security Principals -----------------------
function Test-ReconADSTALE007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $orphanedFSPs = @($stale.OrphanedFSPs)
    if ($orphanedFSPs.Count -eq 0 -or ($orphanedFSPs.Count -eq 1 -and $null -eq $orphanedFSPs[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No orphaned Foreign Security Principals found'
    }

    $sampleList = @($orphanedFSPs | Select-Object -First 10 | ForEach-Object { $_.SID })
    $sampleText = $sampleList -join ', '
    if ($orphanedFSPs.Count -gt 10) { $sampleText += '...' }

    $currentValue = "$($orphanedFSPs.Count) orphaned Foreign Security Principal(s) with unresolvable SIDs: $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            OrphanedCount = $orphanedFSPs.Count
            SampleFSPs    = @($orphanedFSPs | Select-Object -First 20 | ForEach-Object {
                @{
                    SID = $_.SID
                    DN  = $_.DN
                }
            })
        }
}

# -- ADSTALE-008: Orphaned SID History ----------------------------------------
function Test-ReconADSTALE008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $orphanedSIDHistory = @($stale.OrphanedSIDHistory)
    if ($orphanedSIDHistory.Count -eq 0 -or ($orphanedSIDHistory.Count -eq 1 -and $null -eq $orphanedSIDHistory[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No orphaned SID History entries found'
    }

    $totalOrphanedSIDs = 0
    foreach ($entry in $orphanedSIDHistory) {
        $totalOrphanedSIDs += @($entry.OrphanedSIDs).Count
    }

    $sampleList = @($orphanedSIDHistory | Select-Object -First 10 | ForEach-Object {
        "$($_.SamAccountName) ($(@($_.OrphanedSIDs).Count) orphaned SID(s))"
    })
    $sampleText = $sampleList -join ', '
    if ($orphanedSIDHistory.Count -gt 10) { $sampleText += '...' }

    $currentValue = "$($orphanedSIDHistory.Count) object(s) have $totalOrphanedSIDs orphaned SID History entries: $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            AffectedObjects  = $orphanedSIDHistory.Count
            TotalOrphanedSIDs = $totalOrphanedSIDs
            SampleEntries    = @($orphanedSIDHistory | Select-Object -First 20 | ForEach-Object {
                @{
                    SamAccountName  = $_.SamAccountName
                    DN              = $_.DN
                    OrphanedSIDs    = @($_.OrphanedSIDs)
                    TotalSIDHistory = $_.TotalSIDHistory
                }
            })
        }
}

# -- ADSTALE-009: Abandoned OUs -----------------------------------------------
function Test-ReconADSTALE009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $abandonedOUs = @($stale.AbandonedOUs)
    if ($abandonedOUs.Count -eq 0 -or ($abandonedOUs.Count -eq 1 -and $null -eq $abandonedOUs[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No abandoned (empty) OUs found'
    }

    $sampleList = @($abandonedOUs | Select-Object -First 10 | ForEach-Object {
        if ($_.Name) { $_.Name } else { $_.DN }
    })
    $sampleText = $sampleList -join ', '
    if ($abandonedOUs.Count -gt 10) { $sampleText += '...' }

    $currentValue = "$($abandonedOUs.Count) empty OU(s) found: $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            AbandonedCount = $abandonedOUs.Count
            SampleOUs      = @($abandonedOUs | Select-Object -First 20 | ForEach-Object {
                @{
                    DN          = $_.DN
                    Name        = $_.Name
                    Description = $_.Description
                    WhenCreated = $_.WhenCreated
                }
            })
        }
}

# -- ADSTALE-010: Printer Objects ---------------------------------------------
function Test-ReconADSTALE010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $printerObjects = @($stale.PrinterObjects)
    if ($printerObjects.Count -eq 0 -or ($printerObjects.Count -eq 1 -and $null -eq $printerObjects[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No printer objects published in Active Directory'
    }

    # Group by server
    $serverCounts = @{}
    foreach ($printer in $printerObjects) {
        $server = if ($printer.ServerName) { $printer.ServerName } else { '(unknown)' }
        if (-not $serverCounts.ContainsKey($server)) { $serverCounts[$server] = 0 }
        $serverCounts[$server]++
    }

    $serverBreakdown = @($serverCounts.GetEnumerator() | Sort-Object Value -Descending |
        ForEach-Object { "$($_.Value) on $($_.Key)" })

    $currentValue = "$($printerObjects.Count) printer object(s) published in AD: $($serverBreakdown -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            PrinterCount    = $printerObjects.Count
            ServerBreakdown = $serverCounts
            SamplePrinters  = @($printerObjects | Select-Object -First 20 | ForEach-Object {
                @{
                    Name        = $_.Name
                    DN          = $_.DN
                    ServerName  = $_.ServerName
                    UNCName     = $_.UNCName
                    DriverName  = $_.DriverName
                    WhenCreated = $_.WhenCreated
                }
            })
        }
}

# -- ADSTALE-011: DNS Record Staleness ----------------------------------------
function Test-ReconADSTALE011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'StaleObjects' -Subject 'stale objects'
    if ($na) { return $na }

    $stale = $AuditData.StaleObjects
    if (-not $stale) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Stale object data not available'
    }

    $staleDNS = @($stale.StaleDNSRecords)
    if ($staleDNS.Count -eq 0 -or ($staleDNS.Count -eq 1 -and $null -eq $staleDNS[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No stale DNS records found in AD-integrated zones'
    }

    $tombstonedCount = @($staleDNS | Where-Object { $_.Tombstoned -eq $true }).Count

    $sampleList = @($staleDNS | Select-Object -First 10 | ForEach-Object {
        $_.Name
    })
    $sampleText = $sampleList -join ', '
    if ($staleDNS.Count -gt 10) { $sampleText += '...' }

    $currentValue = "$($staleDNS.Count) stale DNS record(s) found"
    if ($tombstonedCount -gt 0) {
        $currentValue += " ($tombstonedCount tombstoned)"
    }
    $currentValue += ": $sampleText"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            StaleCount      = $staleDNS.Count
            TombstonedCount = $tombstonedCount
            SampleRecords   = @($staleDNS | Select-Object -First 20 | ForEach-Object {
                @{
                    Name        = $_.Name
                    DN          = $_.DN
                    WhenChanged = $_.WhenChanged
                    Tombstoned  = $_.Tombstoned
                }
            })
        }
}
