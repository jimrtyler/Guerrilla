# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADGroupPolicyChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADGroupPolicyChecks'
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

# ── ADGPO-001: GPO Inventory with Link Status ────────────────────────────
function Test-ReconADGPO001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData -or $null -eq $gpoData.GPOs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpos = @($gpoData.GPOs)
    if ($gpos.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No GPOs found in the domain' `
            -Details @{ TotalGPOs = 0 }
    }

    $linkedCount = @($gpos | Where-Object { $_.IsLinked -eq $true }).Count
    $unlinkedCount = @($gpos | Where-Object { $_.IsLinked -ne $true }).Count
    $disabledCount = @($gpos | Where-Object { $_.Flags -eq 3 }).Count
    $emptyCount = @($gpos | Where-Object { $_.IsEmpty -eq $true }).Count

    $currentValue = "$($gpos.Count) GPO(s) total: $linkedCount linked, $unlinkedCount unlinked, $disabledCount fully disabled, $emptyCount empty"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            TotalGPOs     = $gpos.Count
            LinkedCount   = $linkedCount
            UnlinkedCount = $unlinkedCount
            DisabledCount = $disabledCount
            EmptyCount    = $emptyCount
            GPOList       = @($gpos | ForEach-Object {
                @{
                    DisplayName     = $_.DisplayName
                    GUID            = $_.GUID
                    IsLinked        = $_.IsLinked
                    Flags           = $_.Flags
                    FlagDescription = $_.FlagDescription
                    IsEmpty         = $_.IsEmpty
                }
            })
        }
}

# ── ADGPO-002: Empty GPOs ─────────────────────────────────────────────────
function Test-ReconADGPO002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData -or -not $gpoData.GPOs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpos = @($gpoData.GPOs)

    # Empty GPOs: Flags=3 (both disabled) OR IsEmpty=$true (no SYSVOL content beyond GPT.INI)
    $emptyGPOs = @($gpos | Where-Object {
        $_.IsEmpty -eq $true -or $_.Flags -eq 3
    })

    if ($emptyGPOs.Count -gt 0) {
        $names = @($emptyGPOs | ForEach-Object { $_.DisplayName })
        $currentValue = "$($emptyGPOs.Count) empty or fully disabled GPO(s) found: $($names -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                EmptyGPOCount = $emptyGPOs.Count
                EmptyGPOs     = @($emptyGPOs | ForEach-Object {
                    @{
                        DisplayName     = $_.DisplayName
                        GUID            = $_.GUID
                        Flags           = $_.Flags
                        FlagDescription = $_.FlagDescription
                        IsEmpty         = $_.IsEmpty
                    }
                })
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No empty GPOs found among $($gpos.Count) GPO(s)" `
        -Details @{ TotalGPOs = $gpos.Count }
}

# ── ADGPO-003: Unlinked GPOs ──────────────────────────────────────────────
function Test-ReconADGPO003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData -or -not $gpoData.GPOs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpos = @($gpoData.GPOs)
    $unlinkedGPOs = @($gpos | Where-Object { $_.IsLinked -ne $true })

    if ($unlinkedGPOs.Count -gt 0) {
        $names = @($unlinkedGPOs | ForEach-Object { $_.DisplayName })
        $currentValue = "$($unlinkedGPOs.Count) unlinked GPO(s) found: $($names -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                UnlinkedCount = $unlinkedGPOs.Count
                UnlinkedGPOs  = @($unlinkedGPOs | ForEach-Object {
                    @{
                        DisplayName = $_.DisplayName
                        GUID        = $_.GUID
                        WhenChanged = $_.WhenChanged
                    }
                })
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($gpos.Count) GPO(s) are linked to at least one container" `
        -Details @{ TotalGPOs = $gpos.Count }
}

# ── ADGPO-004: Disabled GPOs with Content ─────────────────────────────────
function Test-ReconADGPO004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData -or -not $gpoData.GPOs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpos = @($gpoData.GPOs)

    # GPOs that have some section disabled (Flags 1, 2, or 3) but are not empty
    $disabledWithContent = @($gpos | Where-Object {
        $_.Flags -gt 0 -and $_.IsEmpty -ne $true
    })

    if ($disabledWithContent.Count -gt 0) {
        $names = @($disabledWithContent | ForEach-Object {
            "$($_.DisplayName) ($($_.FlagDescription))"
        })
        $currentValue = "$($disabledWithContent.Count) GPO(s) have disabled sections but contain settings: $($names -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                Count = $disabledWithContent.Count
                GPOs  = @($disabledWithContent | ForEach-Object {
                    @{
                        DisplayName     = $_.DisplayName
                        GUID            = $_.GUID
                        Flags           = $_.Flags
                        FlagDescription = $_.FlagDescription
                    }
                })
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No GPOs with disabled sections containing active settings" `
        -Details @{ TotalGPOs = $gpos.Count }
}

# ── ADGPO-005: Duplicated GPOs ────────────────────────────────────────────
function Test-ReconADGPO005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData -or -not $gpoData.GPOs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpos = @($gpoData.GPOs)
    if ($gpos.Count -lt 2) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Fewer than 2 GPOs; no duplicates possible' `
            -Details @{ TotalGPOs = $gpos.Count }
    }

    # Simplified duplicate detection: look for GPOs with similar naming patterns
    # (e.g., "Policy - Copy", "Policy (2)", "Policy_old", "Policy_backup")
    $potentialDuplicates = [System.Collections.Generic.List[hashtable]]::new()
    $duplicatePatterns = @('[\s_-]*(copy|backup|old|v\d|test|temp|clone|dup)', '\s*\(\d+\)\s*$')

    foreach ($gpo in $gpos) {
        $name = $gpo.DisplayName
        if (-not $name) { continue }

        foreach ($pattern in $duplicatePatterns) {
            if ($name -match $pattern) {
                # Find what the base name would be
                $baseName = $name -replace $pattern, ''
                $baseName = $baseName.Trim()

                # Check if a GPO with the base name exists
                $baseGPO = $gpos | Where-Object {
                    $_.DisplayName -eq $baseName -and $_.GUID -ne $gpo.GUID
                }
                if ($baseGPO) {
                    $potentialDuplicates.Add(@{
                        DisplayName = $name
                        GUID        = $gpo.GUID
                        BaseName    = $baseName
                        Pattern     = $pattern
                    })
                }
                break
            }
        }
    }

    if ($potentialDuplicates.Count -gt 0) {
        $names = @($potentialDuplicates | ForEach-Object { $_.DisplayName })
        $currentValue = "$($potentialDuplicates.Count) potentially duplicated GPO(s) detected: $($names -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                PotentialDuplicates = @($potentialDuplicates)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No obvious duplicate GPOs detected among $($gpos.Count) GPO(s)" `
        -Details @{ TotalGPOs = $gpos.Count }
}

# ── ADGPO-006: GPOs with Broken Links ────────────────────────────────────
function Test-ReconADGPO006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpoLinks = $gpoData.GPOLinks
    if (-not $gpoLinks -or $gpoLinks.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'GPO link data not available'
    }

    $gpos = @($gpoData.GPOs)
    # Build a set of known GPO DNs (lowercase for comparison)
    $knownGPODNs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($gpo in $gpos) {
        if ($gpo.DN) { [void]$knownGPODNs.Add($gpo.DN) }
    }

    $brokenLinks = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($containerDN in $gpoLinks.Keys) {
        $links = @($gpoLinks[$containerDN])
        foreach ($link in $links) {
            if ($link.GPODN -and -not $knownGPODNs.Contains($link.GPODN)) {
                $brokenLinks.Add(@{
                    ContainerDN = $containerDN
                    GPODN       = $link.GPODN
                    IsEnabled    = $link.IsEnabled
                })
            }
        }
    }

    if ($brokenLinks.Count -gt 0) {
        $currentValue = "$($brokenLinks.Count) broken GPO link(s) found referencing non-existent GPOs"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                BrokenLinkCount = $brokenLinks.Count
                BrokenLinks     = @($brokenLinks)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'All GPO links reference valid GPOs' `
        -Details @{ TotalLinksChecked = ($gpoLinks.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum }
}

# ── ADGPO-007: GPO Permission Inconsistencies ────────────────────────────
function Test-ReconADGPO007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpoPerms = $gpoData.GPOPermissions
    if (-not $gpoPerms -or $gpoPerms.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'GPO permission data not available'
    }

    # Well-known admin SIDs and names that are expected to have edit rights
    $trustedEditors = @(
        'Domain Admins', 'Enterprise Admins', 'SYSTEM', 'ENTERPRISE DOMAIN CONTROLLERS',
        'S-1-5-18', 'S-1-5-9'
    )

    $issues = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $gpoPerms.Keys) {
        $perm = $gpoPerms[$gpoName]
        $canEdit = @($perm.CanEdit)

        foreach ($editor in $canEdit) {
            $isTrusted = $false
            foreach ($trusted in $trustedEditors) {
                if ($editor -eq $trusted -or $editor -match "^$([regex]::Escape($trusted))\\b") {
                    $isTrusted = $true
                    break
                }
            }

            if (-not $isTrusted -and $editor -notmatch '\bAdmins?\b') {
                $issues.Add(@{
                    GPOName    = $gpoName
                    Principal  = $editor
                    Permission = 'Edit'
                })
            }
        }
    }

    if ($issues.Count -gt 0) {
        $summary = @($issues | ForEach-Object { "$($_.Principal) can edit '$($_.GPOName)'" })
        $displaySummary = if ($summary.Count -le 5) { $summary -join '; ' }
                          else { ($summary | Select-Object -First 5) -join '; ' + " and $($summary.Count - 5) more" }

        $currentValue = "$($issues.Count) non-admin principal(s) with GPO edit permissions: $displaySummary"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                IssueCount = $issues.Count
                Issues     = @($issues)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "GPO edit permissions are restricted to expected admin principals across $($gpoPerms.Count) GPO(s)" `
        -Details @{ GPOsChecked = $gpoPerms.Count }
}

# ── ADGPO-008: GPOs Not Applied Due to WMI Filters ──────────────────────
function Test-ReconADGPO008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData -or -not $gpoData.GPOs) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $wmiFilters = @($gpoData.WMIFilters)
    if ($wmiFilters.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No WMI filters are configured in the domain' `
            -Details @{ WMIFilterCount = 0 }
    }

    # Identify GPOs that reference WMI filters by checking GPO properties
    # The GPO objects from the collector do not have a direct WMIFilter field,
    # but WMI filters being present is itself worth noting
    # WMI filters can restrict application; report all GPOs that have linked ones
    # Since the data model may not directly link GPO->WMI, report the filters that exist
    $currentValue = "$($wmiFilters.Count) WMI filter(s) exist in the domain that may restrict GPO application. Review to ensure security-critical GPOs are not blocked"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            WMIFilterCount = $wmiFilters.Count
            WMIFilters     = @($wmiFilters | ForEach-Object {
                @{
                    Name        = $_.Name
                    Description = $_.Description
                    Query       = $_.Query
                }
            })
        }
}

# ── ADGPO-009: GPOs with No Apply Permission ─────────────────────────────
function Test-ReconADGPO009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $gpoPerms = $gpoData.GPOPermissions
    if (-not $gpoPerms -or $gpoPerms.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'GPO permission data not available'
    }

    $gpos = @($gpoData.GPOs)
    $noApplyGPOs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $gpoPerms.Keys) {
        $perm = $gpoPerms[$gpoName]
        $canApply = @($perm.CanApply)

        # A GPO with no Apply principals will not be processed by anyone
        if ($canApply.Count -eq 0) {
            # Check if this GPO is actually linked (unlinked GPOs without apply are expected)
            $gpoObj = $gpos | Where-Object { $_.DisplayName -eq $gpoName } | Select-Object -First 1
            if ($gpoObj -and $gpoObj.IsLinked) {
                $noApplyGPOs.Add(@{
                    GPOName = $gpoName
                    GUID    = if ($gpoObj) { $gpoObj.GUID } else { '' }
                })
            }
        }
    }

    if ($noApplyGPOs.Count -gt 0) {
        $names = @($noApplyGPOs | ForEach-Object { $_.GPOName })
        $currentValue = "$($noApplyGPOs.Count) linked GPO(s) have no Apply Group Policy permission granted: $($names -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                NoApplyCount = $noApplyGPOs.Count
                NoApplyGPOs  = @($noApplyGPOs)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All linked GPOs have Apply Group Policy permission granted to at least one principal" `
        -Details @{ GPOsChecked = $gpoPerms.Count }
}

# ── ADGPO-010: SYSVOL/AD GPO Version Mismatch ───────────────────────────
function Test-ReconADGPO010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $mismatches = @($gpoData.GPOVersionMismatch)
    if ($mismatches.Count -eq 0 -or ($mismatches.Count -eq 1 -and $null -eq $mismatches[0])) {
        # Check if SYSVOL was accessible
        $sysvolContent = $gpoData.SYSVOLContent
        $sysvolErrors = $false
        if ($sysvolContent) {
            foreach ($key in $sysvolContent.Keys) {
                $entry = $sysvolContent[$key]
                if ($entry -is [hashtable] -and $entry.ContainsKey('Error')) {
                    $sysvolErrors = $true
                    break
                }
            }
        }

        if ($sysvolErrors) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
                -CurrentValue 'SYSVOL was not accessible; version comparison could not be performed'
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'All GPO versions match between AD and SYSVOL' `
            -Details @{ MismatchCount = 0 }
    }

    $names = @($mismatches | Where-Object { $_ } | ForEach-Object { $_.DisplayName })
    $currentValue = "$($mismatches.Count) GPO(s) have AD/SYSVOL version mismatches: $($names -join '; ')"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            MismatchCount = $mismatches.Count
            Mismatches    = @($mismatches | Where-Object { $_ } | ForEach-Object {
                @{
                    DisplayName           = $_.DisplayName
                    GUID                  = $_.GUID
                    ADVersionUser         = $_.ADVersionUser
                    ADVersionComputer     = $_.ADVersionComputer
                    SYSVOLVersionUser     = $_.SYSVOLVersionUser
                    SYSVOLVersionComputer = $_.SYSVOLVersionComputer
                }
            })
        }
}

# ── ADGPO-011: GPO Settings Security Analysis ───────────────────────────
function Test-ReconADGPO011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for security analysis'
    }

    # Check all SYSVOL content entries for error markers indicating inaccessibility
    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot analyze GPO security settings'
    }

    $gposWithSecSettings = 0

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        $hasRegPol = $content.HasRegistryPol -eq $true
        $hasPrefs = $content.HasPreferences -eq $true

        if ($hasRegPol -or $hasPrefs) {
            $gposWithSecSettings++
        }
    }

    # This is an informational check; report what was found
    $currentValue = "$gposWithSecSettings of $($sysvolContent.Count) GPO(s) contain registry policies or preference settings that may affect security configuration. Manual review of GPO reports recommended"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            TotalGPOs              = $sysvolContent.Count
            GPOsWithSecSettings    = $gposWithSecSettings
            Note                   = 'Detailed GPO report analysis (Get-GPOReport -All -ReportType XML) recommended for comprehensive security settings review'
        }
}

# ── ADGPO-012: cPassword/GPP Password Detection ─────────────────────────
function Test-ReconADGPO012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for cPassword scanning'
    }

    # Check all entries for SYSVOL access errors
    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot scan for cPassword values'
    }

    $affectedGPOs = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        if ($content.CPasswordFound -eq $true) {
            $affectedGPOs.Add(@{
                GPOName          = $gpoName
                CPasswordFiles   = @($content.CPasswordLocations)
            })
        }
    }

    if ($affectedGPOs.Count -gt 0) {
        $totalFiles = ($affectedGPOs | ForEach-Object { $_.CPasswordFiles.Count } | Measure-Object -Sum).Sum
        $names = @($affectedGPOs | ForEach-Object { $_.GPOName })
        $currentValue = "CRITICAL: $($affectedGPOs.Count) GPO(s) contain cPassword values (MS14-025) in $totalFiles file(s): $($names -join '; '). These passwords are trivially decryptable by any domain user"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                AffectedGPOCount = $affectedGPOs.Count
                TotalCPassFiles  = $totalFiles
                AffectedGPOs     = @($affectedGPOs)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No cPassword values found in SYSVOL GPP XML files' `
        -Details @{ GPOsScanned = $sysvolContent.Count }
}

# ── ADGPO-013: Scripts in GPOs Analysis ──────────────────────────────────
function Test-ReconADGPO013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for script analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot analyze GPO scripts'
    }

    $gposWithScripts = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        if ($content.HasScripts -eq $true -and $content.ScriptFiles.Count -gt 0) {
            $gposWithScripts.Add(@{
                GPOName     = $gpoName
                ScriptCount = $content.ScriptFiles.Count
                ScriptFiles = @($content.ScriptFiles)
            })
        }
    }

    if ($gposWithScripts.Count -gt 0) {
        $totalScripts = ($gposWithScripts | ForEach-Object { $_.ScriptCount } | Measure-Object -Sum).Sum
        $names = @($gposWithScripts | ForEach-Object { "$($_.GPOName) ($($_.ScriptCount) scripts)" })
        $currentValue = "$($gposWithScripts.Count) GPO(s) contain $totalScripts script file(s) in SYSVOL: $($names -join '; '). Review for hardcoded credentials, unsafe operations, and unauthorized commands"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                GPOsWithScripts  = $gposWithScripts.Count
                TotalScriptFiles = $totalScripts
                GPOs             = @($gposWithScripts)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No script files found in GPO SYSVOL folders' `
        -Details @{ GPOsScanned = $sysvolContent.Count }
}

# ── ADGPO-014: MSI Packages in GPOs ──────────────────────────────────────
function Test-ReconADGPO014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for MSI analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot check for MSI packages'
    }

    $gposWithMSI = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        # MSI packages are typically in Preferences or direct paths; check preference files for .msi references
        $msiFiles = [System.Collections.Generic.List[string]]::new()

        if ($content.PreferenceFiles -and $content.PreferenceFiles.Count -gt 0) {
            foreach ($prefFile in $content.PreferenceFiles) {
                if ($prefFile -match '\.msi$|\.msp$|\.mst$') {
                    $msiFiles.Add($prefFile)
                }
            }
        }

        # Also check script files for .msi references
        if ($content.ScriptFiles -and $content.ScriptFiles.Count -gt 0) {
            foreach ($scriptFile in $content.ScriptFiles) {
                if ($scriptFile -match '\.msi$|\.msp$|\.mst$') {
                    $msiFiles.Add($scriptFile)
                }
            }
        }

        if ($msiFiles.Count -gt 0) {
            $gposWithMSI.Add(@{
                GPOName  = $gpoName
                MSIFiles = @($msiFiles)
            })
        }
    }

    if ($gposWithMSI.Count -gt 0) {
        $totalMSI = ($gposWithMSI | ForEach-Object { $_.MSIFiles.Count } | Measure-Object -Sum).Sum
        $names = @($gposWithMSI | ForEach-Object { $_.GPOName })
        $currentValue = "$($gposWithMSI.Count) GPO(s) contain $totalMSI MSI/software deployment file(s): $($names -join '; '). Verify package sources and integrity"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                GPOsWithMSI   = $gposWithMSI.Count
                TotalMSIFiles = $totalMSI
                GPOs          = @($gposWithMSI)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No MSI package files found in GPO SYSVOL folders' `
        -Details @{ GPOsScanned = $sysvolContent.Count }
}

# ── ADGPO-015: Scheduled Tasks in GPOs ───────────────────────────────────
function Test-ReconADGPO015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for scheduled task analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot check for scheduled tasks in GPOs'
    }

    $gposWithTasks = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        # Scheduled tasks in GPP are stored in ScheduledTasks.xml under Preferences
        $taskFiles = [System.Collections.Generic.List[string]]::new()

        if ($content.PreferenceFiles -and $content.PreferenceFiles.Count -gt 0) {
            foreach ($prefFile in $content.PreferenceFiles) {
                if ($prefFile -match 'ScheduledTasks\.xml$|ScheduledTasks\\') {
                    $taskFiles.Add($prefFile)
                }
            }
        }

        if ($taskFiles.Count -gt 0) {
            $gposWithTasks.Add(@{
                GPOName   = $gpoName
                TaskFiles = @($taskFiles)
            })
        }
    }

    if ($gposWithTasks.Count -gt 0) {
        $names = @($gposWithTasks | ForEach-Object { $_.GPOName })
        $currentValue = "$($gposWithTasks.Count) GPO(s) deploy scheduled tasks via Group Policy Preferences: $($names -join '; '). Review for unauthorized tasks, stored credentials, and least-privilege execution"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                GPOsWithTasks = $gposWithTasks.Count
                GPOs          = @($gposWithTasks)
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No scheduled task configurations found in GPO preferences' `
        -Details @{ GPOsScanned = $sysvolContent.Count }
}

# ── ADGPO-016: Registry Settings Security Review ────────────────────────
function Test-ReconADGPO016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for registry analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot analyze GPO registry settings'
    }

    $gposWithRegPol = [System.Collections.Generic.List[string]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        if ($content.HasRegistryPol -eq $true) {
            $gposWithRegPol.Add($gpoName)
        }
    }

    if ($gposWithRegPol.Count -gt 0) {
        $currentValue = "$($gposWithRegPol.Count) GPO(s) contain Registry.pol files with registry-based policy settings: $($gposWithRegPol -join '; '). Review for settings that may weaken security defaults"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue $currentValue `
            -Details @{
                GPOsWithRegistryPol = $gposWithRegPol.Count
                GPONames            = @($gposWithRegPol)
                Note                = 'Use Get-GPOReport to extract and review specific registry settings deployed by these GPOs'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No Registry.pol files found in GPO SYSVOL folders' `
        -Details @{ GPOsScanned = $sysvolContent.Count }
}

# ── ADGPO-017: Restricted Groups Analysis ────────────────────────────────
function Test-ReconADGPO017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for Restricted Groups analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot analyze Restricted Groups settings'
    }

    # Restricted Groups are in GptTmpl.inf under Machine\Microsoft\Windows NT\SecEdit
    # or via Preferences Groups. Check for Groups.xml in preference files
    $gposWithGroups = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        $groupFiles = [System.Collections.Generic.List[string]]::new()

        # Check preference files for Groups.xml
        if ($content.PreferenceFiles -and $content.PreferenceFiles.Count -gt 0) {
            foreach ($prefFile in $content.PreferenceFiles) {
                if ($prefFile -match 'Groups\.xml$|Groups\\') {
                    $groupFiles.Add($prefFile)
                }
            }
        }

        if ($groupFiles.Count -gt 0) {
            $gposWithGroups.Add(@{
                GPOName    = $gpoName
                GroupFiles = @($groupFiles)
            })
        }
    }

    if ($gposWithGroups.Count -gt 0) {
        $names = @($gposWithGroups | ForEach-Object { $_.GPOName })
        $currentValue = "$($gposWithGroups.Count) GPO(s) configure group membership via Preferences: $($names -join '; '). Verify that local Administrators membership is appropriately restricted"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                GPOsWithGroupConfig = $gposWithGroups.Count
                GPOs                = @($gposWithGroups)
                Note                = 'Review Groups.xml and Restricted Groups settings to ensure least-privilege local admin membership'
            }
    }

    # SYSVOL was readable and no GPP group-membership configurations exist — there
    # is no risky GPP-based local-Administrators change to review. This is the
    # secure/clean state (Restricted Groups remains a recommended hardening control).
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No Group Policy Preferences group-membership configurations found — no GPP-based local Administrators changes to review. Restricted Groups remains a recommended hardening control.' `
        -Details @{ GPOsScanned = $sysvolContent.Count }
}

# ── ADGPO-018: Audit Policy Configuration via GPO ───────────────────────
function Test-ReconADGPO018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for audit policy analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot verify audit policy configuration'
    }

    # Advanced Audit Policy is configured via Registry.pol or audit.csv in SYSVOL
    # Check for GPOs that have audit-related content
    $auditGPOsFound = $false
    $gposWithAuditContent = [System.Collections.Generic.List[string]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        # Audit policy settings are in SecuritySettings or Registry.pol
        if ($content.HasRegistryPol -eq $true) {
            # Registry.pol may contain Advanced Audit Policy settings
            $gposWithAuditContent.Add($gpoName)
            $auditGPOsFound = $true
        }

        # Also check for audit.csv in preferences or script paths
        if ($content.PreferenceFiles -and $content.PreferenceFiles.Count -gt 0) {
            foreach ($prefFile in $content.PreferenceFiles) {
                if ($prefFile -match 'audit\.csv$|Audit\\') {
                    if (-not $gposWithAuditContent.Contains($gpoName)) {
                        $gposWithAuditContent.Add($gpoName)
                    }
                    $auditGPOsFound = $true
                }
            }
        }
    }

    if (-not $auditGPOsFound) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No GPOs with audit policy configuration detected. Configure Advanced Audit Policy via GPO to enable comprehensive security event logging on all domain-joined systems' `
            -Details @{
                GPOsScanned = $sysvolContent.Count
                Note        = 'Advanced Audit Policy should be configured under Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration'
            }
    }

    $currentValue = "$($gposWithAuditContent.Count) GPO(s) contain registry policies that may include audit configuration: $($gposWithAuditContent -join '; '). Verify Advanced Audit Policy covers all required categories"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            GPOsWithAuditConfig = $gposWithAuditContent.Count
            GPONames            = @($gposWithAuditContent)
            Note                = 'Use gpresult /h on a representative system to verify effective audit policy. Ensure Advanced Audit Policy (not legacy) is used'
        }
}

# ── ADGPO-019: Windows Firewall Configuration via GPO ────────────────────
function Test-ReconADGPO019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for firewall analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot verify Windows Firewall GPO configuration'
    }

    # Windows Firewall settings are typically in Registry.pol under
    # HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall
    # Without parsing Registry.pol binary, we check for GPOs named with firewall keywords
    # or that have registry policies
    $gpos = @($gpoData.GPOs)
    $firewallGPOs = @($gpos | Where-Object {
        $_.DisplayName -match 'firewall|fw|network.*(protect|secur)'
    })

    # Also check for GPOs with registry policies that might contain firewall settings
    $gposWithRegPol = [System.Collections.Generic.List[string]]::new()
    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if ($content -is [hashtable] -and $content.HasRegistryPol -eq $true) {
            $gposWithRegPol.Add($gpoName)
        }
    }

    if ($firewallGPOs.Count -gt 0) {
        $names = @($firewallGPOs | ForEach-Object { $_.DisplayName })
        $currentValue = "$($firewallGPOs.Count) GPO(s) appear to configure Windows Firewall: $($names -join '; '). Verify firewall is enabled for all profiles with deny-by-default inbound"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                FirewallGPOCount = $firewallGPOs.Count
                FirewallGPOs     = @($names)
                GPOsWithRegPol   = $gposWithRegPol.Count
                Note             = 'Use gpresult or GPO report to verify firewall is enabled for Domain, Private, and Public profiles'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'No GPOs with obvious Windows Firewall configuration detected. Windows Defender Firewall should be enabled for all profiles (Domain, Private, Public) via GPO with deny-by-default inbound rules' `
        -Details @{
            GPOsScanned    = $sysvolContent.Count
            GPOsWithRegPol = $gposWithRegPol.Count
            Note           = 'Firewall settings may be in Registry.pol files. Verify with gpresult /h on a representative system'
        }
}

# ── ADGPO-020: PowerShell Execution Policy via GPO ──────────────────────
function Test-ReconADGPO020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for PowerShell execution policy analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot verify PowerShell execution policy'
    }

    # PowerShell execution policy GPO setting:
    # Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Script Execution
    # Registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ExecutionPolicy
    # Without parsing Registry.pol, we report based on available data and recommend manual check

    # Check GPO names for PowerShell-related policies
    $gpos = @($gpoData.GPOs)
    $psGPOs = @($gpos | Where-Object {
        $_.DisplayName -match 'powershell|script.*polic|execution.*polic'
    })

    $gposWithRegPol = 0
    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if ($content -is [hashtable] -and $content.HasRegistryPol -eq $true) {
            $gposWithRegPol++
        }
    }

    if ($psGPOs.Count -gt 0) {
        $names = @($psGPOs | ForEach-Object { $_.DisplayName })
        $currentValue = "$($psGPOs.Count) GPO(s) appear to manage PowerShell execution policy: $($names -join '; '). Verify policy is set to AllSigned or RemoteSigned, not Unrestricted or Bypass"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                PSPolicyGPOs   = @($names)
                GPOsWithRegPol = $gposWithRegPol
                Note           = 'Verify execution policy via gpresult or by checking the registry key HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell on target systems'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "No GPOs with obvious PowerShell execution policy configuration found. Execution policy may be set within $gposWithRegPol GPO(s) containing registry policies. Verify PowerShell execution policy is set to AllSigned or RemoteSigned via GPO" `
        -Details @{
            GPOsScanned    = $sysvolContent.Count
            GPOsWithRegPol = $gposWithRegPol
            Note           = 'Check Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on Script Execution'
        }
}

# ── ADGPO-021: PowerShell Logging Configuration ─────────────────────────
function Test-ReconADGPO021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for PowerShell logging analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot verify PowerShell logging configuration'
    }

    # PowerShell logging GPO settings:
    # Module Logging: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    # Script Block Logging: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    # Transcription: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    # Without parsing Registry.pol binary, we check for GPOs named with logging/PowerShell keywords

    $gpos = @($gpoData.GPOs)
    $loggingGPOs = @($gpos | Where-Object {
        $_.DisplayName -match 'powershell|logging|audit|monitor|transcript'
    })

    $gposWithRegPol = 0
    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if ($content -is [hashtable] -and $content.HasRegistryPol -eq $true) {
            $gposWithRegPol++
        }
    }

    if ($loggingGPOs.Count -gt 0) {
        $names = @($loggingGPOs | ForEach-Object { $_.DisplayName })
        $currentValue = "$($loggingGPOs.Count) GPO(s) may configure PowerShell logging: $($names -join '; '). Verify Module Logging, Script Block Logging, and Transcription are all enabled"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                LoggingGPOs    = @($names)
                GPOsWithRegPol = $gposWithRegPol
                RequiredSettings = @(
                    'Module Logging enabled with * for all modules'
                    'Script Block Logging enabled'
                    'PowerShell Transcription enabled with secure output directory'
                )
                Note           = 'Verify with gpresult or by checking registry keys under HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell on target systems'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "No GPOs with obvious PowerShell logging configuration detected. Module Logging, Script Block Logging, and Transcription should be enabled via GPO on all systems to detect PowerShell-based attacks" `
        -Details @{
            GPOsScanned    = $sysvolContent.Count
            GPOsWithRegPol = $gposWithRegPol
            RequiredSettings = @(
                'Module Logging: Computer Configuration > Admin Templates > Windows Components > Windows PowerShell > Turn on Module Logging'
                'Script Block Logging: Computer Configuration > Admin Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging'
                'Transcription: Computer Configuration > Admin Templates > Windows Components > Windows PowerShell > Turn on PowerShell Transcription'
            )
        }
}

# ── ADGPO-022: AppLocker/WDAC Policy Assessment ─────────────────────────
function Test-ReconADGPO022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for AppLocker/WDAC analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot check for AppLocker/WDAC policies'
    }

    # AppLocker policies are in Registry.pol and also have XML in SYSVOL
    # WDAC policies may be deployed via Registry.pol or as .p7b files
    # Check GPO names and preference files for application control indicators
    $gpos = @($gpoData.GPOs)
    $appControlGPOs = @($gpos | Where-Object {
        $_.DisplayName -match 'applocker|app.*control|wdac|application.*whit|SRP|software.*restrict|code.*integrit'
    })

    # Also check for AppLocker XML files in preferences
    $gposWithAppControl = [System.Collections.Generic.List[string]]::new()

    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if (-not ($content -is [hashtable])) { continue }

        if ($content.PreferenceFiles -and $content.PreferenceFiles.Count -gt 0) {
            foreach ($prefFile in $content.PreferenceFiles) {
                if ($prefFile -match 'AppLocker|SRP|CodeIntegrity|\.p7b$') {
                    if (-not $gposWithAppControl.Contains($gpoName)) {
                        $gposWithAppControl.Add($gpoName)
                    }
                }
            }
        }
    }

    $totalFound = $appControlGPOs.Count + $gposWithAppControl.Count
    if ($totalFound -gt 0) {
        $allNames = [System.Collections.Generic.List[string]]::new()
        foreach ($gpo in $appControlGPOs) { $allNames.Add($gpo.DisplayName) }
        foreach ($name in $gposWithAppControl) {
            if (-not $allNames.Contains($name)) { $allNames.Add($name) }
        }

        $currentValue = "$($allNames.Count) GPO(s) appear to configure application control (AppLocker/WDAC/SRP): $($allNames -join '; '). Verify policies are in enforce mode on all targeted systems"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                AppControlGPOs = @($allNames)
                Note           = 'Verify application control policies are in Enforce mode (not Audit Only) using gpresult or Get-AppLockerPolicy on target systems'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'No AppLocker, WDAC, or Software Restriction Policies detected in GPOs. Application control is a critical defense against malware execution and lateral movement' `
        -Details @{
            GPOsScanned = $sysvolContent.Count
            Note        = 'Deploy AppLocker or Windows Defender Application Control via GPO. Start in audit mode, build a baseline, then transition to enforce mode'
        }
}

# ── ADGPO-023: LAPS GPO Configuration ───────────────────────────────────
function Test-ReconADGPO023 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $sysvolContent = $gpoData.SYSVOLContent
    if (-not $sysvolContent -or $sysvolContent.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL content data not available for LAPS configuration analysis'
    }

    $allErrors = $true
    foreach ($key in $sysvolContent.Keys) {
        $entry = $sysvolContent[$key]
        if ($entry -is [hashtable] -and -not $entry.ContainsKey('Error')) {
            $allErrors = $false
            break
        }
    }
    if ($allErrors) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL not accessible; cannot check for LAPS GPO configuration'
    }

    # LAPS GPO settings are in Registry.pol under:
    # Legacy LAPS: HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd
    # Windows LAPS: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS
    # Check GPO names for LAPS indicators
    $gpos = @($gpoData.GPOs)
    $lapsGPOs = @($gpos | Where-Object {
        $_.DisplayName -match 'LAPS|local.*admin.*password|AdmPwd'
    })

    $gposWithRegPol = 0
    foreach ($gpoName in $sysvolContent.Keys) {
        $content = $sysvolContent[$gpoName]
        if ($content -is [hashtable] -and $content.HasRegistryPol -eq $true) {
            $gposWithRegPol++
        }
    }

    if ($lapsGPOs.Count -gt 0) {
        $names = @($lapsGPOs | ForEach-Object { $_.DisplayName })
        $linkedCount = @($lapsGPOs | Where-Object { $_.IsLinked }).Count

        $status = if ($linkedCount -gt 0) { 'PASS' } else { 'WARN' }
        $currentValue = "$($lapsGPOs.Count) GPO(s) appear to configure LAPS: $($names -join '; '). $linkedCount of $($lapsGPOs.Count) are linked"

        if ($linkedCount -eq 0) {
            $currentValue += '. WARNING: None are linked to any OU'
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue `
            -Details @{
                LAPSGPOs    = @($lapsGPOs | ForEach-Object {
                    @{
                        DisplayName = $_.DisplayName
                        GUID        = $_.GUID
                        IsLinked    = $_.IsLinked
                    }
                })
                LinkedCount = $linkedCount
                Note        = 'Verify LAPS is enabled with minimum 24-character passwords and 30-day maximum age. Check ms-Mcs-AdmPwdExpirationTime attributes to confirm LAPS is functioning'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "No GPOs with obvious LAPS configuration detected. LAPS settings may be within $gposWithRegPol GPO(s) containing registry policies. Verify LAPS is deployed to all domain-joined systems" `
        -Details @{
            GPOsScanned    = $sysvolContent.Count
            GPOsWithRegPol = $gposWithRegPol
            Note           = 'Deploy LAPS (legacy or Windows LAPS) via GPO to manage local administrator passwords across all domain-joined systems'
        }
}

# ── ADGPO-024: GPO WMI Filter Review ────────────────────────────────────
function Test-ReconADGPO024 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'GroupPolicyObjects' -Subject 'Group Policy objects'
    if ($na) { return $na }

    $gpoData = $AuditData.GroupPolicies
    if (-not $gpoData) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Group Policy data not available'
    }

    $wmiFilters = @($gpoData.WMIFilters)
    if ($wmiFilters.Count -eq 0 -or ($wmiFilters.Count -eq 1 -and $null -eq $wmiFilters[0])) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No WMI filters defined in the domain' `
            -Details @{ WMIFilterCount = 0 }
    }

    $filterSummary = @($wmiFilters | Where-Object { $_ } | ForEach-Object {
        @{
            Name        = $_.Name
            Description = $_.Description
            Query       = $_.Query
            WhenCreated = $_.WhenCreated
        }
    })

    $names = @($filterSummary | ForEach-Object { $_.Name })
    $currentValue = "$($filterSummary.Count) WMI filter(s) defined: $($names -join '; '). Review queries for correctness and ensure they do not block security-critical GPOs"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            WMIFilterCount = $filterSummary.Count
            WMIFilters     = @($filterSummary)
        }
}
