# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADLogonScriptChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADLogonScriptChecks'
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

# -- ADSCRIPT-001: NETLOGON Share Permissions ---------------------------------
function Test-ReconADSCRIPT001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $perms = $scripts.NetlogonPermissions
    if (-not $perms -or -not $perms.AccessRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'NETLOGON permission data not available'
    }

    # Identities considered administrative / expected to have write access
    $adminPatterns = @(
        '\\Domain Admins$', '\\Enterprise Admins$', '\\Administrators$',
        '\\SYSTEM$', '^BUILTIN\\Administrators$', '^NT AUTHORITY\\SYSTEM$',
        '\\CREATOR OWNER$'
    )

    # Rights that indicate write access
    $writeRights = @('Write', 'Modify', 'FullControl', 'ChangePermissions', 'TakeOwnership')

    $nonAdminWriteEntries = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ace in $perms.AccessRules) {
        if ($ace.AccessType -ne 'Allow') { continue }

        # Check if rights include any write-level permission
        $hasWrite = $false
        foreach ($wr in $writeRights) {
            if ($ace.Rights -match $wr) {
                $hasWrite = $true
                break
            }
        }
        if (-not $hasWrite) { continue }

        # Check if identity is administrative
        $isAdmin = $false
        foreach ($pattern in $adminPatterns) {
            if ($ace.Identity -match $pattern) {
                $isAdmin = $true
                break
            }
        }

        if (-not $isAdmin) {
            $nonAdminWriteEntries.Add(@{
                Identity = $ace.Identity
                Rights   = $ace.Rights
            })
        }
    }

    if ($nonAdminWriteEntries.Count -gt 0) {
        $identities = @($nonAdminWriteEntries | ForEach-Object { $_.Identity }) | Sort-Object -Unique
        $currentValue = "NETLOGON has write access for non-admin identities: $($identities -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                NonAdminWriteAccess = @($nonAdminWriteEntries)
                Owner               = $perms.Owner
                TotalACEs           = $perms.AccessRules.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "NETLOGON share permissions are properly restricted ($($perms.AccessRules.Count) ACE(s))" `
        -Details @{
            Owner     = $perms.Owner
            TotalACEs = $perms.AccessRules.Count
        }
}

# -- ADSCRIPT-002: SYSVOL Share Permissions -----------------------------------
function Test-ReconADSCRIPT002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $perms = $scripts.SysvolPermissions
    if (-not $perms -or -not $perms.AccessRules) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'SYSVOL permission data not available'
    }

    $adminPatterns = @(
        '\\Domain Admins$', '\\Enterprise Admins$', '\\Administrators$',
        '\\SYSTEM$', '^BUILTIN\\Administrators$', '^NT AUTHORITY\\SYSTEM$',
        '\\CREATOR OWNER$'
    )

    $writeRights = @('Write', 'Modify', 'FullControl', 'ChangePermissions', 'TakeOwnership')

    $nonAdminWriteEntries = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($ace in $perms.AccessRules) {
        if ($ace.AccessType -ne 'Allow') { continue }

        $hasWrite = $false
        foreach ($wr in $writeRights) {
            if ($ace.Rights -match $wr) {
                $hasWrite = $true
                break
            }
        }
        if (-not $hasWrite) { continue }

        $isAdmin = $false
        foreach ($pattern in $adminPatterns) {
            if ($ace.Identity -match $pattern) {
                $isAdmin = $true
                break
            }
        }

        if (-not $isAdmin) {
            $nonAdminWriteEntries.Add(@{
                Identity = $ace.Identity
                Rights   = $ace.Rights
            })
        }
    }

    if ($nonAdminWriteEntries.Count -gt 0) {
        $identities = @($nonAdminWriteEntries | ForEach-Object { $_.Identity }) | Sort-Object -Unique
        $currentValue = "SYSVOL has write access for non-admin identities: $($identities -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                NonAdminWriteAccess = @($nonAdminWriteEntries)
                Owner               = $perms.Owner
                TotalACEs           = $perms.AccessRules.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "SYSVOL share permissions are properly restricted ($($perms.AccessRules.Count) ACE(s))" `
        -Details @{
            Owner     = $perms.Owner
            TotalACEs = $perms.AccessRules.Count
        }
}

# -- ADSCRIPT-003: Logon Script Inventory ------------------------------------
function Test-ReconADSCRIPT003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $netlogonFiles = @($scripts.NetlogonFiles)
    $userScripts = @($scripts.UserScripts)

    # Count by extension
    $extensionCounts = @{}
    foreach ($file in $netlogonFiles) {
        $ext = if ($file.Extension) { $file.Extension } else { '(none)' }
        if (-not $extensionCounts.ContainsKey($ext)) { $extensionCounts[$ext] = 0 }
        $extensionCounts[$ext]++
    }

    $totalUsers = 0
    foreach ($us in $userScripts) {
        $totalUsers += [int]$us.UserCount
    }

    $extSummary = @($extensionCounts.GetEnumerator() | Sort-Object Value -Descending |
        ForEach-Object { "$($_.Value) $($_.Key)" })

    $currentValue = "$($netlogonFiles.Count) file(s) in NETLOGON"
    if ($extSummary.Count -gt 0) {
        $currentValue += " ($($extSummary -join ', '))"
    }
    if ($userScripts.Count -gt 0) {
        $currentValue += ". $($userScripts.Count) unique script(s) assigned to $totalUsers user(s)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            TotalNetlogonFiles = $netlogonFiles.Count
            ExtensionCounts    = $extensionCounts
            UniqueUserScripts  = $userScripts.Count
            TotalUsersAssigned = $totalUsers
            UserScripts        = @($userScripts | Select-Object -First 20)
        }
}

# -- ADSCRIPT-004: Hardcoded Credentials in Scripts --------------------------
function Test-ReconADSCRIPT004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $analysis = @($scripts.ScriptAnalysis)
    if ($analysis.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No scripts available for analysis'
    }

    $scriptsWithCreds = @($analysis | Where-Object { $_.HardcodedCredentials -eq $true })

    if ($scriptsWithCreds.Count -gt 0) {
        $totalMatches = 0
        $credSummary = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($s in $scriptsWithCreds) {
            $matchCount = @($s.CredentialMatches).Count
            $totalMatches += $matchCount
            $credSummary.Add(@{
                ScriptPath  = $s.RelativePath
                MatchCount  = $matchCount
                Patterns    = @($s.CredentialMatches | ForEach-Object { $_.Pattern } | Sort-Object -Unique)
            })
        }

        $currentValue = "$($scriptsWithCreds.Count) script(s) contain hardcoded credentials ($totalMatches finding(s))"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                AffectedScripts = @($credSummary)
                TotalScripts    = $analysis.Count
                TotalFindings   = $totalMatches
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No hardcoded credentials found in $($analysis.Count) analyzed script(s)" `
        -Details @{ TotalScripts = $analysis.Count }
}

# -- ADSCRIPT-005: LOLBins Usage in Scripts -----------------------------------
function Test-ReconADSCRIPT005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $analysis = @($scripts.ScriptAnalysis)
    if ($analysis.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No scripts available for analysis'
    }

    $scriptsWithLOLBins = @($analysis | Where-Object { $_.LOLBinsUsage -eq $true })

    if ($scriptsWithLOLBins.Count -gt 0) {
        $allLOLBins = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $lolSummary = [System.Collections.Generic.List[hashtable]]::new()

        foreach ($s in $scriptsWithLOLBins) {
            foreach ($lb in @($s.LOLBinsFound)) { [void]$allLOLBins.Add($lb) }
            $lolSummary.Add(@{
                ScriptPath = $s.RelativePath
                LOLBins    = @($s.LOLBinsFound)
            })
        }

        $currentValue = "$($scriptsWithLOLBins.Count) script(s) reference LOLBins: $($allLOLBins -join ', ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                AffectedScripts = @($lolSummary)
                UniqueLOLBins   = @($allLOLBins)
                TotalScripts    = $analysis.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No LOLBin references found in $($analysis.Count) analyzed script(s)" `
        -Details @{ TotalScripts = $analysis.Count }
}

# -- ADSCRIPT-006: Plaintext Passwords in Scripts ----------------------------
function Test-ReconADSCRIPT006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $analysis = @($scripts.ScriptAnalysis)
    if ($analysis.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No scripts available for analysis'
    }

    $scriptsWithPasswords = @($analysis | Where-Object { $_.PlaintextPasswords -eq $true })

    if ($scriptsWithPasswords.Count -gt 0) {
        $totalMatches = 0
        $pwdSummary = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($s in $scriptsWithPasswords) {
            $matchCount = @($s.PasswordMatches).Count
            $totalMatches += $matchCount
            $pwdSummary.Add(@{
                ScriptPath = $s.RelativePath
                MatchCount = $matchCount
                Patterns   = @($s.PasswordMatches | ForEach-Object { $_.Pattern } | Sort-Object -Unique)
            })
        }

        $currentValue = "$($scriptsWithPasswords.Count) script(s) contain plaintext passwords ($totalMatches finding(s))"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                AffectedScripts = @($pwdSummary)
                TotalScripts    = $analysis.Count
                TotalFindings   = $totalMatches
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No plaintext passwords found in $($analysis.Count) analyzed script(s)" `
        -Details @{ TotalScripts = $analysis.Count }
}

# -- ADSCRIPT-007: World-Writable Script Permissions -------------------------
function Test-ReconADSCRIPT007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $analysis = @($scripts.ScriptAnalysis)
    if ($analysis.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No scripts available for analysis'
    }

    $worldWritable = @($analysis | Where-Object { $_.WorldWritable -eq $true })

    if ($worldWritable.Count -gt 0) {
        $scriptNames = @($worldWritable | ForEach-Object { $_.RelativePath })
        $currentValue = "$($worldWritable.Count) script(s) have world-writable permissions"
        if ($scriptNames.Count -le 10) {
            $currentValue += ": $($scriptNames -join '; ')"
        }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                WorldWritableScripts = $scriptNames
                TotalScripts         = $analysis.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No world-writable scripts found among $($analysis.Count) analyzed file(s)" `
        -Details @{ TotalScripts = $analysis.Count }
}

# -- ADSCRIPT-008: External Resource References ------------------------------
function Test-ReconADSCRIPT008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $analysis = @($scripts.ScriptAnalysis)
    if ($analysis.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No scripts available for analysis'
    }

    $scriptsWithExternal = @($analysis | Where-Object { $_.ExternalResources -eq $true })

    if ($scriptsWithExternal.Count -gt 0) {
        $totalResources = 0
        $extSummary = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($s in $scriptsWithExternal) {
            $resources = @($s.ExternalResourceList)
            $totalResources += $resources.Count
            $extSummary.Add(@{
                ScriptPath = $s.RelativePath
                Resources  = $resources
            })
        }

        $currentValue = "$($scriptsWithExternal.Count) script(s) reference $totalResources external resource(s)"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                AffectedScripts = @($extSummary)
                TotalResources  = $totalResources
                TotalScripts    = $analysis.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No external resource references found in $($analysis.Count) analyzed script(s)" `
        -Details @{ TotalScripts = $analysis.Count }
}

# -- ADSCRIPT-009: Malformed Scripts -----------------------------------------
function Test-ReconADSCRIPT009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $netlogonFiles = @($scripts.NetlogonFiles)
    if ($netlogonFiles.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No NETLOGON files available for analysis'
    }

    # Standard script extensions
    $knownExtensions = @('.bat', '.cmd', '.vbs', '.ps1', '.js', '.wsf', '.kix')

    # Identify unusual extensions in NETLOGON
    $unusualFiles = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($file in $netlogonFiles) {
        $ext = if ($file.Extension) { $file.Extension.ToLower() } else { '' }

        # Flag files with unusual extensions (not standard scripts but not common data files either)
        $isKnownScript = $ext -in $knownExtensions
        $isKnownData = $ext -in @('.txt', '.ini', '.cfg', '.xml', '.csv', '.log', '.dat', '.ico', '.bmp', '.jpg', '.png', '.gif')

        if (-not $isKnownScript -and -not $isKnownData -and -not [string]::IsNullOrEmpty($ext)) {
            $unusualFiles.Add(@{
                RelativePath = $file.RelativePath
                Extension    = $ext
                Size         = $file.Size
            })
        }
    }

    # Check for scripts that failed analysis (present in NetlogonFiles but errored in ScriptAnalysis)
    $analysisErrors = @{}
    if ($scripts.ContainsKey('Errors')) {
        foreach ($key in $scripts.Errors.Keys) {
            if ($key -match '^ScriptAnalysis:') {
                $analysisErrors[$key -replace '^ScriptAnalysis:', ''] = $scripts.Errors[$key]
            }
        }
    }

    # Also check for zero-byte script files
    $emptyScripts = @($netlogonFiles | Where-Object {
        $_.Extension -in $knownExtensions -and $_.Size -eq 0
    })

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($unusualFiles.Count -gt 0) {
        $issues.Add("$($unusualFiles.Count) file(s) with unusual extensions")
    }
    if ($analysisErrors.Count -gt 0) {
        $issues.Add("$($analysisErrors.Count) script(s) failed to parse")
    }
    if ($emptyScripts.Count -gt 0) {
        $issues.Add("$($emptyScripts.Count) empty script file(s)")
    }

    if ($issues.Count -gt 0) {
        $currentValue = "Script quality issues: $($issues -join '; ')"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue $currentValue `
            -Details @{
                UnusualFiles   = @($unusualFiles)
                ParseErrors    = $analysisErrors
                EmptyScripts   = @($emptyScripts | ForEach-Object { $_.RelativePath })
                TotalFiles     = $netlogonFiles.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($netlogonFiles.Count) NETLOGON file(s) have expected extensions and structure" `
        -Details @{ TotalFiles = $netlogonFiles.Count }
}

# -- ADSCRIPT-010: UNC Paths to Non-DC Locations ----------------------------
function Test-ReconADSCRIPT010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $analysis = @($scripts.ScriptAnalysis)
    if ($analysis.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No scripts available for analysis'
    }

    # Collect scripts that have UNC paths flagged as external (non-DC)
    # The collector already identifies external UNC paths via ExternalResourceList,
    # but we specifically look at UNC paths (not HTTP URLs) here
    $scriptsWithNonDCUNC = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($s in $analysis) {
        $uncPaths = @($s.UNCPaths)
        if ($uncPaths.Count -eq 0) { continue }

        # External resources include both UNC and URL; filter to UNC only
        $externalUNCPaths = @()
        if ($s.ExternalResources -eq $true -and $s.ExternalResourceList) {
            $externalUNCPaths = @($s.ExternalResourceList | Where-Object { $_ -match '^\\\\\S' })
        }

        if ($externalUNCPaths.Count -gt 0) {
            $scriptsWithNonDCUNC.Add(@{
                ScriptPath = $s.RelativePath
                UNCPaths   = $externalUNCPaths
            })
        }
    }

    if ($scriptsWithNonDCUNC.Count -gt 0) {
        $totalPaths = 0
        foreach ($entry in $scriptsWithNonDCUNC) { $totalPaths += $entry.UNCPaths.Count }

        $currentValue = "$($scriptsWithNonDCUNC.Count) script(s) contain $totalPaths UNC path(s) to non-DC servers"

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue $currentValue `
            -Details @{
                AffectedScripts = @($scriptsWithNonDCUNC)
                TotalUNCPaths   = $totalPaths
                TotalScripts    = $analysis.Count
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "No UNC paths to non-DC servers found in $($analysis.Count) analyzed script(s)" `
        -Details @{ TotalScripts = $analysis.Count }
}

# -- ADSCRIPT-011: Script Content Analysis Summary ---------------------------
function Test-ReconADSCRIPT011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'LogonScripts' -Subject 'logon scripts'
    if ($na) { return $na }

    $scripts = $AuditData.LogonScripts
    if (-not $scripts) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Logon script data not available'
    }

    $analysis = @($scripts.ScriptAnalysis)
    $netlogonFiles = @($scripts.NetlogonFiles)
    $userScripts = @($scripts.UserScripts)

    if ($analysis.Count -eq 0 -and $netlogonFiles.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No scripts available for content analysis'
    }

    # Compile summary statistics
    $credCount = @($analysis | Where-Object { $_.HardcodedCredentials -eq $true }).Count
    $lolCount = @($analysis | Where-Object { $_.LOLBinsUsage -eq $true }).Count
    $wwCount = @($analysis | Where-Object { $_.WorldWritable -eq $true }).Count
    $extCount = @($analysis | Where-Object { $_.ExternalResources -eq $true }).Count

    $totalUsers = 0
    foreach ($us in $userScripts) { $totalUsers += [int]$us.UserCount }

    $summaryParts = [System.Collections.Generic.List[string]]::new()
    $summaryParts.Add("$($analysis.Count) script(s) analyzed")
    $summaryParts.Add("$($netlogonFiles.Count) total NETLOGON file(s)")
    $summaryParts.Add("$($userScripts.Count) unique script assignment(s) across $totalUsers user(s)")

    $findingParts = [System.Collections.Generic.List[string]]::new()
    if ($credCount -gt 0) { $findingParts.Add("$credCount with credentials") }
    if ($lolCount -gt 0)  { $findingParts.Add("$lolCount with LOLBins") }
    if ($wwCount -gt 0)   { $findingParts.Add("$wwCount world-writable") }
    if ($extCount -gt 0)  { $findingParts.Add("$extCount with external references") }

    $currentValue = $summaryParts -join '. '
    if ($findingParts.Count -gt 0) {
        $currentValue += ". Findings: $($findingParts -join ', ')"
    } else {
        $currentValue += '. No security findings detected'
    }

    $errorCount = 0
    if ($scripts.ContainsKey('Errors')) { $errorCount = $scripts.Errors.Count }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            ScriptsAnalyzed       = $analysis.Count
            TotalNetlogonFiles    = $netlogonFiles.Count
            UniqueUserScripts     = $userScripts.Count
            TotalUsersAssigned    = $totalUsers
            ScriptsWithCredentials = $credCount
            ScriptsWithLOLBins    = $lolCount
            WorldWritableScripts  = $wwCount
            ExternalReferences    = $extCount
            CollectionErrors      = $errorCount
        }
}
