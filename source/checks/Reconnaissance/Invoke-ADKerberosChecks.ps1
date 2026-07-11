# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADKerberosChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADKerberosChecks'
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

# ── ADKERB-001: Kerberoastable Accounts ────────────────────────────────────
function Test-ReconADKERB001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $allAccounts = @($kerb.KerberoastableAccounts ?? @())

    # Exclude krbtgt - it always has SPNs but is not a Kerberoasting target in the
    # traditional sense (its key is the KDC key, not crackable via normal means)
    $accounts = @($allAccounts | Where-Object {
        ($_.SamAccountName ?? '') -ne 'krbtgt'
    })

    if ($accounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Kerberoastable user accounts found (no user accounts with SPNs, excluding krbtgt)' `
            -Details @{ Count = 0 }
    }

    # Separate high-risk (AdminCount > 0) from standard accounts
    $adminAccounts = @($accounts | Where-Object { [int]($_.AdminCount ?? 0) -gt 0 })
    $standardAccounts = @($accounts | Where-Object { [int]($_.AdminCount ?? 0) -eq 0 })

    $now = [datetime]::UtcNow
    $accountDetails = [System.Collections.Generic.List[hashtable]]::new()

    # List admin accounts first (highest risk), then standard
    $ordered = @($adminAccounts) + @($standardAccounts)

    foreach ($acct in $ordered) {
        $pwdAgeDays = $null
        $pwdLastSet = $acct.PwdLastSet
        if ($null -ne $pwdLastSet) {
            $pwdDate = $null
            if ($pwdLastSet -is [datetime]) {
                $pwdDate = $pwdLastSet
            } elseif ($pwdLastSet -is [long] -or $pwdLastSet -is [int64]) {
                if ($pwdLastSet -gt 0) {
                    try { $pwdDate = [datetime]::FromFileTimeUtc($pwdLastSet) } catch { }
                }
            }
            if ($null -ne $pwdDate) {
                $pwdAgeDays = [Math]::Round(($now - $pwdDate).TotalDays, 0)
            }
        }

        $spnCount = @($acct.SPNs ?? @()).Count
        $isAdmin = [int]($acct.AdminCount ?? 0) -gt 0

        $accountDetails.Add(@{
            SamAccountName  = $acct.SamAccountName ?? 'Unknown'
            IsAdmin         = $isAdmin
            SPNCount        = $spnCount
            PasswordAgeDays = $pwdAgeDays
        })
    }

    $currentValue = "$($accounts.Count) Kerberoastable account(s) found"
    if ($adminAccounts.Count -gt 0) {
        $currentValue += " ($($adminAccounts.Count) with AdminCount > 0 - HIGH RISK)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            TotalCount    = $accounts.Count
            AdminCount    = $adminAccounts.Count
            StandardCount = $standardAccounts.Count
            Accounts      = @($accountDetails)
        }
}

# ── ADKERB-002: Kerberoastable Accounts with Weak Encryption ──────────────
function Test-ReconADKERB002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $allAccounts = @($kerb.KerberoastableAccounts ?? @())

    # Exclude krbtgt
    $accounts = @($allAccounts | Where-Object {
        ($_.SamAccountName ?? '') -ne 'krbtgt'
    })

    if ($accounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Kerberoastable accounts to evaluate for encryption types' `
            -Details @{ Count = 0 }
    }

    # Encryption type flags:
    #   1 = DES-CBC-CRC, 2 = DES-CBC-MD5, 4 = RC4-HMAC
    #   8 = AES128-CTS-HMAC-SHA1, 16 = AES256-CTS-HMAC-SHA1
    # A value of 0 or null means no explicit encryption type is set, which defaults
    # to RC4-HMAC (the weakest commonly used cipher).
    $FLAG_DES  = 3   # bits 1 + 2
    $FLAG_RC4  = 4
    $FLAG_AES  = 24  # bits 8 + 16

    $weakAccounts = [System.Collections.Generic.List[hashtable]]::new()
    $rc4DefaultAccounts = [System.Collections.Generic.List[hashtable]]::new()
    $desAccounts = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($acct in $accounts) {
        # Read msDS-SupportedEncryptionTypes from available properties
        $encType = 0
        if ($null -ne $acct.EncryptionTypes) {
            $encType = [int]$acct.EncryptionTypes
        } elseif ($null -ne $acct.SupportedEncryptionTypes) {
            $encType = [int]$acct.SupportedEncryptionTypes
        } elseif ($null -ne $acct.EncryptionType) {
            $encType = [int]$acct.EncryptionType
        }

        $hasDES = ($encType -band $FLAG_DES) -ne 0
        $hasRC4 = ($encType -band $FLAG_RC4) -ne 0
        $hasAES = ($encType -band $FLAG_AES) -ne 0

        # If encType is 0 or not set, the account defaults to RC4
        $isDefaultRC4 = ($encType -eq 0)

        $isWeak = $false
        $reason = ''

        if ($hasDES) {
            $isWeak = $true
            $reason = 'DES enabled'
            $desAccounts.Add(@{
                SamAccountName = $acct.SamAccountName ?? 'Unknown'
                EncryptionType = $encType
                AdminCount     = [int]($acct.AdminCount ?? 0)
            })
        }

        if ($isDefaultRC4) {
            $isWeak = $true
            $reason = 'No encryption type set (defaults to RC4)'
            $rc4DefaultAccounts.Add(@{
                SamAccountName = $acct.SamAccountName ?? 'Unknown'
                EncryptionType = $encType
                AdminCount     = [int]($acct.AdminCount ?? 0)
            })
        } elseif ($hasRC4 -and -not $hasAES) {
            $isWeak = $true
            $reason = 'RC4 only (no AES)'
        }

        if ($isWeak) {
            $weakAccounts.Add(@{
                SamAccountName = $acct.SamAccountName ?? 'Unknown'
                EncryptionType = $encType
                HasDES         = $hasDES
                HasRC4         = $hasRC4 -or $isDefaultRC4
                HasAES         = $hasAES
                AdminCount     = [int]($acct.AdminCount ?? 0)
                Reason         = $reason
            })
        }
    }

    if ($weakAccounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "All $($accounts.Count) Kerberoastable account(s) support AES encryption" `
            -Details @{
                TotalChecked = $accounts.Count
                WeakCount    = 0
            }
    }

    $adminWeak = @($weakAccounts | Where-Object { [int]($_.AdminCount ?? 0) -gt 0 })

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($desAccounts.Count -gt 0) {
        $issues.Add("$($desAccounts.Count) account(s) with DES enabled")
    }
    if ($rc4DefaultAccounts.Count -gt 0) {
        $issues.Add("$($rc4DefaultAccounts.Count) account(s) with no encryption type set (defaults to RC4)")
    }
    $rc4OnlyCount = @($weakAccounts | Where-Object { $_.Reason -eq 'RC4 only (no AES)' }).Count
    if ($rc4OnlyCount -gt 0) {
        $issues.Add("$rc4OnlyCount account(s) with RC4 only (no AES)")
    }

    $currentValue = "$($weakAccounts.Count) of $($accounts.Count) Kerberoastable account(s) use weak encryption: $($issues -join '; ')"
    if ($adminWeak.Count -gt 0) {
        $currentValue += " ($($adminWeak.Count) privileged)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            TotalChecked     = $accounts.Count
            WeakCount        = $weakAccounts.Count
            AdminWeakCount   = $adminWeak.Count
            DESCount         = $desAccounts.Count
            RC4DefaultCount  = $rc4DefaultAccounts.Count
            RC4OnlyCount     = $rc4OnlyCount
            WeakAccounts     = @($weakAccounts)
        }
}

# ── ADKERB-003: AS-REP Roastable Accounts ─────────────────────────────────
function Test-ReconADKERB003 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $accounts = @($kerb.ASREPRoastableAccounts ?? @())

    if ($accounts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No AS-REP roastable accounts found (no accounts with pre-authentication disabled)' `
            -Details @{ Count = 0 }
    }

    $adminAccounts = @($accounts | Where-Object { [int]($_.AdminCount ?? 0) -gt 0 })

    $accountList = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($acct in $accounts) {
        $pwdAgeDays = $null
        $pwdLastSet = $acct.PwdLastSet
        if ($null -ne $pwdLastSet) {
            $pwdDate = $null
            if ($pwdLastSet -is [datetime]) {
                $pwdDate = $pwdLastSet
            } elseif ($pwdLastSet -is [long] -or $pwdLastSet -is [int64]) {
                if ($pwdLastSet -gt 0) {
                    try { $pwdDate = [datetime]::FromFileTimeUtc($pwdLastSet) } catch { }
                }
            }
            if ($null -ne $pwdDate) {
                $pwdAgeDays = [Math]::Round(([datetime]::UtcNow - $pwdDate).TotalDays, 0)
            }
        }

        $accountList.Add(@{
            SamAccountName  = $acct.SamAccountName ?? 'Unknown'
            IsAdmin         = [int]($acct.AdminCount ?? 0) -gt 0
            PasswordAgeDays = $pwdAgeDays
        })
    }

    $currentValue = "$($accounts.Count) AS-REP roastable account(s) found (pre-authentication disabled)"
    if ($adminAccounts.Count -gt 0) {
        $currentValue += " ($($adminAccounts.Count) with AdminCount > 0 - HIGH RISK)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue $currentValue `
        -Details @{
            TotalCount = $accounts.Count
            AdminCount = $adminAccounts.Count
            Accounts   = @($accountList)
        }
}

# ── ADKERB-004: Unconstrained Delegation (Computers) ──────────────────────
function Test-ReconADKERB004 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $allUnconstrained = @($kerb.UnconstrainedDelegation ?? @())

    # Filter to computer objects only (the data collector already excludes DCs
    # via the LDAP filter which removes SERVER_TRUST_ACCOUNT objects)
    $computers = @($allUnconstrained | Where-Object {
        $classes = @($_.ObjectClass ?? @())
        ($classes -contains 'computer') -or ($classes -contains 'Computer')
    })

    if ($computers.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No non-DC computers with unconstrained delegation found' `
            -Details @{ Count = 0 }
    }

    $computerDetails = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($comp in $computers) {
        $computerDetails.Add(@{
            SamAccountName = $comp.SamAccountName ?? 'Unknown'
            DnsHostName    = $comp.DnsHostName ?? ''
            DN             = $comp.DN ?? ''
        })
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($computers.Count) non-DC computer(s) with unconstrained delegation. These can be exploited to capture TGTs from any authenticating principal" `
        -Details @{
            Count     = $computers.Count
            Computers = @($computerDetails)
        }
}

# ── ADKERB-005: Unconstrained Delegation (Users) ──────────────────────────
function Test-ReconADKERB005 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $allUnconstrained = @($kerb.UnconstrainedDelegation ?? @())

    # Filter to user objects (objectClass contains 'user' but NOT 'computer',
    # since computer objects also inherit from user)
    $users = @($allUnconstrained | Where-Object {
        $classes = @($_.ObjectClass ?? @())
        ($classes -contains 'user') -and -not ($classes -contains 'computer')
    })

    if ($users.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No user accounts with unconstrained delegation found' `
            -Details @{ Count = 0 }
    }

    $userDetails = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($u in $users) {
        $userDetails.Add(@{
            SamAccountName = $u.SamAccountName ?? 'Unknown'
            DN             = $u.DN ?? ''
        })
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "CRITICAL: $($users.Count) user account(s) with unconstrained delegation. User accounts should never have unconstrained delegation as compromise allows TGT theft for any authenticating user" `
        -Details @{
            Count = $users.Count
            Users = @($userDetails)
        }
}

# ── ADKERB-006: Constrained Delegation Review ─────────────────────────────
function Test-ReconADKERB006 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $constrained = @($kerb.ConstrainedDelegation ?? @())

    if ($constrained.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No objects with constrained delegation configured' `
            -Details @{ Count = 0 }
    }

    # Sensitive service classes that, when delegated to on a DC, enable privilege escalation
    $sensitiveServices = @('ldap', 'cifs', 'gc', 'host', 'wsman', 'http', 'krbtgt')

    $delegationDetails = [System.Collections.Generic.List[hashtable]]::new()
    $highRiskCount = 0

    foreach ($obj in $constrained) {
        $targets = @($obj.AllowedToDelegateTo ?? @())
        $objClasses = @($obj.ObjectClass ?? @())

        $highRiskTargets = [System.Collections.Generic.List[string]]::new()
        foreach ($target in $targets) {
            $serviceClass = ($target -split '/')[0].ToLower()
            if ($serviceClass -in $sensitiveServices) {
                $highRiskTargets.Add($target)
            }
        }

        if ($highRiskTargets.Count -gt 0) {
            $highRiskCount++
        }

        $delegationDetails.Add(@{
            Name              = $obj.SamAccountName ?? $obj.Name ?? 'Unknown'
            ObjectClass       = if ($objClasses.Count -gt 0) { $objClasses[-1] } else { 'Unknown' }
            DelegationTargets = $targets
            TargetCount       = $targets.Count
            HighRiskTargets   = @($highRiskTargets)
        })
    }

    $currentValue = "$($constrained.Count) object(s) with constrained delegation configured"
    if ($highRiskCount -gt 0) {
        $currentValue += " ($highRiskCount with delegation to sensitive services - review urgently)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue $currentValue `
        -Details @{
            Count         = $constrained.Count
            HighRiskCount = $highRiskCount
            Delegations   = @($delegationDetails)
        }
}

# ── ADKERB-007: Resource-Based Constrained Delegation (RBCD) ──────────────
function Test-ReconADKERB007 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $rbcd = @($kerb.RBCD ?? @())

    if ($rbcd.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No objects with resource-based constrained delegation (RBCD) configured' `
            -Details @{ Count = 0 }
    }

    $rbcdDetails = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($obj in $rbcd) {
        $principals = @($obj.AllowedPrincipals ?? @())
        $principalNames = [System.Collections.Generic.List[string]]::new()

        foreach ($p in $principals) {
            if ($p -is [hashtable]) {
                $principalNames.Add($p.Identity ?? $p.SID ?? 'Unknown')
            } elseif ($p -is [string]) {
                $principalNames.Add($p)
            } else {
                $principalNames.Add('Unknown')
            }
        }

        $rbcdDetails.Add(@{
            Name              = $obj.SamAccountName ?? $obj.Name ?? 'Unknown'
            AllowedPrincipals = @($principalNames)
            PrincipalCount    = $principalNames.Count
        })
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "$($rbcd.Count) object(s) with RBCD configured. Review to ensure no unauthorized delegation paths exist" `
        -Details @{
            Count       = $rbcd.Count
            RBCDObjects = @($rbcdDetails)
        }
}

# ── ADKERB-008: Protocol Transition Abuse Paths ──────────────────────────
function Test-ReconADKERB008 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $t2a4d = @($kerb.ProtocolTransition ?? @())

    if ($t2a4d.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No objects with Kerberos protocol transition (T2A4D) flag set' `
            -Details @{ Count = 0 }
    }

    # Build a lookup of objects that also have constrained delegation targets
    $constrainedSet = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::OrdinalIgnoreCase)
    $constrainedObjs = @($kerb.ConstrainedDelegation ?? @())
    foreach ($c in $constrainedObjs) {
        $name = $c.SamAccountName ?? ''
        if ($name) { [void]$constrainedSet.Add($name) }
    }

    $objectDetails = [System.Collections.Generic.List[hashtable]]::new()
    $abusePathCount = 0

    foreach ($obj in $t2a4d) {
        $objClasses = @($obj.ObjectClass ?? @())
        $targets = @($obj.AllowedToDelegateTo ?? @())
        $name = $obj.SamAccountName ?? $obj.Name ?? 'Unknown'

        # An object with T2A4D AND constrained delegation targets has full abuse
        # potential: it can perform S4U2Self to get a forwardable ticket for any
        # user, then S4U2Proxy to the delegation target services.
        $hasConstrainedDelegation = ($targets.Count -gt 0) -or $constrainedSet.Contains($name)

        if ($hasConstrainedDelegation) {
            $abusePathCount++
        }

        $objectDetails.Add(@{
            Name                    = $name
            ObjectClass             = if ($objClasses.Count -gt 0) { $objClasses[-1] } else { 'Unknown' }
            DelegationTargets       = $targets
            HasConstrainedDelegation = $hasConstrainedDelegation
        })
    }

    # FAIL if any T2A4D accounts also have constrained delegation (full abuse path)
    $status = if ($abusePathCount -gt 0) { 'FAIL' } else { 'WARN' }

    $currentValue = "$($t2a4d.Count) object(s) with protocol transition (TrustedToAuthForDelegation) enabled"
    if ($abusePathCount -gt 0) {
        $currentValue += ". $abusePathCount have constrained delegation targets (S4U2Self + S4U2Proxy abuse path)"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            Count          = $t2a4d.Count
            AbusePathCount = $abusePathCount
            Objects        = @($objectDetails)
        }
}

# ── ADKERB-009: Kerberos Encryption Type Audit ───────────────────────────
function Test-ReconADKERB009 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $encTypes = $kerb.EncryptionTypes
    if (-not $encTypes -or -not $encTypes.Summary) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Encryption type data not available'
    }

    # Encryption type bit flags
    $FLAG_DES = 3   # bits 1 (DES-CBC-CRC) + 2 (DES-CBC-MD5)
    $FLAG_RC4 = 4   # RC4-HMAC
    $FLAG_AES = 24  # bits 8 (AES128) + 16 (AES256)

    # ── Analyze DC encryption types ──
    $summary = $encTypes.Summary
    $dcs = @($encTypes.DomainControllers ?? $encTypes.DCs ?? @())
    $totalDCs  = [int]($summary.TotalDCs ?? $dcs.Count)
    $dcDESCount = [int]($summary.DESEnabled ?? 0)
    $dcRC4Count = [int]($summary.RC4Enabled ?? 0)
    $dcAESCount = [int]($summary.AESEnabled ?? 0)

    # Count DCs with RC4 only (no AES)
    $dcRC4OnlyCount = 0
    foreach ($dc in $dcs) {
        $hasAES = [bool]($dc.HasAES ?? $false)
        $hasRC4 = [bool]($dc.HasRC4 ?? $false)
        if ($hasRC4 -and -not $hasAES) {
            $dcRC4OnlyCount++
        }
    }

    # ── Analyze Kerberoastable account encryption types ──
    $kerbAccounts = @($kerb.KerberoastableAccounts ?? @())
    $acctDESCount = 0
    $acctRC4OnlyCount = 0
    $acctNoEncTypeCount = 0
    $acctAESCount = 0

    foreach ($acct in $kerbAccounts) {
        $encVal = 0
        if ($null -ne $acct.SupportedEncryptionTypes) {
            $encVal = [int]$acct.SupportedEncryptionTypes
        } elseif ($null -ne $acct.EncryptionType) {
            $encVal = [int]$acct.EncryptionType
        }

        $hasDES = ($encVal -band $FLAG_DES) -ne 0
        $hasRC4 = ($encVal -band $FLAG_RC4) -ne 0
        $hasAES = ($encVal -band $FLAG_AES) -ne 0

        if ($encVal -eq 0) {
            $acctNoEncTypeCount++
        }
        if ($hasDES) { $acctDESCount++ }
        if (($hasRC4 -or $encVal -eq 0) -and -not $hasAES) { $acctRC4OnlyCount++ }
        if ($hasAES) { $acctAESCount++ }
    }

    # ── Determine overall status ──
    $hasDESAnywhere = ($dcDESCount -gt 0) -or ($acctDESCount -gt 0)
    $hasRC4OnlyAnywhere = ($dcRC4OnlyCount -gt 0) -or ($acctRC4OnlyCount -gt 0)

    $status = if ($hasDESAnywhere -or $hasRC4OnlyAnywhere) { 'FAIL' }
              elseif ($dcRC4Count -gt 0 -or $acctNoEncTypeCount -gt 0) { 'WARN' }
              else { 'PASS' }

    # ── Build summary message ──
    $issues = [System.Collections.Generic.List[string]]::new()
    if ($dcDESCount -gt 0) { $issues.Add("$dcDESCount DC(s) support DES (critically weak)") }
    if ($dcRC4OnlyCount -gt 0) { $issues.Add("$dcRC4OnlyCount DC(s) support only RC4 without AES") }
    if ($acctDESCount -gt 0) { $issues.Add("$acctDESCount SPN account(s) have DES enabled") }
    if ($acctRC4OnlyCount -gt 0) { $issues.Add("$acctRC4OnlyCount SPN account(s) use RC4 only or default to RC4") }
    if ($dcRC4Count -gt 0 -and $status -eq 'WARN') {
        $issues.Add("$dcRC4Count DC(s) still support RC4 alongside AES")
    }
    if ($acctNoEncTypeCount -gt 0 -and $status -eq 'WARN') {
        $issues.Add("$acctNoEncTypeCount SPN account(s) have no encryption type set (defaults to RC4)")
    }

    $currentValue = if ($issues.Count -gt 0) {
        "Encryption issues: $($issues -join '; ')"
    } else {
        "All $totalDCs DC(s) and $($kerbAccounts.Count) SPN account(s) support AES encryption"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            DomainControllers = @{
                TotalDCs     = $totalDCs
                DESEnabled   = $dcDESCount
                RC4Enabled   = $dcRC4Count
                AESEnabled   = $dcAESCount
                RC4OnlyCount = $dcRC4OnlyCount
            }
            SPNAccounts       = @{
                TotalAccounts   = $kerbAccounts.Count
                DESEnabled      = $acctDESCount
                RC4OnlyOrDefault = $acctRC4OnlyCount
                NoEncTypeSet    = $acctNoEncTypeCount
                AESEnabled      = $acctAESCount
            }
            Issues            = @($issues)
        }
}

# ── ADKERB-010: Kerberos Ticket Lifetime ───────────────────────────────────
function Test-ReconADKERB010 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    $policy = $kerb.KerberosPolicy
    if (-not $policy -or $policy.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos policy data not available. Verify Default Domain Policy via GPMC for ticket lifetime settings'
    }

    # Check if there was an error reading the policy
    if ($policy.ContainsKey('Error') -and $policy.Error) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "Could not read Kerberos policy: $($policy.Error)" `
            -Details @{ Error = $policy.Error }
    }

    $maxTicketAge  = $policy.MaxTicketAge
    $maxRenewAge   = $policy.MaxRenewAge
    $maxServiceAge = $policy.MaxServiceAge
    $maxClockSkew  = $policy.MaxClockSkew

    $issues = [System.Collections.Generic.List[string]]::new()

    # MaxTicketAge is in hours; recommended <= 10
    if ($null -ne $maxTicketAge -and [int]$maxTicketAge -gt 10) {
        $issues.Add("MaxTicketAge=${maxTicketAge}h (recommended: <=10h)")
    }
    # MaxRenewAge is in days; recommended <= 7
    if ($null -ne $maxRenewAge -and [int]$maxRenewAge -gt 7) {
        $issues.Add("MaxRenewAge=${maxRenewAge}d (recommended: <=7d)")
    }

    # FAIL if thresholds exceeded, not just WARN
    $status = if ($issues.Count -gt 0) { 'FAIL' } else { 'PASS' }

    $currentValue = "Kerberos policy: MaxTicketAge=$(if ($null -ne $maxTicketAge) { "${maxTicketAge}h" } else { 'N/A' }), " +
        "MaxRenewAge=$(if ($null -ne $maxRenewAge) { "${maxRenewAge}d" } else { 'N/A' }), " +
        "MaxServiceAge=$(if ($null -ne $maxServiceAge) { "${maxServiceAge}min" } else { 'N/A' }), " +
        "MaxClockSkew=$(if ($null -ne $maxClockSkew) { "${maxClockSkew}min" } else { 'N/A' })"

    if ($issues.Count -gt 0) {
        $currentValue += ". Issues: $($issues -join '; ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            MaxTicketAge  = $maxTicketAge
            MaxRenewAge   = $maxRenewAge
            MaxServiceAge = $maxServiceAge
            MaxClockSkew  = $maxClockSkew
            Issues        = @($issues)
        }
}

# ── ADKERB-011: Computer SPN Audit ────────────────────────────────────────
function Test-ReconADKERB011 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'KerberosConfig' -Subject 'Kerberos configuration'
    if ($na) { return $na }

    $kerb = $AuditData.Kerberos
    if (-not $kerb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Kerberos configuration data not available'
    }

    # ── Aggregate SPN statistics from all available sources ──

    # User SPNs (Kerberoastable accounts)
    $kerbAccounts = @($kerb.KerberoastableAccounts ?? @())
    $totalUserSPNs = 0
    $userSPNServiceTypes = @{}

    foreach ($acct in $kerbAccounts) {
        $spns = @($acct.SPNs ?? @())
        $totalUserSPNs += $spns.Count

        foreach ($spn in $spns) {
            $serviceClass = ($spn -split '/')[0]
            if ($serviceClass) {
                if ($userSPNServiceTypes.ContainsKey($serviceClass)) {
                    $userSPNServiceTypes[$serviceClass]++
                } else {
                    $userSPNServiceTypes[$serviceClass] = 1
                }
            }
        }
    }

    # Constrained delegation target SPNs
    $constrainedTargets = @($kerb.ConstrainedDelegation ?? @())
    $delegationSPNCount = 0
    $delegationServiceTypes = @{}

    foreach ($obj in $constrainedTargets) {
        $targets = @($obj.AllowedToDelegateTo ?? @())
        $delegationSPNCount += $targets.Count

        foreach ($target in $targets) {
            $serviceClass = ($target -split '/')[0]
            if ($serviceClass) {
                if ($delegationServiceTypes.ContainsKey($serviceClass)) {
                    $delegationServiceTypes[$serviceClass]++
                } else {
                    $delegationServiceTypes[$serviceClass] = 1
                }
            }
        }
    }

    # Merge all service types for overall inventory
    $allServiceTypes = @{}
    foreach ($entry in $userSPNServiceTypes.GetEnumerator()) {
        $allServiceTypes[$entry.Key] = $entry.Value
    }
    foreach ($entry in $delegationServiceTypes.GetEnumerator()) {
        if ($allServiceTypes.ContainsKey($entry.Key)) {
            $allServiceTypes[$entry.Key] += $entry.Value
        } else {
            $allServiceTypes[$entry.Key] = $entry.Value
        }
    }

    # Build sorted service type summary
    $serviceTypeSummary = [ordered]@{}
    foreach ($entry in ($allServiceTypes.GetEnumerator() | Sort-Object Value -Descending)) {
        $serviceTypeSummary[$entry.Key] = $entry.Value
    }

    $totalSPNs = $totalUserSPNs + $delegationSPNCount

    $currentValue = "$totalUserSPNs SPN(s) across $($kerbAccounts.Count) Kerberoastable user account(s). " +
        "$($allServiceTypes.Count) distinct service type(s). " +
        "$delegationSPNCount constrained delegation target SPN(s)"

    # INFO check - report inventory for awareness and documentation
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $currentValue `
        -Details @{
            TotalSPNs            = $totalSPNs
            TotalUserSPNs        = $totalUserSPNs
            KerberoastableUsers  = $kerbAccounts.Count
            DelegationTargetSPNs = $delegationSPNCount
            DistinctServiceTypes = $allServiceTypes.Count
            ServiceTypes         = $serviceTypeSummary
        }
}
