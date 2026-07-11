# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-IntuneChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'IntuneChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
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

# ── INTUNE-001: Compliance Policy Inventory ──────────────────────────────
function Test-InfiltrationINTUNE001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'CompliancePolicies') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $policies = $intune.CompliancePolicies
    if (-not $policies -or $policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No Intune compliance policies found' `
            -Details @{ PolicyCount = 0 }
    }

    # Group by platform/type
    $byType = @{}
    foreach ($p in $policies) {
        $type = $p.'@odata.type' ?? 'Unknown'
        if (-not $byType.ContainsKey($type)) { $byType[$type] = 0 }
        $byType[$type]++
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) compliance policies configured" `
        -Details @{
            PolicyCount = $policies.Count
            ByType = @($byType.GetEnumerator() | ForEach-Object {
                @{ Type = $_.Key; Count = $_.Value }
            })
            Policies = @($policies | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    Type = $_.'@odata.type'
                    CreatedDateTime = $_.createdDateTime
                }
            })
        }
}

# ── INTUNE-002: Compliance Summary ───────────────────────────────────────
function Test-InfiltrationINTUNE002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'ComplianceSummary') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.ComplianceSummary) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune compliance summary not available'
    }

    $summary = $intune.ComplianceSummary
    $compliant = $summary.compliantDeviceCount ?? 0
    $nonCompliant = $summary.nonCompliantDeviceCount ?? 0
    $inGracePeriod = $summary.inGracePeriodCount ?? 0
    $notEvaluated = $summary.notEvaluatedDeviceCount ?? 0
    $errorCount = $summary.errorDeviceCount ?? 0
    $conflict = $summary.conflictDeviceCount ?? 0

    $total = $compliant + $nonCompliant + $inGracePeriod + $notEvaluated + $errorCount + $conflict
    $nonCompliantPct = if ($total -gt 0) { [Math]::Round(($nonCompliant / $total) * 100, 1) } else { 0 }

    $status = if ($nonCompliant -eq 0) { 'PASS' }
              elseif ($nonCompliantPct -le 10) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Compliance: $compliant compliant, $nonCompliant non-compliant ($nonCompliantPct%), $inGracePeriod grace period, $errorCount errors" `
        -Details @{
            Compliant = $compliant
            NonCompliant = $nonCompliant
            InGracePeriod = $inGracePeriod
            NotEvaluated = $notEvaluated
            Error = $errorCount
            Conflict = $conflict
            Total = $total
            NonCompliantPercentage = $nonCompliantPct
        }
}

# ── INTUNE-003: Non-Compliant Devices ───────────────────────────────────
function Test-InfiltrationINTUNE003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'ManagedDevices') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.ManagedDevices) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Managed device data not available'
    }

    $devices = $intune.ManagedDevices
    $nonCompliant = @($devices | Where-Object { $_.complianceState -ne 'compliant' })
    $total = $devices.Count
    $pct = if ($total -gt 0) { [Math]::Round(($nonCompliant.Count / $total) * 100, 1) } else { 0 }

    $status = if ($nonCompliant.Count -eq 0) { 'PASS' }
              elseif ($pct -le 10) { 'WARN' }
              else { 'FAIL' }

    # Group non-compliant by compliance state
    $byState = @{}
    foreach ($d in $nonCompliant) {
        $state = $d.complianceState ?? 'unknown'
        if (-not $byState.ContainsKey($state)) { $byState[$state] = 0 }
        $byState[$state]++
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($nonCompliant.Count) of $total devices non-compliant ($pct%)" `
        -Details @{
            NonCompliantCount = $nonCompliant.Count
            TotalDevices = $total
            Percentage = $pct
            ByState = @($byState.GetEnumerator() | ForEach-Object {
                @{ State = $_.Key; Count = $_.Value }
            })
            Devices = @($nonCompliant | Select-Object -First 50 | ForEach-Object {
                @{
                    DeviceName = $_.deviceName
                    OS = $_.operatingSystem
                    ComplianceState = $_.complianceState
                    LastSync = $_.lastSyncDateTime
                }
            })
        }
}

# ── INTUNE-004: Configuration Profile Inventory ─────────────────────────
function Test-InfiltrationINTUNE004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $configs = $intune.DeviceConfigurations
    if (-not $configs -or $configs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No device configuration profiles found' `
            -Details @{ ProfileCount = 0 }
    }

    $byType = @{}
    foreach ($c in $configs) {
        $type = $c.'@odata.type' ?? 'Unknown'
        if (-not $byType.ContainsKey($type)) { $byType[$type] = 0 }
        $byType[$type]++
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($configs.Count) device configuration profiles" `
        -Details @{
            ProfileCount = $configs.Count
            ByType = @($byType.GetEnumerator() | ForEach-Object {
                @{ Type = $_.Key; Count = $_.Value }
            })
            Profiles = @($configs | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    Type = $_.'@odata.type'
                    CreatedDateTime = $_.createdDateTime
                }
            })
        }
}

# ── INTUNE-005: Configuration Profile Assignment Analysis ───────────────
function Test-InfiltrationINTUNE005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.DeviceConfigurations) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Device configuration data not available'
    }

    $configs = $intune.DeviceConfigurations
    # Check for unassigned profiles (no assignments property or empty)
    $unassigned = @($configs | Where-Object {
        -not $_.assignments -or $_.assignments.Count -eq 0
    })

    $status = if ($unassigned.Count -eq 0) { 'PASS' }
              elseif ($unassigned.Count -le 3) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($unassigned.Count) of $($configs.Count) configuration profiles appear unassigned" `
        -Details @{
            TotalProfiles = $configs.Count
            UnassignedCount = $unassigned.Count
            Unassigned = @($unassigned | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; Type = $_.'@odata.type' }
            })
        }
}

# ── INTUNE-006: Windows Update Rings ────────────────────────────────────
function Test-InfiltrationINTUNE006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.DeviceConfigurations) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Device configuration data not available'
    }

    $updateConfigs = @($intune.DeviceConfigurations | Where-Object {
        $_.'@odata.type' -match 'windowsUpdateForBusiness' -or
        $_.'@odata.type' -match 'Update' -or
        $_.displayName -match 'update ring|windows update'
    })

    if ($updateConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Windows Update ring configurations found' `
            -Details @{ UpdateRingCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($updateConfigs.Count) Windows Update ring configurations found" `
        -Details @{
            UpdateRingCount = $updateConfigs.Count
            Rings = @($updateConfigs | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    Type = $_.'@odata.type'
                }
            })
        }
}

# ── INTUNE-007: BitLocker / Encryption Configuration ───────────────────
function Test-InfiltrationINTUNE007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.DeviceConfigurations) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Device configuration data not available'
    }

    $encryptionConfigs = @($intune.DeviceConfigurations | Where-Object {
        $_.'@odata.type' -match 'bitLocker|encryption' -or
        $_.displayName -match 'BitLocker|encryption|disk encrypt'
    })

    if ($encryptionConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No BitLocker/encryption configuration profiles found' `
            -Details @{ EncryptionConfigCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($encryptionConfigs.Count) encryption configuration profile(s) found" `
        -Details @{
            EncryptionConfigCount = $encryptionConfigs.Count
            Configs = @($encryptionConfigs | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; Type = $_.'@odata.type' }
            })
        }
}

# ── INTUNE-008: Defender / Antivirus Configuration ─────────────────────
function Test-InfiltrationINTUNE008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.DeviceConfigurations) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Device configuration data not available'
    }

    $defenderConfigs = @($intune.DeviceConfigurations | Where-Object {
        $_.'@odata.type' -match 'defender|antivirus|endpointProtection' -or
        $_.displayName -match 'Defender|antivirus|endpoint protection|AV policy'
    })

    if ($defenderConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No Defender/antivirus configuration profiles found' `
            -Details @{ DefenderConfigCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($defenderConfigs.Count) Defender/antivirus configuration profile(s) found" `
        -Details @{
            DefenderConfigCount = $defenderConfigs.Count
            Configs = @($defenderConfigs | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; Type = $_.'@odata.type' }
            })
        }
}

# ── INTUNE-009: Attack Surface Reduction (ASR) ─────────────────────────
function Test-InfiltrationINTUNE009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.DeviceConfigurations) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Device configuration data not available'
    }

    $asrConfigs = @($intune.DeviceConfigurations | Where-Object {
        $_.'@odata.type' -match 'attackSurfaceReduction|asr' -or
        $_.displayName -match 'ASR|attack surface reduction'
    })

    if ($asrConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Attack Surface Reduction configuration profiles found' `
            -Details @{ ASRConfigCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($asrConfigs.Count) ASR configuration profile(s) found" `
        -Details @{
            ASRConfigCount = $asrConfigs.Count
            Configs = @($asrConfigs | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; Type = $_.'@odata.type' }
            })
        }
}

# ── INTUNE-010: Endpoint Detection and Response (EDR) ──────────────────
function Test-InfiltrationINTUNE010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.DeviceConfigurations) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Device configuration data not available'
    }

    $edrConfigs = @($intune.DeviceConfigurations | Where-Object {
        $_.'@odata.type' -match 'endpointDetection|edr' -or
        $_.displayName -match 'EDR|endpoint detection|MDE|Microsoft Defender for Endpoint'
    })

    if ($edrConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No EDR configuration profiles found — verify MDE onboarding via another method' `
            -Details @{ EDRConfigCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($edrConfigs.Count) EDR configuration profile(s) found" `
        -Details @{
            EDRConfigCount = $edrConfigs.Count
            Configs = @($edrConfigs | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; Type = $_.'@odata.type' }
            })
        }
}

# ── INTUNE-011: App Protection Policies ─────────────────────────────────
function Test-InfiltrationINTUNE011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'AppProtectionPolicies') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $appPolicies = $intune.AppProtectionPolicies
    if (-not $appPolicies -or $appPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No app protection (MAM) policies found' `
            -Details @{ PolicyCount = 0 }
    }

    $byType = @{}
    foreach ($p in $appPolicies) {
        $type = $p.'@odata.type' ?? 'Unknown'
        if (-not $byType.ContainsKey($type)) { $byType[$type] = 0 }
        $byType[$type]++
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($appPolicies.Count) app protection policies configured" `
        -Details @{
            PolicyCount = $appPolicies.Count
            ByType = @($byType.GetEnumerator() | ForEach-Object {
                @{ Type = $_.Key; Count = $_.Value }
            })
            Policies = @($appPolicies | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    Type = $_.'@odata.type'
                }
            })
        }
}

# ── INTUNE-012: Conditional Launch Settings ─────────────────────────────
function Test-InfiltrationINTUNE012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'AppProtectionPolicies') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $appPolicies = $intune.AppProtectionPolicies
    if (-not $appPolicies -or $appPolicies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No app protection policies — conditional launch not configured' `
            -Details @{ PolicyCount = 0 }
    }

    # Check for policies with conditional launch actions (jailbreak, min OS, etc.)
    $withConditionalLaunch = @($appPolicies | Where-Object {
        $_.minimumRequiredOsVersion -or
        $_.minimumRequiredAppVersion -or
        $_.maximumRequiredOsVersion -or
        $_.'@odata.type' -match 'managedAppProtection'
    })

    $status = if ($withConditionalLaunch.Count -gt 0) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($withConditionalLaunch.Count) app protection policies with conditional launch settings" `
        -Details @{
            TotalPolicies = $appPolicies.Count
            WithConditionalLaunch = $withConditionalLaunch.Count
        }
}

# ── INTUNE-013: Enrollment Restrictions ─────────────────────────────────
function Test-InfiltrationINTUNE013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'EnrollmentConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $enrollConfigs = $intune.EnrollmentConfigurations
    if (-not $enrollConfigs -or $enrollConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No enrollment configurations found' `
            -Details @{ ConfigCount = 0 }
    }

    # Look for platform restrictions
    $platformRestrictions = @($enrollConfigs | Where-Object {
        $_.'@odata.type' -match 'deviceEnrollmentPlatformRestrictions' -or
        $_.'@odata.type' -match 'PlatformRestriction'
    })

    # Look for enrollment limit configurations
    $limitConfigs = @($enrollConfigs | Where-Object {
        $_.'@odata.type' -match 'deviceEnrollmentLimitConfiguration'
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($enrollConfigs.Count) enrollment configs ($($platformRestrictions.Count) platform restrictions, $($limitConfigs.Count) limit configs)" `
        -Details @{
            TotalConfigs = $enrollConfigs.Count
            PlatformRestrictions = $platformRestrictions.Count
            LimitConfigs = $limitConfigs.Count
            Configs = @($enrollConfigs | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    Type = $_.'@odata.type'
                    Priority = $_.priority
                }
            })
        }
}

# ── INTUNE-014: Autopilot Configuration ─────────────────────────────────
function Test-InfiltrationINTUNE014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'AutopilotProfiles') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $profiles = $intune.AutopilotProfiles
    if (-not $profiles -or $profiles.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Windows Autopilot deployment profiles found' `
            -Details @{ ProfileCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($profiles.Count) Autopilot deployment profile(s) configured" `
        -Details @{
            ProfileCount = $profiles.Count
            Profiles = @($profiles | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    DeviceNameTemplate = $_.deviceNameTemplate
                    Language = $_.language
                    ExtractHardwareHash = $_.extractHardwareHash
                }
            })
        }
}

# ── INTUNE-015: Disk Encryption Status ──────────────────────────────────
function Test-InfiltrationINTUNE015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'ManagedDevices') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.ManagedDevices) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Managed device data not available'
    }

    $devices = $intune.ManagedDevices
    $encrypted = @($devices | Where-Object { $_.isEncrypted -eq $true })
    $notEncrypted = @($devices | Where-Object { $_.isEncrypted -eq $false })
    $unknown = @($devices | Where-Object { $null -eq $_.isEncrypted })
    $total = $devices.Count

    $encryptedPct = if ($total -gt 0) { [Math]::Round(($encrypted.Count / $total) * 100, 1) } else { 0 }

    $status = if ($notEncrypted.Count -eq 0 -and $unknown.Count -eq 0) { 'PASS' }
              elseif ($encryptedPct -ge 90) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($encrypted.Count) of $total devices encrypted ($encryptedPct%), $($notEncrypted.Count) not encrypted, $($unknown.Count) unknown" `
        -Details @{
            Encrypted = $encrypted.Count
            NotEncrypted = $notEncrypted.Count
            Unknown = $unknown.Count
            Total = $total
            EncryptedPercentage = $encryptedPct
            NotEncryptedDevices = @($notEncrypted | Select-Object -First 50 | ForEach-Object {
                @{ DeviceName = $_.deviceName; OS = $_.operatingSystem; IsEncrypted = $_.isEncrypted }
            })
        }
}

# ── INTUNE-016: Firewall Policy ─────────────────────────────────────────
function Test-InfiltrationINTUNE016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceConfigurations') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune -or -not $intune.DeviceConfigurations) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Device configuration data not available'
    }

    $firewallConfigs = @($intune.DeviceConfigurations | Where-Object {
        $_.'@odata.type' -match 'firewall' -or
        $_.displayName -match 'firewall|windows firewall'
    })

    if ($firewallConfigs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No firewall configuration profiles found in Intune' `
            -Details @{ FirewallConfigCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($firewallConfigs.Count) firewall configuration profile(s) found" `
        -Details @{
            FirewallConfigCount = $firewallConfigs.Count
            Configs = @($firewallConfigs | ForEach-Object {
                @{ Id = $_.id; DisplayName = $_.displayName; Type = $_.'@odata.type' }
            })
        }
}

# ── INTUNE-017: Security Baselines ──────────────────────────────────────
function Test-InfiltrationINTUNE017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'SecurityBaselines') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $baselines = $intune.SecurityBaselines
    if (-not $baselines -or $baselines.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No security baseline templates found' `
            -Details @{ BaselineCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($baselines.Count) security baseline template(s) available" `
        -Details @{
            BaselineCount = $baselines.Count
            Baselines = @($baselines | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    TemplateType = $_.templateType
                    PublishedDateTime = $_.publishedDateTime
                }
            })
        }
}

# ── INTUNE-018: PowerShell Scripts Deployed ─────────────────────────────
function Test-InfiltrationINTUNE018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceManagementScripts') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $scripts = $intune.DeviceManagementScripts
    if (-not $scripts -or $scripts.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No PowerShell scripts deployed via Intune' `
            -Details @{ ScriptCount = 0 }
    }

    # PowerShell scripts deployed via Intune can be a security risk - review recommended
    $runAsSystem = @($scripts | Where-Object { $_.runAsAccount -eq 'system' })
    $unsignedScripts = @($scripts | Where-Object { $_.enforceSignatureCheck -ne $true })

    $status = if ($runAsSystem.Count -gt 0 -or $unsignedScripts.Count -gt 0) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($scripts.Count) PowerShell scripts deployed via Intune ($($runAsSystem.Count) run as SYSTEM, $($unsignedScripts.Count) unsigned)" `
        -Details @{
            ScriptCount = $scripts.Count
            RunAsSystemCount = $runAsSystem.Count
            Scripts = @($scripts | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    FileName = $_.fileName
                    RunAsAccount = $_.runAsAccount
                    EnforceSignatureCheck = $_.enforceSignatureCheck
                    CreatedDateTime = $_.createdDateTime
                }
            })
        }
}

# ── INTUNE-019: Win32 App Inventory ─────────────────────────────────────
function Test-InfiltrationINTUNE019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'MobileApps') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $apps = $intune.MobileApps
    $win32Apps = @($apps | Where-Object {
        $_.'@odata.type' -eq '#microsoft.graph.win32LobApp'
    })

    if ($win32Apps.Count -eq 0 -and $apps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Win32 apps found in Intune' `
            -Details @{ Win32AppCount = 0; TotalAppCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($win32Apps.Count) Win32 app(s) deployed (of $($apps.Count) total mobile apps)" `
        -Details @{
            Win32AppCount = $win32Apps.Count
            TotalAppCount = $apps.Count
            Win32Apps = @($win32Apps | Select-Object -First 50 | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    Publisher = $_.publisher
                    FileName = $_.fileName
                }
            })
        }
}

# ── INTUNE-020: Device Categories ───────────────────────────────────────
function Test-InfiltrationINTUNE020 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'DeviceCategories') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    $categories = $intune.DeviceCategories
    if (-not $categories -or $categories.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No device categories configured' `
            -Details @{ CategoryCount = 0 }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($categories.Count) device categor(ies) configured" `
        -Details @{
            CategoryCount = $categories.Count
            Categories = @($categories | ForEach-Object {
                @{
                    Id = $_.id
                    DisplayName = $_.displayName
                    Description = $_.description
                }
            })
        }
}

# ── INTUNE-021: Remote Actions Audit ────────────────────────────────────
function Test-InfiltrationINTUNE021 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'Remote actions audit requires Intune audit log data which is not collected in the current data set'
}

# ── INTUNE-022: OneDrive Known Folder Move / Sync ──────────────────────
function Test-InfiltrationINTUNE022 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'OneDrive sync configuration check requires OneDrive admin settings or device-level registry data not available via Graph'
}

# ── INTUNE-023: Multi-Admin Approval for Destructive Actions ─────────
function Test-InfiltrationINTUNE023 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.Intune.Errors) `
        -SourceKey @('Intune', 'OperationApprovalPolicies') -Subject 'Intune configuration'
    if ($na) { return $na }

    $intune = $AuditData.Intune
    if (-not $intune) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Intune data not available'
    }

    # Check if the API returned data (requires beta endpoint)
    if ($intune.Errors -and $intune.Errors['OperationApprovalPolicies']) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "Unable to query approval policies: $($intune.Errors['OperationApprovalPolicies'])"
    }

    $policies = $intune.OperationApprovalPolicies
    if (-not $policies -or $policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No multi-admin approval policies configured — destructive actions (bulk wipe, retire) can be executed by a single admin' `
            -Details @{
                PolicyCount          = 0
                Risk                 = 'A compromised admin account can trigger mass device wipes without secondary approval'
                RecommendedActions   = @('Wipe', 'Retire', 'Delete', 'ScriptDeployment')
            }
    }

    # Analyze what operation types are covered
    $coveredTypes = @($policies | ForEach-Object {
        if ($_.operationApprovalPolicyType) { $_.operationApprovalPolicyType }
    } | Select-Object -Unique)

    $policyDetails = @($policies | ForEach-Object {
        @{
            Id              = $_.id
            DisplayName     = $_.displayName
            PolicyType      = $_.operationApprovalPolicyType
            ApproverGroupIds = $_.approverGroupIds
        }
    })

    # Critical destructive types we want to see covered
    $destructiveTypes = @('deviceWipe', 'deviceRetire', 'deviceDelete')
    $coveredDestructive = @($coveredTypes | Where-Object { $_ -in $destructiveTypes })
    $missingDestructive = @($destructiveTypes | Where-Object { $_ -notin $coveredTypes })

    if ($coveredDestructive.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($policies.Count) approval policies found but none cover destructive device actions (wipe/retire/delete)" `
            -Details @{
                PolicyCount     = $policies.Count
                CoveredTypes    = $coveredTypes
                MissingCritical = $missingDestructive
                Policies        = $policyDetails
            }
    }

    if ($missingDestructive.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($policies.Count) approval policies configured, but missing coverage for: $($missingDestructive -join ', ')" `
            -Details @{
                PolicyCount     = $policies.Count
                CoveredTypes    = $coveredTypes
                MissingCritical = $missingDestructive
                Policies        = $policyDetails
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($policies.Count) multi-admin approval policies active, covering $($coveredTypes -join ', ')" `
        -Details @{
            PolicyCount  = $policies.Count
            CoveredTypes = $coveredTypes
            Policies     = $policyDetails
        }
}
