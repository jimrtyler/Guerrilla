# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-DeviceManagementChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'DeviceManagementChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Fortification$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_" -OrgUnitPath $OrgUnitPath))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented' -OrgUnitPath $OrgUnitPath))
        }
    }

    return @($findings)
}

# ── DEVICE-001: MDM Policy Audit ─────────────────────────────────────────
function Test-FortificationDEVICE001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'MobileDevices' -Subject 'mobile device inventory'
    if ($na) { return $na }

    if ($null -eq $AuditData.MobileDevices) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Mobile device data not available. Verify in Admin Console > Devices > Mobile devices that MDM policies are enforced' `
            -OrgUnitPath $OrgUnitPath
    }

    $devices = @($AuditData.MobileDevices)
    if ($devices.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No mobile devices registered' -OrgUnitPath $OrgUnitPath
    }

    $managed = @($devices | Where-Object {
        $_.status -eq 'APPROVED' -or $_.managementType -eq 'ADVANCED' -or $_.managementType -eq 'BASIC'
    })
    $unmanaged = @($devices | Where-Object {
        $_.status -ne 'APPROVED' -and $_.managementType -ne 'ADVANCED' -and $_.managementType -ne 'BASIC'
    })

    $managedRate = if ($devices.Count -gt 0) { [Math]::Round(($managed.Count / $devices.Count) * 100, 1) } else { 0 }

    $status = if ($managedRate -ge 95) { 'PASS' }
              elseif ($managedRate -ge 75) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$managedRate% ($($managed.Count) of $($devices.Count)) devices under MDM management" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            TotalDevices   = $devices.Count
            ManagedCount   = $managed.Count
            UnmanagedCount = $unmanaged.Count
            ManagedRate    = $managedRate
        }
}

# ── DEVICE-002: Device Approval Requirements ─────────────────────────────
function Test-FortificationDEVICE002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Device approval settings are OU-level policies not exposed via the Admin SDK directory API
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Device approval requirements not available via API. Verify in Admin Console > Devices > Mobile & endpoints > Settings that admin approval is required for device access' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Requiring device approval prevents unauthorized devices from accessing organizational data' }
}

# ── DEVICE-003: Screen Lock Enforcement ──────────────────────────────────
function Test-FortificationDEVICE003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Screen lock enforcement settings not available via API. Verify in Admin Console > Devices > Mobile & endpoints > Settings > Universal settings that screen lock is enforced' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Screen lock should be enforced with minimum PIN/password complexity to prevent unauthorized physical access' }
}

# ── DEVICE-004: Device Encryption Requirements ───────────────────────────
function Test-FortificationDEVICE004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Device encryption requirements not available via API. Verify in Admin Console > Devices > Mobile & endpoints > Settings that device encryption is required' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Encryption protects data at rest on devices in case of physical theft or loss' }
}

# ── DEVICE-005: Compromised Device Blocking ──────────────────────────────
function Test-FortificationDEVICE005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Compromised device blocking settings not available via API. Verify in Admin Console > Devices > Mobile & endpoints > Settings that compromised devices are blocked' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Compromised device detection should automatically block access to organizational data' }
}

# ── DEVICE-006: Jailbroken/Rooted Device Policy ─────────────────────────
function Test-FortificationDEVICE006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Jailbroken/rooted device policy not available via API. Verify in Admin Console > Devices > Mobile & endpoints > Settings that jailbroken/rooted devices are blocked' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Jailbroken (iOS) or rooted (Android) devices bypass OS security controls and should not access organizational data' }
}

# ── DEVICE-007: Chrome Browser Management ────────────────────────────────
function Test-FortificationDEVICE007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ChromePolicies' -Subject 'Chrome browser policies'
    if ($na) { return $na }

    if ($AuditData.ChromePolicies) {
        $policies = $AuditData.ChromePolicies
        $policyCount = if ($policies -is [array]) { $policies.Count }
                       elseif ($policies -is [hashtable]) { $policies.Keys.Count }
                       else { 0 }

        $status = if ($policyCount -gt 0) { 'PASS' } else { 'WARN' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "$policyCount Chrome browser policy setting(s) configured" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ PolicyCount = $policyCount }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chrome browser policy data not available. Verify in Admin Console > Devices > Chrome > Settings that browser management policies are configured' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Chrome Browser Cloud Management provides centralized policy enforcement for managed browsers' }
}

# ── DEVICE-008: Chrome Extension Whitelist/Blocklist ─────────────────────
function Test-FortificationDEVICE008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ChromePolicies' -Subject 'Chrome extension policies'
    if ($na) { return $na }

    # Chrome extension policies are part of Chrome Browser Cloud Management
    if ($AuditData.ChromePolicies) {
        $policies = $AuditData.ChromePolicies
        # Look for extension-related policies
        $extensionPolicy = $null
        if ($policies -is [hashtable]) {
            $extensionPolicy = $policies['ExtensionInstallBlocklist'] ?? $policies['ExtensionInstallAllowlist'] ??
                               $policies['ExtensionInstallForcelist']
        }

        if ($extensionPolicy) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'Chrome extension management policies are configured' `
                -OrgUnitPath $OrgUnitPath `
                -Details @{ Note = 'Extension allowlist/blocklist policies detected' }
        }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chrome extension policy data not available. Verify in Admin Console > Devices > Chrome > Apps & extensions that extension installation is restricted via allowlist' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Malicious extensions can steal credentials, exfiltrate data, and intercept browsing activity' }
}

# ── DEVICE-009: Chrome OS Device Policies ────────────────────────────────
function Test-FortificationDEVICE009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'ChromeDevices' -Subject 'Chrome OS device inventory'
    if ($na) { return $na }

    # $null (not collected) -> WARN; but @() (collected, zero devices) must reach the PASS
    # below, not be swallowed here by `-not @()`. The NA guard above already SKIPs on a
    # collection error, so an empty array here genuinely means "zero Chrome OS devices."
    if ($null -eq $AuditData.ChromeDevices) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Chrome OS device data not available. Verify in Admin Console > Devices > Chrome > Devices that Chrome OS devices are managed' `
            -OrgUnitPath $OrgUnitPath
    }

    $devices = @($AuditData.ChromeDevices)
    if ($devices.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Chrome OS devices registered' -OrgUnitPath $OrgUnitPath
    }

    $active = @($devices | Where-Object { $_.status -eq 'ACTIVE' })
    $deprovisioned = @($devices | Where-Object { $_.status -eq 'DEPROVISIONED' })
    $disabled = @($devices | Where-Object { $_.status -eq 'DISABLED' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($devices.Count) Chrome OS device(s): $($active.Count) active, $($deprovisioned.Count) deprovisioned, $($disabled.Count) disabled" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            TotalDevices       = $devices.Count
            ActiveCount        = $active.Count
            DeprovisionedCount = $deprovisioned.Count
            DisabledCount      = $disabled.Count
        }
}

# ── DEVICE-010: Endpoint Verification Settings ───────────────────────────
function Test-FortificationDEVICE010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Endpoint verification settings not available via API. Verify in Admin Console > Devices > Settings that endpoint verification is enabled for context-aware access' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Endpoint verification provides device trust signals used by context-aware access policies' }
}

# ── DEVICE-011: Company-Owned Device Inventory ───────────────────────────
function Test-FortificationDEVICE011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('MobileDevices', 'ChromeDevices') -Subject 'device inventory'
    if ($na) { return $na }

    $totalDevices = 0
    $deviceBreakdown = @{}

    if ($AuditData.MobileDevices) {
        $mobileCount = @($AuditData.MobileDevices).Count
        $totalDevices += $mobileCount
        $deviceBreakdown['MobileDevices'] = $mobileCount
    }

    if ($AuditData.ChromeDevices) {
        $chromeCount = @($AuditData.ChromeDevices).Count
        $totalDevices += $chromeCount
        $deviceBreakdown['ChromeOSDevices'] = $chromeCount
    }

    if ($totalDevices -eq 0 -and -not $AuditData.MobileDevices -and -not $AuditData.ChromeDevices) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Device inventory data not available. Verify in Admin Console > Devices that company-owned devices are registered and tracked' `
            -OrgUnitPath $OrgUnitPath
    }

    $breakdownStr = @($deviceBreakdown.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ', '

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$totalDevices managed device(s) in inventory ($breakdownStr)" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalDevices = $totalDevices; Breakdown = $deviceBreakdown }
}
