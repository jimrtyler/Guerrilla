# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADLoggingChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADLoggingChecks'
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

# Helper: shared with ADNetworkChecks but redefined locally so this file doesn't depend
# on dot-source ordering. PowerShell hashtables and OrderedDictionary support .Value on
# the parser's Entry shape; we just want the raw string value as an int.
function ConvertTo-LogPolicyRegInt {
    param($Entry)
    if (-not $Entry) { return $null }
    $raw = "$($Entry.Value)".Trim()
    if (-not $raw) { return $null }
    if ($raw -match '^0x([0-9a-fA-F]+)$') {
        try { return [int]([Convert]::ToInt32($Matches[1], 16)) } catch { return $null }
    }
    if ($raw -match '^-?\d+$') {
        try { return [int]$raw } catch { return $null }
    }
    return $null
}

# Helper: produce a "Registry.pol not parsed, verify manually" WARN. Many of the logging
# settings live in admin templates which this MVP doesn't read.
function New-LogManualVerifyFinding {
    param(
        [Parameter(Mandatory)][hashtable]$CheckDefinition,
        [Parameter(Mandatory)][string]$RegistryPath,
        [Parameter(Mandatory)][string]$ExpectedValueDescription
    )
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue ("Could not verify from SYSVOL security-settings INI. This setting is typically delivered via administrative template (Registry.pol) which this MVP does not parse. Verify on a member host: Get-ItemProperty '$RegistryPath'. Expected: $ExpectedValueDescription.") `
        -Details @{ ManualVerifyPath = $RegistryPath; Caveat = 'Registry.pol not parsed in MVP' }
}

# ── ADLOG-001: Advanced Audit Policy Configured ────────────────────────────
# Detected by checking whether audit.csv exists in the Default Domain Controllers Policy
# SYSVOL folder. The collector doesn't read this file currently, so we derive the DNS
# name and check ourselves. (We deliberately don't extend the collector for one check.)
function Test-ReconADLOG001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    $conn = $AuditData.Connection
    if (-not $conn) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Connection metadata not present in AuditData.'
    }
    $domainDns = ($conn.DomainDN -replace '^DC=', '' -replace ',DC=', '.').ToLower()
    $ddcpGuid = '{6AC1786C-016F-11D2-945F-00C04fB984F9}'
    $auditCsvPath = "\\$domainDns\SYSVOL\$domainDns\Policies\$ddcpGuid\MACHINE\Microsoft\Windows NT\Audit\Audit.csv"

    try {
        if (Test-Path -LiteralPath $auditCsvPath -ErrorAction Stop) {
            $lineCount = 0
            try {
                $lineCount = @(Get-Content -LiteralPath $auditCsvPath -ErrorAction Stop |
                    Where-Object { $_ -and -not $_.StartsWith('Machine Name') }).Count
            } catch { }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue "Advanced Audit Policy configured in Default Domain Controllers Policy (audit.csv present, $lineCount subcategory row(s))" `
                -Details @{ AuditCsvPath = $auditCsvPath; Rows = $lineCount }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'No audit.csv in Default Domain Controllers Policy — legacy nine-category audit policy is in use, which is too coarse for modern investigations' `
            -Details @{ AuditCsvPath = $auditCsvPath }
    } catch {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "Could not test SYSVOL path: $($_.Exception.Message)"
    }
}

# ── ADLOG-002: PowerShell Script Block Logging ─────────────────────────────
function Test-ReconADLOG002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if ($net -and $net.DefaultDomainPolicy) {
        $val = $null
        $entry = $net.DefaultDomainPolicy.Registry['MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging']
        if ($entry) { $val = ConvertTo-LogPolicyRegInt -Entry $entry }
        if ($val -eq 1) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'PowerShell Script Block Logging enabled via Default Domain Policy security settings (EnableScriptBlockLogging = 1)' `
                -Details @{ ConfiguredValue = 1 }
        }
        if ($val -eq 0) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                -CurrentValue 'PowerShell Script Block Logging explicitly disabled in Default Domain Policy (EnableScriptBlockLogging = 0)' `
                -Details @{ ConfiguredValue = 0 }
        }
    }
    return New-LogManualVerifyFinding -CheckDefinition $CheckDefinition `
        -RegistryPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -ExpectedValueDescription 'EnableScriptBlockLogging = 1'
}

# ── ADLOG-003: PowerShell Module Logging ───────────────────────────────────
function Test-ReconADLOG003 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if ($net -and $net.DefaultDomainPolicy) {
        $val = $null
        $entry = $net.DefaultDomainPolicy.Registry['MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging']
        if ($entry) { $val = ConvertTo-LogPolicyRegInt -Entry $entry }
        if ($val -eq 1) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'PowerShell Module Logging enabled via Default Domain Policy security settings' `
                -Details @{ ConfiguredValue = 1 }
        }
    }
    return New-LogManualVerifyFinding -CheckDefinition $CheckDefinition `
        -RegistryPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        -ExpectedValueDescription 'EnableModuleLogging = 1 and a ModuleNames list (* recommended)'
}

# ── ADLOG-004: Process Creation Auditing with Command Line ─────────────────
function Test-ReconADLOG004 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'NetworkConfig' -Subject 'network policy configuration'
    if ($na) { return $na }
    $net = $AuditData.Network
    if ($net -and $net.DefaultDomainPolicy) {
        $entry = $net.DefaultDomainPolicy.Registry['MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled']
        $val = if ($entry) { ConvertTo-LogPolicyRegInt -Entry $entry } else { $null }
        if ($val -eq 1) {
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'Process creation events include command line (ProcessCreationIncludeCmdLine_Enabled = 1)' `
                -Details @{ ConfiguredValue = 1 }
        }
    }
    return New-LogManualVerifyFinding -CheckDefinition $CheckDefinition `
        -RegistryPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
        -ExpectedValueDescription 'ProcessCreationIncludeCmdLine_Enabled = 1, and Advanced Audit Policy "Audit Process Creation" = Success'
}

# ── ADLOG-005: Microsoft Defender Tamper Protection Policy ─────────────────
function Test-ReconADLOG005 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Defender Tamper Protection state is set in the MDE cloud portal (Settings > Endpoints > Advanced features) and not visible from SYSVOL. Verify out-of-band. Also enumerate exclusion entries: every entry under HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions on a representative endpoint is a hole an attacker will find — keep the list tight.' `
        -Details @{ Caveat = 'Tamper Protection not detectable from AD'; ManualPortal = 'security.microsoft.com > Settings > Endpoints > Advanced features' }
}

# ── ADLOG-006: Windows Event Forwarding SubscriptionManager ────────────────
function Test-ReconADLOG006 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    return New-LogManualVerifyFinding -CheckDefinition $CheckDefinition `
        -RegistryPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager' `
        -ExpectedValueDescription 'A SubscriptionManager URL pointing at your WEF collector (e.g. Server=http://wec-server.domain.tld:5985/wsman/SubscriptionManager/WEC,Refresh=60)'
}

# ── ADLOG-007: Sysmon Deployment Indicator ─────────────────────────────────
function Test-ReconADLOG007 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Sysmon presence is not detectable from SYSVOL / LDAP. Verify on representative hosts: Get-CimInstance Win32_Service -Filter "Name=''Sysmon64''". If you have a WEF collector, query for "Microsoft-Windows-Sysmon/Operational" events in the last 7 days.' `
        -Details @{ Caveat = 'Endpoint-level service state not detectable from AD'; ManualVerify = "Get-CimInstance Win32_Service -Filter `"Name='Sysmon64'`"" }
}
