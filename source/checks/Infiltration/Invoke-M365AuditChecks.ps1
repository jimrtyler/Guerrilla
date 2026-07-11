# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-M365AuditChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'M365AuditChecks'
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

# ── M365AUDIT-001: Unified Audit Log Enabled ─────────────────────────
function Test-InfiltrationM365AUDIT001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Audit') -Subject 'audit log configuration'
    if ($na) { return $na }

    $audit = $AuditData.M365Services.AuditConfig
    if (-not $audit) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Audit configuration data not available (EXO module not connected)'
    }

    $ualEnabled = $audit.UnifiedAuditLogIngestionEnabled

    if ($null -eq $ualEnabled) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'UnifiedAuditLogIngestionEnabled property not available in audit configuration'
    }

    $status = if ($ualEnabled -eq $true) { 'PASS' } else { 'FAIL' }

    $description = if ($ualEnabled -eq $true) {
        'Unified Audit Log ingestion is enabled'
    } else {
        'Unified Audit Log ingestion is DISABLED — critical security logging is not active'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            UnifiedAuditLogIngestionEnabled = $ualEnabled
        }
}

# ── M365AUDIT-002: Audit Log Retention ───────────────────────────────
function Test-InfiltrationM365AUDIT002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Audit') -Subject 'audit log configuration'
    if ($na) { return $na }

    $audit = $AuditData.M365Services.AuditConfig
    if (-not $audit) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Audit configuration data not available (EXO module not connected)'
    }

    $retentionDays = $audit.AuditLogAgeLimit
    $adminAuditAgeLimit = $audit.AdminAuditLogAgeLimit

    # Parse retention if it is a timespan string (e.g., "90.00:00:00")
    $retentionNumeric = $null
    if ($retentionDays -is [int] -or $retentionDays -is [double]) {
        $retentionNumeric = [int]$retentionDays
    } elseif ($retentionDays -is [string] -and $retentionDays -match '^(\d+)') {
        $retentionNumeric = [int]$Matches[1]
    } elseif ($retentionDays -is [timespan]) {
        $retentionNumeric = [int]$retentionDays.TotalDays
    }

    if ($null -eq $retentionNumeric -and $null -eq $adminAuditAgeLimit) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Audit log retention settings not available — unable to determine retention period'
    }

    # Default M365 E3 retention is 180 days, E5 is 365 days
    $status = if ($null -eq $retentionNumeric) { 'WARN' }
              elseif ($retentionNumeric -ge 365) { 'PASS' }
              elseif ($retentionNumeric -ge 180) { 'WARN' }
              else { 'FAIL' }

    $description = if ($null -eq $retentionNumeric) {
        "Audit log retention: AdminAuditLogAgeLimit=$adminAuditAgeLimit (numeric retention not determined)"
    } elseif ($retentionNumeric -ge 365) {
        "Audit log retention set to $retentionNumeric days (meets 365-day recommendation)"
    } elseif ($retentionNumeric -ge 180) {
        "Audit log retention set to $retentionNumeric days (default E3 — consider extending to 365 days with E5 or add-on)"
    } else {
        "Audit log retention set to $retentionNumeric days — below recommended minimum of 180 days"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            AuditLogAgeLimit = $retentionDays
            AdminAuditLogAgeLimit = $adminAuditAgeLimit
            RetentionDays = $retentionNumeric
            RecommendedMinDays = 180
            RecommendedOptimalDays = 365
        }
}

# ── M365AUDIT-003: Audit Log Search ──────────────────────────────────
function Test-InfiltrationM365AUDIT003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'Audit') -Subject 'audit log configuration'
    if ($na) { return $na }

    $audit = $AuditData.M365Services.AuditConfig
    if (-not $audit) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Audit configuration data not available (EXO module not connected)'
    }

    # Verify UAL is enabled (prerequisite for search)
    $ualEnabled = $audit.UnifiedAuditLogIngestionEnabled
    $adminAuditEnabled = $audit.AdminAuditLogEnabled

    if ($ualEnabled -eq $false) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Audit log search unavailable — Unified Audit Log ingestion is disabled' `
            -Details @{
                UnifiedAuditLogIngestionEnabled = $false
                AdminAuditLogEnabled = $adminAuditEnabled
            }
    }

    # Check admin audit log is also enabled
    $status = if ($ualEnabled -eq $true -and $adminAuditEnabled -eq $true) { 'PASS' }
              elseif ($ualEnabled -eq $true) { 'PASS' }
              elseif ($adminAuditEnabled -eq $true) { 'WARN' }
              else { 'FAIL' }

    $description = if ($ualEnabled -eq $true -and $adminAuditEnabled -eq $true) {
        'Audit log search is operational — UAL and admin audit logging are both enabled'
    } elseif ($ualEnabled -eq $true) {
        'Unified Audit Log is enabled. Admin audit log status could not be confirmed'
    } else {
        'Audit log search capability may be limited — verify UAL and admin audit settings'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            UnifiedAuditLogIngestionEnabled = $ualEnabled
            AdminAuditLogEnabled = $adminAuditEnabled
            LogLevel = $audit.LogLevel
        }
}
