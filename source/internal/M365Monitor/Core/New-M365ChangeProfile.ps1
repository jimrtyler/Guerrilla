# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function New-M365ChangeProfile {
    <#
    .SYNOPSIS
        Builds an M365 change profile from categorized audit events by running all detection functions.

    .DESCRIPTION
        Analyzes categorized M365 audit events through each Test-M365* detection function,
        collects all flagged changes, and returns a unified change profile with threat indicators.

    .PARAMETER CategorizedEvents
        Hashtable of categorized events from Get-M365AuditEvents.

    .PARAMETER DetectionConfig
        Hashtable of detection configuration overrides (thresholds, patterns, etc.).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CategorizedEvents,

        [hashtable]$DetectionConfig = @{},
        [hashtable]$DetectionFilter = @{}
    )

    # Helper: check if a detection signal is enabled in the filter
    function Test-DetectionEnabled([string]$SignalKey) {
        if (-not $DetectionFilter -or $DetectionFilter.Count -eq 0) { return $true }
        return $DetectionFilter[$SignalKey] -ne $false
    }

    $profile = [PSCustomObject]@{
        PSTypeName                 = 'Guerrilla.M365ChangeProfile'
        TenantId                   = ''
        ThreatLevel                = 'Clean'
        ThreatScore                = 0.0
        Indicators                 = @()
        TransportRuleChanges       = [System.Collections.Generic.List[PSCustomObject]]::new()
        ForwardingRules            = [System.Collections.Generic.List[PSCustomObject]]::new()
        EDiscoverySearches         = [System.Collections.Generic.List[PSCustomObject]]::new()
        DLPPolicyChanges           = [System.Collections.Generic.List[PSCustomObject]]::new()
        ExternalSharingChanges     = [System.Collections.Generic.List[PSCustomObject]]::new()
        TeamsExternalAccessChanges = [System.Collections.Generic.List[PSCustomObject]]::new()
        BulkFileExfiltrations      = [System.Collections.Generic.List[PSCustomObject]]::new()
        PowerAutomateFlows         = [System.Collections.Generic.List[PSCustomObject]]::new()
        DefenderAlertChanges       = [System.Collections.Generic.List[PSCustomObject]]::new()
        AuditLogDisablements       = [System.Collections.Generic.List[PSCustomObject]]::new()
        SecurityAlerts             = @()
    }

    # ── Transport Rule Changes ───────────────────────────────────────────
    if ((Test-DetectionEnabled 'transportRuleChanges') -and $CategorizedEvents.ExchangeTransportRules -and $CategorizedEvents.ExchangeTransportRules.Count -gt 0) {
        $detected = Test-M365TransportRuleChange -Events @($CategorizedEvents.ExchangeTransportRules)
        foreach ($item in $detected) {
            $profile.TransportRuleChanges.Add($item)
        }
    }

    # ── Forwarding Rules ─────────────────────────────────────────────────
    if ((Test-DetectionEnabled 'forwardingRules') -and $CategorizedEvents.ExchangeForwardingRules -and $CategorizedEvents.ExchangeForwardingRules.Count -gt 0) {
        $detected = Test-M365ForwardingRule -Events @($CategorizedEvents.ExchangeForwardingRules)
        foreach ($item in $detected) {
            $profile.ForwardingRules.Add($item)
        }
    }

    # ── eDiscovery Searches ──────────────────────────────────────────────
    if ((Test-DetectionEnabled 'eDiscoverySearches') -and $CategorizedEvents.EDiscoverySearches -and $CategorizedEvents.EDiscoverySearches.Count -gt 0) {
        $detected = Test-M365EDiscoverySearch -Events @($CategorizedEvents.EDiscoverySearches)
        foreach ($item in $detected) {
            $profile.EDiscoverySearches.Add($item)
        }
    }

    # ── DLP Policy Changes ───────────────────────────────────────────────
    if ((Test-DetectionEnabled 'dlpPolicyChanges') -and $CategorizedEvents.DLPPolicyChanges -and $CategorizedEvents.DLPPolicyChanges.Count -gt 0) {
        $detected = Test-M365DLPPolicyChange -Events @($CategorizedEvents.DLPPolicyChanges)
        foreach ($item in $detected) {
            $profile.DLPPolicyChanges.Add($item)
        }
    }

    # ── External Sharing Changes ─────────────────────────────────────────
    if ((Test-DetectionEnabled 'externalSharingChanges') -and $CategorizedEvents.SharePointSharingChanges -and $CategorizedEvents.SharePointSharingChanges.Count -gt 0) {
        $detected = Test-M365ExternalSharingChange -Events @($CategorizedEvents.SharePointSharingChanges)
        foreach ($item in $detected) {
            $profile.ExternalSharingChanges.Add($item)
        }
    }

    # ── Teams External Access Changes ────────────────────────────────────
    if ((Test-DetectionEnabled 'teamsExternalAccess') -and $CategorizedEvents.TeamsAccessChanges -and $CategorizedEvents.TeamsAccessChanges.Count -gt 0) {
        $detected = Test-M365TeamsExternalAccess -Events @($CategorizedEvents.TeamsAccessChanges)
        foreach ($item in $detected) {
            $profile.TeamsExternalAccessChanges.Add($item)
        }
    }

    # ── Bulk File Exfiltration ───────────────────────────────────────────
    if ((Test-DetectionEnabled 'bulkFileExfiltration') -and $CategorizedEvents.SharePointFileOperations -and $CategorizedEvents.SharePointFileOperations.Count -gt 0) {
        $threshold = if ($DetectionConfig.bulkExfiltrationThreshold) { $DetectionConfig.bulkExfiltrationThreshold } else { 100 }
        $windowMin = if ($DetectionConfig.bulkExfiltrationWindowMinutes) { $DetectionConfig.bulkExfiltrationWindowMinutes } else { 30 }

        $detected = Test-M365BulkFileExfiltration `
            -Events @($CategorizedEvents.SharePointFileOperations) `
            -Threshold $threshold `
            -WindowMinutes $windowMin
        foreach ($item in $detected) {
            $profile.BulkFileExfiltrations.Add($item)
        }
    }

    # ── Power Automate Flows ─────────────────────────────────────────────
    if ((Test-DetectionEnabled 'powerAutomateFlows') -and $CategorizedEvents.PowerPlatformFlows -and $CategorizedEvents.PowerPlatformFlows.Count -gt 0) {
        $extPatterns = if ($DetectionConfig.externalConnectorPatterns) {
            $DetectionConfig.externalConnectorPatterns
        } else { @() }

        $detected = Test-M365PowerAutomateFlow `
            -Events @($CategorizedEvents.PowerPlatformFlows) `
            -ExternalConnectorPatterns $extPatterns
        foreach ($item in $detected) {
            $profile.PowerAutomateFlows.Add($item)
        }
    }

    # ── Defender Alert Changes ───────────────────────────────────────────
    if ((Test-DetectionEnabled 'defenderAlertChanges') -and $CategorizedEvents.DefenderAlertChanges -and $CategorizedEvents.DefenderAlertChanges.Count -gt 0) {
        $detected = Test-M365DefenderAlertChange -Events @($CategorizedEvents.DefenderAlertChanges)
        foreach ($item in $detected) {
            $profile.DefenderAlertChanges.Add($item)
        }
    }

    # ── Audit Log Disablements ───────────────────────────────────────────
    if ((Test-DetectionEnabled 'auditLogDisablement') -and $CategorizedEvents.AuditLogChanges -and $CategorizedEvents.AuditLogChanges.Count -gt 0) {
        $detected = Test-M365AuditLogDisablement -Events @($CategorizedEvents.AuditLogChanges)
        foreach ($item in $detected) {
            $profile.AuditLogDisablements.Add($item)
        }
    }

    # ── Attach security alerts as-is ─────────────────────────────────────
    if ($CategorizedEvents.SecurityAlerts -and $CategorizedEvents.SecurityAlerts.Count -gt 0) {
        $profile.SecurityAlerts = @($CategorizedEvents.SecurityAlerts)
    }

    # ── Score the profile ────────────────────────────────────────────────
    $profile = Get-M365MonitorThreatScore -Profile $profile

    return $profile
}
