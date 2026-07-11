# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-M365MonitorThreatScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Profile,

        [hashtable]$Weights
    )

    # Default weights
    if (-not $Weights) {
        $Weights = @{
            m365TransportRuleChange    = 60
            m365ForwardingRule         = 70
            m365EDiscoverySearch       = 55
            m365DLPPolicyChange        = 50
            m365ExternalSharingChange  = 45
            m365TeamsExternalAccess    = 40
            m365BulkFileExfiltration   = 75
            m365PowerAutomateFlow      = 50
            m365DefenderAlertChange    = 65
            m365AuditLogDisablement    = 95
        }
    }

    $score = 0.0
    $indicators = [System.Collections.Generic.List[string]]::new()

    # Audit log disablement — strongest M365 signal
    if ($Profile.AuditLogDisablements.Count -gt 0) {
        $n = $Profile.AuditLogDisablements.Count
        $score += $Weights.m365AuditLogDisablement
        $actors = @($Profile.AuditLogDisablements | ForEach-Object { $_.Actor } | Where-Object { $_ } | Sort-Object -Unique)
        $actorDisplay = if ($actors.Count -gt 0) { $actors -join ', ' } else { 'unknown' }
        $indicators.Add(
            "AUDIT LOG DISABLEMENT - $n audit log configuration change(s) reducing visibility, actor(s): $actorDisplay"
        )
    }

    # Bulk file exfiltration — high-volume data theft
    if ($Profile.BulkFileExfiltrations.Count -gt 0) {
        $n = $Profile.BulkFileExfiltrations.Count
        $score += $Weights.m365BulkFileExfiltration
        $maxCount = ($Profile.BulkFileExfiltrations | Sort-Object { $_.Details.FileCount } -Descending | Select-Object -First 1).Details.FileCount
        $actors = @($Profile.BulkFileExfiltrations | ForEach-Object { $_.Actor } | Where-Object { $_ } | Sort-Object -Unique)
        $actorDisplay = if ($actors.Count -gt 0) { $actors -join ', ' } else { 'unknown' }
        $indicators.Add(
            "BULK FILE EXFILTRATION - $n burst(s) detected, max $maxCount files in window by: $actorDisplay"
        )
    }

    # Forwarding rules — mail exfiltration
    if ($Profile.ForwardingRules.Count -gt 0) {
        $n = $Profile.ForwardingRules.Count
        $score += $Weights.m365ForwardingRule
        $destinations = @($Profile.ForwardingRules | ForEach-Object { $_.Details.ForwardingDestination } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $destDisplay = if ($destinations.Count -gt 0) { " to: $($destinations -join ', ')" } else { '' }
        $actors = @($Profile.ForwardingRules | ForEach-Object { $_.Actor } | Where-Object { $_ } | Sort-Object -Unique)
        $actorDisplay = if ($actors.Count -gt 0) { $actors -join ', ' } else { 'unknown' }
        $indicators.Add(
            "FORWARDING RULE - $n mailbox forwarding rule(s) created/modified by $actorDisplay$destDisplay"
        )
    }

    # Defender alert changes — security posture weakening
    if ($Profile.DefenderAlertChanges.Count -gt 0) {
        $n = $Profile.DefenderAlertChanges.Count
        $score += $Weights.m365DefenderAlertChange
        $disabled = @($Profile.DefenderAlertChanges | Where-Object { $_.Details.IsDisabling })
        $detail = if ($disabled.Count -gt 0) { "$($disabled.Count) disabled/removed" } else { "$n modified" }
        $policyNames = @($Profile.DefenderAlertChanges | ForEach-Object { $_.Details.PolicyName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $policyDisplay = if ($policyNames.Count -gt 0) { ": $($policyNames -join ', ')" } else { '' }
        $indicators.Add(
            "DEFENDER ALERT CHANGE - $detail alert policy change(s) in Microsoft 365 Defender$policyDisplay"
        )
    }

    # Transport rule changes — mail flow manipulation
    if ($Profile.TransportRuleChanges.Count -gt 0) {
        $n = $Profile.TransportRuleChanges.Count
        $score += $Weights.m365TransportRuleChange
        $rules = @($Profile.TransportRuleChanges | ForEach-Object { $_.Details.TargetName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $ruleDisplay = if ($rules.Count -gt 0) { ": $($rules -join ', ')" } else { '' }
        $indicators.Add(
            "TRANSPORT RULE CHANGE - $n transport/mail flow rule change(s)$ruleDisplay"
        )
    }

    # eDiscovery searches — data reconnaissance
    if ($Profile.EDiscoverySearches.Count -gt 0) {
        $n = $Profile.EDiscoverySearches.Count
        $score += $Weights.m365EDiscoverySearch
        $actors = @($Profile.EDiscoverySearches | ForEach-Object { $_.Actor } | Where-Object { $_ } | Sort-Object -Unique)
        $actorDisplay = if ($actors.Count -gt 0) { $actors -join ', ' } else { 'unknown' }
        $searchNames = @($Profile.EDiscoverySearches | ForEach-Object { $_.Details.SearchName } | Where-Object { $_ } | Sort-Object -Unique | Select-Object -First 3)
        $searchDisplay = if ($searchNames.Count -gt 0) { ": $($searchNames -join ', ')" } else { '' }
        $indicators.Add(
            "EDISCOVERY SEARCH - $n compliance search(es) initiated by $actorDisplay$searchDisplay"
        )
    }

    # DLP policy changes — data protection weakening
    if ($Profile.DLPPolicyChanges.Count -gt 0) {
        $n = $Profile.DLPPolicyChanges.Count
        $score += $Weights.m365DLPPolicyChange
        $disabled = @($Profile.DLPPolicyChanges | Where-Object { $_.Details.IsDisabling })
        $detail = if ($disabled.Count -gt 0) { "$($disabled.Count) disabled/deleted" } else { "$n modified" }
        $indicators.Add(
            "DLP POLICY CHANGE - $detail DLP policy change(s)"
        )
    }

    # Power Automate flows — automation abuse
    if ($Profile.PowerAutomateFlows.Count -gt 0) {
        $n = $Profile.PowerAutomateFlows.Count
        $score += $Weights.m365PowerAutomateFlow
        $external = @($Profile.PowerAutomateFlows | Where-Object { $_.Details.HasExternalConnector })
        $detail = if ($external.Count -gt 0) { "$($external.Count) with external connector(s)" } else { "$n created/modified" }
        $indicators.Add(
            "POWER AUTOMATE FLOW - $detail flow change(s)"
        )
    }

    # External sharing changes — tenant boundary weakening
    if ($Profile.ExternalSharingChanges.Count -gt 0) {
        $n = $Profile.ExternalSharingChanges.Count
        $score += $Weights.m365ExternalSharingChange
        $weakened = @($Profile.ExternalSharingChanges | Where-Object { $_.Details.SharingWeakened })
        $detail = if ($weakened.Count -gt 0) { "$($weakened.Count) expanded external access" } else { "$n modified" }
        $indicators.Add(
            "EXTERNAL SHARING CHANGE - $detail sharing policy change(s)"
        )
    }

    # Teams external access — collaboration boundary changes
    if ($Profile.TeamsExternalAccessChanges.Count -gt 0) {
        $n = $Profile.TeamsExternalAccessChanges.Count
        $score += $Weights.m365TeamsExternalAccess
        $indicators.Add(
            "TEAMS EXTERNAL ACCESS - $n Teams external/guest access policy change(s)"
        )
    }

    # Assign threat level
    $threatLevel = switch ($true) {
        ($score -ge 100) { 'CRITICAL'; break }
        ($score -ge 60)  { 'HIGH'; break }
        ($score -ge 30)  { 'MEDIUM'; break }
        ($score -gt 0)   { 'LOW'; break }
        default          { 'Clean' }
    }

    $Profile.ThreatScore = $score
    $Profile.ThreatLevel = $threatLevel
    $Profile.Indicators = @($indicators)

    return $Profile
}
