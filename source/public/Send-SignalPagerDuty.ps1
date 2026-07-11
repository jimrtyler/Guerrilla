# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalPagerDuty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RoutingKey,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [ValidateSet('critical', 'error', 'warning', 'info')]
        [string]$Severity = 'critical'
    )

    # Determine severity from threat levels if not explicitly set
    if (-not $PSBoundParameters.ContainsKey('Severity')) {
        $critCount = @($Threats | Where-Object ThreatLevel -eq 'CRITICAL').Count
        $highCount = @($Threats | Where-Object ThreatLevel -eq 'HIGH').Count
        $Severity = if ($critCount -gt 0) { 'critical' }
                    elseif ($highCount -gt 0) { 'error' }
                    else { 'warning' }
    }

    # Build custom details
    $details = @{}
    foreach ($t in ($Threats | Sort-Object -Property ThreatScore -Descending | Select-Object -First 20)) {
        $details[$t.Email] = "$($t.ThreatLevel) (Score: $($t.ThreatScore.ToString('N0'))) - $($t.Indicators -join '; ')"
    }

    $body = @{
        routing_key  = $RoutingKey
        event_action = 'trigger'
        payload      = @{
            summary   = $Subject
            source    = 'Guerrilla'
            severity  = $Severity
            component = 'Google Workspace'
            group     = 'compromise-detection'
            class     = 'threat-alert'
            timestamp = [datetime]::UtcNow.ToString('o')
            custom_details = $details
        }
    } | ConvertTo-Json -Depth 10 -Compress

    try {
        $response = Invoke-RestMethod -TimeoutSec 30 -Uri 'https://events.pagerduty.com/v2/enqueue' `
            -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop

        return [PSCustomObject]@{
            Provider = 'PagerDuty'
            Success  = $true
            Message  = "PagerDuty event created (dedup_key: $($response.dedup_key))"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            $response = Invoke-RestMethod -TimeoutSec 30 -Uri 'https://events.pagerduty.com/v2/enqueue' `
                -Method Post -Body $body -ContentType 'application/json' -ErrorAction Stop

            return [PSCustomObject]@{
                Provider = 'PagerDuty'
                Success  = $true
                Message  = "PagerDuty event created on retry (dedup_key: $($response.dedup_key))"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'PagerDuty'
                Success  = $false
                Message  = 'Failed to create PagerDuty event'
                Error    = $_.Exception.Message
            }
        }
    }
}
