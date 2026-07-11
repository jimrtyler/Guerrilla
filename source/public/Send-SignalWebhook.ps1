# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalWebhook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$WebhookUrl,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$Threats,

        [Parameter(Mandatory)]
        [PSCustomObject]$ScanResult,

        [hashtable]$Headers = @{},

        [string]$AuthToken
    )

    # Build generic JSON payload suitable for SIEM ingestion
    $payload = @{
        source    = 'Guerrilla'
        version   = '2.0.0'
        timestamp = [datetime]::UtcNow.ToString('o')
        scan      = @{
            scanId             = $ScanResult.ScanId
            scanTime           = $ScanResult.Timestamp.ToString('o')
            mode               = $ScanResult.ScanMode
            totalUsersScanned  = $ScanResult.TotalUsersScanned
            totalEventsAnalyzed = $ScanResult.TotalEventsAnalyzed
        }
        threats = @($Threats | ForEach-Object {
            @{
                email       = $_.Email
                threatLevel = $_.ThreatLevel
                threatScore = $_.ThreatScore
                indicators  = @($_.Indicators)
                isKnownCompromised = $_.IsKnownCompromised
                wasRemediated      = $_.WasRemediated
                attackerIps = @($_.KnownAttackerIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
                cloudIps    = @($_.CloudIpLogins | ForEach-Object { $_.IpAddress } | Sort-Object -Unique)
            }
        })
        summary = @{
            totalThreats  = $Threats.Count
            criticalCount = @($Threats | Where-Object ThreatLevel -eq 'CRITICAL').Count
            highCount     = @($Threats | Where-Object ThreatLevel -eq 'HIGH').Count
            mediumCount   = @($Threats | Where-Object ThreatLevel -eq 'MEDIUM').Count
            lowCount      = @($Threats | Where-Object ThreatLevel -eq 'LOW').Count
        }
    } | ConvertTo-Json -Depth 10 -Compress

    $requestHeaders = @{ 'Content-Type' = 'application/json' }
    if ($AuthToken) {
        $requestHeaders['Authorization'] = "Bearer $AuthToken"
    }
    foreach ($key in $Headers.Keys) {
        $requestHeaders[$key] = $Headers[$key]
    }

    try {
        Invoke-RestMethod -TimeoutSec 30 -Uri $WebhookUrl -Method Post -Body $payload -Headers $requestHeaders -ErrorAction Stop
        return [PSCustomObject]@{
            Provider = 'Webhook'
            Success  = $true
            Message  = "Webhook POST sent to $WebhookUrl ($($Threats.Count) threat(s))"
            Error    = $null
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            Invoke-RestMethod -TimeoutSec 30 -Uri $WebhookUrl -Method Post -Body $payload -Headers $requestHeaders -ErrorAction Stop
            return [PSCustomObject]@{
                Provider = 'Webhook'
                Success  = $true
                Message  = "Webhook POST sent on retry to $WebhookUrl ($($Threats.Count) threat(s))"
                Error    = $null
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Webhook'
                Success  = $false
                Message  = "Failed to POST to $WebhookUrl"
                Error    = $_.Exception.Message
            }
        }
    }
}
