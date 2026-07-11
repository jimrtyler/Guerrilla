# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalPushover {
    <#
    .SYNOPSIS
        Sends a push notification via Pushover.net.
    .DESCRIPTION
        Delivers alert notifications to Pushover mobile/desktop apps using
        the Pushover Message API. Supports priority levels mapped from
        Guerrilla threat levels, with optional sound and URL parameters.
    .PARAMETER ApiToken
        Pushover application API token.
    .PARAMETER UserKey
        Pushover user key (or group key for team delivery).
    .PARAMETER Message
        The notification body text (max 1024 characters).
    .PARAMETER Title
        Optional notification title.
    .PARAMETER Priority
        Pushover priority: -2 (silent), -1 (quiet), 0 (normal), 1 (high), 2 (emergency).
        Emergency (2) requires Retry and Expire parameters.
    .PARAMETER Sound
        Notification sound name. Default: 'siren' for security alerts.
    .PARAMETER Url
        Optional URL to include in the notification.
    .PARAMETER UrlTitle
        Display text for the optional URL.
    .PARAMETER Retry
        Required when Priority=2. Seconds between retries (minimum 30).
    .PARAMETER Expire
        Required when Priority=2. Seconds before notification stops retrying (max 10800).
    .EXAMPLE
        Send-SignalPushover -ApiToken $token -UserKey $user -Message '3 CRITICAL threats detected' -Title 'Guerrilla Alert' -Priority 1
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ApiToken,

        [Parameter(Mandatory)]
        [string]$UserKey,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Title = 'Guerrilla Signal',

        [ValidateRange(-2, 2)]
        [int]$Priority = 0,

        [string]$Sound = 'siren',

        [string]$Url,

        [string]$UrlTitle,

        [int]$Retry = 60,

        [int]$Expire = 3600
    )

    $uri = 'https://api.pushover.net/1/messages.json'

    # Truncate message to Pushover's 1024-char limit
    if ($Message.Length -gt 1024) {
        $Message = $Message.Substring(0, 1021) + '...'
    }

    $form = @{
        token   = $ApiToken
        user    = $UserKey
        message = $Message
        title   = $Title
        priority = $Priority
        sound   = $Sound
        html    = 1
    }

    if ($Url)      { $form['url'] = $Url }
    if ($UrlTitle)  { $form['url_title'] = $UrlTitle }

    # Emergency priority requires retry/expire
    if ($Priority -eq 2) {
        $form['retry']  = [Math]::Max(30, $Retry)
        $form['expire'] = [Math]::Min(10800, $Expire)
    }

    try {
        $response = Invoke-RestMethod -TimeoutSec 30 -Uri $uri -Method Post -Body $form -ErrorAction Stop

        if ($response.status -eq 1) {
            return [PSCustomObject]@{
                Provider = 'Pushover'
                Success  = $true
                Message  = "Push notification sent (request: $($response.request))"
                Error    = $null
            }
        } else {
            return [PSCustomObject]@{
                Provider = 'Pushover'
                Success  = $false
                Message  = 'Pushover returned non-success status'
                Error    = ($response.errors -join '; ')
            }
        }
    } catch {
        Start-Sleep -Seconds 3
        try {
            $response = Invoke-RestMethod -TimeoutSec 30 -Uri $uri -Method Post -Body $form -ErrorAction Stop

            if ($response.status -eq 1) {
                return [PSCustomObject]@{
                    Provider = 'Pushover'
                    Success  = $true
                    Message  = "Push notification sent on retry (request: $($response.request))"
                    Error    = $null
                }
            } else {
                return [PSCustomObject]@{
                    Provider = 'Pushover'
                    Success  = $false
                    Message  = 'Pushover returned non-success status on retry'
                    Error    = ($response.errors -join '; ')
                }
            }
        } catch {
            return [PSCustomObject]@{
                Provider = 'Pushover'
                Success  = $false
                Message  = 'Failed to send push notification'
                Error    = $_.Exception.Message
            }
        }
    }
}
