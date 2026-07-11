# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Send-SignalTwilio {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccountSid,

        [Parameter(Mandatory)]
        [string]$AuthToken,

        [Parameter(Mandatory)]
        [string]$FromNumber,

        [Parameter(Mandatory)]
        [string[]]$ToNumbers,

        [Parameter(Mandatory)]
        [string]$MessageBody
    )

    $credential = [System.Management.Automation.PSCredential]::new(
        $AccountSid,
        ($AuthToken | ConvertTo-SecureString -AsPlainText -Force)
    )

    $uri = "https://api.twilio.com/2010-04-01/Accounts/$AccountSid/Messages.json"
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($number in $ToNumbers) {
        $form = @{
            From = $FromNumber
            To   = $number
            Body = $MessageBody
        }

        try {
            $response = Invoke-RestMethod -TimeoutSec 30 -Uri $uri -Method Post `
                -Authentication Basic -Credential $credential `
                -Form $form -ErrorAction Stop

            $results.Add([PSCustomObject]@{
                Provider = 'Twilio'
                Success  = $true
                Message  = "SMS sent to $number (SID: $($response.sid))"
                Error    = $null
            })
        } catch {
            $results.Add([PSCustomObject]@{
                Provider = 'Twilio'
                Success  = $false
                Message  = "Failed to send SMS to $number"
                Error    = $_.Exception.Message
            })
            Write-Warning "Twilio SMS to $number failed: $($_.Exception.Message)"
        }
    }

    return @($results)
}
