# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADKrbtgtChange {
    [CmdletBinding()]
    param(
        [bool]$KrbtgtChanged = $false
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if (-not $KrbtgtChanged) { return @() }

    $detectionId = "adKrbtgtPasswordChange_$([datetime]::UtcNow.ToString('yyyyMMddHHmm'))"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'krbtgt Password Reset Detected'
        DetectionType = 'adKrbtgtPasswordChange'
        Description   = "KRBTGT PASSWORD CHANGE - The krbtgt account password has been reset. This invalidates all existing Kerberos tickets. This may be a legitimate security operation or indicate an attacker attempting to forge Golden Tickets."
        Details       = @{
            Account    = 'krbtgt'
            Timestamp  = [datetime]::UtcNow.ToString('o')
        }
        Count         = 1
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
