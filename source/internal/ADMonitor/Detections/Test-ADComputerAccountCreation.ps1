# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADComputerAccountCreation {
    [CmdletBinding()]
    param(
        [array]$NewComputers = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($NewComputers.Count -eq 0) { return @() }

    $computerNames = @($NewComputers | ForEach-Object { $_.SAM })
    $detectionId = "adComputerAccountCreation_$(($computerNames | Sort-Object) -join '_')"

    # Check for suspicious patterns in computer names
    $suspiciousComputers = @($NewComputers | Where-Object {
        # Short random-looking names
        ($_.SAM -replace '\$$', '').Length -le 4 -or
        # Names that match DC naming patterns but are not in Domain Controllers OU
        ($_.SAM -match '^DC\d' -and $_.DN -notmatch 'OU=Domain Controllers') -or
        # Names that look like workstations placed in unusual OUs
        $_.DN -match 'CN=Computers,'
    })

    $description = "$($NewComputers.Count) new computer account(s) detected: $($computerNames -join ', ')"
    if ($suspiciousComputers.Count -gt 0) {
        $description += " ($($suspiciousComputers.Count) in potentially suspicious locations)"
    }

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'New Computer Account Created'
        DetectionType = 'adComputerAccountCreation'
        Description   = "COMPUTER ACCOUNT CREATION - $description"
        Details       = @{
            Computers = @($NewComputers | ForEach-Object {
                @{
                    SAM         = $_.SAM
                    DN          = $_.DN
                    WhenCreated = $_.WhenCreated
                }
            })
            SuspiciousCount = $suspiciousComputers.Count
        }
        Count         = $NewComputers.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
