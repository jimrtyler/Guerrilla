# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADServiceAccountCreation {
    [CmdletBinding()]
    param(
        [array]$NewServiceAccounts = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($NewServiceAccounts.Count -eq 0) { return @() }

    $accountNames = @($NewServiceAccounts | ForEach-Object { $_.SAM })
    $detailStr = "New service account(s): $($accountNames -join ', ')"
    $detectionId = "adServiceAccountCreation_$(($accountNames | Sort-Object) -join '_')"

    $indicators.Add([PSCustomObject]@{
        DetectionId   = $detectionId
        DetectionName = 'New Service Account Created'
        DetectionType = 'adServiceAccountCreation'
        Description   = "SERVICE ACCOUNT CREATION - $($NewServiceAccounts.Count) new service account(s) detected: $detailStr"
        Details       = @{
            Accounts = @($NewServiceAccounts | ForEach-Object {
                @{
                    SAM         = $_.SAM
                    DN          = $_.DN
                    WhenCreated = $_.WhenCreated
                }
            })
        }
        Count         = $NewServiceAccounts.Count
        Score         = 0
        Severity      = ''
    })

    return @($indicators)
}
