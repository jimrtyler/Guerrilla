# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADSensitivePasswordChange {
    [CmdletBinding()]
    param(
        [array]$PasswordChanges = @(),
        [array]$GroupChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Detect password changes on accounts that are members of privileged groups
    # This is inferred from group membership data; if an admin account's
    # password was recently changed and we detect membership changes in the same sweep,
    # it may indicate credential manipulation
    if ($PasswordChanges.Count -eq 0) { return @() }

    foreach ($change in $PasswordChanges) {
        $accountName = if ($change.ContainsKey('SAM')) { $change.SAM } else { 'Unknown' }
        $isPrivileged = if ($change.ContainsKey('IsPrivileged')) { $change.IsPrivileged } else { $false }

        if (-not $isPrivileged) { continue }

        $detectionId = "adSensitivePasswordChange_$($accountName)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Sensitive Account Password Change: $accountName"
            DetectionType = 'adSensitivePasswordChange'
            Description   = "SENSITIVE PASSWORD CHANGE - Password changed for privileged account '$accountName'"
            Details       = @{
                Account      = $accountName
                DN           = if ($change.ContainsKey('DN')) { $change.DN } else { '' }
                IsPrivileged = $true
                Groups       = if ($change.ContainsKey('Groups')) { @($change.Groups) } else { @() }
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
