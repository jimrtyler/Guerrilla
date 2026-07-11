# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365DLPPolicyChange {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # High-risk operations: deletion, disablement
    $highRiskPatterns = @(
        'Remove-DlpPolicy', 'Remove-DlpCompliancePolicy', 'Remove-DlpComplianceRule',
        'Disable-DlpPolicy', 'DlpPolicyRemoved', 'DlpRuleRemoved'
    )

    # Weakening patterns in property changes
    $weakeningPatterns = @(
        'Mode.*(?:Disable|TestWithoutNotifications|Off)'
        'IsEnabled.*(?:False|false)'
        'BlockAccess.*(?:False|false)'
        'NotifyUser.*(?:False|false)'
        'GenerateIncidentReport.*(?:False|false)'
    )

    foreach ($event in $Events) {
        $operationType = $event.OperationType ?? $event.Activity ?? ''
        $policyName = $event.TargetName ?? ''
        $isWeakened = $false
        $isRemoved = $false
        $changeDetails = [System.Collections.Generic.List[string]]::new()

        # Check for high-risk operations
        foreach ($pattern in $highRiskPatterns) {
            if ($operationType -match [regex]::Escape($pattern) -or $event.Activity -match [regex]::Escape($pattern)) {
                $isRemoved = $true
                $changeDetails.Add("DLP policy removed/disabled: $operationType")
                break
            }
        }

        # Check property changes for weakening
        if (-not $isRemoved) {
            foreach ($prop in $event.ModifiedProps) {
                $propName = $prop.Name ?? ''
                $newVal = $prop.NewValue ?? ''
                $oldVal = $prop.OldValue ?? ''
                $combined = "$propName=$newVal"

                foreach ($pattern in $weakeningPatterns) {
                    if ($combined -match $pattern) {
                        $isWeakened = $true
                        $changeDetails.Add("$propName changed from '$oldVal' to '$newVal' (weakened)")
                        break
                    }
                }

                # Scope reduction (removing protected locations)
                if ($propName -match 'ExchangeLocation|SharePointLocation|OneDriveLocation|TeamsLocation') {
                    if ($oldVal -and (-not $newVal -or $newVal -eq '' -or $newVal -eq '""')) {
                        $isWeakened = $true
                        $changeDetails.Add("$propName scope removed (was: $oldVal)")
                    }
                }

                # Sensitivity label downgrade
                if ($propName -match 'ContentContainsSensitiveInformation|SensitiveInformationType') {
                    $changeDetails.Add("Sensitive information type changed: $propName")
                }
            }
        }

        $isDisabling = $isRemoved -or $isWeakened

        # Severity assessment
        $severity = if ($isRemoved) { 'Critical' }
                    elseif ($isWeakened) { 'High' }
                    elseif ($operationType -match 'New-Dlp|Create') { 'Low' }
                    else { 'Medium' }

        $description = if ($isRemoved) {
            "DLP policy '$policyName' removed by $($event.Actor)"
        } elseif ($isWeakened) {
            "DLP policy '$policyName' weakened by $($event.Actor)"
        } else {
            "DLP policy '$policyName' modified by $($event.Actor)"
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365DLPPolicyChange'
            Description   = $description
            Details       = @{
                PolicyName    = $policyName
                OperationType = $operationType
                IsDisabling   = $isDisabling
                IsWeakened    = $isWeakened
                IsRemoved     = $isRemoved
                ChangeNotes   = @($changeDetails)
                ModifiedProps = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
