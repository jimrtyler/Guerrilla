# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365ExternalSharingChange {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Sharing capability levels (ordered from most restrictive to least)
    $sharingLevels = @{
        'Disabled'                        = 0
        'ExistingExternalUserSharingOnly' = 1
        'ExternalUserSharingOnly'         = 2
        'ExternalUserAndGuestSharing'     = 3
        'Anyone'                          = 4
    }

    foreach ($event in $Events) {
        $activity = $event.Activity ?? ''
        $targetName = $event.TargetName ?? ''
        $sharingWeakened = $false
        $changeDetails = [System.Collections.Generic.List[string]]::new()
        $oldLevel = -1
        $newLevel = -1

        foreach ($prop in $event.ModifiedProps) {
            $propName = $prop.Name ?? ''
            $newVal = $prop.NewValue ?? ''
            $oldVal = $prop.OldValue ?? ''

            # SharingCapability changes
            if ($propName -match 'SharingCapability|SharingAllowed|ExternalSharing') {
                $cleanOld = ($oldVal -replace '"', '').Trim()
                $cleanNew = ($newVal -replace '"', '').Trim()

                # Determine if sharing was weakened
                foreach ($level in $sharingLevels.Keys) {
                    if ($cleanOld -match $level) { $oldLevel = $sharingLevels[$level] }
                    if ($cleanNew -match $level) { $newLevel = $sharingLevels[$level] }
                }

                if ($newLevel -gt $oldLevel -and $oldLevel -ge 0) {
                    $sharingWeakened = $true
                    $changeDetails.Add("$propName weakened from '$cleanOld' to '$cleanNew'")
                } elseif ($cleanNew -match 'true|enabled|Anyone' -and $cleanOld -match 'false|disabled') {
                    $sharingWeakened = $true
                    $changeDetails.Add("$propName enabled: '$cleanOld' -> '$cleanNew'")
                } else {
                    $changeDetails.Add("$propName changed: '$cleanOld' -> '$cleanNew'")
                }
            }

            # Anonymous link settings
            if ($propName -match 'AnonymousLink|DefaultLink|RequireAnonymousLink') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                $cleanOld = ($oldVal -replace '"', '').Trim()

                if ($cleanNew -match 'View|Edit|AnonymousAccess|true' -and $cleanOld -notmatch 'View|Edit|AnonymousAccess|true') {
                    $sharingWeakened = $true
                    $changeDetails.Add("Anonymous link access enabled: $propName = '$cleanNew'")
                } else {
                    $changeDetails.Add("$propName changed: '$cleanOld' -> '$cleanNew'")
                }
            }

            # Link expiration removed or extended
            if ($propName -match 'ExpirationDays|LinkExpiration|DefaultLinkExpiration') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                $cleanOld = ($oldVal -replace '"', '').Trim()

                if ($cleanNew -eq '0' -or $cleanNew -eq '' -or $cleanNew -eq 'null') {
                    $sharingWeakened = $true
                    $changeDetails.Add("Link expiration removed: $propName was '$cleanOld'")
                } elseif ($cleanNew -and $cleanOld) {
                    try {
                        if ([int]$cleanNew -gt [int]$cleanOld) {
                            $sharingWeakened = $true
                            $changeDetails.Add("Link expiration extended: $propName from $cleanOld to $cleanNew days")
                        }
                    } catch { }
                }
            }

            # Guest access settings
            if ($propName -match 'AllowGuestAccess|GuestAccess|ShowPeoplePickerSuggestionsForGuestUsers') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                if ($cleanNew -match 'true|enabled') {
                    $changeDetails.Add("Guest access setting enabled: $propName")
                }
            }
        }

        # Severity assessment
        $severity = if ($sharingWeakened -and $newLevel -ge 3) { 'High' }
                    elseif ($sharingWeakened) { 'Medium' }
                    elseif ($activity -match 'anonymous|anyone') { 'Medium' }
                    else { 'Low' }

        $description = if ($sharingWeakened) {
            "SharePoint sharing policy weakened on '$targetName' by $($event.Actor)"
        } else {
            "SharePoint sharing policy modified on '$targetName' by $($event.Actor)"
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365ExternalSharingChange'
            Description   = $description
            Details       = @{
                TargetSite      = $targetName
                Activity        = $activity
                SharingWeakened = $sharingWeakened
                OldSharingLevel = $oldLevel
                NewSharingLevel = $newLevel
                ChangeNotes     = @($changeDetails)
                ModifiedProps   = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
