# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-M365TeamsExternalAccess {
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Events = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($event in $Events) {
        $activity = $event.Activity ?? ''
        $targetName = $event.TargetName ?? ''
        $changeDetails = [System.Collections.Generic.List[string]]::new()
        $accessWeakened = $false

        foreach ($prop in $event.ModifiedProps) {
            $propName = $prop.Name ?? ''
            $newVal = $prop.NewValue ?? ''
            $oldVal = $prop.OldValue ?? ''

            # External access (federation) settings
            if ($propName -match 'AllowFederatedUsers|AllowTeamsConsumer|AllowPublicUsers') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                $cleanOld = ($oldVal -replace '"', '').Trim()

                if ($cleanNew -match 'true|True' -and $cleanOld -match 'false|False') {
                    $accessWeakened = $true
                    $changeDetails.Add("External access enabled: $propName set to True")
                } elseif ($cleanNew -match 'false|False' -and $cleanOld -match 'true|True') {
                    $changeDetails.Add("External access restricted: $propName set to False")
                } else {
                    $changeDetails.Add("$propName changed: '$cleanOld' -> '$cleanNew'")
                }
            }

            # Guest access settings
            if ($propName -match 'AllowGuestUser|AllowGuestAccess|GuestAccessEnabled') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                $cleanOld = ($oldVal -replace '"', '').Trim()

                if ($cleanNew -match 'true|True' -and $cleanOld -match 'false|False') {
                    $accessWeakened = $true
                    $changeDetails.Add("Guest access enabled: $propName set to True")
                } else {
                    $changeDetails.Add("$propName changed: '$cleanOld' -> '$cleanNew'")
                }
            }

            # Domain allow/block list changes
            if ($propName -match 'AllowedDomains|BlockedDomains') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                $cleanOld = ($oldVal -replace '"', '').Trim()

                if ($propName -match 'AllowedDomains' -and $cleanNew -match 'AllowAllKnownDomains|\*') {
                    $accessWeakened = $true
                    $changeDetails.Add("Allowed domains set to all: $propName = '$cleanNew'")
                } elseif ($propName -match 'BlockedDomains' -and (-not $cleanNew -or $cleanNew -eq '' -or $cleanNew -eq '[]')) {
                    $accessWeakened = $true
                    $changeDetails.Add("Blocked domains list cleared")
                } else {
                    $changeDetails.Add("$propName changed: '$cleanOld' -> '$cleanNew'")
                }
            }

            # Meeting policy changes that allow external participants
            if ($propName -match 'AllowAnonymousUsersToJoinMeeting|AllowAnonymousUsersToStartMeeting|AutoAdmittedUsers') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                if ($cleanNew -match 'true|Everyone|EveryoneInCompanyAndFederated') {
                    $accessWeakened = $true
                    $changeDetails.Add("Meeting policy weakened: $propName = '$cleanNew'")
                } else {
                    $changeDetails.Add("$propName changed to: '$cleanNew'")
                }
            }

            # External app access
            if ($propName -match 'AllowExternalApps|AllowSideloading|AllowThirdPartyApps') {
                $cleanNew = ($newVal -replace '"', '').Trim()
                if ($cleanNew -match 'true|True') {
                    $changeDetails.Add("External app access enabled: $propName = True")
                }
            }
        }

        # Severity assessment
        $severity = if ($accessWeakened) { 'Medium' }
                    elseif ($activity -match 'guest|federation|external') { 'Low' }
                    else { 'Low' }

        $description = if ($accessWeakened) {
            "Teams external access weakened: '$targetName' by $($event.Actor)"
        } else {
            "Teams access policy modified: '$targetName' by $($event.Actor)"
        }

        $results.Add([PSCustomObject]@{
            Timestamp     = $event.Timestamp
            Actor         = $event.Actor
            DetectionType = 'm365TeamsExternalAccess'
            Description   = $description
            Details       = @{
                PolicyName     = $targetName
                Activity       = $activity
                AccessWeakened = $accessWeakened
                ChangeNotes    = @($changeDetails)
                ModifiedProps  = $event.ModifiedProps
            }
            Severity      = $severity
        })
    }

    return @($results)
}
