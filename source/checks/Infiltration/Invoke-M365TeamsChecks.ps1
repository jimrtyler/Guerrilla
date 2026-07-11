# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-M365TeamsChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'M365TeamsChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_"))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented'))
        }
    }

    return @($findings)
}

# ── M365TEAMS-001: External Access (Federation) ─────────────────────
function Test-InfiltrationM365TEAMS001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.ExternalAccessConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams external access data not available (Teams admin module not connected)'
    }

    $config = $teams.ExternalAccessConfig
    $allowFederated = $config.AllowFederatedUsers
    $allowTeamsConsumer = $config.AllowTeamsConsumer
    $allowPublicUsers = $config.AllowPublicUsers
    $allowedDomains = $config.AllowedDomains
    $blockedDomains = $config.BlockedDomains

    # Determine if federation is restricted to specific domains
    $hasAllowList = ($allowedDomains -and $allowedDomains.Count -gt 0)
    $hasBlockList = ($blockedDomains -and $blockedDomains.Count -gt 0)

    $openCount = 0
    if ($allowFederated -eq $true) { $openCount++ }
    if ($allowTeamsConsumer -eq $true) { $openCount++ }
    if ($allowPublicUsers -eq $true) { $openCount++ }

    $status = if ($openCount -eq 0) { 'PASS' }
              elseif ($allowFederated -eq $true -and $hasAllowList) { 'PASS' }
              elseif ($openCount -le 1 -and $hasBlockList) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "External access: Federated=$allowFederated, Consumer=$allowTeamsConsumer, Public=$allowPublicUsers. Domain restrictions: AllowList=$hasAllowList, BlockList=$hasBlockList" `
        -Details @{
            AllowFederatedUsers = $allowFederated
            AllowTeamsConsumer = $allowTeamsConsumer
            AllowPublicUsers = $allowPublicUsers
            HasAllowedDomainList = $hasAllowList
            HasBlockedDomainList = $hasBlockList
            AllowedDomainCount = if ($allowedDomains) { $allowedDomains.Count } else { 0 }
            BlockedDomainCount = if ($blockedDomains) { $blockedDomains.Count } else { 0 }
            OpenChannelCount = $openCount
        }
}

# ── M365TEAMS-002: Guest Access ──────────────────────────────────────
function Test-InfiltrationM365TEAMS002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.GuestConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams guest configuration data not available (Teams admin module not connected)'
    }

    $config = $teams.GuestConfig
    $allowGuestAccess = $config.AllowGuestUser

    # Check if guest capabilities are restricted when access is enabled
    $guestCallingEnabled = $config.AllowIPVideo ?? $true
    $guestScreenSharing = $config.ScreenSharingMode ?? 'EntireScreen'
    $allowBox = $config.AllowBox ?? $false
    $allowDropBox = $config.AllowDropBox ?? $false
    $allowGoogleDrive = $config.AllowGoogleDrive ?? $false

    $thirdPartyStorageEnabled = ($allowBox -eq $true -or $allowDropBox -eq $true -or $allowGoogleDrive -eq $true)

    $status = if ($allowGuestAccess -eq $false) { 'PASS' }
              elseif ($allowGuestAccess -eq $true -and -not $thirdPartyStorageEnabled) { 'WARN' }
              elseif ($allowGuestAccess -eq $true -and $thirdPartyStorageEnabled) { 'FAIL' }
              else { 'PASS' }

    $description = if ($allowGuestAccess -eq $false) {
        'Guest access is disabled in Teams'
    } elseif ($thirdPartyStorageEnabled) {
        'Guest access enabled with third-party cloud storage allowed — consider restricting capabilities'
    } else {
        'Guest access enabled with restricted third-party storage'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            AllowGuestUser = $allowGuestAccess
            AllowIPVideo = $guestCallingEnabled
            ScreenSharingMode = $guestScreenSharing
            AllowBox = $allowBox
            AllowDropBox = $allowDropBox
            AllowGoogleDrive = $allowGoogleDrive
            ThirdPartyStorageEnabled = $thirdPartyStorageEnabled
        }
}

# ── M365TEAMS-003: External Meeting Participants ─────────────────────
function Test-InfiltrationM365TEAMS003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.MeetingPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams meeting policy data not available (Teams admin module not connected)'
    }

    $policies = $teams.MeetingPolicies
    $globalPolicy = $policies | Where-Object {
        $_.Identity -eq 'Global' -or $_.Identity -match 'Tag:Global'
    } | Select-Object -First 1

    if (-not $globalPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Global meeting policy not found in Teams configuration'
    }

    $allowExternal = $globalPolicy.AllowExternalParticipantGiveRequestControl
    $autoAdmit = $globalPolicy.AutoAdmittedUsers

    $status = if ($allowExternal -eq $false -and $autoAdmit -eq 'EveryoneInCompany') { 'PASS' }
              elseif ($allowExternal -eq $false) { 'PASS' }
              elseif ($autoAdmit -eq 'Everyone') { 'FAIL' }
              else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "External participant control: GiveRequestControl=$allowExternal, AutoAdmit=$autoAdmit" `
        -Details @{
            AllowExternalParticipantGiveRequestControl = $allowExternal
            AutoAdmittedUsers = $autoAdmit
            PolicyCount = $policies.Count
        }
}

# ── M365TEAMS-004: Anonymous Meeting Join ────────────────────────────
function Test-InfiltrationM365TEAMS004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.MeetingPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams meeting policy data not available (Teams admin module not connected)'
    }

    $policies = $teams.MeetingPolicies
    $globalPolicy = $policies | Where-Object {
        $_.Identity -eq 'Global' -or $_.Identity -match 'Tag:Global'
    } | Select-Object -First 1

    if (-not $globalPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Global meeting policy not found in Teams configuration'
    }

    $anonymousJoin = $globalPolicy.AllowAnonymousUsersToJoinMeeting
    $dialInBypass = $globalPolicy.AllowPSTNUsersToBypassLobby

    $status = if ($anonymousJoin -eq $false) { 'PASS' }
              elseif ($anonymousJoin -eq $true -and $dialInBypass -eq $true) { 'FAIL' }
              elseif ($anonymousJoin -eq $true) { 'WARN' }
              else { 'PASS' }

    $description = if ($anonymousJoin -eq $false) {
        'Anonymous users cannot join meetings (recommended)'
    } elseif ($anonymousJoin -eq $true -and $dialInBypass -eq $true) {
        'Anonymous join AND PSTN lobby bypass are both enabled — high risk'
    } else {
        'Anonymous users can join meetings — consider disabling for sensitive environments'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            AllowAnonymousUsersToJoinMeeting = $anonymousJoin
            AllowPSTNUsersToBypassLobby = $dialInBypass
        }
}

# ── M365TEAMS-005: Recording and Transcription ──────────────────────
function Test-InfiltrationM365TEAMS005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.MeetingPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams meeting policy data not available (Teams admin module not connected)'
    }

    $policies = $teams.MeetingPolicies
    $globalPolicy = $policies | Where-Object {
        $_.Identity -eq 'Global' -or $_.Identity -match 'Tag:Global'
    } | Select-Object -First 1

    if (-not $globalPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Global meeting policy not found in Teams configuration'
    }

    $allowRecording = $globalPolicy.AllowCloudRecording ?? 'Unknown'
    $allowTranscription = $globalPolicy.AllowTranscription ?? 'Unknown'
    $recordingStorageMode = $globalPolicy.RecordingStorageMode ?? 'Unknown'

    # Recording should be intentionally configured — not necessarily disabled
    $status = if ($allowRecording -eq $true -and $recordingStorageMode -eq 'OneDriveForBusiness') { 'PASS' }
              elseif ($allowRecording -eq $false) { 'PASS' }
              elseif ($allowRecording -eq $true) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Cloud recording: $allowRecording, Transcription: $allowTranscription, Storage: $recordingStorageMode" `
        -Details @{
            AllowCloudRecording = $allowRecording
            AllowTranscription = $allowTranscription
            RecordingStorageMode = $recordingStorageMode
        }
}

# ── M365TEAMS-006: Messaging Policies ────────────────────────────────
function Test-InfiltrationM365TEAMS006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.MessagingPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams messaging policy data not available (Teams admin module not connected)'
    }

    $policies = $teams.MessagingPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Teams messaging policies found'
    }

    $globalPolicy = $policies | Where-Object {
        $_.Identity -eq 'Global' -or $_.Identity -match 'Tag:Global'
    } | Select-Object -First 1

    # Check external messaging settings
    $allowUrlPreviews = $globalPolicy.AllowUrlPreviews ?? $true
    $allowUserChat = $globalPolicy.AllowUserChat ?? $true
    $chatPermissionRole = $globalPolicy.ChatPermissionRole ?? 'Unknown'

    $status = if ($chatPermissionRole -eq 'Restricted') { 'PASS' }
              elseif ($chatPermissionRole -eq 'Full') { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($policies.Count) messaging policies. Global: UrlPreviews=$allowUrlPreviews, UserChat=$allowUserChat, ChatRole=$chatPermissionRole" `
        -Details @{
            PolicyCount = $policies.Count
            AllowUrlPreviews = $allowUrlPreviews
            AllowUserChat = $allowUserChat
            ChatPermissionRole = $chatPermissionRole
            Policies = @($policies | ForEach-Object {
                @{
                    Identity = $_.Identity
                    AllowUrlPreviews = $_.AllowUrlPreviews
                    AllowOwnerDeleteMessage = $_.AllowOwnerDeleteMessage
                    AllowUserDeleteMessage = $_.AllowUserDeleteMessage
                    AllowUserEditMessage = $_.AllowUserEditMessage
                    ChatPermissionRole = $_.ChatPermissionRole
                }
            })
        }
}

# ── M365TEAMS-007: App Permission Policies ───────────────────────────
function Test-InfiltrationM365TEAMS007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.AppPermissionPolicies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams app permission policy data not available (Teams admin module not connected)'
    }

    $policies = $teams.AppPermissionPolicies
    if ($policies.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No Teams app permission policies found'
    }

    $globalPolicy = $policies | Where-Object {
        $_.Identity -eq 'Global' -or $_.Identity -match 'Tag:Global'
    } | Select-Object -First 1

    $thirdPartyApps = $globalPolicy.DefaultCatalogAppsType ?? 'Unknown'
    $customApps = $globalPolicy.GlobalCatalogAppsType ?? 'Unknown'
    $privateApps = $globalPolicy.PrivateCatalogAppsType ?? 'Unknown'

    $thirdPartyBlocked = ($thirdPartyApps -eq 'BlockAllApps')

    $status = if ($thirdPartyBlocked) { 'PASS' }
              elseif ($thirdPartyApps -eq 'AllowedAppList') { 'PASS' }
              elseif ($thirdPartyApps -eq 'BlockedAppList') { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "App permissions: ThirdParty=$thirdPartyApps, Custom=$customApps, Private=$privateApps" `
        -Details @{
            PolicyCount = $policies.Count
            DefaultCatalogAppsType = $thirdPartyApps
            GlobalCatalogAppsType = $customApps
            PrivateCatalogAppsType = $privateApps
            ThirdPartyAppsBlocked = $thirdPartyBlocked
        }
}

# ── M365TEAMS-008: File Sharing Settings ─────────────────────────────
function Test-InfiltrationM365TEAMS008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.M365Services.Errors) `
        -SourceKey @('M365Services', 'TeamsAdmin', 'TeamsApps') -Subject 'Teams configuration'
    if ($na) { return $na }

    $teams = $AuditData.M365Services.Teams
    if (-not $teams -or -not $teams.GuestConfig) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Teams client configuration / guest config data not available (Teams admin module not connected)'
    }

    $config = $teams.GuestConfig

    # Check cloud storage integrations
    $allowBox = $config.AllowBox ?? $false
    $allowDropBox = $config.AllowDropBox ?? $false
    $allowGoogleDrive = $config.AllowGoogleDrive ?? $false
    $allowShareFile = $config.AllowShareFile ?? $false
    $allowEgnyte = $config.AllowEgnyte ?? $false

    $enabledProviders = [System.Collections.Generic.List[string]]::new()
    if ($allowBox -eq $true) { $enabledProviders.Add('Box') }
    if ($allowDropBox -eq $true) { $enabledProviders.Add('Dropbox') }
    if ($allowGoogleDrive -eq $true) { $enabledProviders.Add('Google Drive') }
    if ($allowShareFile -eq $true) { $enabledProviders.Add('ShareFile') }
    if ($allowEgnyte -eq $true) { $enabledProviders.Add('Egnyte') }

    $status = if ($enabledProviders.Count -eq 0) { 'PASS' }
              elseif ($enabledProviders.Count -le 2) { 'WARN' }
              else { 'FAIL' }

    $description = if ($enabledProviders.Count -eq 0) {
        'No third-party cloud storage providers enabled — file sharing restricted to SharePoint/OneDrive'
    } else {
        "$($enabledProviders.Count) third-party storage provider(s) enabled: $($enabledProviders -join ', ')"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $description `
        -Details @{
            AllowBox = $allowBox
            AllowDropBox = $allowDropBox
            AllowGoogleDrive = $allowGoogleDrive
            AllowShareFile = $allowShareFile
            AllowEgnyte = $allowEgnyte
            EnabledProviderCount = $enabledProviders.Count
            EnabledProviders = @($enabledProviders)
        }
}
