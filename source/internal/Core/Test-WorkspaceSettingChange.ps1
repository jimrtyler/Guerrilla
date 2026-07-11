# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-WorkspaceSettingChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AdminEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Security-relevant settings to monitor
    $securitySettings = @(
        'CHANGE_APPLICATION_SETTING'
        'CHANGE_ORGANIZATION_SETTING'
        'CHANGE_DOMAIN_SETTING'
        'CHANGE_SECURITY_SETTING'
        'CHANGE_DATA_LOCALIZATION_SETTING'
        'CHANGE_GMAIL_SETTING'
        'CHANGE_CALENDAR_SETTING'
        'CHANGE_DRIVE_SETTING'
        'CHANGE_SITES_SETTING'
        'CHANGE_GROUPS_SETTING'
        'CHANGE_MOBILE_SETTING'
    )

    # High-severity setting keywords
    $highSeverityKeywords = @(
        'password'
        'two.?step'
        '2sv'
        'sso'
        'saml'
        'ldap'
        'oauth'
        'api.?access'
        'sharing'
        'external'
        'less.?secure'
        'imap'
        'pop'
        'smtp'
        'forwarding'
        'whitelist'
        'allowlist'
        'trusted'
        'security'
        'compliance'
        'audit'
        'dlp'
        'encryption'
        'mobile.?management'
        'device.?management'
    )

    foreach ($event in $AdminEvents) {
        if ($event.EventName -notin $securitySettings) { continue }

        $settingName = $event.Params['SETTING_NAME'] ?? $event.Params['APPLICATION_NAME'] ?? ''
        $oldValue = $event.Params['OLD_VALUE'] ?? ''
        $newValue = $event.Params['NEW_VALUE'] ?? ''
        $orgUnit = $event.Params['ORG_UNIT_NAME'] ?? ''

        $isHighSeverity = $false
        foreach ($keyword in $highSeverityKeywords) {
            if ($settingName -match $keyword -or $event.EventName -match $keyword) {
                $isHighSeverity = $true
                break
            }
        }

        $results.Add([PSCustomObject]@{
            Timestamp      = $event.Timestamp
            User           = $event.User
            EventName      = $event.EventName
            IpAddress      = $event.IpAddress
            SettingName    = $settingName
            OldValue       = $oldValue
            NewValue       = $newValue
            OrgUnit        = $orgUnit
            IsHighSeverity = $isHighSeverity
            Params         = $event.Params
        })
    }

    return @($results)
}
