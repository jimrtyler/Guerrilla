# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraTenantSettingChange {
    [CmdletBinding()]
    param(
        [hashtable[]]$AuditEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Tenant-level setting activities
    $tenantActivities = @(
        'Set company information'
        'Set company allowed data location'
        'Set tenant level setting'
        'Update company settings'
        'Set password reset policy'
        'Set self-service password reset policy'
        'Set company branding'
        'Set directory feature on tenant'
        'Update authorization policy'
        'Update external identities policy'
        'Set external collaboration settings'
        'Set Cross-tenant access settings'
        'Update Cross-tenant access settings'
        'Set cross-tenant access policy'
        'Update cross-tenant access policy'
        'Update consent settings'
        'Set consent settings'
        'Update policy'
    )

    # High-severity setting keywords
    $highSeverityKeywords = @(
        'password'
        'authentication'
        'authorization'
        'consent'
        'external.*identit'
        'cross.*tenant'
        'collaboration'
        'federation'
        'conditional.*access'
        'mfa'
        'multi.*factor'
        'self.*service'
        'security.*default'
        'legacy.*auth'
    )

    foreach ($event in $AuditEvents) {
        $activity = $event.ActivityDisplayName
        $isTenantSetting = $false

        foreach ($ta in $tenantActivities) {
            if ($activity -match [regex]::Escape($ta)) {
                $isTenantSetting = $true
                break
            }
        }

        # Also match by category for policy changes
        if (-not $isTenantSetting -and $event.Category -in @('Policy', 'DirectoryManagement')) {
            if ($activity -match 'setting|policy|configuration|company') {
                $isTenantSetting = $true
            }
        }

        if (-not $isTenantSetting) { continue }

        # Extract setting details
        $settingName = ''
        $oldValue = ''
        $newValue = ''
        foreach ($resource in $event.TargetResources) {
            if ($resource.DisplayName) { $settingName = $resource.DisplayName }
            foreach ($prop in $resource.ModifiedProperties) {
                if (-not $settingName -and $prop.DisplayName) { $settingName = $prop.DisplayName }
                if ($prop.OldValue) { $oldValue = $prop.OldValue -replace '"', '' }
                if ($prop.NewValue) { $newValue = $prop.NewValue -replace '"', '' }
            }
        }

        # Check severity
        $isHighSeverity = $false
        $checkStr = "$activity $settingName"
        foreach ($keyword in $highSeverityKeywords) {
            if ($checkStr -match $keyword) {
                $isHighSeverity = $true
                break
            }
        }

        $initiator = $event.InitiatedBy.UserPrincipalName
        if (-not $initiator) { $initiator = $event.InitiatedBy.AppDisplayName }

        $results.Add([PSCustomObject]@{
            Timestamp      = $event.Timestamp
            Activity       = $activity
            Result         = $event.Result
            InitiatedBy    = $initiator
            SettingName    = $settingName
            OldValue       = $oldValue
            NewValue       = $newValue
            IsHighSeverity = $isHighSeverity
            Category       = $event.Category
        })
    }

    return @($results)
}
