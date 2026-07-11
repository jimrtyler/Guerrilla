# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-EntraAuthChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraAuthChecks'
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

# ── EIDAUTH-001: Authentication Methods Policy Audit ─────────────────────
function Test-InfiltrationEIDAUTH001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $policy = $AuditData.AuthMethods.AuthMethodsPolicy
    if (-not $policy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authentication methods policy not available'
    }

    $configs = $AuditData.AuthMethods.MethodConfigurations
    $enabledMethods = @($configs | Where-Object { $_.state -eq 'enabled' })
    $disabledMethods = @($configs | Where-Object { $_.state -eq 'disabled' })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($enabledMethods.Count) methods enabled, $($disabledMethods.Count) disabled" `
        -Details @{
            EnabledCount   = $enabledMethods.Count
            DisabledCount  = $disabledMethods.Count
            EnabledMethods = @($enabledMethods | ForEach-Object {
                @{ Id = $_.id; Type = $_.'@odata.type'; State = $_.state }
            })
        }
}

# ── EIDAUTH-002: MFA Registration Status ─────────────────────────────────
function Test-InfiltrationEIDAUTH002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $registrationDetails -or $registrationDetails.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User registration details not available'
    }

    $total = $registrationDetails.Count
    $mfaRegistered = @($registrationDetails | Where-Object { $_.isMfaRegistered -eq $true }).Count
    $mfaCapable = @($registrationDetails | Where-Object { $_.isMfaCapable -eq $true }).Count
    $notRegistered = $total - $mfaRegistered
    $percentage = if ($total -gt 0) { [Math]::Round(($mfaRegistered / $total) * 100, 1) } else { 0 }

    $status = if ($percentage -ge 99) { 'PASS' }
              elseif ($percentage -ge 90) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "MFA registered: $mfaRegistered / $total users ($percentage%)" `
        -Details @{
            TotalUsers      = $total
            MfaRegistered   = $mfaRegistered
            MfaCapable      = $mfaCapable
            NotRegistered   = $notRegistered
            Percentage      = $percentage
        }
}

# ── EIDAUTH-003: MFA Method Distribution ─────────────────────────────────
function Test-InfiltrationEIDAUTH003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $registrationDetails -or $registrationDetails.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User registration details not available'
    }

    $methodCounts = @{}
    foreach ($user in $registrationDetails) {
        foreach ($method in @($user.methodsRegistered)) {
            if ($method) {
                $methodCounts[$method] = ($methodCounts[$method] ?? 0) + 1
            }
        }
    }

    $distribution = @($methodCounts.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
        @{ Method = $_.Key; Count = $_.Value; Percentage = [Math]::Round(($_.Value / $registrationDetails.Count) * 100, 1) }
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "MFA methods in use: $($methodCounts.Count) distinct types" `
        -Details @{
            Distribution = $distribution
            TotalUsers   = $registrationDetails.Count
        }
}

# ── EIDAUTH-004: Users with Only SMS/Voice MFA ──────────────────────────
function Test-InfiltrationEIDAUTH004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $registrationDetails -or $registrationDetails.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User registration details not available'
    }

    $weakMethods = @('mobilePhone', 'officePhone', 'alternateMobilePhone', 'smsSignIn')
    $strongMethods = @('microsoftAuthenticatorPush', 'softwareOneTimePasscode',
        'hardwareOneTimePasscode', 'microsoftAuthenticatorPasswordless',
        'fido2', 'windowsHelloForBusiness', 'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator')

    $weakOnlyUsers = @($registrationDetails | Where-Object {
        $_.isMfaRegistered -eq $true -and
        $_.methodsRegistered -and
        ($_.methodsRegistered | Where-Object { $_ -in $strongMethods }).Count -eq 0 -and
        ($_.methodsRegistered | Where-Object { $_ -in $weakMethods }).Count -gt 0
    })

    $status = if ($weakOnlyUsers.Count -eq 0) { 'PASS' }
              elseif ($weakOnlyUsers.Count -le 5) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($weakOnlyUsers.Count) users have only weak MFA methods (SMS/voice)" `
        -Details @{
            WeakOnlyCount = $weakOnlyUsers.Count
            Users         = @($weakOnlyUsers | Select-Object -First 50 | ForEach-Object {
                @{ UserPrincipalName = $_.userPrincipalName; Methods = @($_.methodsRegistered) }
            })
        }
}

# ── EIDAUTH-005: Users with No MFA ──────────────────────────────────────
function Test-InfiltrationEIDAUTH005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $registrationDetails -or $registrationDetails.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User registration details not available'
    }

    $noMfa = @($registrationDetails | Where-Object { $_.isMfaRegistered -ne $true })
    $total = $registrationDetails.Count
    $percentage = if ($total -gt 0) { [Math]::Round(($noMfa.Count / $total) * 100, 1) } else { 0 }

    $status = if ($noMfa.Count -eq 0) { 'PASS' }
              elseif ($percentage -le 5) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($noMfa.Count) users ($percentage%) have no MFA methods registered" `
        -Details @{
            NoMfaCount = $noMfa.Count
            TotalUsers = $total
            Percentage = $percentage
            Users      = @($noMfa | Select-Object -First 50 | ForEach-Object {
                @{ UserPrincipalName = $_.userPrincipalName; Id = $_.id }
            })
        }
}

# ── EIDAUTH-006: FIDO2 Security Key Inventory ───────────────────────────
function Test-InfiltrationEIDAUTH006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $registrationDetails) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User registration details not available'
    }

    $fido2Users = @($registrationDetails | Where-Object {
        $_.methodsRegistered -contains 'fido2'
    })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($fido2Users.Count) users have FIDO2 security keys registered" `
        -Details @{
            Fido2UserCount = $fido2Users.Count
            TotalUsers     = $registrationDetails.Count
        }
}

# ── EIDAUTH-007: FIDO2 ROCA Vulnerability Check ─────────────────────────
function Test-InfiltrationEIDAUTH007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # ROCA check requires detailed FIDO2 key data which may not be in registration details
    # This is a known-vulnerable AAGUID check
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'ROCA vulnerability check requires detailed FIDO2 key metadata (AAGUID analysis)'
}

# ── EIDAUTH-008: Passwordless Readiness ──────────────────────────────────
function Test-InfiltrationEIDAUTH008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $registrationDetails = $AuditData.AuthMethods.UserRegistrationDetails
    if (-not $registrationDetails -or $registrationDetails.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'User registration details not available'
    }

    $passwordlessMethods = @('fido2', 'windowsHelloForBusiness', 'microsoftAuthenticatorPasswordless',
        'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator')

    $passwordlessCapable = @($registrationDetails | Where-Object {
        $_.isPasswordlessCapable -eq $true -or
        ($_.methodsRegistered | Where-Object { $_ -in $passwordlessMethods }).Count -gt 0
    })

    $total = $registrationDetails.Count
    $percentage = if ($total -gt 0) { [Math]::Round(($passwordlessCapable.Count / $total) * 100, 1) } else { 0 }

    $status = if ($percentage -ge 80) { 'PASS' }
              elseif ($percentage -ge 30) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($passwordlessCapable.Count) users ($percentage%) are passwordless-capable" `
        -Details @{
            PasswordlessCapable = $passwordlessCapable.Count
            TotalUsers          = $total
            Percentage          = $percentage
        }
}

# ── EIDAUTH-009: Windows Hello for Business ──────────────────────────────
function Test-InfiltrationEIDAUTH009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.AuthMethods.Errors) `
        -SourceKey @('AuthMethods', 'AuthMethodsPolicy') -Subject 'authentication method configurations'
    if ($na) { return $na }

    $configs = $AuditData.AuthMethods.MethodConfigurations
    $whfb = $configs | Where-Object { $_.id -eq 'windowsHelloForBusiness' -or $_.'@odata.type' -match 'windowsHelloForBusiness' } | Select-Object -First 1

    if (-not $whfb) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Windows Hello for Business configuration not found'
    }

    $status = if ($whfb.state -eq 'enabled') { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Windows Hello for Business: $($whfb.state)" `
        -Details @{ State = $whfb.state; Configuration = $whfb }
}

# ── EIDAUTH-010: Temporary Access Pass Policy ────────────────────────────
function Test-InfiltrationEIDAUTH010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.AuthMethods.Errors) `
        -SourceKey @('AuthMethods', 'AuthMethodsPolicy') -Subject 'authentication method configurations'
    if ($na) { return $na }

    $configs = $AuditData.AuthMethods.MethodConfigurations
    $tap = $configs | Where-Object { $_.id -eq 'TemporaryAccessPass' -or $_.'@odata.type' -match 'temporaryAccessPass' } | Select-Object -First 1

    if (-not $tap) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Temporary Access Pass not configured'
    }

    $isOneTime = $tap.isUsableOnce
    $maxLifetime = $tap.maximumLifetimeInMinutes

    $status = if ($tap.state -ne 'enabled') { 'PASS' }
              elseif ($isOneTime -and $maxLifetime -le 60) { 'PASS' }
              elseif ($isOneTime) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "TAP: $($tap.state), one-time: $isOneTime, max lifetime: $maxLifetime min" `
        -Details @{
            State           = $tap.state
            IsUsableOnce    = $isOneTime
            MaxLifetime     = $maxLifetime
            DefaultLifetime = $tap.defaultLifetimeInMinutes
            DefaultLength   = $tap.defaultLength
        }
}

# ── EIDAUTH-011: SSPR Configuration ──────────────────────────────────────
function Test-InfiltrationEIDAUTH011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $authzPolicy = $AuditData.AuthMethods.AuthorizationPolicy
    if (-not $authzPolicy) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authorization policy not available'
    }

    $allowedToReset = $authzPolicy.allowedToUseSSPR ?? $false

    $status = if ($allowedToReset) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "SSPR enabled: $allowedToReset" `
        -Details @{
            SSPREnabled = $allowedToReset
        }
}

# ── EIDAUTH-012: SSPR Methods and Requirements ──────────────────────────
function Test-InfiltrationEIDAUTH012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # SSPR method details require additional API calls or directory settings
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'SSPR method configuration details require additional data collection'
}

# ── EIDAUTH-013: Password Protection Configuration ──────────────────────
function Test-InfiltrationEIDAUTH013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.AuthMethods.Errors) `
        -SourceKey @('AuthMethods', 'DirectorySettings') -Subject 'directory (password protection) settings'
    if ($na) { return $na }

    $settings = $AuditData.AuthMethods.DirectorySettings
    $passwordSettings = $settings | Where-Object {
        $_.displayName -match 'Password Rule Settings' -or
        $_.templateId -eq '5cf42378-d67d-4f36-ba46-e8b86229381d'
    } | Select-Object -First 1

    if (-not $passwordSettings) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Password protection settings not found — Azure AD Password Protection may not be configured'
    }

    $bannedPasswordEnabled = ($passwordSettings.values | Where-Object { $_.name -eq 'BannedPasswordCheckOnPremisesMode' }).value
    $enableBannedPasswordCheck = ($passwordSettings.values | Where-Object { $_.name -eq 'EnableBannedPasswordCheck' }).value

    $status = if ($enableBannedPasswordCheck -eq 'True') { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Banned password check: $enableBannedPasswordCheck, on-premises mode: $bannedPasswordEnabled" `
        -Details @{
            EnableBannedPasswordCheck       = $enableBannedPasswordCheck
            BannedPasswordCheckOnPremisesMode = $bannedPasswordEnabled
        }
}

# ── EIDAUTH-014: Custom Banned Password List ────────────────────────────
function Test-InfiltrationEIDAUTH014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.AuthMethods.Errors) `
        -SourceKey @('AuthMethods', 'DirectorySettings') -Subject 'directory (password protection) settings'
    if ($na) { return $na }

    $settings = $AuditData.AuthMethods.DirectorySettings
    $passwordSettings = $settings | Where-Object {
        $_.displayName -match 'Password Rule Settings' -or
        $_.templateId -eq '5cf42378-d67d-4f36-ba46-e8b86229381d'
    } | Select-Object -First 1

    if (-not $passwordSettings) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Password protection settings not found'
    }

    $bannedPasswordList = ($passwordSettings.values | Where-Object { $_.name -eq 'BannedPasswordList' }).value

    $hasCustomList = $bannedPasswordList -and $bannedPasswordList.Length -gt 0
    $status = if ($hasCustomList) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Custom banned password list: $(if ($hasCustomList) { 'configured' } else { 'not configured' })" `
        -Details @{ HasCustomList = $hasCustomList }
}

# ── EIDAUTH-015: Legacy Authentication Protocol Usage ────────────────────
function Test-InfiltrationEIDAUTH015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Legacy auth usage detection requires sign-in logs analysis
    # Check if CA policies block legacy auth as a proxy
    $caData = $AuditData.ConditionalAccess
    if (-not $caData -or -not $caData.Policies) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'CA policy data needed to assess legacy auth blocking'
    }

    $enabledPolicies = @($caData.Policies | Where-Object { $_.state -eq 'enabled' })
    $legacyBlockPolicies = @($enabledPolicies | Where-Object {
        ($_.conditions.clientAppTypes -contains 'exchangeActiveSync' -or
         $_.conditions.clientAppTypes -contains 'other') -and
        $_.grantControls.builtInControls -contains 'block'
    })

    $status = if ($legacyBlockPolicies.Count -gt 0) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Legacy auth blocking policies: $($legacyBlockPolicies.Count)" `
        -Details @{
            BlockPolicyCount = $legacyBlockPolicies.Count
            Note             = 'Full legacy auth usage analysis requires sign-in log data'
        }
}

# ── EIDAUTH-016: ROPC Flow Enabled ──────────────────────────────────────
function Test-InfiltrationEIDAUTH016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $apps = $AuditData.Applications.AppRegistrations
    if (-not $apps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Application registration data not available'
    }

    $ropcApps = @($apps | Where-Object {
        $_.isFallbackPublicClient -eq $true -or $_.allowPublicClient -eq $true
    })

    $status = if ($ropcApps.Count -eq 0) { 'PASS' }
              elseif ($ropcApps.Count -le 3) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($ropcApps.Count) app registrations allow public client / ROPC flow" `
        -Details @{
            RopcAppCount = $ropcApps.Count
            Apps         = @($ropcApps | Select-Object -First 20 | ForEach-Object {
                @{ AppId = $_.appId; DisplayName = $_.displayName }
            })
        }
}

# ── EIDAUTH-017: Per-User MFA vs CA Conflict ────────────────────────────
function Test-InfiltrationEIDAUTH017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    # Per-user MFA status requires legacy MFA management API
    # We can detect the conflict by checking if CA MFA policies exist
    $caData = $AuditData.ConditionalAccess
    $hasCaMfa = $false
    if ($caData -and $caData.Policies) {
        $mfaPolicies = @($caData.Policies | Where-Object {
            $_.state -eq 'enabled' -and
            $_.grantControls.builtInControls -contains 'mfa'
        })
        $hasCaMfa = $mfaPolicies.Count -gt 0
    }

    if (-not $hasCaMfa) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'No CA-based MFA policies found — verify if per-user MFA is being used instead' `
            -Details @{ HasCaMfa = $false }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'CA-based MFA detected. Verify per-user MFA is disabled to avoid conflicts (requires legacy MFA admin portal)' `
        -Details @{
            HasCaMfa = $true
            Note     = 'Per-user MFA status check requires legacy MFA management portal API'
        }
}

# ── EIDAUTH-018: Microsoft Authenticator Login Context (MS.AAD.3.3) ──────
function Test-InfiltrationEIDAUTH018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $configs = $AuditData.AuthMethods.MethodConfigurations
    if (-not $configs -or $configs.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Authentication method configurations not available — Not Assessed'
    }

    $authenticator = $configs | Where-Object {
        $_.id -eq 'MicrosoftAuthenticator' -or $_.'@odata.type' -match 'microsoftAuthenticator'
    } | Select-Object -First 1

    if (-not $authenticator) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Microsoft Authenticator method configuration not present — Not Assessed'
    }

    # MS.AAD.3.3 only applies when Authenticator is enabled. If disabled, the control
    # is satisfied by virtue of the method not being available.
    if ($authenticator.state -ne 'enabled') {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Microsoft Authenticator is not enabled — login context requirement not applicable' `
            -Details @{ AuthenticatorState = $authenticator.state }
    }

    $appState = $authenticator.featureSettings.displayAppInformationRequiredState.state
    $locState = $authenticator.featureSettings.displayLocationInformationRequiredState.state

    # SCuBA MS.AAD.3.3 = show login context (application name). Location is a recommended add-on.
    $appShown = $appState -eq 'enabled'
    $locShown = $locState -eq 'enabled'

    $status = if (-not $appShown) { 'FAIL' }
              elseif (-not $locShown) { 'WARN' }
              else { 'PASS' }

    $currentValue = if (-not $appShown) {
        'Microsoft Authenticator is enabled but application name is NOT shown in notifications — fails login-context requirement'
    } elseif (-not $locShown) {
        'Application name is shown; geographic location is not enabled (recommended)'
    } else {
        'Microsoft Authenticator shows application name and geographic location in notifications'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            AuthenticatorState              = $authenticator.state
            DisplayAppInformationState      = $appState ?? 'default'
            DisplayLocationInformationState = $locState ?? 'default'
            AppNameShown                    = $appShown
            LocationShown                   = $locShown
        }
}
