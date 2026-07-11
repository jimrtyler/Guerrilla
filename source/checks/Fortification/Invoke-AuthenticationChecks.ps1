# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-AuthenticationChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'AuthenticationChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Fortification$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                if ($finding) { $findings.Add($finding) }
            } catch {
                $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'ERROR' `
                    -CurrentValue "Check failed: $_" -OrgUnitPath $OrgUnitPath))
            }
        } else {
            $findings.Add((New-AuditFinding -CheckDefinition $check -Status 'SKIP' `
                -CurrentValue 'Check not yet implemented' -OrgUnitPath $OrgUnitPath))
        }
    }

    return @($findings)
}

# ── AUTH-001: 2SV Enforcement ───────────────────────────────────────────────
function Test-FortificationAUTH001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    $users = @($AuditData.Users | Where-Object { -not $_.suspended })
    if ($users.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No active users found' -OrgUnitPath $OrgUnitPath
    }

    $enforced = @($users | Where-Object { $_.isEnforcedIn2Sv -eq $true })
    $notEnforced = @($users | Where-Object { $_.isEnforcedIn2Sv -ne $true })
    $enforcedRate = [Math]::Round(($enforced.Count / $users.Count) * 100, 1)

    $status = if ($enforcedRate -ge 95) { 'PASS' }
              elseif ($enforcedRate -ge 50) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "$enforcedRate% ($($enforced.Count) of $($users.Count) active users) have 2SV enforced"

    $details = @{ EnforcedCount = $enforced.Count; TotalActive = $users.Count; Rate = $enforcedRate }
    if ($notEnforced.Count -gt 0) {
        $details.AffectedItems = @($notEnforced | ForEach-Object { $_.primaryEmail })
        $details.AffectedLabel = 'Active users without 2SV enforced'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details $details
}

# ── AUTH-002: 2SV Enrollment Rate ───────────────────────────────────────────
function Test-FortificationAUTH002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    $users = @($AuditData.Users | Where-Object { -not $_.suspended })
    if ($users.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No active users found' -OrgUnitPath $OrgUnitPath
    }

    $enrolled = @($users | Where-Object { $_.isEnrolledIn2Sv -eq $true })
    $notEnrolled = @($users | Where-Object { $_.isEnrolledIn2Sv -ne $true })
    $rate = [Math]::Round(($enrolled.Count / $users.Count) * 100, 1)

    $status = if ($rate -ge 95) { 'PASS' }
              elseif ($rate -ge 80) { 'WARN' }
              else { 'FAIL' }

    $currentValue = "$rate% ($($enrolled.Count) of $($users.Count) active users) enrolled in 2SV"

    $details = @{ EnrolledCount = $enrolled.Count; TotalActive = $users.Count; Rate = $rate }
    if ($notEnrolled.Count -gt 0) {
        $details.AffectedItems = @($notEnrolled | ForEach-Object { $_.primaryEmail })
        $details.AffectedLabel = 'Active users not enrolled in 2SV'
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details $details
}

# ── AUTH-003: 2SV Method Strength ───────────────────────────────────────────
function Test-FortificationAUTH003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: allowed 2SV sign-in factors come from the Cloud Identity policy.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'security.two_step_verification_enforcement_factor' -Field 'allowedSignInFactorSet')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No 2SV enforcement-factor policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }

    $allowsAll  = @($vals | Where-Object { "$_" -match '(?i)\bALL\b' })
    $keyOnly    = @($vals | Where-Object { "$_" -match '(?i)SECURITY_KEY|FIDO|PASSKEY' })
    $note = "Allowed sign-in factor set: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"

    if ($allowsAll.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "All 2SV methods permitted (incl. phishable SMS/voice) — $note" -OrgUnitPath $OrgUnitPath
    }
    if ($keyOnly.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Phishing-resistant 2SV methods enforced — $note" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "2SV method set is restricted but not security-key-only — $note" -OrgUnitPath $OrgUnitPath
}

# ── AUTH-004: Password Minimum Length ───────────────────────────────────────
function Test-FortificationAUTH004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.password { minimumLength=number }. Grade the WEAKEST targeted OU.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.password' -Field 'minimumLength')
    $nums = @($vals | Where-Object { $null -ne $_ } | ForEach-Object { [int]$_ })
    if ($nums.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No password-length policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $minLen = ($nums | Measure-Object -Minimum).Minimum
    $status = if ($minLen -ge 12) { 'PASS' } elseif ($minLen -ge 8) { 'WARN' } else { 'FAIL' }
    $scope  = if ($nums.Count -gt 1) { " (weakest of $($nums.Count) targeted policies)" } else { '' }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Minimum password length: $minLen characters$scope" -OrgUnitPath $OrgUnitPath
}

# ── AUTH-005: Password Reuse Restriction ────────────────────────────────────
function Test-FortificationAUTH005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.password { allowReuse=bool }. Insecure when reuse is allowed anywhere.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.password' -Field 'allowReuse')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No password-reuse policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $reuseAllowed = @($vals | Where-Object { $_ -eq $true })
    if ($reuseAllowed.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Password reuse allowed in $($reuseAllowed.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Password reuse restricted' -OrgUnitPath $OrgUnitPath
}

# ── AUTH-006: Session Duration ──────────────────────────────────────────────
function Test-FortificationAUTH006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.session_controls { webSessionDuration=str("1209600s") }. Grade LONGEST OU.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.session_controls' -Field 'webSessionDuration')
    $seconds = @($vals | ForEach-Object { ConvertFrom-GoogleDurationSeconds $_ } | Where-Object { $null -ne $_ })
    if ($seconds.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No web-session-duration policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $maxSec = ($seconds | Measure-Object -Maximum).Maximum
    $hours  = [Math]::Round($maxSec / 3600, 1)
    $status = if ($hours -le 12) { 'PASS' } elseif ($hours -le 24) { 'WARN' } else { 'FAIL' }
    $scope  = if ($seconds.Count -gt 1) { " (longest of $($seconds.Count) targeted policies)" } else { '' }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Web session duration: $hours hours$scope" -OrgUnitPath $OrgUnitPath
}

# ── AUTH-007: SSO Configuration ─────────────────────────────────────────────
function Test-FortificationAUTH007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # SSO configuration is not directly exposed in the Directory API user listing
    # but we can check if the tenant has SSO-related indicators
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'SSO configuration requires manual verification. Check Admin Console > Security > SSO' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'SSO profile settings are not fully exposed via the Admin SDK Directory API' }
}

# ── AUTH-008: Less Secure Apps Access ───────────────────────────────────────
function Test-FortificationAUTH008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.less_secure_apps { allowLessSecureApps=bool }.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.less_secure_apps' -Field 'allowLessSecureApps')
    if ($vals.Count -eq 0) {
        # Type not returned — LSA was deprecated/removed for most editions in 2024.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'Less secure apps access is deprecated and disabled by Google for most Workspace editions' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'No less_secure_apps policy returned; LSA deprecated in 2024.' }
    }
    $allowed = @($vals | Where-Object { $_ -eq $true })
    if ($allowed.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Less secure apps allowed in $($allowed.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Less secure apps blocked' -OrgUnitPath $OrgUnitPath
}

# ── AUTH-009: App Passwords Policy ──────────────────────────────────────────
function Test-FortificationAUTH009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'App password policy requires manual verification. Check Admin Console > Security > 2-Step Verification settings' `
        -OrgUnitPath $OrgUnitPath
}

# ── AUTH-010: Recovery Options Configuration ────────────────────────────────
function Test-FortificationAUTH010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    $superAdmins = @($AuditData.Users | Where-Object { $_.isAdmin -eq $true -and -not $_.suspended })
    if ($superAdmins.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No super admins found' -OrgUnitPath $OrgUnitPath
    }

    $adminsWithRecovery = @($superAdmins | Where-Object {
        $_.recoveryEmail -or $_.recoveryPhone
    })

    if ($adminsWithRecovery.Count -gt 0) {
        $adminEmails = @($adminsWithRecovery | ForEach-Object { $_.primaryEmail })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($adminsWithRecovery.Count) super admin(s) have personal recovery options configured" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                SuperAdminsWithRecovery = $adminEmails
                AffectedItems           = $adminEmails
                AffectedLabel           = 'Super admins with personal recovery options'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No super admins have personal recovery options configured' `
        -OrgUnitPath $OrgUnitPath
}

# ── AUTH-011: Login Challenge Settings ──────────────────────────────────────
function Test-FortificationAUTH011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.login_challenges { enableEmployeeIdChallenge=bool } — an extra
    # login challenge that hardens against suspicious sign-ins. Recommend enabling.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.login_challenges' -Field 'enableEmployeeIdChallenge')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No login-challenges policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $disabled = @($vals | Where-Object { $_ -ne $true })
    if ($disabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Employee-ID login challenge not enabled in $($disabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Employee-ID login challenge enabled' -OrgUnitPath $OrgUnitPath
}

# ── AUTH-012: Super Admin 2SV Enrollment ────────────────────────────────────
function Test-FortificationAUTH012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    $superAdmins = @($AuditData.Users | Where-Object { $_.isAdmin -eq $true -and -not $_.suspended })
    if ($superAdmins.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No super admins found' -OrgUnitPath $OrgUnitPath
    }

    $notEnrolled = @($superAdmins | Where-Object { $_.isEnrolledIn2Sv -ne $true })

    if ($notEnrolled.Count -gt 0) {
        $adminEmails = @($notEnrolled | ForEach-Object { $_.primaryEmail })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($notEnrolled.Count) of $($superAdmins.Count) super admin(s) not enrolled in 2SV" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                NotEnrolled      = $adminEmails
                TotalSuperAdmins = $superAdmins.Count
                AffectedItems    = $adminEmails
                AffectedLabel    = 'Super admins without 2SV enrolled'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($superAdmins.Count) super admins enrolled in 2SV" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalSuperAdmins = $superAdmins.Count }
}

# ── AUTH-013: Stale Super Admin Accounts ────────────────────────────────────
function Test-FortificationAUTH013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'user inventory'
    if ($na) { return $na }

    $superAdmins = @($AuditData.Users | Where-Object { $_.isAdmin -eq $true -and -not $_.suspended })
    if ($superAdmins.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No super admins found' -OrgUnitPath $OrgUnitPath
    }

    $staleDays = 90
    $now = [datetime]::UtcNow
    $staleAdmins = [System.Collections.Generic.List[string]]::new()

    foreach ($admin in $superAdmins) {
        $lastLogin = $null
        if ($admin.lastLoginTime) {
            try { $lastLogin = [datetime]::Parse($admin.lastLoginTime) } catch { }
        }
        if (-not $lastLogin -or ($now - $lastLogin).TotalDays -gt $staleDays) {
            $staleAdmins.Add($admin.primaryEmail)
        }
    }

    if ($staleAdmins.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($staleAdmins.Count) super admin(s) inactive for more than $staleDays days" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{
                StaleAdmins   = @($staleAdmins)
                ThresholdDays = $staleDays
                AffectedItems = @($staleAdmins)
                AffectedLabel = 'Stale super admin accounts'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($superAdmins.Count) super admins have logged in within the last $staleDays days" `
        -OrgUnitPath $OrgUnitPath
}

# ── AUTH-014: 2SV Enrollment Allowed ────────────────────────────────────────
function Test-FortificationAUTH014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.two_step_verification_enrollment { allowEnrollment=bool }. true=GOOD.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.two_step_verification_enrollment' -Field 'allowEnrollment')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No 2SV-enrollment policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $disabled = @($vals | Where-Object { $_ -ne $true })
    if ($disabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "2SV enrollment not allowed in $($disabled.Count) of $($vals.Count) targeted policy/policies (blocks MFA adoption)" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Users allowed to enroll in 2SV' -OrgUnitPath $OrgUnitPath
}

# ── AUTH-015: 2SV Enrollment Grace Period ───────────────────────────────────
function Test-FortificationAUTH015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.two_step_verification_grace_period { enrollmentGracePeriod=str("604800s") }.
    # Grade the LONGEST OU; 0 is strongest.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.two_step_verification_grace_period' -Field 'enrollmentGracePeriod')
    $seconds = @($vals | ForEach-Object { ConvertFrom-GoogleDurationSeconds $_ } | Where-Object { $null -ne $_ })
    if ($seconds.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No 2SV-grace-period policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $maxSec = ($seconds | Measure-Object -Maximum).Maximum
    $hours  = [Math]::Round($maxSec / 3600, 1)
    $status = if ($hours -le 168) { 'PASS' } else { 'WARN' }
    $scope  = if ($seconds.Count -gt 1) { " (longest of $($seconds.Count) targeted policies)" } else { '' }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "2SV enrollment grace period: $hours hours$scope" -OrgUnitPath $OrgUnitPath
}

# ── AUTH-016: Advanced Protection Self-Enrollment ───────────────────────────
function Test-FortificationAUTH016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.advanced_protection_program { enableAdvancedProtectionSelfEnrollment=bool }. true=GOOD.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.advanced_protection_program' -Field 'enableAdvancedProtectionSelfEnrollment')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No advanced-protection policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $disabled = @($vals | Where-Object { $_ -ne $true })
    if ($disabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Advanced Protection self-enrollment not allowed in $($disabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Advanced Protection self-enrollment allowed' -OrgUnitPath $OrgUnitPath
}

# ── AUTH-017: Super Admin Account Self-Recovery ─────────────────────────────
function Test-FortificationAUTH017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: security.super_admin_account_recovery { enableAccountRecovery=bool }. true=BAD.
    # Weakest-OU-wins: self-recovery enabled anywhere is a takeover path -> FAIL.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'security.super_admin_account_recovery' -Field 'enableAccountRecovery')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No super-admin-recovery policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Super admin self-recovery enabled in $($enabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Super admin self-recovery disabled' -OrgUnitPath $OrgUnitPath
}

# ── AUTH-018: Account self-recovery disabled for users and non-super admins (GWS.COMMONCONTROLS.8.2) ──
function Test-FortificationAUTH018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    Test-GwsPolicyBoolean -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath `
        -Type 'security.user_account_recovery' -Field 'enableAccountRecovery' -SecureValue $false -Status 'FAIL' `
        -BadMsg 'Account self-recovery is enabled' -GoodMsg 'Account self-recovery is disabled'
}
