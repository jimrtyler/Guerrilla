# PSGuerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/PSGuerrilla | https://creativecommons.org/licenses/by/4.0/
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

    # This check evaluates the OU policy for allowed 2SV methods
    # Without direct API access to the 2SV policy settings, we infer from user data
    $users = @($AuditData.Users | Where-Object { -not $_.suspended -and $_.isEnrolledIn2Sv -eq $true })
    if ($users.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No 2SV-enrolled users found' -OrgUnitPath $OrgUnitPath
    }

    # The Admin SDK doesn't expose per-user 2SV method in the users.list response.
    # This check is reported as INFO with guidance to verify in Admin Console.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Verify in Admin Console that security keys are the required 2SV method' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'API does not expose per-user 2SV method type. Manual verification recommended.' }
}

# ── AUTH-004: Password Minimum Length ───────────────────────────────────────
function Test-FortificationAUTH004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Password policy details are not fully exposed via the Directory API
    # Check OU policies if available
    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $policy.passwordMinLength) {
        $minLen = [int]$policy.passwordMinLength
        $status = if ($minLen -ge 12) { 'PASS' }
                  elseif ($minLen -ge 8) { 'WARN' }
                  else { 'FAIL' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Minimum password length: $minLen characters" -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Password policy details not available via API. Verify minimum length of 12+ characters in Admin Console' `
        -OrgUnitPath $OrgUnitPath
}

# ── AUTH-005: Password Reuse Restriction ────────────────────────────────────
function Test-FortificationAUTH005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.passwordReuseRestriction) {
        $status = if ($policy.passwordReuseRestriction -eq $true) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.passwordReuseRestriction) { 'Password reuse restricted' } else { 'Password reuse allowed' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Password reuse policy not available via API. Verify in Admin Console' `
        -OrgUnitPath $OrgUnitPath
}

# ── AUTH-006: Session Duration ──────────────────────────────────────────────
function Test-FortificationAUTH006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $policy.sessionDurationHours) {
        $hours = [int]$policy.sessionDurationHours
        $status = if ($hours -le 12) { 'PASS' }
                  elseif ($hours -le 24) { 'WARN' }
                  else { 'FAIL' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Session duration: $hours hours" -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Session duration policy not available via API. Verify in Admin Console that sessions are limited to 12 hours or less' `
        -OrgUnitPath $OrgUnitPath
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

    # Google deprecated LSA access for most accounts in 2024
    # Check if any users still have it enabled based on OU policy
    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.lessSecureApps) {
        $status = if ($policy.lessSecureApps -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.lessSecureApps) { 'Less secure apps allowed' } else { 'Less secure apps blocked' }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    # Google removed LSA for most Workspace editions by late 2024
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Less secure apps access is deprecated and disabled by Google for most Workspace editions' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Google deprecated LSA access in 2024. Verify if legacy edition.' }
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

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Login challenge settings require manual verification. Check Admin Console > Security > Login challenges' `
        -OrgUnitPath $OrgUnitPath
}

# ── AUTH-012: Super Admin 2SV Enrollment ────────────────────────────────────
function Test-FortificationAUTH012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

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
