# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-ADPasswordPolicyChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'ADPasswordPolicyChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Recon$($check.id -replace '-', '')"
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

# ── ADPWD-001: Default Domain Password Policy Overview ─────────────────────
function Test-ReconADPWD001 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $minLen   = [int]($dp.MinPasswordLength ?? 0)
    $complex  = [bool]($dp.PasswordComplexity ?? $false)
    $history  = [int]($dp.PasswordHistoryCount ?? 0)
    $maxAge   = $dp.MaxPasswordAge
    $lockout  = [int]($dp.LockoutThreshold ?? 0)
    $reversible = [bool]($dp.ReversibleEncryption ?? $false)

    # Determine max age in days (AD stores as negative TimeSpan ticks)
    $maxAgeDays = 0
    if ($maxAge -is [timespan]) {
        $maxAgeDays = [Math]::Abs($maxAge.TotalDays)
    }

    $issues = [System.Collections.Generic.List[string]]::new()
    if ($minLen -lt 14)   { $issues.Add("MinLength=$minLen (requires 14+)") }
    if (-not $complex)    { $issues.Add('Complexity not enabled') }
    if ($history -lt 24)  { $issues.Add("History=$history (requires 24+)") }
    if ($maxAgeDays -gt 365 -or $maxAgeDays -eq 0) {
        $issues.Add("MaxAge=$([Math]::Round($maxAgeDays, 0))d (requires <=365)")
    }
    if ($reversible)      { $issues.Add('Reversible encryption enabled') }
    if ($lockout -eq 0)   { $issues.Add('No account lockout configured') }

    $status = if ($issues.Count -eq 0) { 'PASS' } else { 'FAIL' }

    $summary = "MinLen=$minLen, Complexity=$complex, History=$history, MaxAge=$([Math]::Round($maxAgeDays, 0))d, Lockout=$lockout"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $summary `
        -Details @{
            MinPasswordLength    = $minLen
            PasswordComplexity   = $complex
            PasswordHistoryCount = $history
            MaxPasswordAgeDays   = [Math]::Round($maxAgeDays, 0)
            LockoutThreshold     = $lockout
            ReversibleEncryption = $reversible
            Issues               = @($issues)
        }
}

# ── ADPWD-002: Fine-Grained Password Policy Enumeration ───────────────────
function Test-ReconADPWD002 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $fgpps = @($AuditData.PasswordPolicies.FineGrainedPolicies ?? @())

    if ($fgpps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No fine-grained password policies (FGPPs) defined' `
            -Details @{ FGPPCount = 0 }
    }

    $policyDetails = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($fgpp in $fgpps) {
        $appliesToCount = @($fgpp.AppliesTo ?? @()).Count
        $policyDetails.Add(@{
            Name             = $fgpp.Name ?? 'Unknown'
            Precedence       = [int]($fgpp.Precedence ?? 0)
            MinPasswordLength = [int]($fgpp.MinPasswordLength ?? 0)
            Complexity       = [bool]($fgpp.PasswordComplexity ?? $false)
            HistoryCount     = [int]($fgpp.PasswordHistoryCount ?? 0)
            AppliesToCount   = $appliesToCount
        })
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$($fgpps.Count) fine-grained password policy(ies) defined" `
        -Details @{
            FGPPCount = $fgpps.Count
            Policies  = @($policyDetails)
        }
}

# ── ADPWD-003: FGPP Application Strength ──────────────────────────────────
function Test-ReconADPWD003 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $fgpps = @($AuditData.PasswordPolicies.FineGrainedPolicies ?? @())
    $dp = $AuditData.PasswordPolicies.DefaultPolicy

    if ($fgpps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No FGPPs defined; only default policy applies'
    }

    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default policy data not available for comparison'
    }

    $dpMinLen  = [int]($dp.MinPasswordLength ?? 0)
    $dpComplex = [bool]($dp.PasswordComplexity ?? $false)
    $dpHistory = [int]($dp.PasswordHistoryCount ?? 0)
    $dpMaxAge  = if ($dp.MaxPasswordAge -is [timespan]) { [Math]::Abs($dp.MaxPasswordAge.TotalDays) } else { 0 }

    $weakFgpps = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($fgpp in $fgpps) {
        $reasons = [System.Collections.Generic.List[string]]::new()
        $fMinLen  = [int]($fgpp.MinPasswordLength ?? 0)
        $fComplex = [bool]($fgpp.PasswordComplexity ?? $false)
        $fHistory = [int]($fgpp.PasswordHistoryCount ?? 0)
        $fMaxAge  = if ($fgpp.MaxPasswordAge -is [timespan]) { [Math]::Abs($fgpp.MaxPasswordAge.TotalDays) } else { 0 }

        if ($fMinLen -lt $dpMinLen) { $reasons.Add("MinLength $fMinLen < default $dpMinLen") }
        if ($dpComplex -and -not $fComplex) { $reasons.Add('Complexity disabled vs default enabled') }
        if ($fHistory -lt $dpHistory) { $reasons.Add("History $fHistory < default $dpHistory") }
        if ($fMaxAge -gt $dpMaxAge -and $dpMaxAge -gt 0) { $reasons.Add("MaxAge $([Math]::Round($fMaxAge,0))d > default $([Math]::Round($dpMaxAge,0))d") }

        if ($reasons.Count -gt 0) {
            $weakFgpps.Add(@{
                Name    = $fgpp.Name ?? 'Unknown'
                Reasons = @($reasons)
            })
        }
    }

    if ($weakFgpps.Count -gt 0) {
        $names = @($weakFgpps | ForEach-Object { $_.Name })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "$($weakFgpps.Count) FGPP(s) have weaker settings than the default policy: $($names -join ', ')" `
            -Details @{ WeakFGPPs = @($weakFgpps) }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "All $($fgpps.Count) FGPP(s) meet or exceed default policy standards"
}

# ── ADPWD-004: Minimum Password Length ─────────────────────────────────────
function Test-ReconADPWD004 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $minLen = [int]($dp.MinPasswordLength ?? 0)
    $status = if ($minLen -ge 14) { 'PASS' }
              elseif ($minLen -ge 8) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Minimum password length: $minLen characters" `
        -Details @{ MinPasswordLength = $minLen }
}

# ── ADPWD-005: Password Complexity Requirement ────────────────────────────
function Test-ReconADPWD005 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $complex = [bool]($dp.PasswordComplexity ?? $false)
    $status = if ($complex) { 'PASS' } else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Password complexity: $(if ($complex) { 'Enabled' } else { 'Disabled' })" `
        -Details @{ PasswordComplexity = $complex }
}

# ── ADPWD-006: Account Lockout Policy ─────────────────────────────────────
function Test-ReconADPWD006 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $threshold = [int]($dp.LockoutThreshold ?? 0)

    $lockoutDurationMin = 0
    if ($dp.LockoutDuration -is [timespan]) {
        $lockoutDurationMin = [Math]::Abs($dp.LockoutDuration.TotalMinutes)
    }

    $observationMin = 0
    if ($dp.LockoutObservationWindow -is [timespan]) {
        $observationMin = [Math]::Abs($dp.LockoutObservationWindow.TotalMinutes)
    }

    $status = if ($threshold -eq 0) { 'FAIL' }
              elseif ($threshold -gt 10) { 'WARN' }
              else { 'PASS' }

    $currentValue = if ($threshold -eq 0) {
        'Account lockout is not configured (unlimited failed attempts allowed)'
    } else {
        "Lockout after $threshold failed attempts, duration $([Math]::Round($lockoutDurationMin, 0))min, observation window $([Math]::Round($observationMin, 0))min"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            LockoutThreshold         = $threshold
            LockoutDurationMinutes   = [Math]::Round($lockoutDurationMin, 0)
            ObservationWindowMinutes = [Math]::Round($observationMin, 0)
        }
}

# ── ADPWD-007: Password History Count ─────────────────────────────────────
function Test-ReconADPWD007 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $history = [int]($dp.PasswordHistoryCount ?? 0)
    $status = if ($history -ge 24) { 'PASS' }
              elseif ($history -ge 12) { 'WARN' }
              else { 'FAIL' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "Password history: $history passwords remembered" `
        -Details @{ PasswordHistoryCount = $history }
}

# ── ADPWD-008: Maximum Password Age ───────────────────────────────────────
function Test-ReconADPWD008 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $maxAgeDays = 0
    if ($dp.MaxPasswordAge -is [timespan]) {
        $maxAgeDays = [Math]::Abs($dp.MaxPasswordAge.TotalDays)
    }

    # A max age of 0 means passwords never expire
    $status = if ($maxAgeDays -eq 0) { 'FAIL' }
              elseif ($maxAgeDays -gt 365) { 'FAIL' }
              elseif ($maxAgeDays -gt 180) { 'WARN' }
              else { 'PASS' }

    $currentValue = if ($maxAgeDays -eq 0) {
        'Maximum password age: Not set (passwords never expire)'
    } else {
        "Maximum password age: $([Math]::Round($maxAgeDays, 0)) days"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{ MaxPasswordAgeDays = [Math]::Round($maxAgeDays, 0) }
}

# ── ADPWD-009: Users with Password Never Expires ──────────────────────────
function Test-ReconADPWD009 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $users = @($AuditData.PasswordPolicies.UsersPasswordNeverExpires ?? @())

    if ($users.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No users have the password-never-expires flag set' `
            -Details @{ Count = 0 }
    }

    # Separate admin and non-admin accounts
    $adminUsers = @($users | Where-Object { [int]($_.AdminCount ?? 0) -gt 0 })
    $first20 = @($users | Select-Object -First 20 | ForEach-Object { $_.SamAccountName })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
        -CurrentValue "$($users.Count) user(s) have password-never-expires set ($($adminUsers.Count) with AdminCount > 0)" `
        -Details @{
            TotalCount         = $users.Count
            AdminCount         = $adminUsers.Count
            SampleAccounts     = $first20
            Truncated          = ($users.Count -gt 20)
        }
}

# ── ADPWD-010: Blank Passwords (DSInternals) ──────────────────────────────
function Test-ReconADPWD010 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $dsAvailable = $AuditData.ModuleAvailability.DSInternals -eq $true

    if (-not $dsAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Requires DSInternals module for NT hash analysis. Install with: Install-Module DSInternals' `
            -Details @{ Reason = 'DSInternals module not available' }
    }

    # DSInternals being installed does NOT mean the NT-hash analysis ran. No collector populates
    # this result field today, so an absent field means the analysis was never performed — report
    # Not Assessed rather than a false PASS ("clean") without ever checking.
    if ($null -eq $AuditData.PasswordPolicies.BlankPasswordUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DSInternals is installed, but NT-hash analysis was not performed (no hash dataset collected — requires replication / ntds.dit access on a DC). Not Assessed.' `
            -Details @{ Reason = 'NT-hash analysis not performed' }
    }
    $blankPwdUsers = @($AuditData.PasswordPolicies.BlankPasswordUsers)

    if ($blankPwdUsers.Count -gt 0) {
        $first20 = @($blankPwdUsers | Select-Object -First 20 | ForEach-Object { $_.SamAccountName })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($blankPwdUsers.Count) account(s) have blank passwords" `
            -Details @{
                Count          = $blankPwdUsers.Count
                SampleAccounts = $first20
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No accounts with blank passwords detected'
}

# ── ADPWD-011: Duplicate Password Hashes (DSInternals) ────────────────────
function Test-ReconADPWD011 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $dsAvailable = $AuditData.ModuleAvailability.DSInternals -eq $true

    if (-not $dsAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Requires DSInternals module for NT hash analysis. Install with: Install-Module DSInternals' `
            -Details @{ Reason = 'DSInternals module not available' }
    }

    if ($null -eq $AuditData.PasswordPolicies.DuplicateHashGroups) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DSInternals is installed, but NT-hash analysis was not performed (no hash dataset collected — requires replication / ntds.dit access on a DC). Not Assessed.' `
            -Details @{ Reason = 'NT-hash analysis not performed' }
    }
    $dupeGroups = @($AuditData.PasswordPolicies.DuplicateHashGroups)

    if ($dupeGroups.Count -gt 0) {
        $totalAffected = ($dupeGroups | ForEach-Object { @($_.Accounts).Count } | Measure-Object -Sum).Sum
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$totalAffected account(s) share passwords across $($dupeGroups.Count) group(s) of duplicate hashes" `
            -Details @{
                DuplicateGroupCount = $dupeGroups.Count
                TotalAffected       = $totalAffected
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No duplicate password hashes detected'
}

# ── ADPWD-012: Have I Been Pwned Check (DSInternals) ──────────────────────
function Test-ReconADPWD012 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $dsAvailable = $AuditData.ModuleAvailability.DSInternals -eq $true

    if (-not $dsAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Requires DSInternals module for HIBP hash comparison. Install with: Install-Module DSInternals' `
            -Details @{ Reason = 'DSInternals module not available' }
    }

    if ($null -eq $AuditData.PasswordPolicies.HIBPCompromisedUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DSInternals is installed, but no HIBP/NT-hash comparison was performed (requires replication / ntds.dit access plus a pwned-password dataset). Not Assessed.' `
            -Details @{ Reason = 'HIBP comparison not performed' }
    }
    $compromised = @($AuditData.PasswordPolicies.HIBPCompromisedUsers)

    if ($compromised.Count -gt 0) {
        $first20 = @($compromised | Select-Object -First 20 | ForEach-Object { $_.SamAccountName })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($compromised.Count) account(s) have passwords found in HIBP breach database" `
            -Details @{
                Count          = $compromised.Count
                SampleAccounts = $first20
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No accounts with passwords found in HIBP breach database'
}

# ── ADPWD-013: Custom Dictionary Check (DSInternals) ──────────────────────
function Test-ReconADPWD013 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $dsAvailable = $AuditData.ModuleAvailability.DSInternals -eq $true

    if (-not $dsAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Requires DSInternals module for custom dictionary password analysis. Install with: Install-Module DSInternals' `
            -Details @{ Reason = 'DSInternals module not available' }
    }

    if ($null -eq $AuditData.PasswordPolicies.DictionaryMatchUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DSInternals is installed, but NT-hash dictionary analysis was not performed (no hash dataset collected — requires replication / ntds.dit access on a DC). Not Assessed.' `
            -Details @{ Reason = 'NT-hash analysis not performed' }
    }
    $dictMatches = @($AuditData.PasswordPolicies.DictionaryMatchUsers)

    if ($dictMatches.Count -gt 0) {
        $first20 = @($dictMatches | Select-Object -First 20 | ForEach-Object { $_.SamAccountName })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($dictMatches.Count) account(s) have passwords matching custom dictionary entries" `
            -Details @{
                Count          = $dictMatches.Count
                SampleAccounts = $first20
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No accounts with dictionary-based passwords detected'
}

# ── ADPWD-014: Default/Common Passwords (DSInternals) ─────────────────────
function Test-ReconADPWD014 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $dsAvailable = $AuditData.ModuleAvailability.DSInternals -eq $true

    if (-not $dsAvailable) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Requires DSInternals module for common password hash analysis. Install with: Install-Module DSInternals' `
            -Details @{ Reason = 'DSInternals module not available' }
    }

    if ($null -eq $AuditData.PasswordPolicies.CommonPasswordUsers) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'DSInternals is installed, but NT-hash analysis was not performed (no hash dataset collected — requires replication / ntds.dit access on a DC). Not Assessed.' `
            -Details @{ Reason = 'NT-hash analysis not performed' }
    }
    $commonPwd = @($AuditData.PasswordPolicies.CommonPasswordUsers)

    if ($commonPwd.Count -gt 0) {
        $first20 = @($commonPwd | Select-Object -First 20 | ForEach-Object { $_.SamAccountName })
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "$($commonPwd.Count) account(s) use default or commonly known passwords" `
            -Details @{
                Count          = $commonPwd.Count
                SampleAccounts = $first20
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'No accounts with default or commonly known passwords detected'
}

# ── ADPWD-015: Password Age Distribution ──────────────────────────────────
function Test-ReconADPWD015 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $users = @($AuditData.PasswordPolicies.UsersPasswordNeverExpires ?? @())

    # Also attempt to use a broader user list if available
    $allUsers = @($AuditData.AllUsers ?? $AuditData.PasswordPolicies.AllUsers ?? $users)

    if ($allUsers.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No user data available for password age distribution analysis'
    }

    $now = [datetime]::UtcNow
    $under90   = 0
    $d90to180  = 0
    $d180to365 = 0
    $over365   = 0
    $neverSet  = 0
    $totalAnalyzed = 0

    foreach ($user in $allUsers) {
        $totalAnalyzed++
        $pwdLastSet = $user.PwdLastSet

        if ($null -eq $pwdLastSet -or $pwdLastSet -eq 0) {
            $neverSet++
            continue
        }

        # Handle both DateTime and FileTime (Int64) formats
        $pwdDate = $null
        if ($pwdLastSet -is [datetime]) {
            $pwdDate = $pwdLastSet
        } elseif ($pwdLastSet -is [long] -or $pwdLastSet -is [int64]) {
            if ($pwdLastSet -gt 0) {
                try { $pwdDate = [datetime]::FromFileTimeUtc($pwdLastSet) } catch { }
            }
        }

        if ($null -eq $pwdDate) {
            $neverSet++
            continue
        }

        $ageDays = ($now - $pwdDate).TotalDays
        if ($ageDays -lt 90)      { $under90++ }
        elseif ($ageDays -lt 180) { $d90to180++ }
        elseif ($ageDays -lt 365) { $d180to365++ }
        else                      { $over365++ }
    }

    $over365Pct = if ($totalAnalyzed -gt 0) { [Math]::Round(($over365 / $totalAnalyzed) * 100, 1) } else { 0 }
    $status = if ($over365Pct -gt 20) { 'WARN' } else { 'PASS' }

    $currentValue = "Password age distribution across $totalAnalyzed accounts: " +
        "<90d=$under90, 90-180d=$d90to180, 180-365d=$d180to365, >365d=$over365 ($over365Pct%), never set=$neverSet"

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{
            TotalAnalyzed = $totalAnalyzed
            Under90Days   = $under90
            Days90to180   = $d90to180
            Days180to365  = $d180to365
            Over365Days   = $over365
            Over365Pct    = $over365Pct
            NeverSet      = $neverSet
        }
}

# ── ADPWD-016: LAPS Deployment ────────────────────────────────────────────
function Test-ReconADPWD016 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $pp = $AuditData.PasswordPolicies
    $lapsDeployed = [bool]($pp.LAPSDeployed ?? $false)

    if (-not $lapsDeployed) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'LAPS is not deployed. Local administrator passwords are not being managed' `
            -Details @{
                LAPSDeployed = $false
                LAPSType     = $pp.LAPSType ?? 'None'
            }
    }

    $lapsComputers  = [int]($pp.LAPSComputers ?? 0)
    $totalComputers = [int]($pp.TotalComputers ?? 0)

    $coveragePct = if ($totalComputers -gt 0) {
        [Math]::Round(($lapsComputers / $totalComputers) * 100, 1)
    } else { 0 }

    $status = if ($coveragePct -ge 80) { 'PASS' } else { 'WARN' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "LAPS deployed ($($pp.LAPSType)): $lapsComputers of $totalComputers computers covered ($coveragePct%)" `
        -Details @{
            LAPSDeployed    = $true
            LAPSType        = $pp.LAPSType ?? 'Unknown'
            LAPSComputers   = $lapsComputers
            TotalComputers  = $totalComputers
            CoveragePercent = $coveragePct
        }
}

# ── ADPWD-017: LAPS Password Expiration ───────────────────────────────────
function Test-ReconADPWD017 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $pp = $AuditData.PasswordPolicies
    $lapsDeployed = [bool]($pp.LAPSDeployed ?? $false)

    if (-not $lapsDeployed) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'LAPS is not deployed; password expiration check not applicable' `
            -Details @{ LAPSDeployed = $false }
    }

    # LAPS expiration data would come from GPO or policy analysis
    $lapsExpiration = $AuditData.PasswordPolicies.LAPSExpirationDays ?? $null

    if ($null -ne $lapsExpiration) {
        $status = if ([int]$lapsExpiration -le 30) { 'PASS' }
                  elseif ([int]$lapsExpiration -le 60) { 'WARN' }
                  else { 'WARN' }

        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "LAPS password expiration configured at $lapsExpiration days" `
            -Details @{
                LAPSExpirationDays = [int]$lapsExpiration
                LAPSType           = $pp.LAPSType ?? 'Unknown'
            }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "LAPS is deployed ($($pp.LAPSType)). Verify password expiration policy is configured via GPO (recommended: 30 days or less)" `
        -Details @{
            LAPSType = $pp.LAPSType ?? 'Unknown'
            Note     = 'LAPS expiration settings are configured via Group Policy. Manual verification recommended.'
        }
}

# ── ADPWD-018: Windows LAPS vs Legacy LAPS ────────────────────────────────
function Test-ReconADPWD018 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $pp = $AuditData.PasswordPolicies
    $lapsType = $pp.LAPSType ?? 'None'

    $description = switch ($lapsType) {
        'Windows' { 'Windows LAPS (native) is deployed. This is the recommended modern solution with encrypted password storage and Azure AD support.' }
        'Legacy'  { 'Legacy Microsoft LAPS is deployed. Consider migrating to Windows LAPS for encrypted storage, Azure AD backup, and DSRM password management.' }
        'Both'    { 'Both Legacy and Windows LAPS are deployed. This may indicate an ongoing migration. Ensure all systems transition to Windows LAPS.' }
        'None'    { 'No LAPS solution is deployed. Local administrator passwords are not centrally managed.' }
        default   { "LAPS type: $lapsType" }
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue $description `
        -Details @{
            LAPSType       = $lapsType
            LAPSDeployed   = [bool]($pp.LAPSDeployed ?? $false)
        }
}

# ── ADPWD-019: Azure AD Password Protection ──────────────────────────────
function Test-ReconADPWD019 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue 'Azure AD Password Protection status requires manual verification. Check Azure AD portal > Security > Authentication methods > Password protection for banned password list and on-premises agent deployment' `
        -Details @{
            Note = 'Azure AD Password Protection configuration is not accessible via standard LDAP queries. Verify that the on-premises proxy agent is deployed on DCs and that custom banned password lists are configured.'
            ManualSteps = @(
                'Check Azure portal > Microsoft Entra ID > Security > Authentication methods > Password protection'
                'Verify on-premises proxy agent is installed on domain controllers'
                'Confirm custom banned password list is configured'
                'Verify mode is set to Enforced (not Audit)'
            )
        }
}

# ── ADPWD-020: BitLocker Recovery Keys in AD ──────────────────────────────
function Test-ReconADPWD020 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $bitlockerKeys = [int]($AuditData.PasswordPolicies.BitLockerKeys ?? 0)

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "$bitlockerKeys BitLocker recovery key(s) stored in Active Directory" `
        -Details @{
            BitLockerKeyCount = $bitlockerKeys
            Note              = if ($bitlockerKeys -eq 0) {
                'No BitLocker keys found. Verify whether BitLocker is deployed and configured to back up keys to AD.'
            } else {
                'BitLocker recovery keys are stored in AD. Ensure read access is restricted to authorized administrators only.'
            }
        }
}

# ── ADPWD-021: Lockout Threshold Value ────────────────────────────────────
function Test-ReconADPWD021 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $threshold = [int]($dp.LockoutThreshold ?? 0)

    $status = if ($threshold -eq 0) { 'FAIL' }
              elseif ($threshold -gt 10) { 'WARN' }
              else { 'PASS' }

    $currentValue = if ($threshold -eq 0) {
        'Lockout threshold: 0 (disabled - unlimited failed logon attempts allowed)'
    } elseif ($threshold -gt 10) {
        "Lockout threshold: $threshold (too permissive; recommended: 3-10 attempts)"
    } else {
        "Lockout threshold: $threshold attempts"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{ LockoutThreshold = $threshold }
}

# ── ADPWD-022: Lockout Observation Window ─────────────────────────────────
function Test-ReconADPWD022 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][hashtable]$CheckDefinition
    )

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'PasswordPolicies' -Subject 'password policies'
    if ($na) { return $na }

    $dp = $AuditData.PasswordPolicies.DefaultPolicy
    if (-not $dp) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Default domain password policy data not available'
    }

    $threshold = [int]($dp.LockoutThreshold ?? 0)
    if ($threshold -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue 'Lockout observation window is moot because lockout threshold is 0 (disabled)' `
            -Details @{ LockoutThreshold = 0; ObservationWindowMinutes = 0 }
    }

    $observationMin = 0
    if ($dp.LockoutObservationWindow -is [timespan]) {
        $observationMin = [Math]::Abs($dp.LockoutObservationWindow.TotalMinutes)
    }

    $status = if ($observationMin -eq 0 -or $observationMin -lt 15) { 'FAIL' } else { 'PASS' }

    $currentValue = if ($observationMin -eq 0) {
        'Lockout observation window: 0 minutes (failed attempt counter never resets based on time)'
    } else {
        "Lockout observation window: $([Math]::Round($observationMin, 0)) minutes"
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue `
        -Details @{ ObservationWindowMinutes = [Math]::Round($observationMin, 0) }
}
