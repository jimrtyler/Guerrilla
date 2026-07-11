# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-OAuthSecurityChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'OAuthSecurityChecks'
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

# ── OAUTH-001: OAuth App Whitelist/Blocklist ─────────────────────────────
function Test-FortificationOAUTH001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: api_controls.unconfigured_third_party_apps { accessLevel=enum } governs how
    # third-party apps that have not been explicitly allow/blocklisted are treated. An
    # "allow all / sign-in + all-APIs" value means there is effectively no allowlist gate;
    # a "blocked/restricted/signin-only" value means unconfigured apps are gated.
    # Grade WEAKEST-OU-WINS. Enum strings are not fully documented — see caveat.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'api_controls.unconfigured_third_party_apps' -Field 'accessLevel')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No api_controls.unconfigured_third_party_apps policy returned for this tenant' `
            -OrgUnitPath $OrgUnitPath
    }
    # Insecure: anything that lets unconfigured apps in (ALLOW_ALL / sign-in + all APIs).
    $insecure = @($vals | Where-Object { "$_" -match '(?i)ALLOW_ALL|UNRESTRICTED|ALL_APIS|\bALL\b' })
    # Secure: explicitly blocked / restricted / sign-in only. CONFIRMED (live): UNSPECIFIED_UBER_BLOCK
    # = block-all of unconfigured apps -> secure (matches BLOCK; listed explicitly for clarity).
    # A bare "UNSPECIFIED"/not-set value matches neither set and falls through to WARN (never PASS).
    $secure   = @($vals | Where-Object { "$_" -match '(?i)UBER_BLOCK|BLOCK|RESTRICT|SIGN_?IN_?ONLY|ALLOW_LISTED|ALLOWLIST' })
    $note = "Unconfigured third-party app access: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"

    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Unconfigured third-party apps are allowed (no effective allowlist gate) — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Enum interpretation: "allow all / all-APIs" treated as insecure. Confirm exact enum strings against a live tenant.' }
    }
    if ($secure.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Unconfigured third-party apps are gated (blocked/restricted/allowlist) — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    # Unrecognized enum -> never PASS.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Unrecognized unconfigured-third-party-app access value — manual confirmation required. $note" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Enum value not recognized; verify in Admin Console > Security > API controls > App access control.' }
}

# ── OAUTH-002: Installed OAuth Apps Inventory ────────────────────────────
function Test-FortificationOAUTH002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OAuthApps' -Subject 'OAuth token activity'
    if ($na) { return $na }

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to enumerate installed apps' `
            -OrgUnitPath $OrgUnitPath
    }

    # Enumerate unique apps from token events
    $uniqueApps = @{}
    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        if ($appName -and -not $uniqueApps.ContainsKey($appName)) {
            $scope = $event.Params.scope
            $uniqueApps[$appName] = @{
                AppName = $appName
                Scopes  = if ($scope) { @($scope -split '\s+') } else { @() }
            }
        }
    }

    $appCount = $uniqueApps.Count
    $status = if ($appCount -eq 0) { 'PASS' }
              elseif ($appCount -le 20) { 'WARN' }
              else { 'FAIL' }

    $appNames = @($uniqueApps.Keys | Sort-Object)

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$appCount unique OAuth app(s) detected with token grants" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ AppCount = $appCount; AppNames = $appNames }
}

# ── OAUTH-003: OAuth Scope Analysis ──────────────────────────────────────
function Test-FortificationOAUTH003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OAuthApps' -Subject 'OAuth token activity'
    if ($na) { return $na }

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to analyze scopes' `
            -OrgUnitPath $OrgUnitPath
    }

    $highRiskPatterns = @('gmail', 'mail.google', 'drive', 'admin', 'calendar', 'contacts', 'directory')
    $highRiskApps = [System.Collections.Generic.List[hashtable]]::new()
    $seenApps = @{}

    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        $scope = $event.Params.scope
        if (-not $appName -or $seenApps.ContainsKey($appName)) { continue }

        if ($scope) {
            $scopeLower = $scope.ToLower()
            $matchedScopes = @($highRiskPatterns | Where-Object { $scopeLower -match $_ })
            if ($matchedScopes.Count -gt 0) {
                $seenApps[$appName] = $true
                $highRiskApps.Add(@{
                    AppName       = $appName
                    Scopes        = $scope
                    MatchedRisks  = $matchedScopes
                })
            }
        }
    }

    if ($highRiskApps.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No applications found with high-risk OAuth scopes' `
            -OrgUnitPath $OrgUnitPath
    }

    $status = if ($highRiskApps.Count -gt 5) { 'FAIL' } else { 'WARN' }
    $appSummary = @($highRiskApps | ForEach-Object { "$($_.AppName) [$($_.MatchedRisks -join ', ')]" })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($highRiskApps.Count) app(s) with high-risk scopes (gmail, drive, admin, calendar)" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ HighRiskApps = $appSummary; TotalHighRisk = $highRiskApps.Count }
}

# ── OAUTH-004: OAuth App Risk Scoring ────────────────────────────────────
function Test-FortificationOAUTH004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OAuthApps' -Subject 'OAuth token activity'
    if ($na) { return $na }

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to perform risk scoring' `
            -OrgUnitPath $OrgUnitPath
    }

    # Score apps based on the breadth and sensitivity of granted scopes
    $scopeWeights = @{
        'admin'     = 10
        'gmail'     = 8
        'mail'      = 8
        'drive'     = 7
        'calendar'  = 5
        'contacts'  = 4
        'directory' = 6
        'groups'    = 5
        'user'      = 3
    }

    $appScores = @{}
    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        $scope = $event.Params.scope
        if (-not $appName -or $appScores.ContainsKey($appName)) { continue }

        $score = 0
        if ($scope) {
            $scopeLower = $scope.ToLower()
            foreach ($key in $scopeWeights.Keys) {
                if ($scopeLower -match $key) {
                    $score += $scopeWeights[$key]
                }
            }
        }
        $appScores[$appName] = $score
    }

    $highRisk = @($appScores.GetEnumerator() | Where-Object { $_.Value -ge 10 } | Sort-Object Value -Descending)
    $mediumRisk = @($appScores.GetEnumerator() | Where-Object { $_.Value -ge 5 -and $_.Value -lt 10 })

    $status = if ($highRisk.Count -gt 3) { 'FAIL' }
              elseif ($highRisk.Count -gt 0 -or $mediumRisk.Count -gt 5) { 'WARN' }
              else { 'PASS' }

    $currentValue = "$($highRisk.Count) high-risk and $($mediumRisk.Count) medium-risk app(s) based on scope analysis"
    $topApps = @($highRisk | Select-Object -First 10 | ForEach-Object { "$($_.Key) (score: $($_.Value))" })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath `
        -Details @{ HighRiskCount = $highRisk.Count; MediumRiskCount = $mediumRisk.Count; TopRiskApps = $topApps }
}

# ── OAUTH-005: Unverified App Access Policy ──────────────────────────────
function Test-FortificationOAUTH005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Unverified app access policy not available via API. Verify in Admin Console > Security > API controls > App access control > Settings that unverified apps are blocked' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Unverified apps have not passed Google OAuth verification and may pose security risks' }
}

# ── OAUTH-006: API Access Control ────────────────────────────────────────
function Test-FortificationOAUTH006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: api_controls.app_approval_requests { allowedForAll=enum }. CONFIRMED (live tenant +
    # Google's Aug-2025 app-access-request-approval rollout): this governs whether the app-access
    # REQUEST workflow is available to all users. When ENABLED, users can request access to
    # unconfigured apps for ADMIN APPROVAL — access is not auto-granted, so this is a governance
    # positive (PASS). It is NOT "apps allowed for all". DISABLED / unknown -> WARN (no self-service
    # request path, or value not recognized — review). The actual app gate is OAUTH-001/007.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'api_controls.app_approval_requests' -Field 'allowedForAll')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No api_controls.app_approval_requests policy returned for this tenant' `
            -OrgUnitPath $OrgUnitPath
    }
    $note = "App-access request workflow: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    $enabled = @($vals | Where-Object { $_ -eq $true -or "$_" -match '(?i)^(ENABLED|ON|TRUE|ALLOWED)$' })
    if ($enabled.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "App-access request-and-approve workflow enabled (users request unconfigured apps; admins approve) — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "App-access request workflow not confirmed enabled — $note" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'ENABLED is the recommended governed posture (request -> admin approval). DISABLED means users are blocked with no request path; verify under Security > API controls. The actual app gate is OAUTH-001/007.' }
}

# ── OAUTH-007: Marketplace App Installation Restrictions ─────────────────
function Test-FortificationOAUTH007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: workspace_marketplace.apps_access_options { accessLevel=enum(ALLOW_LISTED_APPS…) }.
    # "allow all" lets users install any Marketplace app (insecure); ALLOW_LISTED_APPS
    # (allowlist-only) is secure. Grade WEAKEST-OU-WINS. Enum strings not fully documented.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol `
        -Type 'workspace_marketplace.apps_access_options' -Field 'accessLevel')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No workspace_marketplace.apps_access_options policy returned for this tenant' `
            -OrgUnitPath $OrgUnitPath
    }
    # Insecure: "allow all" installation.
    $insecure = @($vals | Where-Object { "$_" -match '(?i)ALLOW_ALL|UNRESTRICTED|ALL_APPS|\bALL\b' })
    # Secure: allowlist-only.
    $secure   = @($vals | Where-Object { "$_" -match '(?i)ALLOW_LISTED|ALLOWLIST|ALLOW_NONE|BLOCK|RESTRICT' })
    $note = "Marketplace app access: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"

    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Marketplace installation allows all apps (no allowlist) — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Enum interpretation: "allow all" treated as insecure. Confirm exact enum strings against a live tenant.' }
    }
    if ($secure.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Marketplace installation restricted to an allowlist — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    # Unrecognized enum -> never PASS.
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Unrecognized Marketplace access value — manual confirmation required. $note" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Enum value not recognized; verify in Admin Console > Apps > Marketplace apps > Settings.' }
}

# ── OAUTH-008: Domain-Wide Delegation Grants Audit ───────────────────────
function Test-FortificationOAUTH008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainWideDelegation' -Subject 'domain-wide delegation grants'
    if ($na) { return $na }

    if (-not $AuditData.DomainWideDelegation) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Domain-wide delegation data not available. Verify in Admin Console > Security > API controls > Domain-wide delegation' `
            -OrgUnitPath $OrgUnitPath
    }

    $grants = @($AuditData.DomainWideDelegation)
    if ($grants.Count -eq 0) {
        # Empty means "could not enumerate" (no GA list API for DWD grants), not "none exist" —
        # never PASS here or the finding is a false all-clear.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'Domain-wide delegation grants could not be enumerated via the Directory API — verify manually in Admin Console > Security > API controls > Domain-wide delegation' `
            -OrgUnitPath $OrgUnitPath
    }

    # Analyze scope breadth of each grant
    $broadGrants = [System.Collections.Generic.List[string]]::new()
    $sensitiveScopes = @('gmail', 'drive', 'admin', 'calendar', 'directory')

    foreach ($grant in $grants) {
        $clientId = $grant.clientId ?? $grant.ClientId ?? 'Unknown'
        $scopes = $grant.scopes ?? $grant.Scopes ?? @()
        $scopeStr = ($scopes -join ' ').ToLower()

        foreach ($sensitive in $sensitiveScopes) {
            if ($scopeStr -match $sensitive) {
                $broadGrants.Add("$clientId (scopes include: $sensitive)")
                break
            }
        }
    }

    $status = if ($broadGrants.Count -gt 0) { 'FAIL' }
              elseif ($grants.Count -gt 5) { 'WARN' }
              else { 'PASS' }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$($grants.Count) domain-wide delegation grant(s) found; $($broadGrants.Count) with sensitive scopes" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ TotalGrants = $grants.Count; SensitiveGrants = @($broadGrants); }
}

# ── OAUTH-009: Service Account Key Enumeration ───────────────────────────
function Test-FortificationOAUTH009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Service account keys are managed in Google Cloud Console, not directly in Workspace Admin SDK
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Service account key inventory requires Google Cloud Console access. Verify in Cloud Console > IAM > Service accounts that all keys are rotated and unused keys removed' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Service account keys are managed in Google Cloud Console and should be rotated within 90 days' }
}

# ── OAUTH-010: Connected Apps With Sensitive Scopes ──────────────────────
function Test-FortificationOAUTH010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'OAuthApps' -Subject 'OAuth token activity'
    if ($na) { return $na }

    if (-not $AuditData.OAuthApps) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue 'OAuth token events not available. Collect token activity data from Reports API to identify apps with sensitive scopes' `
            -OrgUnitPath $OrgUnitPath
    }

    $sensitiveScopes = @{
        'Drive'    = @('drive', 'drive.file', 'drive.readonly')
        'Gmail'    = @('gmail', 'mail.google')
        'Calendar' = @('calendar')
    }

    $appsByService = @{ Drive = [System.Collections.Generic.List[string]]::new(); Gmail = [System.Collections.Generic.List[string]]::new(); Calendar = [System.Collections.Generic.List[string]]::new() }
    $seenApps = @{}

    foreach ($event in $AuditData.OAuthApps) {
        $appName = $event.Params.app_name
        $scope = $event.Params.scope
        if (-not $appName -or -not $scope -or $seenApps.ContainsKey($appName)) { continue }
        $seenApps[$appName] = $true
        $scopeLower = $scope.ToLower()

        foreach ($service in $sensitiveScopes.Keys) {
            foreach ($pattern in $sensitiveScopes[$service]) {
                if ($scopeLower -match $pattern) {
                    $appsByService[$service].Add($appName)
                    break
                }
            }
        }
    }

    $totalSensitive = ($appsByService.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
    $status = if ($totalSensitive -gt 10) { 'FAIL' }
              elseif ($totalSensitive -gt 5) { 'WARN' }
              else { 'PASS' }

    $breakdown = @($appsByService.GetEnumerator() | Where-Object { $_.Value.Count -gt 0 } |
        ForEach-Object { "$($_.Key): $($_.Value.Count) app(s)" })

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue "$totalSensitive app(s) with Drive, Gmail, or Calendar access ($($breakdown -join '; '))" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            DriveApps    = @($appsByService.Drive)
            GmailApps    = @($appsByService.Gmail)
            CalendarApps = @($appsByService.Calendar)
            TotalCount   = $totalSensitive
        }
}
