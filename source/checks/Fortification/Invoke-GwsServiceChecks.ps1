# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Workspace Service Security dispatcher + checks for the SCuBA Sites, Classroom, and
# Gemini baselines. Sites and Classroom settings are read from the Cloud Identity Policy
# API (the same source used by the existing Collaboration/Drive/Admin checks). Gemini's
# granular controls (Alpha features, conversation history/retention, sharing) are NOT
# exposed by the Admin SDK or the Cloud Identity Policy API. Those checks INFER their
# state from admin audit-log setting-change events (Get-FortificationData ->
# ConvertTo-GeminiDerivedSettings — the same source ScubaGoggles derives them from) and
# LABEL the verdict as inferred. When no change-event exists in the retention window the
# state is unknowable to us and to ScubaGoggles alike, so the check honestly SKIPs.
# Per the project honesty rule: never PASS on uncollectable data.

function Invoke-GwsServiceChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'GwsServiceChecks'
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

# ══ GOOGLE SITES ═════════════════════════════════════════════════════════════

# ── GWS-SITES-001: Sites Service Disabled (GWS.SITES.1.1v1) ──────────────────
function Test-FortificationGWSSITES001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Cloud Identity Policy API: sites.service_status { serviceState=enum(ENABLED/DISABLED) }.
    # SCuBA SHOULD-disable: the service being OFF in every targeted policy is the secure posture.
    # Grade the WEAKEST (most-enabled) OU — if ANY targeted policy has Sites ENABLED the tenant
    # WARNs (SHOULD, not SHALL; selective per-OU enablement is permitted with justification).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'sites.service_status' -Field 'serviceState')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No sites.service_status policy returned for this tenant. Verify in Admin Console > Apps > Google Workspace > Sites > Service status' `
            -OrgUnitPath $OrgUnitPath
    }
    $states   = @($vals | ForEach-Object { "$_" })
    $note     = "Service state: $((@($states) | Select-Object -Unique) -join ', ') (across $($states.Count) targeted policy/policies)"
    $enabled  = @($states | Where-Object { $_ -match '(?i)^ENABLED$' })
    $disabled = @($states | Where-Object { $_ -match '(?i)^DISABLED$' })
    $unknown  = @($states | Where-Object { $_ -notmatch '(?i)^(ENABLED|DISABLED)$' })

    if ($unknown.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized Sites service state — verify manually whether the service is disabled — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Sites service is enabled in $($enabled.Count) of $($states.Count) targeted policy/policies — SCuBA recommends disabling it except where selectively justified — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.SITES.1.1 recommends the Sites service be OFF for everyone; enable selectively per OU/group only where justified' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Sites service disabled in all $($disabled.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ══ GOOGLE CLASSROOM ═════════════════════════════════════════════════════════

# ── GWS-CLASS-001: Who Can Join Classes (GWS.CLASSROOM.1.1v1) ────────────────
function Test-FortificationGWSCLASS001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: classroom.class_membership { whoCanJoinClasses=enum }.
    # Secure = domain-only. Documented enums: ANYONE_IN_DOMAIN (domain-only, secure),
    # ANYONE_IN_ALLOWLISTED_DOMAINS (allowlist, acceptable -> WARN), ANY_GOOGLE_WORKSPACE_USER
    # / ANYONE (open -> FAIL). Grade WEAKEST OU. Unknown enum -> WARN (never PASS blindly).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'classroom.class_membership' -Field 'whoCanJoinClasses')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No classroom.class_membership policy returned for this tenant. Verify in Admin Console > Apps > Additional Google services > Classroom > Class settings' `
            -OrgUnitPath $OrgUnitPath
    }
    $levels = @($vals | ForEach-Object { "$_" })
    $note   = "Who can join classes: $((@($levels) | Select-Object -Unique) -join ', ') (across $($levels.Count) targeted policy/policies)"
    $open   = @($levels | Where-Object { $_ -match '(?i)^(ANY_GOOGLE_WORKSPACE_USER|ANYONE)$' })
    $secure = @($levels | Where-Object { $_ -match '(?i)^ANYONE_IN_DOMAIN$' })
    $allow  = @($levels | Where-Object { $_ -match '(?i)^ANYONE_IN_ALLOWLISTED_DOMAINS$' })
    $known  = @($levels | Where-Object { $_ -match '(?i)^(ANY_GOOGLE_WORKSPACE_USER|ANYONE|ANYONE_IN_DOMAIN|ANYONE_IN_ALLOWLISTED_DOMAINS)$' })

    if ($open.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Class membership is open beyond the domain in $($open.Count) of $($levels.Count) targeted policy/policies — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.CLASSROOM.1.1 recommends restricting to users in your domain only' }
    }
    if ($known.Count -ne $levels.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized class-membership value — verify manually that joining is domain-restricted — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    if ($allow.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Class membership permits allowlisted domains in $($allow.Count) of $($levels.Count) targeted policy/policies — confirm the allowlist is intended — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Class membership restricted to users in your domain in all $($secure.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ── GWS-CLASS-002: Which Classes Users Can Join (GWS.CLASSROOM.1.2v1) ────────
function Test-FortificationGWSCLASS002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: classroom.class_membership { whichClassesCanUsersJoin=enum }.
    # Documented enums: CLASSES_IN_DOMAIN (secure), CLASSES_IN_ALLOWLISTED_DOMAINS (allowlist
    # -> WARN), ANY_GOOGLE_WORKSPACE_CLASS (open -> FAIL). Grade WEAKEST OU; unknown -> WARN.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'classroom.class_membership' -Field 'whichClassesCanUsersJoin')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No classroom.class_membership policy returned for this tenant. Verify in Admin Console > Apps > Additional Google services > Classroom > Class settings' `
            -OrgUnitPath $OrgUnitPath
    }
    $levels = @($vals | ForEach-Object { "$_" })
    $note   = "Which classes users can join: $((@($levels) | Select-Object -Unique) -join ', ') (across $($levels.Count) targeted policy/policies)"
    $open   = @($levels | Where-Object { $_ -match '(?i)^ANY_GOOGLE_WORKSPACE_CLASS$' })
    $secure = @($levels | Where-Object { $_ -match '(?i)^CLASSES_IN_DOMAIN$' })
    $allow  = @($levels | Where-Object { $_ -match '(?i)^CLASSES_IN_ALLOWLISTED_DOMAINS$' })
    $known  = @($levels | Where-Object { $_ -match '(?i)^(ANY_GOOGLE_WORKSPACE_CLASS|CLASSES_IN_DOMAIN|CLASSES_IN_ALLOWLISTED_DOMAINS)$' })

    if ($open.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Users may join classes outside the domain in $($open.Count) of $($levels.Count) targeted policy/policies — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.CLASSROOM.1.2 recommends restricting to classes in your domain only' }
    }
    if ($known.Count -ne $levels.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized value — verify manually that users may only join domain classes — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    if ($allow.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Users may join classes in allowlisted domains in $($allow.Count) of $($levels.Count) targeted policy/policies — confirm the allowlist is intended — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Users may only join classes in your domain in all $($secure.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ── GWS-CLASS-003: API Data Access Restricted (GWS.CLASSROOM.2.1v1) ──────────
function Test-FortificationGWSCLASS003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: classroom.api_data_access { enableApiAccess=bool }. SCuBA: users should NOT
    # be able to authorize apps -> enableApiAccess=false is secure. Grade WEAKEST OU: FAIL if
    # API data access is enabled in any targeted policy.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'classroom.api_data_access' -Field 'enableApiAccess')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No classroom.api_data_access policy returned for this tenant. Verify in Admin Console > Apps > Additional Google services > Classroom > Data access' `
            -OrgUnitPath $OrgUnitPath
    }
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Users can authorize apps to access Classroom data in $($enabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.CLASSROOM.2.1 recommends users not be able to authorize apps to access Classroom data' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Classroom API data access is disabled in all $($vals.Count) targeted policy/policies" `
        -OrgUnitPath $OrgUnitPath
}

# ── GWS-CLASS-004: Roster Import Disabled (GWS.CLASSROOM.3.1v1) ──────────────
function Test-FortificationGWSCLASS004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: classroom.roster_import { rosterImportOption=enum(OFF/ON_CLEVER) }.
    # SCuBA: roster import SHOULD be OFF. Grade WEAKEST OU; unknown enum -> WARN.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'classroom.roster_import' -Field 'rosterImportOption')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No classroom.roster_import policy returned for this tenant. Verify in Admin Console > Apps > Additional Google services > Classroom > Roster import' `
            -OrgUnitPath $OrgUnitPath
    }
    $opts  = @($vals | ForEach-Object { "$_" })
    $note  = "Roster import: $((@($opts) | Select-Object -Unique) -join ', ') (across $($opts.Count) targeted policy/policies)"
    $off   = @($opts | Where-Object { $_ -match '(?i)^OFF$' })
    $on    = @($opts | Where-Object { $_ -match '(?i)^ON_' })
    $known = @($opts | Where-Object { $_ -match '(?i)^(OFF|ON_CLEVER)$' })

    if ($known.Count -ne $opts.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized roster-import value — verify manually that roster import is off — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    if ($on.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Roster import is enabled in $($on.Count) of $($opts.Count) targeted policy/policies — SCuBA recommends turning it off — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Roster import is off in all $($off.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ── GWS-CLASS-005: Student Unenrollment Restricted (GWS.CLASSROOM.4.1v1) ─────
function Test-FortificationGWSCLASS005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: classroom.student_unenrollment { whoCanUnenrollStudents=enum }. Secure =
    # teachers only. Known spellings: TEACHERS_ONLY (secure); STUDENTS_AND_TEACHERS / values
    # permitting students (insecure -> WARN, SHOULD control). Grade WEAKEST OU; unknown -> WARN.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'classroom.student_unenrollment' -Field 'whoCanUnenrollStudents')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No classroom.student_unenrollment policy returned for this tenant. Verify in Admin Console > Apps > Additional Google services > Classroom > Student unenrollment' `
            -OrgUnitPath $OrgUnitPath
    }
    $opts    = @($vals | ForEach-Object { "$_" })
    $note    = "Who can unenroll students: $((@($opts) | Select-Object -Unique) -join ', ') (across $($opts.Count) targeted policy/policies)"
    $teacher = @($opts | Where-Object { $_ -match '(?i)^TEACHERS_ONLY$' })
    $student = @($opts | Where-Object { $_ -match '(?i)STUDENT' })
    $known   = @($opts | Where-Object { $_ -match '(?i)^(TEACHERS_ONLY|STUDENTS_AND_TEACHERS)$' })

    if ($known.Count -ne $opts.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized student-unenrollment value — verify manually that only teachers may unenroll — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    if ($student.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Students may unenroll themselves in $($student.Count) of $($opts.Count) targeted policy/policies — SCuBA recommends teachers only — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Only teachers may unenroll students in all $($teacher.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ── GWS-CLASS-006: Class Creation Restricted (GWS.CLASSROOM.5.1v1) ───────────
function Test-FortificationGWSCLASS006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Policy API: classroom.teacher_permissions { whoCanCreateClasses=enum }. Documented enums:
    # VERIFIED_TEACHERS_ONLY (secure), ALL_PENDING_AND_VERIFIED_TEACHERS (looser -> WARN),
    # ANYONE_IN_DOMAIN (open -> FAIL). Grade WEAKEST OU; unknown -> WARN.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'classroom.teacher_permissions' -Field 'whoCanCreateClasses')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No classroom.teacher_permissions policy returned for this tenant. Verify in Admin Console > Apps > Additional Google services > Classroom > General settings > Teacher permissions' `
            -OrgUnitPath $OrgUnitPath
    }
    $levels = @($vals | ForEach-Object { "$_" })
    $note   = "Who can create classes: $((@($levels) | Select-Object -Unique) -join ', ') (across $($levels.Count) targeted policy/policies)"
    $open   = @($levels | Where-Object { $_ -match '(?i)^ANYONE_IN_DOMAIN$' })
    $secure = @($levels | Where-Object { $_ -match '(?i)^VERIFIED_TEACHERS_ONLY$' })
    $loose  = @($levels | Where-Object { $_ -match '(?i)^ALL_PENDING_AND_VERIFIED_TEACHERS$' })
    $known  = @($levels | Where-Object { $_ -match '(?i)^(ANYONE_IN_DOMAIN|VERIFIED_TEACHERS_ONLY|ALL_PENDING_AND_VERIFIED_TEACHERS)$' })

    if ($open.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Anyone in the domain can create classes in $($open.Count) of $($levels.Count) targeted policy/policies — $note" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.CLASSROOM.5.1 recommends restricting class creation to verified teachers only' }
    }
    if ($known.Count -ne $levels.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Unrecognized class-creation value — verify manually that only verified teachers may create classes — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    if ($loose.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Pending (unverified) teachers may create classes in $($loose.Count) of $($levels.Count) targeted policy/policies — SCuBA recommends verified teachers only — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Class creation restricted to verified teachers in all $($secure.Count) targeted policy/policies — $note" `
        -OrgUnitPath $OrgUnitPath
}

# ══ GEMINI FOR WORKSPACE ═════════════════════════════════════════════════════
# HONESTY NOTE: the Cloud Identity Policy API and Admin SDK do not expose the granular
# Gemini controls (Alpha features, conversation history, retention, sharing). ScubaGoggles
# itself derives these from Admin audit-log events, which this read-only theater does not
# replay. GEMINI-002..005 therefore return SKIP / Not Assessed with the Admin console path —
# they never emit PASS. GEMINI-001 is a best-effort read of gemini_app.service_status if the
# tenant exposes it; otherwise it also SKIPs.

# ── GWS-GEMINI-001: Gemini App Access Restricted (GWS.GEMINI.1.1v1) ──────────
function Test-FortificationGWSGEMINI001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # Best-effort: the Policy API exposes gemini_app as an additional service, so its
    # service_status { serviceState } MAY be present. That is service on/off, NOT the precise
    # "OFF for users without a license" toggle — so even when readable we can only WARN that
    # the granular license-gating must be confirmed; we never claim a clean PASS for 1.1 from
    # service status alone. When the type is absent we SKIP (Not Assessed) honestly.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'gemini_app.service_status' -Field 'serviceState')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Gemini app access (OFF for users without a license) is not exposed via the Cloud Identity Policy API or Admin SDK. Not Assessed — verify in Admin Console > Generative AI > Gemini app > User access' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'The license-gating toggle for GWS.GEMINI.1.1 has no read API; ScubaGoggles derives Gemini settings from Admin audit-log events' }
    }
    $states   = @($vals | ForEach-Object { "$_" })
    $note     = "Gemini app service state: $((@($states) | Select-Object -Unique) -join ', ') (across $($states.Count) targeted policy/policies)"
    $disabled = @($states | Where-Object { $_ -match '(?i)^DISABLED$' })
    if ($disabled.Count -eq $states.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Gemini app service is disabled in all $($disabled.Count) targeted policy/policies — no unlicensed access surface — $note" `
            -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Gemini app service is enabled — the policy API exposes only service on/off, not the 'OFF for users without a license' toggle. Verify license-gating in Admin Console > Generative AI > Gemini app > User access — $note" `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'GWS.GEMINI.1.1 requires access OFF for users without a license; the license-gating toggle is not exposed by the read APIs' }
}

# ── GWS-GEMINI-002: Alpha Features Disabled (GWS.GEMINI.2.1v1) ───────────────
function Test-FortificationGWSGEMINI002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # No config API exposes the Alpha-features toggle. Infer it from the admin
    # audit log (ScubaGoggles method); if no change-event exists, honestly SKIP.
    $d = if ($AuditData.GeminiDerivedSettings) { $AuditData.GeminiDerivedSettings['AlphaFeatures'] } else { $null }
    if (-not $d) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Gemini Alpha-features setting is exposed by no config API and no admin change-event was found in the audit-log window. Not Assessed — verify in Admin Console > Generative AI > Gemini for Workspace > Alpha features (should be off)' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.GEMINI.2.1 has no read API; inferred from admin audit-log events (ScubaGoggles method) when a change exists. No change event found — Not Assessed.' }
    }

    $status = if ($d.Value -eq 'off') { 'PASS' } else { 'FAIL' }
    $cv = if ($d.Value -eq 'off') {
        "Inferred from audit-log ($($d.Timestamp)): Alpha features OFF"
    } else {
        "Inferred from audit-log ($($d.Timestamp)): Alpha features ON — should be off"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $cv -OrgUnitPath $OrgUnitPath -Details (Get-GeminiInferredDetails -Derived $d)
}

# ── GWS-GEMINI-003: Conversation History Enabled (GWS.GEMINI.3.1v1) ──────────
function Test-FortificationGWSGEMINI003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # No config API exposes conversation-history. Infer from the admin audit log.
    $d = if ($AuditData.GeminiDerivedSettings) { $AuditData.GeminiDerivedSettings['ConversationHistory'] } else { $null }
    if (-not $d) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Gemini conversation-history setting is exposed by no config API and no admin change-event was found in the audit-log window. Not Assessed — verify in Admin Console > Generative AI > Gemini app > Gemini conversation history (should be enabled)' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.GEMINI.3.1 has no read API; inferred from admin audit-log events when a change exists. No change event found — Not Assessed.' }
    }

    $status = if ($d.Value -eq 'on') { 'PASS' } else { 'WARN' }
    $cv = if ($d.Value -eq 'on') {
        "Inferred from audit-log ($($d.Timestamp)): conversation history ENABLED"
    } else {
        "Inferred from audit-log ($($d.Timestamp)): conversation history DISABLED — should be enabled for oversight/eDiscovery"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $cv -OrgUnitPath $OrgUnitPath -Details (Get-GeminiInferredDetails -Derived $d)
}

# ── GWS-GEMINI-004: Conversation Retention >= 18 Months (GWS.GEMINI.3.2v1) ───
function Test-FortificationGWSGEMINI004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # No config API exposes the retention period. Infer from the admin audit log.
    $d = if ($AuditData.GeminiDerivedSettings) { $AuditData.GeminiDerivedSettings['RetentionMonths'] } else { $null }
    if (-not $d) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Gemini conversation-retention period is exposed by no config API and no admin change-event was found in the audit-log window. Not Assessed — verify in Admin Console > Generative AI > Gemini app > Gemini conversation history (retention should be at least 18 months)' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.GEMINI.3.2 has no read API; inferred from admin audit-log events when a change exists. No change event found — Not Assessed.' }
    }

    $status = if ([int]$d.Value -ge 18) { 'PASS' } else { 'WARN' }
    $cv = "Inferred from audit-log ($($d.Timestamp)): retention $($d.Value) month(s)" + $(if ([int]$d.Value -ge 18) { '' } else { ' — should be at least 18' })
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $cv -OrgUnitPath $OrgUnitPath -Details (Get-GeminiInferredDetails -Derived $d)
}

# ── GWS-GEMINI-005: Conversation Sharing Disabled (GWS.GEMINI.4.1v1) ─────────
function Test-FortificationGWSGEMINI005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # No config API exposes conversation-sharing. Infer from the admin audit log.
    $d = if ($AuditData.GeminiDerivedSettings) { $AuditData.GeminiDerivedSettings['ConversationSharing'] } else { $null }
    if (-not $d) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Gemini conversation-sharing setting is exposed by no config API and no admin change-event was found in the audit-log window. Not Assessed — verify in Admin Console > Generative AI > Gemini app > Sharing (conversation sharing via link should be OFF)' `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'GWS.GEMINI.4.1 has no read API; inferred from admin audit-log events when a change exists. No change event found — Not Assessed.' }
    }

    $status = if ($d.Value -eq 'off') { 'PASS' } else { 'FAIL' }
    $cv = if ($d.Value -eq 'off') {
        "Inferred from audit-log ($($d.Timestamp)): conversation sharing via link OFF"
    } else {
        "Inferred from audit-log ($($d.Timestamp)): conversation sharing via link ON — should be off (data-exposure risk)"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
        -CurrentValue $cv -OrgUnitPath $OrgUnitPath -Details (Get-GeminiInferredDetails -Derived $d)
}
