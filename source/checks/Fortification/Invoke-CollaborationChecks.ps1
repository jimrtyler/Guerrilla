# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-CollaborationChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'CollaborationChecks'
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

# ── COLLAB-001: Meet Recording Settings ──────────────────────────────────
function Test-FortificationCOLLAB001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.automatic_recording { enabled=bool }. Automatic recording captures every
    # meeting by default; weakest-OU-wins (FAIL if enabled in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.automatic_recording' -Field 'enabled')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.automatic_recording policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Automatic Meet recording enabled in $($enabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Recording should be restricted to organizers or disabled for sensitive OUs to prevent unauthorized capture' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Automatic Meet recording is disabled' -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-002: Meet External Participant Settings ───────────────────────
function Test-FortificationCOLLAB002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.meet_joining { allowedAudience=enum(TRUSTED…) } controls who may join meetings
    # this OU hosts. ENUM GUESS: TRUSTED restricts to trusted/internal audiences (secure); a
    # value that admits anyone external is insecure. Unknown values WARN — never PASS blindly.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.meet_joining' -Field 'allowedAudience')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.meet_joining policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $note = "Allowed Meet audience: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    # Clearly-insecure: an audience that explicitly admits anyone / all external participants.
    $insecure = @($vals | Where-Object { "$_" -match '(?i)\b(ALL|ANYONE|EVERYONE|PUBLIC|NO_RESTRICTION|UNRESTRICTED)\b' })
    $trusted  = @($vals | Where-Object { "$_" -match '(?i)TRUSTED|INTERNAL|RESTRICTED|LOGGED_IN' })
    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Meet permits an unrestricted external audience — $note" -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'External participants should require knocking or host approval before joining meetings' }
    }
    if ($trusted.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Meet join audience restricted to trusted participants — $note" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Meet join audience could not be confirmed as restricted — $note" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-003: Meet Anonymous Join Settings ─────────────────────────────
function Test-FortificationCOLLAB003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.safety_domain { usersAllowedToJoin=enum(LOGGED_IN…) }. ENUM GUESS: LOGGED_IN
    # requires a Google account (no anonymous join, secure); a value permitting anonymous /
    # all users is insecure. Unknown values WARN — never PASS blindly.
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.safety_domain' -Field 'usersAllowedToJoin')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.safety_domain policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $note = "Users allowed to join: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
    $insecure = @($vals | Where-Object { "$_" -match '(?i)ANONYMOUS|\b(ALL|ANYONE|EVERYONE|PUBLIC)\b' })
    $loggedIn = @($vals | Where-Object { "$_" -match '(?i)LOGGED_IN|SIGNED_IN|AUTHENTICATED' })
    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Meet permits anonymous / unauthenticated join — $note" -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Anonymous users without Google accounts should not be able to join meetings without explicit approval' }
    }
    if ($loggedIn.Count -eq $vals.Count) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue "Meet requires signed-in users to join — $note" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue "Meet join eligibility could not be confirmed as restricted — $note" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-004: Chat External Communication ──────────────────────────────
function Test-FortificationCOLLAB004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1 PRIMARY: chat.external_chat_restriction { allowExternalChat=bool,
    # externalChatRestriction=enum }. External chat with no restriction lets users message and
    # share data to outside contacts freely; weakest-OU-wins. ENUM GUESS: NO_RESTRICTION/ALL/
    # UNRESTRICTED is fully open (insecure); any other restriction value is "allowed but limited"
    # (WARN). Unknown values WARN — never PASS blindly. (OrgUnitPolicies fallback retained below.)
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CloudIdentityPolicies', 'OrgUnits') -Subject 'Chat external-communication policy'
    if ($na) { return $na }

    $pol = $AuditData.CloudIdentityPolicies
    if ($pol) {
        $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'chat.external_chat_restriction')
        if ($vals.Count -gt 0) {
            $allowed     = @($vals | Where-Object { $_.allowExternalChat -eq $true })
            $unrestricted = @($allowed | Where-Object { "$($_.externalChatRestriction)" -match '(?i)\b(NO_RESTRICTION|ALL|UNRESTRICTED)\b' })
            if ($unrestricted.Count -gt 0) {
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                    -CurrentValue "External Chat is enabled with no restriction in $($unrestricted.Count) of $($vals.Count) targeted policy/policies" `
                    -OrgUnitPath $OrgUnitPath `
                    -Details @{ Note = 'External chat allows users to communicate with and share data to contacts outside the organization' }
            }
            if ($allowed.Count -gt 0) {
                $restrictions = (@($allowed | ForEach-Object { "$($_.externalChatRestriction)" }) | Select-Object -Unique) -join ', '
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                    -CurrentValue "External Chat is enabled but restricted in $($allowed.Count) of $($vals.Count) targeted policy/policies (restriction: $restrictions)" `
                    -OrgUnitPath $OrgUnitPath `
                    -Details @{ Note = 'External chat allows users to communicate with and share data to contacts outside the organization' }
            }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -CurrentValue 'External Chat communication is disabled' -OrgUnitPath $OrgUnitPath
        }
    }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.chatExternalEnabled) {
        $status = if ($policy.chatExternalEnabled -eq $false) { 'PASS' } else { 'FAIL' }
        $currentValue = if ($policy.chatExternalEnabled) {
            'External Chat communication is enabled - users can message external contacts'
        } else {
            'External Chat communication is disabled'
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue $currentValue -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chat external communication settings not available via API. Verify in Admin Console > Apps > Google Chat > Chat settings that external chat is restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'External chat allows users to communicate with and share data to contacts outside the organization' }
}

# ── COLLAB-005: Chat History Settings ────────────────────────────────────
function Test-FortificationCOLLAB005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: chat.chat_history { historyOnByDefault=bool }. History off conceals communications;
    # weakest-OU-wins (FAIL if history off in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'chat.chat_history' -Field 'historyOnByDefault')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No chat.chat_history policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $historyOff = @($vals | Where-Object { $_ -ne $true })
    if ($historyOff.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Chat history off by default in $($historyOff.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Chat history should be enabled for compliance and audit. Disabled history can conceal malicious communications' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Chat history is on by default' -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-006: Chat Spaces External Access ──────────────────────────────
function Test-FortificationCOLLAB006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: chat.chat_external_spaces { enabled=bool }. External spaces let outsiders into
    # Chat spaces; weakest-OU-wins (FAIL if enabled in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'chat.chat_external_spaces' -Field 'enabled')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No chat.chat_external_spaces policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $enabled = @($vals | Where-Object { $_ -eq $true })
    if ($enabled.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "External Chat spaces enabled in $($enabled.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Chat spaces with external members can expose internal communications and shared files to unauthorized parties' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'External Chat spaces are disabled' -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-007: Chat App Installation Settings ───────────────────────────
function Test-FortificationCOLLAB007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Chat app installation settings not available via API. Verify in Admin Console > Apps > Google Chat > Chat settings > Apps that installation is restricted to approved apps' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Uncontrolled chat app (bot) installation can grant third-party integrations access to conversation data' }
}

# ── COLLAB-008: Calendar External Sharing ────────────────────────────────
function Test-FortificationCOLLAB008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1 PRIMARY: calendar.primary_calendar_max_allowed_external_sharing
    # { maxAllowedExternalSharing=enum }. The most-permissive value shares all event details
    # externally (insecure); weakest-OU-wins. CONFIRMED enums (live tenant): EXTERNAL_ALL_INFO_*
    # (READ_ONLY / READ_WRITE / READ_WRITE_MANAGE) share full event details externally -> FAIL;
    # EXTERNAL_FREE_BUSY_ONLY / EXTERNAL_NO_SHARING are limited -> PASS. Older-shape guesses kept as
    # a fallback. Unknown values WARN — never PASS blindly. (OrgUnitPolicies fallback retained.)
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CloudIdentityPolicies', 'OrgUnits') -Subject 'Calendar external-sharing policy'
    if ($na) { return $na }

    $pol = $AuditData.CloudIdentityPolicies
    if ($pol) {
        $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'calendar.primary_calendar_max_allowed_external_sharing' -Field 'maxAllowedExternalSharing')
        if ($vals.Count -gt 0) {
            $note = "Max allowed external sharing: $((@($vals) | Select-Object -Unique) -join ', ') (across $($vals.Count) targeted policy/policies)"
            $permissive = @($vals | Where-Object { "$_" -match '(?i)(EXTERNAL_ALL_INFO|READ_WRITE|SHARE_ALL|READ_ALL|MANAGE|EVERYTHING)' })
            $limited    = @($vals | Where-Object { "$_" -match '(?i)(EXTERNAL_FREE_BUSY|EXTERNAL_NO_SHARING|FREE_BUSY|DOMAIN_ONLY|^NONE$|^LIMITED$)' })
            if ($permissive.Count -gt 0) {
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                    -CurrentValue "Calendar shares full event details externally — $note" -OrgUnitPath $OrgUnitPath `
                    -Details @{ Note = 'Sharing full calendar details externally exposes meeting content, attendees, and organizational schedules' }
            }
            if ($limited.Count -eq $vals.Count) {
                return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                    -CurrentValue "Calendar external sharing limited — $note" -OrgUnitPath $OrgUnitPath
            }
            return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -CurrentValue "Calendar external sharing level could not be confirmed as limited — $note" -OrgUnitPath $OrgUnitPath
        }
    }

    $policy = $AuditData.OrgUnitPolicies[$OrgUnitPath]
    if ($policy -and $null -ne $policy.calendarExternalSharing) {
        $status = switch ($policy.calendarExternalSharing) {
            'NONE'        { 'PASS' }
            'FREE_BUSY'   { 'PASS' }
            'READ_ONLY'   { 'WARN' }
            'READ_WRITE'  { 'FAIL' }
            'FULL_ACCESS' { 'FAIL' }
            default       { 'WARN' }
        }
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status `
            -CurrentValue "Calendar external sharing: $($policy.calendarExternalSharing)" `
            -OrgUnitPath $OrgUnitPath
    }

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Calendar external sharing settings not available via API. Verify in Admin Console > Apps > Calendar > Sharing settings that external sharing is limited to free/busy information' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Sharing full calendar details externally exposes meeting content, attendees, and organizational schedules' }
}

# ── COLLAB-009: Calendar External Invitations ────────────────────────────
function Test-FortificationCOLLAB009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Calendar external invitation settings not available via API. Verify in Admin Console > Apps > Calendar > Sharing settings that external invitation warnings are enabled' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'External invitation warnings help prevent accidental disclosure of meeting details to external recipients' }
}

# ── COLLAB-010: Calendar Appointment Slots External Visibility ───────────
function Test-FortificationCOLLAB010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue 'Calendar appointment slot visibility settings not available via API. Verify in Admin Console > Apps > Calendar > Sharing settings that appointment slot external visibility is restricted' `
        -OrgUnitPath $OrgUnitPath `
        -Details @{ Note = 'Appointment slot visibility controls how much scheduling detail is exposed to external users' }
}

# ── COLLAB-011: Meet External Participant Labeling ───────────────────────
function Test-FortificationCOLLAB011 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.safety_external_participants { enableExternalLabel=bool }. External participants
    # should be visibly labeled so hosts/attendees can spot outsiders; true=secure. Weakest-OU-wins
    # (WARN if labeling off in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.safety_external_participants' -Field 'enableExternalLabel')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.safety_external_participants policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $off = @($vals | Where-Object { $_ -ne $true })
    if ($off.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "External participant labeling off in $($off.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'External participants should be visibly labeled so hosts and attendees can identify outsiders in meetings' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'External participant labeling is enabled' -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-012: Meet Host Management ─────────────────────────────────────
function Test-FortificationCOLLAB012 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    # GWS-1: meet.safety_host_management { enableHostManagement=bool }. Host management gives hosts
    # moderation controls (mute/remove/lock) to prevent meeting hijacking/disruption; true=secure.
    # Weakest-OU-wins (WARN if host management off in any targeted OU).
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'meet.safety_host_management' -Field 'enableHostManagement')
    if ($vals.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No meet.safety_host_management policy returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $off = @($vals | Where-Object { $_ -ne $true })
    if ($off.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Host management off in $($off.Count) of $($vals.Count) targeted policy/policies" `
            -OrgUnitPath $OrgUnitPath `
            -Details @{ Note = 'Host management gives meeting hosts moderation controls (mute, remove, lock) to prevent meeting hijacking and disruption' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Host management is enabled' -OrgUnitPath $OrgUnitPath
}

# Shared guard + policy resolver for the Groups checks (GWS.GROUPS.*).
# All read the single groups_for_business.groups_sharing policy.
function Get-GroupSharingValues {
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath, [string]$Field)
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CloudIdentityPolicies', 'OrgUnits') -Subject 'Groups for Business sharing policy'
    if ($na) { return @{ Na = $na } }
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return @{ Na = (New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' -OrgUnitPath $OrgUnitPath) }
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type 'groups_for_business.groups_sharing' -Field $Field)
    if ($vals.Count -eq 0) {
        return @{ Na = (New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "No groups_for_business.groups_sharing policy returned for this tenant" -OrgUnitPath $OrgUnitPath) }
    }
    return @{ Vals = $vals }
}

# ── GROUP-001: GWS.GROUPS.1.1 — External access to Groups restricted ───────
function Test-FortificationGROUP001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-GroupSharingValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Field 'collaborationCapability'
    if ($r.Na) { return $r.Na }
    # Secure = DOMAIN_USERS_ONLY. Weakest-OU-wins.
    $insecure = @($r.Vals | Where-Object { "$_" -ne 'DOMAIN_USERS_ONLY' })
    if ($insecure.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Group sharing allows external access in $($insecure.Count) of $($r.Vals.Count) targeted policy/policies (not DOMAIN_USERS_ONLY)" `
            -OrgUnitPath $OrgUnitPath -Details @{ Note = 'External access exposes group content — including student/staff data — to people outside the organization' }
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Group sharing is limited to domain users in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── GROUP-002: GWS.GROUPS.1.2 — Owners cannot add external members ─────────
function Test-FortificationGROUP002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-GroupSharingValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Field 'ownersCanAllowExternalMembers'
    if ($r.Na) { return $r.Na }
    $on = @($r.Vals | Where-Object { $_ -eq $true })
    if ($on.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Group owners can add external members in $($on.Count) of $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Group owners cannot add external members in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── GROUP-003: GWS.GROUPS.1.3 — No incoming mail from the public ───────────
function Test-FortificationGROUP003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-GroupSharingValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Field 'ownersCanAllowIncomingMailFromPublic'
    if ($r.Na) { return $r.Na }
    $on = @($r.Vals | Where-Object { $_ -eq $true })
    if ($on.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Group owners can allow incoming mail from the public in $($on.Count) of $($r.Vals.Count) targeted policy/policies — an inbound phishing/spam vector" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Groups cannot receive mail from outside the org in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── GROUP-004: GWS.GROUPS.2.1 — Group creation restricted to admins ────────
function Test-FortificationGROUP004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-GroupSharingValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Field 'createGroupsAccessLevel'
    if ($r.Na) { return $r.Na }
    # Secure = ADMIN_ONLY. Any looser value (USERS_IN_DOMAIN / ANYONE_CAN_CREATE) is not restricted.
    $open = @($r.Vals | Where-Object { "$_" -ne 'ADMIN_ONLY' })
    if ($open.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Group creation is not restricted to admins in $($open.Count) of $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Group creation is restricted to administrators in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── GROUP-005: GWS.GROUPS.3.1 — Conversation visibility defaults to members ─
function Test-FortificationGROUP005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-GroupSharingValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Field 'viewTopicsDefaultAccessLevel'
    if ($r.Na) { return $r.Na }
    # Secure = GROUP_MEMBERS. Broader default exposes conversation archives.
    $broad = @($r.Vals | Where-Object { "$_" -ne 'GROUP_MEMBERS' })
    if ($broad.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Default conversation visibility is broader than group members in $($broad.Count) of $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Default conversation visibility is limited to group members in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# Shared resolver for the Chat/Meet tail checks (single field, weakest-OU-wins).
function Get-CollabPolicyValues {
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath, [string]$Type, [string]$Field, [string]$Subject)
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CloudIdentityPolicies', 'OrgUnits') -Subject $Subject
    if ($na) { return @{ Na = $na } }
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return @{ Na = (New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' -OrgUnitPath $OrgUnitPath) }
    }
    $vals = @(Resolve-GooglePolicyValue -Policies $pol -Type $Type -Field $Field)
    if ($vals.Count -eq 0) {
        return @{ Na = (New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue "No $Type policy returned for this tenant" -OrgUnitPath $OrgUnitPath) }
    }
    return @{ Vals = $vals }
}

# ── COLLAB-013: GWS.CHAT.2.1 — External file sharing disabled ──────────────
function Test-FortificationCOLLAB013 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-CollabPolicyValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Type 'chat.chat_file_sharing' -Field 'externalFileSharing' -Subject 'Chat external file-sharing policy'
    if ($r.Na) { return $r.Na }
    $open = @($r.Vals | Where-Object { "$_" -ne 'NO_FILES' })
    if ($open.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Chat external file sharing is enabled in $($open.Count) of $($r.Vals.Count) targeted policy/policies — a data-exfiltration path" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Chat external file sharing is disabled (NO_FILES) in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-014: GWS.CHAT.3.1 — Space history on ───────────────────────────
function Test-FortificationCOLLAB014 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-CollabPolicyValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Type 'chat.space_history' -Field 'historyState' -Subject 'Chat space history policy'
    if ($r.Na) { return $r.Na }
    $off = @($r.Vals | Where-Object { "$_" -ne 'HISTORY_ALWAYS_ON' })
    if ($off.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Chat space history is not always-on in $($off.Count) of $($r.Vals.Count) targeted policy/policies — conversations may not be retained for oversight" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Chat space history is always on in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-015: GWS.MEET.2.1 — Meeting join restricted to the org ──────────
function Test-FortificationCOLLAB015 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-CollabPolicyValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Type 'meet.safety_access' -Field 'meetingsAllowedToJoin' -Subject 'Meet meeting-access policy'
    if ($r.Na) { return $r.Na }
    $secure = @('SAME_ORGANIZATION_ONLY', 'ANY_WORKSPACE_ORGANIZATION')
    $open = @($r.Vals | Where-Object { "$_" -notin $secure })
    if ($open.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
            -CurrentValue "Meeting access is not restricted to the organization in $($open.Count) of $($r.Vals.Count) targeted policy/policies — external/unauthenticated parties can join" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Meeting access is restricted to the organization in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-016: GWS.MEET.5.2 — Automatic transcription off by default ──────
function Test-FortificationCOLLAB016 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-CollabPolicyValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Type 'meet.automatic_transcription' -Field 'enabled' -Subject 'Meet automatic-transcription policy'
    if ($r.Na) { return $r.Na }
    $on = @($r.Vals | Where-Object { $_ -eq $true })
    if ($on.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Automatic transcription is on by default in $($on.Count) of $($r.Vals.Count) targeted policy/policies — meeting content is captured without a deliberate decision" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Automatic transcription is off by default in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-017: GWS.CALENDAR.3.1 — Calendar interoperability managed ───────
function Test-FortificationCOLLAB017 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-CollabPolicyValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Type 'calendar.interoperability' -Field 'enableInteroperability' -Subject 'Calendar interoperability policy'
    if ($r.Na) { return $r.Na }
    $on = @($r.Vals | Where-Object { $_ -eq $true })
    if ($on.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Calendar interoperability is enabled in $($on.Count) of $($r.Vals.Count) targeted policy/policies — calendar data bridges to an external system" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Calendar interoperability is off in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-018: GWS.CALENDAR.4.1 — Appointment payments disabled ───────────
function Test-FortificationCOLLAB018 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-CollabPolicyValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Type 'calendar.appointment_schedules' -Field 'enablePayments' -Subject 'Calendar appointment-schedule policy'
    if ($r.Na) { return $r.Na }
    $on = @($r.Vals | Where-Object { $_ -eq $true })
    if ($on.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Paid appointment schedules are enabled in $($on.Count) of $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Paid appointment schedules are disabled in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── COLLAB-019: GWS.MEET.5.1 — Automatic recording off by default ──────────
function Test-FortificationCOLLAB019 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $r = Get-CollabPolicyValues -AuditData $AuditData -CheckDefinition $CheckDefinition -OrgUnitPath $OrgUnitPath -Type 'meet.automatic_recording' -Field 'enabled' -Subject 'Meet automatic-recording policy'
    if ($r.Na) { return $r.Na }
    $on = @($r.Vals | Where-Object { $_ -eq $true })
    if ($on.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Automatic recording is on by default in $($on.Count) of $($r.Vals.Count) targeted policy/policies — meetings are captured without a deliberate decision" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue "Automatic recording is off by default in all $($r.Vals.Count) targeted policy/policies" -OrgUnitPath $OrgUnitPath
}

# ── GROUP-006: GWS.GROUPS.4.1 — Groups visible in the directory ────────────
function Test-FortificationGROUP006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('CloudIdentityPolicies', 'OrgUnits') -Subject 'Groups for Business sharing policy'
    if ($na) { return $na }
    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' -OrgUnitPath $OrgUnitPath
    }
    # GWS.GROUPS.4.1 is non-compliant if owners can hide groups OR new groups are hidden by default.
    $ownerHide = @(Resolve-GooglePolicyValue -Policies $pol -Type 'groups_for_business.groups_sharing' -Field 'ownersCanHideGroups')
    $newHidden = @(Resolve-GooglePolicyValue -Policies $pol -Type 'groups_for_business.groups_sharing' -Field 'newGroupsAreHidden')
    if ($ownerHide.Count -eq 0 -and $newHidden.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'No groups_for_business.groups_sharing hide-group settings returned for this tenant' -OrgUnitPath $OrgUnitPath
    }
    $oh = @($ownerHide | Where-Object { $_ -eq $true })
    $nh = @($newHidden | Where-Object { $_ -eq $true })
    if ($oh.Count -gt 0 -or $nh.Count -gt 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
            -CurrentValue "Groups can be hidden from the directory (owners-can-hide in $($oh.Count), new-groups-hidden in $($nh.Count) targeted policy/policies)" -OrgUnitPath $OrgUnitPath
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
        -CurrentValue 'Groups are visible in the directory (not hideable, not hidden by default)' -OrgUnitPath $OrgUnitPath
}
