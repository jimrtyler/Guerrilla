# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# K12 Baseline checks. These assess the Guerrilla K12 Secure Configuration
# Baseline (docs/baselines/k12-secure-configuration-baseline.md), a candidate
# community baseline authored by Guerrilla. It is not a consensus standard;
# the definitions carry a guerrillaBaseline field, never an invented external
# framework ID.
#
# OU-scoped checks read $AuditData.StudentOUs and emit one finding per student
# OU. Without the scope they return the honest Not Assessed branch
# (Get-StudentScopeNotAssessed); they never assess the whole tenant as if it
# were the student population.

function Invoke-K12Checks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData,

        [string]$OrgUnitPath = '/'
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'K12Checks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                # OU-scoped K12 checks return one finding per student OU.
                $result = & $funcName -AuditData $AuditData -CheckDefinition $check -OrgUnitPath $OrgUnitPath
                foreach ($f in @($result)) { if ($f) { $findings.Add($f) } }
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

# ── GWS-K12-004: Vendor Delegated Access Review (K12-IDENT-002) ──────────
function Test-GWSK12004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'DomainWideDelegation' -Subject 'domain-wide delegation grants'
    if ($na) { return $na }

    $grants = @($AuditData.DomainWideDelegation)
    if ($grants.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No domain-wide delegation grants exist in this tenant.' `
            -OrgUnitPath $OrgUnitPath
    }

    # Scopes that reach user content or the directory. A grant carrying any of
    # these is standing vendor access to student data and belongs on a review
    # list; which vendors are legitimate is the district's determination, so
    # this reports WARN with the list, never a hard FAIL.
    $sensitivePattern = '(?i)auth/(gmail|drive|admin\.directory|contacts|calendar|cloud-platform|apps\.groups|classroom)'
    $review = foreach ($g in $grants) {
        $scopes = @($g.scopes)
        $sensitive = @($scopes | Where-Object { "$_" -match $sensitivePattern })
        if ($sensitive.Count) {
            [pscustomobject]@{
                ClientId       = "$($g.clientId)"
                DisplayText    = "$($g.displayText)"
                SensitiveCount = $sensitive.Count
                ScopeCount     = $scopes.Count
            }
        }
    }
    $review = @($review)

    if ($review.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue ("$($grants.Count) domain-wide delegation grant(s) exist; none carries mail, Drive, " +
                'directory, contacts, calendar, or Classroom scopes. Review the list for departed vendors as part of routine hygiene.') `
            -OrgUnitPath $OrgUnitPath -Details @{ GrantCount = $grants.Count }
    }

    $names = @($review | ForEach-Object {
        $label = if ($_.DisplayText) { $_.DisplayText } else { "client $($_.ClientId)" }
        "$label ($($_.SensitiveCount) sensitive of $($_.ScopeCount) scopes)"
    })
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue ("$($review.Count) of $($grants.Count) domain-wide delegation grant(s) carry scopes reaching " +
            "user content or the directory: $($names -join '; '). Confirm each maps to a current vendor contract " +
            'and the narrowest workable scope set; remove grants for departed vendors.') `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            GrantCount     = $grants.Count
            ReviewCount    = $review.Count
            ReviewClients  = @($review | ForEach-Object { $_.ClientId })
            Note           = 'Grant age and last use are not exposed by the delegation API; a token-activity collector is proposed to strengthen staleness detection.'
        }
}

# ── GWS-K12-005: Delegated Admin Least Privilege (K12-IDENT-003) ─────────
function Test-GWSK12005 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey @('Roles', 'RoleAssignments') -Subject 'admin roles and role assignments'
    if ($na) { return $na }

    $roles = @($AuditData.Roles)
    $assignments = @($AuditData.RoleAssignments)
    if ($roles.Count -eq 0 -or $assignments.Count -eq 0) {
        # A tenant always has system roles and at least one super-admin
        # assignment; an empty result is a collection gap, not a clean tenant.
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue ('Not Assessed: the roles or role-assignments list came back empty, which no real tenant ' +
                'produces. This control was not evaluated; absence of evidence is not compliance.') `
            -OrgUnitPath $OrgUnitPath -Details @{ NotAssessed = $true }
    }

    # Index roles by id; identify the broad-reach privileges (user management,
    # security settings, org-unit management). Privilege names are matched by
    # pattern with an honest fallthrough: an unrecognized privilege set never
    # silently passes.
    $broadPattern = '(?i)^(USERS?_|SECURITY_|ORGANIZATION_UNITS?_|GROUPS?_ALL)'
    $rolesById = @{}
    foreach ($r in $roles) { $rolesById["$($r.roleId)"] = $r }

    $review = foreach ($a in $assignments) {
        $role = $rolesById["$($a.roleId)"]
        if (-not $role) { continue }
        if ($role.isSuperAdminRole) { continue }  # super-admin count is ADMIN-001's business
        $scopeType = "$($a.scopeType)"
        if ($scopeType -eq 'ORG_UNIT') { continue }  # OU-scoped delegation is the goal state
        $broad = @(@($role.rolePrivileges) | Where-Object { "$($_.privilegeName)" -match $broadPattern })
        if ($broad.Count) {
            [pscustomobject]@{
                RoleName   = "$($role.roleName)"
                AssignedTo = "$($a.assignedTo)"
                Privileges = @($broad | ForEach-Object { "$($_.privilegeName)" } | Select-Object -Unique)
            }
        }
    }
    $review = @($review)

    if ($review.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue ("All delegated (non-super-admin) role assignments with user-management or security " +
                'privileges are scoped to organizational units, or no such delegated assignments exist ' +
                "($($assignments.Count) assignment(s) across $($roles.Count) role(s) reviewed).") `
            -OrgUnitPath $OrgUnitPath
    }

    $byRole = @($review | Group-Object RoleName | ForEach-Object { "$($_.Name) ($($_.Count) holder(s))" })
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
        -CurrentValue ("$($review.Count) delegated admin assignment(s) carry user-management, security, or org-unit " +
            "privileges across the whole domain rather than scoped to an OU: $($byRole -join '; '). Confirm each " +
            'holder needs domain-wide reach; scope the assignment to their organizational unit where they do not.') `
        -OrgUnitPath $OrgUnitPath `
        -Details @{
            ReviewCount = $review.Count
            Roles       = @($review | ForEach-Object RoleName | Select-Object -Unique)
        }
}

# ── GWS-K12-009: Departed Student Account Disposition (K12-LIFE-001) ─────
function Test-GWSK12009 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
        -SourceKey 'Users' -Subject 'the user directory'
    if ($na) { return $na }

    $dormantDays = 365  # a full year spans summer break; dormancy is not vacation
    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $present = Test-GwsOrgUnitPresent -AuditData $AuditData -OrgUnitPath $stuOu
        if ($null -eq $present) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
                -OrgUnitPath $stuOu `
                -CurrentValue ('Not Assessed: the tenant OU tree was not collected, so the student OU could not be ' +
                    'verified. This control was not evaluated; absence of evidence is not compliance.') `
                -Details @{ NotAssessed = $true }
            continue
        }
        if (-not $present) {
            New-StudentOuAbsentSkip -CheckDefinition $CheckDefinition -OrgUnitPath $stuOu
            continue
        }

        $inScope = @(@($AuditData.Users) | Where-Object {
            $p = "$($_.orgUnitPath)"
            $p -eq $stuOu -or $p.StartsWith("$stuOu/")
        })

        $now = if ($script:GuerrillaTestMode) { [datetime]'2026-01-01T00:00:00Z' } else { [datetime]::UtcNow }
        $dormantActive = @($inScope | Where-Object {
            -not $_.suspended -and $_.lastLoginTime -and
            ([datetime]"$($_.lastLoginTime)").Year -gt 1970 -and
            ($now - [datetime]"$($_.lastLoginTime)").TotalDays -gt $dormantDays
        })
        $suspendedCount = @($inScope | Where-Object { $_.suspended }).Count

        if ($inScope.Count -eq 0) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("Student OU '$stuOu' exists but contains no user accounts. Confirm this is the " +
                    'intended student OU; an empty designation usually means the wrong path was provided.') `
                -Details @{ UserCount = 0 }
            continue
        }

        if ($dormantActive.Count -eq 0) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("No active account in '$stuOu' has gone $dormantDays+ days without a sign-in " +
                    "($($inScope.Count) account(s) reviewed, $suspendedCount suspended). Note: suspended accounts " +
                    'still hold Drive data; resolve ownership before any deletion.') `
                -Details @{ UserCount = $inScope.Count; SuspendedCount = $suspendedCount }
        } else {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("$($dormantActive.Count) account(s) in '$stuOu' are active but have not signed in " +
                    "for over $dormantDays days, consistent with departed students who were never offboarded " +
                    "($($inScope.Count) account(s) reviewed, $suspendedCount suspended). Suspend or archive " +
                    'departed students, and resolve Drive ownership before deletion. Drive ownership transfer is ' +
                    'not assessed by this check (no Drive collection); treat it as a manual review step.') `
                -Details @{
                    UserCount      = $inScope.Count
                    DormantActive  = $dormantActive.Count
                    SuspendedCount = $suspendedCount
                    ThresholdDays  = $dormantDays
                }
        }
    }
    return @($findings)
}

# ── Shared per-OU gate: presence of the student OU in the collected tree ──
function Get-K12StudentOuGate {
    # Returns a SKIP finding when the student OU cannot be honestly assessed
    # (tree unavailable, or path absent from the tree); $null when assessable.
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$StudentOuPath)

    $present = Test-GwsOrgUnitPresent -AuditData $AuditData -OrgUnitPath $StudentOuPath
    if ($null -eq $present) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -OrgUnitPath $StudentOuPath `
            -CurrentValue ('Not Assessed: the tenant OU tree was not collected, so the student OU could not be ' +
                'verified. This control was not evaluated; absence of evidence is not compliance.') `
            -Details @{ NotAssessed = $true }
    }
    if (-not $present) {
        return New-StudentOuAbsentSkip -CheckDefinition $CheckDefinition -OrgUnitPath $StudentOuPath
    }
    return $null
}

# Shared evidence suffix when group-targeted policies of the same type exist:
# group membership cannot be resolved to an OU, so the value some students
# receive may differ from the OU-resolved value.
function Get-K12GroupOverrideNote {
    param($Resolved)
    if ($Resolved -and $Resolved.GroupOverride) {
        ' Group-targeted policies of this type also exist; students in those groups may receive a different value.'
    } else { '' }
}

# ── GWS-K12-001: Student OU Sharing Not Inherited From Staff (K12-DATA-001) ──
function Test-GWSK12001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }

    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $gate = Get-K12StudentOuGate -AuditData $AuditData -CheckDefinition $CheckDefinition -StudentOuPath $stuOu
        if ($gate) { $gate; continue }

        # settings/drive_and_docs.external_sharing, field externalSharingMode:
        # DISALLOWED | ALLOWLISTED_DOMAINS | ALLOWED (verified against the
        # Policy API catalog and ScubaGoggles GWS.DRIVEDOCS.1.1).
        $r = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'drive_and_docs.external_sharing' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'externalSharingMode'
        $groupNote = Get-K12GroupOverrideNote $r

        if (-not $r.Found) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("No Drive external-sharing policy was returned for '$stuOu' or any ancestor. " +
                    "Google's documented default permits external sharing, so the student OU is running on an " +
                    "unexamined default. Set Drive sharing explicitly on the student OU.$groupNote") `
                -Details @{ Setting = 'drive_and_docs.external_sharing' }
            continue
        }

        $mode = "$($r.Value)"
        if (-not $r.Inherited) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("Drive external sharing on '$stuOu' is a local decision (policy applied at the OU " +
                    "itself, mode $mode), not an inherited staff default.$groupNote") `
                -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath }
            continue
        }

        # Inherited: whether that matters depends on what is inherited.
        if ($mode -eq 'DISALLOWED') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("'$stuOu' inherits its Drive external-sharing setting from '$($r.SourceOuPath)', and " +
                    "the inherited value is DISALLOWED (external sharing off). Inheriting a fully-disabled setting " +
                    "is safe; revisit if the parent setting is ever relaxed.$groupNote") `
                -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath; Inherited = $true }
        } elseif ($mode -eq 'ALLOWLISTED_DOMAINS') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("'$stuOu' inherits Drive external sharing (allowlisted domains) from " +
                    "'$($r.SourceOuPath)'. The allowlist was chosen for that population, not for students. Make an " +
                    "explicit sharing decision on the student OU.$groupNote") `
                -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath; Inherited = $true }
        } elseif ($mode -eq 'ALLOWED') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("'$stuOu' inherits unrestricted Drive external sharing (ALLOWED) from " +
                    "'$($r.SourceOuPath)'. Nobody chose this for students; it is a staff-population default reaching " +
                    "student accounts through inheritance. Set sharing on the student OU explicitly.$groupNote") `
                -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath; Inherited = $true }
        } else {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("'$stuOu' inherits an unrecognized Drive external-sharing value '$mode' from " +
                    "'$($r.SourceOuPath)'. Manual confirmation required; an unrecognized value is never assumed " +
                    "safe.$groupNote") `
                -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath; Inherited = $true }
        }
    }
    return @($findings)
}

# ── GWS-K12-002: Student External Drive Sharing Restricted (K12-DATA-002) ──
function Test-GWSK12002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }

    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $gate = Get-K12StudentOuGate -AuditData $AuditData -CheckDefinition $CheckDefinition -StudentOuPath $stuOu
        if ($gate) { $gate; continue }

        $r = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'drive_and_docs.external_sharing' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'externalSharingMode'
        $groupNote = Get-K12GroupOverrideNote $r

        if (-not $r.Found) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("No Drive external-sharing policy was returned for '$stuOu' or any ancestor. " +
                    "Google's documented default permits external sharing. Confirm and set the student sharing mode " +
                    "explicitly (Admin Console > Apps > Drive and Docs > Sharing settings).$groupNote") `
                -Details @{ Setting = 'drive_and_docs.external_sharing' }
            continue
        }

        $mode = "$($r.Value)"
        switch ($mode) {
            'DISALLOWED' {
                New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                    -OrgUnitPath $stuOu `
                    -CurrentValue ("External Drive sharing for '$stuOu' is disabled (DISALLOWED), resolved from " +
                        "'$($r.SourceOuPath)'.$groupNote") `
                    -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath }
            }
            'ALLOWLISTED_DOMAINS' {
                New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                    -OrgUnitPath $stuOu `
                    -CurrentValue ("External Drive sharing for '$stuOu' is restricted to allowlisted domains, " +
                        "resolved from '$($r.SourceOuPath)'. Review the domain allowlist periodically; every listed " +
                        "domain can receive student documents.$groupNote") `
                    -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath }
            }
            'ALLOWED' {
                # Warn-on-sharing softens ALLOWED but does not restrict it. The
                # warn flag lives in the same setting type (merge semantics).
                $warn = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'drive_and_docs.external_sharing' `
                    -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'warnForExternalSharing'
                if ($warn.Found -and $warn.Value -eq $true) {
                    New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                        -OrgUnitPath $stuOu `
                        -CurrentValue ("Students in '$stuOu' can share Drive files externally; a warning is shown " +
                            "before external shares (warn-on-external). This is the weakest acceptable student " +
                            "posture under the K12 baseline; confirm it matches the district's policy for this age " +
                            "band, and prefer allowlisted domains or off.$groupNote") `
                        -Details @{ Mode = $mode; WarnOnShare = $true; SourceOu = $r.SourceOuPath }
                } else {
                    New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                        -OrgUnitPath $stuOu `
                        -CurrentValue ("Students in '$stuOu' can share Drive files with any external account, with " +
                            "no warning prompt (mode ALLOWED, resolved from '$($r.SourceOuPath)'). Restrict student " +
                            "external sharing to off or allowlisted domains, or at minimum enable the external-share " +
                            "warning.$groupNote") `
                        -Details @{ Mode = $mode; WarnOnShare = $false; SourceOu = $r.SourceOuPath }
                }
            }
            default {
                New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                    -OrgUnitPath $stuOu `
                    -CurrentValue ("Unrecognized Drive external-sharing mode '$mode' for '$stuOu'. Manual " +
                        "confirmation required; an unrecognized value is never assumed safe.$groupNote") `
                    -Details @{ Mode = $mode; SourceOu = $r.SourceOuPath }
            }
        }
    }
    return @($findings)
}

# ── GWS-K12-003: Students Cannot Authorize Third-Party Apps (K12-IDENT-001) ──
function Test-GWSK12003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }

    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $gate = Get-K12StudentOuGate -AuditData $AuditData -CheckDefinition $CheckDefinition -StudentOuPath $stuOu
        if ($gate) { $gate; continue }

        # settings/api_controls.unconfigured_third_party_apps, field accessLevel.
        # Live values (per ScubaGoggles and Guerrilla live validation):
        # BLOCK_ALL_SCOPES, ALLOW_SIGN_IN_SCOPES_ONLY, UNSPECIFIED_UBER_BLOCK.
        $r = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'api_controls.unconfigured_third_party_apps' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'accessLevel'
        $groupNote = Get-K12GroupOverrideNote $r

        if (-not $r.Found) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("No third-party app access policy was returned for '$stuOu' or any ancestor. " +
                    'Unconfigured third-party apps may be able to request access to student data. Confirm App ' +
                    "access control (Admin Console > Security > API controls) and block unconfigured apps for " +
                    "student OUs.$groupNote") `
                -Details @{ Setting = 'api_controls.unconfigured_third_party_apps' }
            continue
        }

        $level = "$($r.Value)"
        if ($level -eq 'BLOCK_ALL_SCOPES') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("Unconfigured third-party apps are blocked for '$stuOu' (BLOCK_ALL_SCOPES, resolved " +
                    "from '$($r.SourceOuPath)'). Students can only use apps the district has explicitly " +
                    "allowlisted.$groupNote") `
                -Details @{ AccessLevel = $level; SourceOu = $r.SourceOuPath }
        } elseif ($level -eq 'UNSPECIFIED_UBER_BLOCK') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("Unconfigured third-party apps are blocked for '$stuOu' by the unconfigured-state " +
                    "block (UNSPECIFIED_UBER_BLOCK, resolved from '$($r.SourceOuPath)'). Effective posture is " +
                    'blocked; consider setting BLOCK_ALL_SCOPES explicitly so the decision is recorded rather than ' +
                    "implied.$groupNote") `
                -Details @{
                    AccessLevel = $level
                    SourceOu    = $r.SourceOuPath
                    Note        = 'Guerrilla live validation observed this value as block-all; CISA ScubaGoggles grades it non-compliant for want of explicit configuration. Both agree the effective state blocks unconfigured apps.'
                }
        } elseif ($level -eq 'ALLOW_SIGN_IN_SCOPES_ONLY') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("Unconfigured third-party apps can use Google sign-in (profile scopes) for accounts " +
                    "in '$stuOu' (ALLOW_SIGN_IN_SCOPES_ONLY, resolved from '$($r.SourceOuPath)'). Data-scope access " +
                    'is blocked, but students can still create accounts on external services with their school ' +
                    "identity. Prefer BLOCK_ALL_SCOPES for student OUs.$groupNote") `
                -Details @{ AccessLevel = $level; SourceOu = $r.SourceOuPath }
        } elseif ($level -match '(?i)ALLOW') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("Accounts in '$stuOu' can authorize unconfigured third-party apps (accessLevel " +
                    "'$level', resolved from '$($r.SourceOuPath)'). Any external service a student signs into can " +
                    'request access to their school account data without district review. Block unconfigured apps ' +
                    "for student OUs and allowlist reviewed apps only.$groupNote") `
                -Details @{ AccessLevel = $level; SourceOu = $r.SourceOuPath }
        } else {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' `
                -OrgUnitPath $stuOu `
                -CurrentValue ("Unrecognized third-party app access level '$level' for '$stuOu'. Manual " +
                    "confirmation required; an unrecognized value is never assumed safe.$groupNote") `
                -Details @{ AccessLevel = $level; SourceOu = $r.SourceOuPath }
        }
    }
    return @($findings)
}

# ── GWS-K12-006: Student Communication Boundaries (K12-SAFE-001) ─────────
function Test-GWSK12006 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }

    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $gate = Get-K12StudentOuGate -AuditData $AuditData -CheckDefinition $CheckDefinition -StudentOuPath $stuOu
        if ($gate) { $gate; continue }

        # This is a configuration-posture check. A FAIL means a setting permits
        # a class of external contact the district has not affirmatively
        # decided to permit for students; it does not mean such contact has
        # occurred. Wording below stays factual on purpose.
        $parts = [System.Collections.Generic.List[string]]::new()
        $failCount = 0
        $warnCount = 0

        # Chat: settings/chat.external_chat_restriction (allowExternalChat +
        # externalChatRestriction; TRUSTED_DOMAINS is the restricted variant).
        $chatAllow = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'chat.external_chat_restriction' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'allowExternalChat'
        $groupNote = Get-K12GroupOverrideNote $chatAllow
        if (-not $chatAllow.Found) {
            $parts.Add('Chat: no external-chat policy returned; the documented default is external chat off, but confirm it in the Admin Console')
            $warnCount++
        } elseif ($chatAllow.Value -eq $true) {
            $chatRestrict = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'chat.external_chat_restriction' `
                -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'externalChatRestriction'
            if ($chatRestrict.Found -and "$($chatRestrict.Value)" -eq 'TRUSTED_DOMAINS') {
                $parts.Add('Chat: external chat is limited to allowlisted (trusted) domains; every listed domain can exchange messages with students')
                $warnCount++
            } else {
                $parts.Add('Chat: external chat is on with no domain restriction, so accounts outside the district can message students and be messaged by them')
                $failCount++
            }
        } else {
            $parts.Add('Chat: external chat is off')
        }

        # Meet: settings/meet.safety_access, field meetingsAllowedToJoin
        # (SAME_ORGANIZATION_ONLY | ANY_WORKSPACE_ORGANIZATION | ALL) governs
        # which meetings students can join.
        $meet = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'meet.safety_access' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'meetingsAllowedToJoin'
        if (-not $meet.Found) {
            $parts.Add('Meet: no safety-access policy returned; confirm which meetings students can join in the Admin Console')
            $warnCount++
        } else {
            switch ("$($meet.Value)") {
                'SAME_ORGANIZATION_ONLY' { $parts.Add('Meet: students can join district-hosted meetings only') }
                'ANY_WORKSPACE_ORGANIZATION' {
                    $parts.Add('Meet: students can join meetings hosted by any Google Workspace organization, not just the district')
                    $warnCount++
                }
                'ALL' {
                    $parts.Add('Meet: students can join any meeting, including ones created by personal Google accounts')
                    $failCount++
                }
                default {
                    $parts.Add("Meet: unrecognized safety-access value '$($meet.Value)'; manual confirmation required")
                    $warnCount++
                }
            }
        }

        # Gmail: external-mail restriction for student OUs is configured through
        # Gmail routing/compliance rules, which have no Policy API surface. Said
        # plainly rather than implied assessed.
        $parts.Add('Gmail: external mail restrictions are configured via Gmail routing rules, which this check cannot read; review them manually if the district restricts student external mail')

        $summary = ($parts -join '. ') + '.'
        $detail = @{ Services = @('Chat', 'Meet', 'Gmail (manual)') }
        if ($failCount) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' -OrgUnitPath $stuOu `
                -CurrentValue ("Communication boundary settings for '$stuOu' permit unrestricted external contact " +
                    "on at least one service. $summary$groupNote") -Details $detail
        } elseif ($warnCount) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' -OrgUnitPath $stuOu `
                -CurrentValue ("Communication boundary settings for '$stuOu' need review. $summary$groupNote") `
                -Details $detail
        } else {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' -OrgUnitPath $stuOu `
                -CurrentValue ("Communication boundaries for '$stuOu' are restricted. $summary$groupNote") `
                -Details $detail
        }
    }
    return @($findings)
}

# ── GWS-K12-007: Guardian Access Integrity (K12-SAFE-002) ────────────────
function Test-GWSK12007 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }

    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $gate = Get-K12StudentOuGate -AuditData $AuditData -CheckDefinition $CheckDefinition -StudentOuPath $stuOu
        if ($gate) { $gate; continue }

        # settings/classroom.guardian_access: allowAccess (guardian email
        # summaries master switch) + whoCanManageGuardianAccess
        # (DOMAIN_ADMINS_ONLY | VERIFIED_TEACHERS_AND_DOMAIN_ADMINS). No
        # consensus baseline evaluates this setting; the direction here is the
        # Guerrilla K12 candidate baseline's own.
        $allow = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'classroom.guardian_access' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'allowAccess'
        $groupNote = Get-K12GroupOverrideNote $allow

        if (-not $allow.Found) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' -OrgUnitPath $stuOu `
                -CurrentValue ("No Classroom guardian-access policy was returned for '$stuOu' or any ancestor. " +
                    'Confirm the guardian settings in the Admin Console (Apps > Google Workspace > Classroom): ' +
                    "whether guardian summaries are in use is a decision the district should make deliberately.$groupNote") `
                -Details @{ Setting = 'classroom.guardian_access' }
            continue
        }

        if ($allow.Value -ne $true) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' -OrgUnitPath $stuOu `
                -CurrentValue ("Guardian access to Classroom information is disabled for '$stuOu' (resolved from " +
                    "'$($allow.SourceOuPath)'). There is no guardian surface to protect. If the district intends " +
                    "to offer guardian summaries, enable and configure them deliberately.$groupNote") `
                -Details @{ AllowAccess = $false; SourceOu = $allow.SourceOuPath }
            continue
        }

        $manage = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'classroom.guardian_access' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'whoCanManageGuardianAccess'
        $manageVal = if ($manage.Found) { "$($manage.Value)" } else { '' }

        if ($manageVal -eq 'DOMAIN_ADMINS_ONLY') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' -OrgUnitPath $stuOu `
                -CurrentValue ("Guardian access is enabled for '$stuOu' and only domain administrators can manage " +
                    'who is registered as a guardian (resolved from ' +
                    "'$($manage.SourceOuPath)'). Keep the admin-side verification step documented: the setting " +
                    "controls who registers guardians, not how identities are verified.$groupNote") `
                -Details @{ AllowAccess = $true; WhoCanManage = $manageVal; SourceOu = $manage.SourceOuPath }
        } elseif ($manageVal -eq 'VERIFIED_TEACHERS_AND_DOMAIN_ADMINS') {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' -OrgUnitPath $stuOu `
                -CurrentValue ("Guardian access is enabled for '$stuOu' and verified teachers can register and " +
                    "remove guardians as well as admins (resolved from '$($manage.SourceOuPath)'). That is a wider " +
                    'registration surface than admin-only: confirm the district has a documented identity-check ' +
                    'procedure teachers follow before inviting a guardian, or restrict management to domain ' +
                    "admins.$groupNote") `
                -Details @{ AllowAccess = $true; WhoCanManage = $manageVal; SourceOu = $manage.SourceOuPath }
        } else {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' -OrgUnitPath $stuOu `
                -CurrentValue ("Guardian access is enabled for '$stuOu' but the guardian-management setting " +
                    "returned '$manageVal', which this check does not recognize. Manual confirmation required; an " +
                    "unrecognized value is never assumed safe.$groupNote") `
                -Details @{ AllowAccess = $true; WhoCanManage = $manageVal }
        }
    }
    return @($findings)
}

# ── GWS-K12-008: Managed Student Chromebook Posture (K12-DEVICE-001) ─────
function Test-GWSK12008 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $gate = Get-K12StudentOuGate -AuditData $AuditData -CheckDefinition $CheckDefinition -StudentOuPath $stuOu
        if ($gate) { $gate; continue }

        # Per-OU Chrome policies come from the collector's per-student-OU
        # policies:resolve calls; a per-OU failure was recorded under
        # 'ChromePolicies:<path>'.
        $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition -ErrorMap $AuditData.Errors `
            -SourceKey "ChromePolicies:$stuOu" -Subject "Chrome policies for '$stuOu'"
        if ($na) { $na; continue }

        $byOu = $AuditData.ChromePoliciesByOu
        $ouPolicies = if ($byOu -is [System.Collections.IDictionary]) {
            $byOu[$stuOu]
        } elseif ($null -ne $byOu -and (Test-GwsValueHasField $byOu $stuOu)) {
            $byOu.$stuOu
        } else { $null }
        if ($null -eq $ouPolicies) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' -OrgUnitPath $stuOu `
                -CurrentValue ("Not Assessed: Chrome policies were not resolved for '$stuOu' (Chrome policy scope " +
                    'not delegated, or device management not collected). This control was not evaluated; absence ' +
                    'of evidence is not compliance.') `
                -Details @{ NotAssessed = $true }
            continue
        }

        # resolvedPolicies entries carry value.policySchema + value.value.
        $bySchema = @{}
        foreach ($p in @($ouPolicies)) {
            if ($null -eq $p -or $null -eq $p.value) { continue }
            $schema = "$($p.value.policySchema)"
            if ($schema -and -not $bySchema.ContainsKey($schema)) { $bySchema[$schema] = $p.value.value }
        }
        $get = {
            param($schema, $field)
            $v = $bySchema[$schema]
            if (Test-GwsValueHasField $v $field) { $v.$field } else { $null }
        }

        $parts = [System.Collections.Generic.List[string]]::new()
        $failCount = 0
        $warnCount = 0

        # chrome.devices.ForcedReenrollment.reenrollmentMode:
        # AUTO_REENROLLMENT (safe) | MANUAL_REENROLLMENT | NO_REENROLLMENT.
        $reenroll = & $get 'chrome.devices.ForcedReenrollment' 'reenrollmentMode'
        if ($null -eq $reenroll) {
            $parts.Add('forced re-enrollment: not returned, confirm in the Admin Console'); $warnCount++
        } elseif ("$reenroll" -eq 'AUTO_REENROLLMENT') {
            $parts.Add('forced re-enrollment: automatic after wipe (devices cannot leave management by wiping)')
        } elseif ("$reenroll" -eq 'NO_REENROLLMENT') {
            $parts.Add('forced re-enrollment: DISABLED, a wiped student device leaves management entirely'); $failCount++
        } else {
            $parts.Add("forced re-enrollment: $reenroll (manual re-enrollment leaves a gap between wipe and re-enroll)"); $warnCount++
        }

        # chrome.users.appsconfig.AllowedInstallSources.chromeWebStoreInstallSources:
        # BLOCK_ALL_APPS (allowlist mode, safe) | ALLOW_ALL_APPS (blocklist mode).
        $installMode = & $get 'chrome.users.appsconfig.AllowedInstallSources' 'chromeWebStoreInstallSources'
        if ($null -eq $installMode) {
            $parts.Add('extension install mode: not returned, confirm in the Admin Console'); $warnCount++
        } elseif ("$installMode" -match '(?i)^BLOCK_ALL_APPS') {
            $parts.Add('extension install mode: allowlist (students install only district-reviewed extensions)')
        } elseif ("$installMode" -match '(?i)^ALLOW_ALL_APPS') {
            $parts.Add('extension install mode: blocklist (students can install any extension the district has not explicitly blocked)'); $warnCount++
        } else {
            $parts.Add("extension install mode: unrecognized value '$installMode', manual confirmation required"); $warnCount++
        }

        # chrome.users.appsconfig.BlockExternalExtensions.blockExternalExtensions:
        # true = sideloading outside the Web Store is blocked.
        $blockExternal = & $get 'chrome.users.appsconfig.BlockExternalExtensions' 'blockExternalExtensions'
        if ($null -eq $blockExternal) {
            $parts.Add('external (sideloaded) extensions: setting not returned, confirm in the Admin Console'); $warnCount++
        } elseif ($blockExternal -eq $true) {
            $parts.Add('external (sideloaded) extensions: blocked')
        } else {
            $parts.Add('external (sideloaded) extensions: PERMITTED, students can load extensions from outside the Web Store'); $failCount++
        }

        $summary = "Chromebook posture for '$stuOu': " + ($parts -join '; ') + '.'
        if ($failCount) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' -OrgUnitPath $stuOu `
                -CurrentValue $summary -Details @{ FailComponents = $failCount; WarnComponents = $warnCount }
        } elseif ($warnCount) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' -OrgUnitPath $stuOu `
                -CurrentValue $summary -Details @{ WarnComponents = $warnCount }
        } else {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' -OrgUnitPath $stuOu `
                -CurrentValue $summary
        }
    }
    return @($findings)
}

# ── GWS-K12-010: Student Account Security Floor (K12-ACCT-001) ───────────
function Test-GWSK12010 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition, [string]$OrgUnitPath = '/')

    $noScope = Get-StudentScopeNotAssessed -CheckDefinition $CheckDefinition -AuditData $AuditData
    if ($noScope) { return $noScope }

    $pol = $AuditData.CloudIdentityPolicies
    if (-not $pol) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue 'Cloud Identity Policy API not available (cloud-identity.policies.readonly not delegated, or API disabled)' `
            -OrgUnitPath $OrgUnitPath
    }

    $findings = foreach ($stuOu in @($AuditData.StudentOUs)) {
        $gate = Get-K12StudentOuGate -AuditData $AuditData -CheckDefinition $CheckDefinition -StudentOuPath $stuOu
        if ($gate) { $gate; continue }

        $parts = [System.Collections.Generic.List[string]]::new()
        $failCount = 0
        $warnCount = 0

        # Self-recovery: settings/security.user_account_recovery,
        # enableAccountRecovery (safe = false; ScubaGoggles GWS.COMMONCONTROLS.8.2
        # grades the same direction tenant-wide). Student-controlled recovery
        # channels are an account-takeover path regardless of age band.
        $recovery = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'security.user_account_recovery' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'enableAccountRecovery'
        $groupNote = Get-K12GroupOverrideNote $recovery
        if (-not $recovery.Found) {
            $parts.Add('self-recovery: no policy returned (the documented default is off); confirm in the Admin Console'); $warnCount++
        } elseif ($recovery.Value -eq $true) {
            $parts.Add('self-recovery: ENABLED, students can recover accounts through channels they control (a takeover path); recovery for students should run through the district'); $failCount++
        } else {
            $parts.Add('self-recovery: disabled (recovery runs through the district)')
        }

        # Password floor: settings/security.password (minimumLength,
        # allowedStrength STRONG|WEAK). The 12+ direction matches
        # GWS.COMMONCONTROLS.5.2.
        $minLen = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'security.password' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'minimumLength'
        $strength = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'security.password' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'allowedStrength'
        if (-not $minLen.Found -and -not $strength.Found) {
            $parts.Add('password policy: not returned; confirm in the Admin Console'); $warnCount++
        } else {
            $lenText = if ($minLen.Found) { "minimum length $($minLen.Value)" } else { 'minimum length not returned' }
            $strText = if ($strength.Found) { "strength $($strength.Value)" } else { 'strength not returned' }
            if (($minLen.Found -and [int]$minLen.Value -lt 12) -or ($strength.Found -and "$($strength.Value)" -ne 'STRONG')) {
                $parts.Add("password policy: $lenText, $strText; the floor for any age band is STRONG with length 12 or more"); $warnCount++
            } else {
                $parts.Add("password policy: $lenText, $strText")
            }
        }

        # 2SV: settings/security.two_step_verification_enforcement.enforcedFrom
        # is a timestamp; enforced when parseable, nonzero, and in the past.
        # Age-banded honesty: not enforced is CONTEXT for the district's age
        # band decision, never a blind FAIL of a third grader.
        $enforce = Resolve-GwsStudentOuPolicy -Policies $pol -Type 'security.two_step_verification_enforcement' `
            -OrgUnitPath $stuOu -OrgUnits $AuditData.Tenant.OrgUnits -Field 'enforcedFrom'
        $enforced = $false
        if ($enforce.Found) {
            $ts = $null
            try { $ts = [datetime]"$($enforce.Value)" } catch { $ts = $null }
            if ($null -ne $ts) {
                $nowRef = if ($script:GuerrillaTestMode) { [datetime]'2026-01-01T00:00:00Z' } else { [datetime]::UtcNow }
                $enforced = ($ts.Year -gt 1970 -and $ts -le $nowRef)
            }
        }
        if ($enforced) {
            $parts.Add('2-Step Verification: enforced for this OU')
        } else {
            $parts.Add('2-Step Verification: not enforced for this OU. For OUs serving students old enough to hold a second factor, enforce 2SV; for younger bands this is an accepted, documented exception, not a failure')
        }

        $summary = "Account security floor for '$stuOu': " + ($parts -join '; ') + '.'
        $detail = @{ TwoStepEnforced = $enforced }
        if ($failCount) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'FAIL' -OrgUnitPath $stuOu `
                -CurrentValue "$summary$groupNote" -Details $detail
        } elseif ($warnCount) {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'WARN' -OrgUnitPath $stuOu `
                -CurrentValue "$summary$groupNote" -Details $detail
        } else {
            New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' -OrgUnitPath $stuOu `
                -CurrentValue "$summary$groupNote" -Details $detail
        }
    }
    return @($findings)
}
