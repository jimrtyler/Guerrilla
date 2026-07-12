# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

# Student-OU scope: the shared machinery behind every OU-scoped K12 check.
#
# Student posture is an OU subtree, not a tenant-wide property. A check that
# assesses student posture must be TOLD which OUs hold students (-StudentOU);
# when it is not told, it reports Not Assessed. It never silently assesses the
# whole tenant as if that were the student population.

function ConvertTo-GuerrillaStudentOuList {
    <#
    .SYNOPSIS
        Normalizes a -StudentOU argument into a canonical, deduplicated, sorted list.
    .DESCRIPTION
        Trims entries, drops blanks, deduplicates case-insensitively, and sorts
        ordinally so the same scope always produces the same list (the list is
        part of the run's comparison-series identity). With -EnsureLeadingSlash
        (GWS OU paths), a missing leading '/' is added and a trailing '/' is
        stripped (except on the root itself). AD DNs are passed through as
        trimmed strings.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][string[]]$StudentOu,
        [switch]$EnsureLeadingSlash
    )
    $normalized = foreach ($entry in @($StudentOu)) {
        $s = "$entry".Trim()
        if (-not $s) { continue }
        if ($EnsureLeadingSlash) {
            if (-not $s.StartsWith('/')) { $s = "/$s" }
            if ($s.Length -gt 1) { $s = $s.TrimEnd('/') }
        }
        $s
    }
    @($normalized | Sort-Object -Unique)
}

function Get-GuerrillaOuScopeString {
    <#
    .SYNOPSIS
        Canonical OU-scope identity string for run-history series matching.
    .DESCRIPTION
        A run's comparison series must include its OU scope: a student-scoped
        run diffed against a whole-tenant run reports scope differences as
        drift, which is false drift. This helper renders (targetOu, studentOus)
        canonically, with the defaults old records imply when the fields are
        absent (targetOu '/', no student OUs), so pre-scope whole-tenant
        history keeps matching whole-tenant runs and any scoped run starts its
        own series.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$TargetOu,
        [AllowNull()][AllowEmptyCollection()][string[]]$StudentOu
    )
    $t = "$TargetOu".Trim()
    if (-not $t) { $t = '/' }
    $s = @(ConvertTo-GuerrillaStudentOuList -StudentOu $StudentOu) -join ','
    "targetOu=$t;studentOus=$s"
}

function Get-StudentScopeNotAssessed {
    <#
    .SYNOPSIS
        Returns the honest Not Assessed finding when an OU-scoped check has no
        student OU scope to work with; $null when the scope is usable.
    .DESCRIPTION
        Input absence renders as Not Assessed, never as a fabricated PASS and
        never as a silent whole-tenant assessment. Call this FIRST in every
        OU-scoped check.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$CheckDefinition,
        [Parameter(Mandatory)][hashtable]$AuditData
    )
    if (@($AuditData.StudentOUs).Count -eq 0 -or -not ($AuditData.StudentOUs | Where-Object { "$_".Trim() })) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
            -CurrentValue ('Not Assessed: no student OU scope provided; this check requires it. ' +
                'Pass -StudentOU with the organizational unit path(s) that contain student accounts ' +
                '(or set the Student OUs field in Show-Guerrilla). This control was not evaluated; ' +
                'absence of evidence is not compliance.') `
            -Details @{
                NotAssessed  = $true
                MissingInput = 'StudentOU'
            }
    }
    return $null
}

function New-StudentOuAbsentSkip {
    <#
    .SYNOPSIS
        The Not Assessed finding for one named student OU that is not present
        in the tenant's collected OU tree (typo, renamed OU, wrong tenant).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$CheckDefinition,
        [Parameter(Mandatory)][string]$OrgUnitPath
    )
    New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -OrgUnitPath $OrgUnitPath `
        -CurrentValue ("Not Assessed: student OU '$OrgUnitPath' was not found in the tenant's OU tree. " +
            'Check the path for typos or renames. This control was not evaluated for that OU; ' +
            'absence of evidence is not compliance.') `
        -Details @{
            NotAssessed = $true
            MissingOu   = $OrgUnitPath
        }
}

function Test-GwsOrgUnitPresent {
    <#
    .SYNOPSIS
        Three-way answer for "does this OU path exist in the collected OU tree?"
    .DESCRIPTION
        $true   the OU path is in $AuditData.Tenant.OrgUnits
        $false  the tree was collected and the path is not in it
        $null   the tree is unavailable (collection failed or never ran), so
                presence is UNKNOWN. The caller must go Not Assessed, not guess.
        The root '/' is always present when the tree is available (orgunits.list
        does not return the root node itself).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$AuditData,
        [Parameter(Mandatory)][string]$OrgUnitPath
    )
    $errors = $AuditData.Errors
    if ($errors -is [System.Collections.IDictionary] -and $errors.Contains('OrgUnits')) { return $null }
    $tree = $AuditData.Tenant.OrgUnits
    if ($null -eq $tree) { return $null }
    if ($OrgUnitPath -eq '/') { return $true }
    foreach ($ou in @($tree)) {
        if ("$($ou.orgUnitPath)" -eq $OrgUnitPath) { return $true }
    }
    return $false
}

function Test-GwsValueHasField {
    <#
    .SYNOPSIS
        Shape-immune "does this value object carry this field": live collector
        objects are PSCustomObjects, fixture data may be hashtables. Both count.
    #>
    [CmdletBinding()]
    param($Object, [Parameter(Mandatory)][string]$Field)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return [bool]$Object.Contains($Field) }
    return $Object.PSObject.Properties.Name -contains $Field
}

function Resolve-GwsStudentOuPolicy {
    <#
    .SYNOPSIS
        Resolves the EFFECTIVE Cloud Identity policy value for one specific OU,
        by nearest-ancestor, from the tenant-wide policies.list data.
    .DESCRIPTION
        policies.list returns one policy per (setting type, targeted OU/group);
        each carries policyQuery naming its target. The effective setting for an
        OU is the policy on its nearest ancestor (including itself). This walks
        the OU's ancestor chain from deepest to shallowest and returns the first
        match; a policy whose target OU id cannot be mapped to a collected OU
        path is the customer-root default (orgunits.list does not return the
        root node), used when no ancestor carries a policy. At the same level an
        ADMIN-authored policy wins over the SYSTEM default.

        Returns $null when the Policy API was unavailable (caller SKIPs), else:
          Found         a policy of this type resolved for this OU
          Value         the requested field value (or whole value object without -Field)
          SourceOuPath  which OU the winning policy targets ('(root)' for the default)
          Inherited     the winning policy targets an ancestor, not the OU itself
          AdminAuthored ADMIN-authored (vs the SYSTEM default)
          GroupOverride a group-targeted policy of this type exists in the
                        tenant; group membership cannot be resolved to an OU, so
                        some students may receive a different value. Callers
                        surface this in evidence.
    #>
    [CmdletBinding()]
    param(
        $Policies,
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$OrgUnitPath,
        [AllowNull()]$OrgUnits,
        [string]$Field
    )

    if (-not $Policies -or -not $Policies.ByType) { return $null }

    $candidates = @($Policies.ByType[$Type])
    $result = [pscustomobject]@{
        Found         = $false
        Value         = $null
        SourceOuPath  = $null
        Inherited     = $false
        AdminAuthored = $false
        GroupOverride = $false
    }
    if ($candidates.Count -eq 0) { return $result }

    # Map collected OU ids to paths ('id:03x...' and 'orgUnits/03x...' both -> bare id).
    $idToPath = @{}
    foreach ($ou in @($OrgUnits)) {
        if ($null -eq $ou) { continue }
        $bare = "$($ou.orgUnitId)" -replace '^(id:|orgUnits/)', ''
        if ($bare) { $idToPath[$bare] = "$($ou.orgUnitPath)" }
    }

    # Ancestor chain, deepest first: '/Students/HS' -> '/Students/HS', '/Students'.
    $chain = [System.Collections.Generic.List[string]]::new()
    if ($OrgUnitPath -ne '/') {
        $parts = @($OrgUnitPath.Trim('/') -split '/')
        for ($i = $parts.Count; $i -ge 1; $i--) {
            $chain.Add('/' + (($parts[0..($i - 1)]) -join '/'))
        }
    }

    # Attribute each candidate policy to an OU path (or the root default).
    $attributed = foreach ($p in $candidates) {
        if ($null -eq $p) { continue }
        $q = $p.policyQuery
        if ($q -and (Test-GwsValueHasField $q 'group') -and "$($q.group)") {
            $result.GroupOverride = $true
            continue
        }
        $ouRef = if ($q) { "$($q.orgUnit)" -replace '^orgUnits/', '' } else { '' }
        $path = if ($ouRef -and $idToPath.ContainsKey($ouRef)) { $idToPath[$ouRef] } else { '(root)' }
        $sortOrder = -1.0
        if ($q -and (Test-GwsValueHasField $q 'sortOrder') -and $null -ne $q.sortOrder) {
            $sortOrder = [double]$q.sortOrder
        }
        [pscustomobject]@{ Policy = $p; Path = $path; Admin = ("$($p.type)" -eq 'ADMIN'); SortOrder = $sortOrder }
    }
    $attributed = @($attributed)

    # Precedence order: nearest ancestor first, root default last; within one OU
    # the highest sortOrder wins (the API's documented tiebreak), then ADMIN over
    # SYSTEM. Field values can be SPLIT across policies (the API's merge
    # semantics), so -Field extraction walks the whole precedence list and takes
    # the field from the first policy that carries it.
    $precedence = [System.Collections.Generic.List[object]]::new()
    foreach ($ancestor in $chain) {
        foreach ($c in @($attributed | Where-Object { $_.Path -eq $ancestor } |
                Sort-Object @{ e = { $_.SortOrder }; Descending = $true }, @{ e = { -not $_.Admin } })) {
            $precedence.Add($c)
        }
    }
    foreach ($c in @($attributed | Where-Object { $_.Path -eq '(root)' } |
            Sort-Object @{ e = { $_.SortOrder }; Descending = $true }, @{ e = { -not $_.Admin } })) {
        $precedence.Add($c)
    }
    if ($precedence.Count -eq 0) { return $result }

    $winner = $null
    $value = $null
    if ($PSBoundParameters.ContainsKey('Field') -and $Field) {
        foreach ($c in $precedence) {
            $v = $c.Policy.setting.value
            if (Test-GwsValueHasField $v $Field) {
                $winner = $c
                $value = $v.$Field
                break
            }
        }
        # No policy carries the field: unresolved, never invent a PASS/FAIL.
        if (-not $winner) { return $result }
    } else {
        $winner = $precedence[0]
        $value = $winner.Policy.setting.value
    }

    $result.Found = $true
    $result.Value = $value
    $result.SourceOuPath = $winner.Path
    $result.Inherited = ($winner.Path -ne $OrgUnitPath)
    $result.AdminAuthored = $winner.Admin
    return $result
}
