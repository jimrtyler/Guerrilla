# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Admin & User Management): verifies the one placeholder that maps
# to a real Cloud Identity policy type — ADMIN-012 (Groups for Business) via
# groups_for_business.service_status — grades correctly (DISABLED->PASS, ENABLED->WARN since
# granular sharing isn't in the policy API, unknown enum->WARN never PASS, weakest-OU-wins,
# unavailable->SKIP, type-absent->SKIP). ADMIN-008 (directory sharing), ADMIN-009 (profile
# visibility, both via directory.workspace_resource_type_visibility — see verify-gws1-admin-p3.ps1)
# and ADMIN-011 (group creation, via groups_for_business.groups_sharing — see
# verify-gws1-admin-p2.ps1) are all now policy-backed; with no policy data they SKIP.
# Run: pwsh -File Tests/verify-gws1-admin-checks.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$out = & $mod {
    # Build a CloudIdentityPolicies object: type -> array of value objects. Real policy values
    # are PSCustomObjects (ConvertFrom-Json), so cast hashtable fixtures to match.
    function New-Pol([hashtable]$map) {
        $byType = @{}
        foreach ($k in $map.Keys) {
            $lst = [System.Collections.Generic.List[object]]::new()
            foreach ($v in @($map[$k])) {
                $val = if ($v -is [hashtable]) { [PSCustomObject]$v } else { $v }
                $lst.Add([PSCustomObject]@{ setting = [PSCustomObject]@{ type = "settings/$k"; value = $val } })
            }
            $byType[$k] = $lst
        }
        [PSCustomObject]@{ All = @(); ByType = $byType; Count = 0 }
    }
    $def = @{ id = 'ADMIN-XXX'; name = 'x'; severity = 'Medium'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $r = @{}

    # ── Helper shape immunity (mirror of the auth test, on a groups value object) ──
    $normal = New-Pol @{ 'groups_for_business.service_status' = @{ serviceState = 'DISABLED' } }
    $r.ShapeNormal = @(Resolve-GooglePolicyValue -Policies $normal -Type 'groups_for_business.service_status' -Field 'serviceState')[0]
    $polShape = New-Pol @{ 'groups_for_business.service_status' = ([PSCustomObject]@{ setting = [PSCustomObject]@{ value = [PSCustomObject]@{ serviceState = 'DISABLED' } } }) }
    $r.ShapePolicy = @(Resolve-GooglePolicyValue -Policies $polShape -Type 'groups_for_business.service_status' -Field 'serviceState')[0]
    $r.Unavailable = ($null -eq (Resolve-GooglePolicyValue -Policies $null -Type 'groups_for_business.service_status' -Field 'serviceState'))

    # ── ADMIN-012: Groups for Business service status ──
    $r.A012_pass    = St (@{ CloudIdentityPolicies = (New-Pol @{ 'groups_for_business.service_status' = @{ serviceState = 'DISABLED' } }) }) 'Test-FortificationADMIN012'  # disabled -> PASS
    $r.A012_warn    = St (@{ CloudIdentityPolicies = (New-Pol @{ 'groups_for_business.service_status' = @{ serviceState = 'ENABLED' } }) }) 'Test-FortificationADMIN012'   # enabled -> WARN (granular not in API)
    $r.A012_weak    = St (@{ CloudIdentityPolicies = (New-Pol @{ 'groups_for_business.service_status' = @(@{ serviceState = 'DISABLED' }, @{ serviceState = 'ENABLED' }) }) }) 'Test-FortificationADMIN012'  # weakest (one enabled) -> WARN
    $r.A012_unknown = St (@{ CloudIdentityPolicies = (New-Pol @{ 'groups_for_business.service_status' = @{ serviceState = 'SOMETHING_NEW' } }) }) 'Test-FortificationADMIN012'  # unknown enum -> WARN, never PASS
    $r.A012_absent  = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }) 'Test-FortificationADMIN012'  # type absent -> SKIP
    $r.A012_skip    = St (@{ CloudIdentityPolicies = $null }) 'Test-FortificationADMIN012'  # API unavailable -> SKIP

    # ── Placeholders intentionally LEFT manual (no policy type in this category's bindings) ──
    # These take no AuditData and must stay WARN manual-verify so the check count is unchanged.
    $empty = @{}
    $r.A008 = St $empty 'Test-FortificationADMIN008'
    $r.A009 = St $empty 'Test-FortificationADMIN009'
    $r.A011 = St $empty 'Test-FortificationADMIN011'

    $r
}

Add-R 'Helper immune to value-object shape'      ($out.ShapeNormal -eq 'DISABLED') ("got=$($out.ShapeNormal)")
Add-R 'Helper immune to policy-object shape'     ($out.ShapePolicy -eq 'DISABLED') ("got=$($out.ShapePolicy)")
Add-R 'Unavailable API -> $null'                 ($out.Unavailable) ''
Add-R 'ADMIN-012 service DISABLED -> PASS'       ($out.A012_pass -eq 'PASS') ("got=$($out.A012_pass)")
Add-R 'ADMIN-012 service ENABLED -> WARN'        ($out.A012_warn -eq 'WARN') ("got=$($out.A012_warn)")
Add-R 'ADMIN-012 weakest OU (1 enabled) -> WARN' ($out.A012_weak -eq 'WARN') ("got=$($out.A012_weak)")
Add-R 'ADMIN-012 unknown enum -> WARN (no PASS)' ($out.A012_unknown -eq 'WARN') ("got=$($out.A012_unknown)")
Add-R 'ADMIN-012 type absent -> SKIP'            ($out.A012_absent -eq 'SKIP') ("got=$($out.A012_absent)")
Add-R 'ADMIN-012 API unavailable -> SKIP'        ($out.A012_skip -eq 'SKIP') ("got=$($out.A012_skip)")
Add-R 'ADMIN-008 now policy-backed, no data -> SKIP' ($out.A008 -eq 'SKIP') ("got=$($out.A008)")
Add-R 'ADMIN-009 now policy-backed, no data -> SKIP' ($out.A009 -eq 'SKIP') ("got=$($out.A009)")
Add-R 'ADMIN-011 now policy-backed, no data -> SKIP' ($out.A011 -eq 'SKIP') ("got=$($out.A011)")

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($r in $results) {
    $mark = if ($r.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($r.Name)"; if ($r.Detail) { $line += "  ($($r.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
