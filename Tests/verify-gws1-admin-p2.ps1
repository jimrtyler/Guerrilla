# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Admin Management, part 2): verifies the two converted ADMIN checks
# (010/011) read real Cloud Identity policy values from groups_for_business.groups_sharing and
# grade correctly — covering PASS, FAIL, the unknown-enum -> WARN path (ADMIN-011), multi-OU
# "weakest wins", and the unavailable -> SKIP path.
# Run: pwsh -File Tests/verify-gws1-admin-p2.ps1

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
    $def = @{ id = 'ADMIN-XXX'; name = 'x'; severity = 'High'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $gs = 'groups_for_business.groups_sharing'
    $r = @{}

    # ── ADMIN-010: external membership (ownersCanAllowExternalMembers bool) ──
    $r.A010_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @{ ownersCanAllowExternalMembers = $false } }) }) 'Test-FortificationADMIN010'
    $r.A010_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @{ ownersCanAllowExternalMembers = $true } }) }) 'Test-FortificationADMIN010'
    # Multi-OU weakest-wins: one OU disallows, one allows -> FAIL.
    $r.A010_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @(@{ ownersCanAllowExternalMembers = $false }, @{ ownersCanAllowExternalMembers = $true }) }) }) 'Test-FortificationADMIN010'

    # ── ADMIN-011: group creation access level (createGroupsAccessLevel enum) ──
    $r.A011_pass    = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @{ createGroupsAccessLevel = 'ADMIN_ONLY' } }) }) 'Test-FortificationADMIN011'
    $r.A011_fail    = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @{ createGroupsAccessLevel = 'ANYONE_CAN_CREATE' } }) }) 'Test-FortificationADMIN011'
    $r.A011_unknown = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @{ createGroupsAccessLevel = 'SOME_FUTURE_VALUE' } }) }) 'Test-FortificationADMIN011'
    # Multi-OU weakest-wins: one admin-restricted OU, one open OU -> FAIL (most open decides).
    $r.A011_weak    = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @(@{ createGroupsAccessLevel = 'ADMIN_ONLY' }, @{ createGroupsAccessLevel = 'USERS_IN_DOMAIN' }) }) }) 'Test-FortificationADMIN011'
    # Case-insensitive open spelling.
    $r.A011_ci      = St (@{ CloudIdentityPolicies = (New-Pol @{ $gs = @{ createGroupsAccessLevel = 'anyone' } }) }) 'Test-FortificationADMIN011'

    # ── Unavailable API -> SKIP ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.Skip010 = St $none 'Test-FortificationADMIN010'
    $r.Skip011 = St $none 'Test-FortificationADMIN011'

    $r
}

Add-R 'ADMIN-010 external disallowed -> PASS'   ($out.A010_pass -eq 'PASS') ("got=$($out.A010_pass)")
Add-R 'ADMIN-010 external allowed -> FAIL'       ($out.A010_fail -eq 'FAIL') ("got=$($out.A010_fail)")
Add-R 'ADMIN-010 weakest OU (allowed) -> FAIL'   ($out.A010_weak -eq 'FAIL') ("got=$($out.A010_weak)")
Add-R 'ADMIN-011 admin-restricted -> PASS'       ($out.A011_pass -eq 'PASS') ("got=$($out.A011_pass)")
Add-R 'ADMIN-011 open creation -> FAIL'          ($out.A011_fail -eq 'FAIL') ("got=$($out.A011_fail)")
Add-R 'ADMIN-011 unknown enum -> WARN'           ($out.A011_unknown -eq 'WARN') ("got=$($out.A011_unknown)")
Add-R 'ADMIN-011 weakest OU (open) -> FAIL'      ($out.A011_weak -eq 'FAIL') ("got=$($out.A011_weak)")
Add-R 'ADMIN-011 open (case-insensitive) -> FAIL' ($out.A011_ci -eq 'FAIL') ("got=$($out.A011_ci)")
Add-R 'Unavailable -> SKIP (010/011)'            ($out.Skip010 -eq 'SKIP' -and $out.Skip011 -eq 'SKIP') ("$($out.Skip010)/$($out.Skip011)")

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
