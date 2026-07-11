# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Admin Management, phase 3): verifies the two converted ADMIN checks
# (008/009) read real Cloud Identity policy values from the single directory.* policy type
# (directory.workspace_resource_type_visibility) and grade correctly — WARN-on-exposure,
# weakest-OU-wins, and the unavailable -> SKIP path. Also confirms the ADMIN check count is 13.
# Run: pwsh -File Tests/verify-gws1-admin-p3.ps1

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

    $T = 'directory.workspace_resource_type_visibility'
    $r = @{}

    # ── ADMIN-008: Directory Sharing Settings -> domainSharedContacts (WARN if visible) ──
    $r.A008_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ $T = @{ domainSharedContacts = $true } }) }) 'Test-FortificationADMIN008'   # visible -> WARN
    $r.A008_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ $T = @{ domainSharedContacts = $false } }) }) 'Test-FortificationADMIN008'  # restricted -> PASS
    $r.A008_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ $T = @(@{ domainSharedContacts = $false }, @{ domainSharedContacts = $true }) }) }) 'Test-FortificationADMIN008'  # weakest OU visible -> WARN

    # ── ADMIN-009: User Profile Visibility -> googleGroups (WARN if visible) ──
    $r.A009_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ $T = @{ googleGroups = $true } }) }) 'Test-FortificationADMIN009'   # visible -> WARN
    $r.A009_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ $T = @{ googleGroups = $false } }) }) 'Test-FortificationADMIN009'  # restricted -> PASS
    $r.A009_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ $T = @(@{ googleGroups = $false }, @{ googleGroups = $true }) }) }) 'Test-FortificationADMIN009'  # weakest OU visible -> WARN

    # ── Unavailable API -> SKIP ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.A008_skip = St $none 'Test-FortificationADMIN008'
    $r.A009_skip = St $none 'Test-FortificationADMIN009'

    # ── Type/field absent -> SKIP (never invent PASS/FAIL from a missing value) ──
    $other = @{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }
    $r.A008_absent = St $other 'Test-FortificationADMIN008'
    $r.A009_absent = St $other 'Test-FortificationADMIN009'

    # ── ADMIN check count must remain 13 ──
    $r.AdminCount = (Get-AuditCategoryDefinitions -Category 'AdminManagementChecks').checks.Count

    $r
}

Add-R 'ADMIN-008 domainSharedContacts visible -> WARN'   ($out.A008_warn -eq 'WARN') ("got=$($out.A008_warn)")
Add-R 'ADMIN-008 domainSharedContacts restricted -> PASS' ($out.A008_pass -eq 'PASS') ("got=$($out.A008_pass)")
Add-R 'ADMIN-008 weakest OU (visible) -> WARN'            ($out.A008_weak -eq 'WARN') ("got=$($out.A008_weak)")
Add-R 'ADMIN-008 unavailable -> SKIP'                     ($out.A008_skip -eq 'SKIP') ("got=$($out.A008_skip)")
Add-R 'ADMIN-008 field absent -> SKIP'                    ($out.A008_absent -eq 'SKIP') ("got=$($out.A008_absent)")
Add-R 'ADMIN-009 googleGroups visible -> WARN'            ($out.A009_warn -eq 'WARN') ("got=$($out.A009_warn)")
Add-R 'ADMIN-009 googleGroups restricted -> PASS'        ($out.A009_pass -eq 'PASS') ("got=$($out.A009_pass)")
Add-R 'ADMIN-009 weakest OU (visible) -> WARN'           ($out.A009_weak -eq 'WARN') ("got=$($out.A009_weak)")
Add-R 'ADMIN-009 unavailable -> SKIP'                    ($out.A009_skip -eq 'SKIP') ("got=$($out.A009_skip)")
Add-R 'ADMIN-009 field absent -> SKIP'                   ($out.A009_absent -eq 'SKIP') ("got=$($out.A009_absent)")
Add-R 'ADMIN check count is 13'                          ($out.AdminCount -eq 13) ("got=$($out.AdminCount)")

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
