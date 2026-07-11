# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 phase 3 (Authentication): verifies the four net-new converted AUTH checks
# (014/015/016/017) read real Cloud Identity policy values and grade correctly —
# secure case, insecure case, and the unavailable -> SKIP path. AUTH-015 also covers
# a long-grace WARN and a short-grace PASS.
# Run: pwsh -File Tests/verify-gws1-auth-p3.ps1

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
    $def = @{ id = 'AUTH-XXX'; name = 'x'; severity = 'High'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $r = @{}
    $none = @{ CloudIdentityPolicies = $null }

    # ── AUTH-014: 2SV enrollment allowed (true=GOOD; weakest-OU-wins) ──
    $r.A014_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.two_step_verification_enrollment' = @{ allowEnrollment = $true } }) }) 'Test-FortificationAUTH014'
    $r.A014_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.two_step_verification_enrollment' = @(@{ allowEnrollment = $true }, @{ allowEnrollment = $false }) }) }) 'Test-FortificationAUTH014'
    $r.A014_skip = St $none 'Test-FortificationAUTH014'

    # ── AUTH-015: 2SV enrollment grace period (longest OU; <=168h PASS) ──
    $r.A015_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.two_step_verification_grace_period' = @{ enrollmentGracePeriod = '604800s' } }) }) 'Test-FortificationAUTH015'   # 7d -> PASS
    $r.A015_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.two_step_verification_grace_period' = @{ enrollmentGracePeriod = '1209600s' } }) }) 'Test-FortificationAUTH015'  # 14d -> WARN
    $r.A015_skip = St $none 'Test-FortificationAUTH015'

    # ── AUTH-016: advanced protection self-enrollment (true=GOOD; weakest-OU-wins) ──
    $r.A016_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.advanced_protection_program' = @{ enableAdvancedProtectionSelfEnrollment = $true } }) }) 'Test-FortificationAUTH016'
    $r.A016_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.advanced_protection_program' = @{ enableAdvancedProtectionSelfEnrollment = $false } }) }) 'Test-FortificationAUTH016'
    $r.A016_skip = St $none 'Test-FortificationAUTH016'

    # ── AUTH-017: super admin self-recovery (true=BAD; weakest-OU-wins) ──
    $r.A017_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.super_admin_account_recovery' = @{ enableAccountRecovery = $false } }) }) 'Test-FortificationAUTH017'
    $r.A017_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.super_admin_account_recovery' = @(@{ enableAccountRecovery = $false }, @{ enableAccountRecovery = $true }) }) }) 'Test-FortificationAUTH017'
    $r.A017_skip = St $none 'Test-FortificationAUTH017'

    $r
}

Add-R 'AUTH-014 enrollment allowed -> PASS'        ($out.A014_pass -eq 'PASS') ("got=$($out.A014_pass)")
Add-R 'AUTH-014 disabled in an OU -> WARN'         ($out.A014_warn -eq 'WARN') ("got=$($out.A014_warn)")
Add-R 'AUTH-014 unavailable -> SKIP'               ($out.A014_skip -eq 'SKIP') ("got=$($out.A014_skip)")
Add-R 'AUTH-015 7-day grace -> PASS'               ($out.A015_pass -eq 'PASS') ("got=$($out.A015_pass)")
Add-R 'AUTH-015 14-day grace -> WARN'              ($out.A015_warn -eq 'WARN') ("got=$($out.A015_warn)")
Add-R 'AUTH-015 unavailable -> SKIP'               ($out.A015_skip -eq 'SKIP') ("got=$($out.A015_skip)")
Add-R 'AUTH-016 self-enroll allowed -> PASS'       ($out.A016_pass -eq 'PASS') ("got=$($out.A016_pass)")
Add-R 'AUTH-016 self-enroll disabled -> WARN'      ($out.A016_warn -eq 'WARN') ("got=$($out.A016_warn)")
Add-R 'AUTH-016 unavailable -> SKIP'               ($out.A016_skip -eq 'SKIP') ("got=$($out.A016_skip)")
Add-R 'AUTH-017 self-recovery off -> PASS'         ($out.A017_pass -eq 'PASS') ("got=$($out.A017_pass)")
Add-R 'AUTH-017 self-recovery on in an OU -> FAIL' ($out.A017_fail -eq 'FAIL') ("got=$($out.A017_fail)")
Add-R 'AUTH-017 unavailable -> SKIP'               ($out.A017_skip -eq 'SKIP') ("got=$($out.A017_skip)")

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
