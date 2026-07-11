# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Authentication): verifies Resolve-GooglePolicyValue is immune to
# both return shapes (value-object and policy-object), and that the six converted AUTH checks
# (003/004/005/006/008/011) read real Cloud Identity policy values and grade correctly —
# including multi-OU "weakest wins" and the unavailable -> SKIP path.
# Run: pwsh -File Tests/verify-gws1-auth-checks.ps1

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

    # ── Shape immunity of the helper ──
    # Normal shape: Get-GooglePolicySetting yields the value object directly.
    $normal = New-Pol @{ 'security.password' = @{ minimumLength = 10 } }
    $r.ShapeNormal = @(Resolve-GooglePolicyValue -Policies $normal -Type 'security.password' -Field 'minimumLength')[0]
    # Policy shape: the "value" is itself a policy-shaped object (.setting.value) — must be unwrapped.
    $polShape = New-Pol @{ 'security.password' = ([PSCustomObject]@{ setting = [PSCustomObject]@{ value = [PSCustomObject]@{ minimumLength = 10 } } }) }
    $r.ShapePolicy = @(Resolve-GooglePolicyValue -Policies $polShape -Type 'security.password' -Field 'minimumLength')[0]
    # Unavailable vs absent.
    $r.Unavailable = ($null -eq (Resolve-GooglePolicyValue -Policies $null -Type 'security.password' -Field 'minimumLength'))
    $r.AbsentEmpty = (@(Resolve-GooglePolicyValue -Policies $normal -Type 'meet.safety_access' -Field 'x').Count -eq 0)
    # Duration parser.
    $r.Dur14d = (ConvertFrom-GoogleDurationSeconds '1209600s')
    $r.DurBad = ($null -eq (ConvertFrom-GoogleDurationSeconds 'banana'))

    # ── AUTH-003: 2SV method strength ──
    $r.A003_all  = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.two_step_verification_enforcement_factor' = @{ allowedSignInFactorSet = 'ALL' } }) }) 'Test-FortificationAUTH003'
    $r.A003_key  = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.two_step_verification_enforcement_factor' = @{ allowedSignInFactorSet = 'SECURITY_KEY' } }) }) 'Test-FortificationAUTH003'

    # ── AUTH-004: password min length (weakest of multiple OUs) ──
    $r.A004_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 14 } }) }) 'Test-FortificationAUTH004'
    $r.A004_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 8 } }) }) 'Test-FortificationAUTH004'
    $r.A004_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @(@{ minimumLength = 14 }, @{ minimumLength = 6 }) }) }) 'Test-FortificationAUTH004'  # weakest=6 -> FAIL

    # ── AUTH-005: password reuse ──
    $r.A005_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ allowReuse = $true } }) }) 'Test-FortificationAUTH005'
    $r.A005_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ allowReuse = $false } }) }) 'Test-FortificationAUTH005'

    # ── AUTH-006: session duration ──
    $r.A006_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.session_controls' = @{ webSessionDuration = '1209600s' } }) }) 'Test-FortificationAUTH006'  # 14d
    $r.A006_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.session_controls' = @{ webSessionDuration = '28800s' } }) }) 'Test-FortificationAUTH006'      # 8h

    # ── AUTH-008: less secure apps ──
    $r.A008_fail    = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.less_secure_apps' = @{ allowLessSecureApps = $true } }) }) 'Test-FortificationAUTH008'
    $r.A008_absent  = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }) 'Test-FortificationAUTH008'  # type absent -> PASS (deprecated)

    # ── AUTH-011: login challenges ──
    $r.A011_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.login_challenges' = @{ enableEmployeeIdChallenge = $false } }) }) 'Test-FortificationAUTH011'
    $r.A011_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.login_challenges' = @{ enableEmployeeIdChallenge = $true } }) }) 'Test-FortificationAUTH011'

    # ── Unavailable API -> SKIP (sampled across the converted checks) ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.Skip003 = St $none 'Test-FortificationAUTH003'
    $r.Skip004 = St $none 'Test-FortificationAUTH004'
    $r.Skip006 = St $none 'Test-FortificationAUTH006'

    $r
}

Add-R 'Helper immune to value-object shape'   ($out.ShapeNormal -eq 10) ("got=$($out.ShapeNormal)")
Add-R 'Helper immune to policy-object shape'  ($out.ShapePolicy -eq 10) ("got=$($out.ShapePolicy)")
Add-R 'Unavailable API -> $null'              ($out.Unavailable) ''
Add-R 'Absent type -> empty array'            ($out.AbsentEmpty) ''
Add-R 'Duration "1209600s" -> 1209600'        ($out.Dur14d -eq 1209600) ("got=$($out.Dur14d)")
Add-R 'Duration non-numeric -> $null'         ($out.DurBad) ''
Add-R 'AUTH-003 ALL factors -> FAIL'          ($out.A003_all -eq 'FAIL') ("got=$($out.A003_all)")
Add-R 'AUTH-003 security key -> PASS'         ($out.A003_key -eq 'PASS') ("got=$($out.A003_key)")
Add-R 'AUTH-004 len 14 -> PASS'               ($out.A004_pass -eq 'PASS') ("got=$($out.A004_pass)")
Add-R 'AUTH-004 len 8 -> WARN'                ($out.A004_warn -eq 'WARN') ("got=$($out.A004_warn)")
Add-R 'AUTH-004 weakest OU (6) -> FAIL'       ($out.A004_weak -eq 'FAIL') ("got=$($out.A004_weak)")
Add-R 'AUTH-005 reuse allowed -> FAIL'        ($out.A005_fail -eq 'FAIL') ("got=$($out.A005_fail)")
Add-R 'AUTH-005 reuse restricted -> PASS'     ($out.A005_pass -eq 'PASS') ("got=$($out.A005_pass)")
Add-R 'AUTH-006 14-day session -> FAIL'       ($out.A006_fail -eq 'FAIL') ("got=$($out.A006_fail)")
Add-R 'AUTH-006 8-hour session -> PASS'       ($out.A006_pass -eq 'PASS') ("got=$($out.A006_pass)")
Add-R 'AUTH-008 LSA allowed -> FAIL'          ($out.A008_fail -eq 'FAIL') ("got=$($out.A008_fail)")
Add-R 'AUTH-008 type absent -> PASS'          ($out.A008_absent -eq 'PASS') ("got=$($out.A008_absent)")
Add-R 'AUTH-011 challenge off -> WARN'        ($out.A011_warn -eq 'WARN') ("got=$($out.A011_warn)")
Add-R 'AUTH-011 challenge on -> PASS'         ($out.A011_pass -eq 'PASS') ("got=$($out.A011_pass)")
Add-R 'Unavailable -> SKIP (003/004/006)'     ($out.Skip003 -eq 'SKIP' -and $out.Skip004 -eq 'SKIP' -and $out.Skip006 -eq 'SKIP') ("$($out.Skip003)/$($out.Skip004)/$($out.Skip006)")

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
