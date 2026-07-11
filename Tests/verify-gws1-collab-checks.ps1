# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Collaboration): verifies the five converted COLLAB checks read real
# Cloud Identity policy values and grade correctly — including multi-OU "weakest wins", enum
# WARN-on-unknown, and the unavailable -> SKIP path.
#   COLLAB-001 meet.automatic_recording.enabled               (bool, weakest-OU-wins)
#   COLLAB-002 meet.meet_joining.allowedAudience              (enum)
#   COLLAB-003 meet.safety_domain.usersAllowedToJoin          (enum)
#   COLLAB-005 chat.chat_history.historyOnByDefault           (bool, weakest-OU-wins)
#   COLLAB-006 chat.chat_external_spaces.enabled              (bool, weakest-OU-wins)
# Run: pwsh -File Tests/verify-gws1-collab-checks.ps1

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
    $def = @{ id = 'COLLAB-XXX'; name = 'x'; severity = 'High'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $r = @{}

    # ── COLLAB-001: Meet automatic recording (bool, weakest-OU-wins) ──
    $r.C001_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.automatic_recording' = @{ enabled = $true } }) }) 'Test-FortificationCOLLAB001'
    $r.C001_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.automatic_recording' = @{ enabled = $false } }) }) 'Test-FortificationCOLLAB001'
    $r.C001_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.automatic_recording' = @(@{ enabled = $false }, @{ enabled = $true }) }) }) 'Test-FortificationCOLLAB001'  # any-on -> FAIL

    # ── COLLAB-002: Meet join audience (enum) ──
    $r.C002_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.meet_joining' = @{ allowedAudience = 'ALL' } }) }) 'Test-FortificationCOLLAB002'
    $r.C002_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.meet_joining' = @{ allowedAudience = 'TRUSTED' } }) }) 'Test-FortificationCOLLAB002'
    $r.C002_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.meet_joining' = @{ allowedAudience = 'SOMETHING_NEW' } }) }) 'Test-FortificationCOLLAB002'  # unknown -> WARN

    # ── COLLAB-003: Meet anonymous join (enum) ──
    $r.C003_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_domain' = @{ usersAllowedToJoin = 'ANONYMOUS' } }) }) 'Test-FortificationCOLLAB003'
    $r.C003_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_domain' = @{ usersAllowedToJoin = 'LOGGED_IN' } }) }) 'Test-FortificationCOLLAB003'
    $r.C003_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'meet.safety_domain' = @{ usersAllowedToJoin = 'SOMETHING_NEW' } }) }) 'Test-FortificationCOLLAB003'  # unknown -> WARN

    # ── COLLAB-005: Chat history (bool, weakest-OU-wins) ──
    $r.C005_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.chat_history' = @{ historyOnByDefault = $false } }) }) 'Test-FortificationCOLLAB005'
    $r.C005_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.chat_history' = @{ historyOnByDefault = $true } }) }) 'Test-FortificationCOLLAB005'
    $r.C005_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.chat_history' = @(@{ historyOnByDefault = $true }, @{ historyOnByDefault = $false }) }) }) 'Test-FortificationCOLLAB005'  # any-off -> FAIL

    # ── COLLAB-006: Chat external spaces (bool, weakest-OU-wins) ──
    $r.C006_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.chat_external_spaces' = @{ enabled = $true } }) }) 'Test-FortificationCOLLAB006'
    $r.C006_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.chat_external_spaces' = @{ enabled = $false } }) }) 'Test-FortificationCOLLAB006'

    # ── Absent type -> SKIP (API available but no policy of this type returned) ──
    $other = @{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }
    $r.C001_absent = St $other 'Test-FortificationCOLLAB001'
    $r.C006_absent = St $other 'Test-FortificationCOLLAB006'

    # ── Unavailable API -> SKIP (sampled across the converted checks) ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.Skip001 = St $none 'Test-FortificationCOLLAB001'
    $r.Skip002 = St $none 'Test-FortificationCOLLAB002'
    $r.Skip003 = St $none 'Test-FortificationCOLLAB003'
    $r.Skip005 = St $none 'Test-FortificationCOLLAB005'
    $r.Skip006 = St $none 'Test-FortificationCOLLAB006'

    $r
}

Add-R 'COLLAB-001 recording on -> FAIL'        ($out.C001_fail -eq 'FAIL') ("got=$($out.C001_fail)")
Add-R 'COLLAB-001 recording off -> PASS'       ($out.C001_pass -eq 'PASS') ("got=$($out.C001_pass)")
Add-R 'COLLAB-001 weakest OU (on) -> FAIL'     ($out.C001_weak -eq 'FAIL') ("got=$($out.C001_weak)")
Add-R 'COLLAB-002 ALL audience -> FAIL'        ($out.C002_fail -eq 'FAIL') ("got=$($out.C002_fail)")
Add-R 'COLLAB-002 TRUSTED -> PASS'             ($out.C002_pass -eq 'PASS') ("got=$($out.C002_pass)")
Add-R 'COLLAB-002 unknown enum -> WARN'        ($out.C002_warn -eq 'WARN') ("got=$($out.C002_warn)")
Add-R 'COLLAB-003 anonymous -> FAIL'           ($out.C003_fail -eq 'FAIL') ("got=$($out.C003_fail)")
Add-R 'COLLAB-003 LOGGED_IN -> PASS'           ($out.C003_pass -eq 'PASS') ("got=$($out.C003_pass)")
Add-R 'COLLAB-003 unknown enum -> WARN'        ($out.C003_warn -eq 'WARN') ("got=$($out.C003_warn)")
Add-R 'COLLAB-005 history off -> FAIL'         ($out.C005_fail -eq 'FAIL') ("got=$($out.C005_fail)")
Add-R 'COLLAB-005 history on -> PASS'          ($out.C005_pass -eq 'PASS') ("got=$($out.C005_pass)")
Add-R 'COLLAB-005 weakest OU (off) -> FAIL'    ($out.C005_weak -eq 'FAIL') ("got=$($out.C005_weak)")
Add-R 'COLLAB-006 external spaces on -> FAIL'  ($out.C006_fail -eq 'FAIL') ("got=$($out.C006_fail)")
Add-R 'COLLAB-006 external spaces off -> PASS' ($out.C006_pass -eq 'PASS') ("got=$($out.C006_pass)")
Add-R 'COLLAB-001 absent type -> SKIP'         ($out.C001_absent -eq 'SKIP') ("got=$($out.C001_absent)")
Add-R 'COLLAB-006 absent type -> SKIP'         ($out.C006_absent -eq 'SKIP') ("got=$($out.C006_absent)")
Add-R 'Unavailable -> SKIP (001/002/003/005/006)' ($out.Skip001 -eq 'SKIP' -and $out.Skip002 -eq 'SKIP' -and $out.Skip003 -eq 'SKIP' -and $out.Skip005 -eq 'SKIP' -and $out.Skip006 -eq 'SKIP') ("$($out.Skip001)/$($out.Skip002)/$($out.Skip003)/$($out.Skip005)/$($out.Skip006)")

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
