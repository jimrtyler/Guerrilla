# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Collaboration, part 2): verifies the two policy-primary /
# OrgUnitPolicies-fallback conversions — COLLAB-004 (Chat External Communication) and
# COLLAB-008 (Calendar External Sharing) — read real Cloud Identity policy values and grade
# correctly: PASS, FAIL, unknown-enum -> WARN, and the policy-unavailable -> OrgUnitPolicies
# fallback / SKIP path (must not throw).
# Run: pwsh -File Tests/verify-gws1-collab-p2.ps1

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

    # ── COLLAB-004: Chat external communication (policy primary) ──
    # PASS: external chat disabled.
    $r.C004_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.external_chat_restriction' = @{ allowExternalChat = $false; externalChatRestriction = 'NO_RESTRICTION' } }) }) 'Test-FortificationCOLLAB004'
    # FAIL: external chat allowed AND no restriction.
    $r.C004_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.external_chat_restriction' = @{ allowExternalChat = $true; externalChatRestriction = 'NO_RESTRICTION' } }) }) 'Test-FortificationCOLLAB004'
    # WARN: external chat allowed but restricted (trusted-domains / unrecognized restriction).
    $r.C004_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.external_chat_restriction' = @{ allowExternalChat = $true; externalChatRestriction = 'TRUSTED_DOMAINS' } }) }) 'Test-FortificationCOLLAB004'
    # weakest-OU-wins: one OU open -> FAIL even though another OU is disabled.
    $r.C004_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'chat.external_chat_restriction' = @(@{ allowExternalChat = $false; externalChatRestriction = 'ALL' }, @{ allowExternalChat = $true; externalChatRestriction = 'UNRESTRICTED' }) }) }) 'Test-FortificationCOLLAB004'
    # Policy unavailable -> OrgUnitPolicies fallback (FAIL when external chat enabled).
    $r.C004_fb_fail = St (@{ CloudIdentityPolicies = $null; OrgUnitPolicies = @{ '/' = [PSCustomObject]@{ chatExternalEnabled = $true } } }) 'Test-FortificationCOLLAB004'
    # Policy unavailable AND no OrgUnitPolicies -> reaches fallback's manual-verify (WARN), no throw.
    $r.C004_skip = St (@{ CloudIdentityPolicies = $null; OrgUnitPolicies = @{} }) 'Test-FortificationCOLLAB004'

    # ── COLLAB-008: Calendar external sharing (policy primary) ──
    # PASS: limited sharing.
    $r.C008_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'calendar.primary_calendar_max_allowed_external_sharing' = @{ maxAllowedExternalSharing = 'FREE_BUSY_ONLY' } }) }) 'Test-FortificationCOLLAB008'
    # FAIL: permissive (shares all info).
    $r.C008_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'calendar.primary_calendar_max_allowed_external_sharing' = @{ maxAllowedExternalSharing = 'READ_WRITE_ACCESS' } }) }) 'Test-FortificationCOLLAB008'
    # WARN: unrecognized enum.
    $r.C008_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'calendar.primary_calendar_max_allowed_external_sharing' = @{ maxAllowedExternalSharing = 'SOME_FUTURE_VALUE' } }) }) 'Test-FortificationCOLLAB008'
    # weakest-OU-wins: one permissive OU -> FAIL.
    $r.C008_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'calendar.primary_calendar_max_allowed_external_sharing' = @(@{ maxAllowedExternalSharing = 'NONE' }, @{ maxAllowedExternalSharing = 'SHARE_ALL_INFO' }) }) }) 'Test-FortificationCOLLAB008'
    # CONFIRMED live enums: EXTERNAL_ALL_INFO_* -> FAIL; EXTERNAL_FREE_BUSY_ONLY -> PASS.
    $r.C008_real_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'calendar.primary_calendar_max_allowed_external_sharing' = @{ maxAllowedExternalSharing = 'EXTERNAL_ALL_INFO_READ_ONLY' } }) }) 'Test-FortificationCOLLAB008'
    $r.C008_real_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'calendar.primary_calendar_max_allowed_external_sharing' = @{ maxAllowedExternalSharing = 'EXTERNAL_FREE_BUSY_ONLY' } }) }) 'Test-FortificationCOLLAB008'
    # Policy unavailable -> OrgUnitPolicies fallback (FAIL on READ_WRITE).
    $r.C008_fb_fail = St (@{ CloudIdentityPolicies = $null; OrgUnitPolicies = @{ '/' = [PSCustomObject]@{ calendarExternalSharing = 'READ_WRITE' } } }) 'Test-FortificationCOLLAB008'
    # Policy unavailable AND no OrgUnitPolicies -> reaches fallback's manual-verify (WARN), no throw.
    $r.C008_skip = St (@{ CloudIdentityPolicies = $null; OrgUnitPolicies = @{} }) 'Test-FortificationCOLLAB008'

    $r
}

Add-R 'COLLAB-004 external chat disabled -> PASS'        ($out.C004_pass -eq 'PASS') ("got=$($out.C004_pass)")
Add-R 'COLLAB-004 allowed + no restriction -> FAIL'      ($out.C004_fail -eq 'FAIL') ("got=$($out.C004_fail)")
Add-R 'COLLAB-004 allowed but restricted -> WARN'        ($out.C004_warn -eq 'WARN') ("got=$($out.C004_warn)")
Add-R 'COLLAB-004 weakest OU (open) -> FAIL'             ($out.C004_weak -eq 'FAIL') ("got=$($out.C004_weak)")
Add-R 'COLLAB-004 no policy -> OrgUnitPolicies FAIL'     ($out.C004_fb_fail -eq 'FAIL') ("got=$($out.C004_fb_fail)")
Add-R 'COLLAB-004 no policy + no OUP -> WARN (no throw)' ($out.C004_skip -eq 'WARN') ("got=$($out.C004_skip)")
Add-R 'COLLAB-008 limited sharing -> PASS'               ($out.C008_pass -eq 'PASS') ("got=$($out.C008_pass)")
Add-R 'COLLAB-008 permissive sharing -> FAIL'            ($out.C008_fail -eq 'FAIL') ("got=$($out.C008_fail)")
Add-R 'COLLAB-008 unknown enum -> WARN'                  ($out.C008_warn -eq 'WARN') ("got=$($out.C008_warn)")
Add-R 'COLLAB-008 weakest OU (permissive) -> FAIL'       ($out.C008_weak -eq 'FAIL') ("got=$($out.C008_weak)")
Add-R 'COLLAB-008 EXTERNAL_ALL_INFO_READ_ONLY -> FAIL'   ($out.C008_real_fail -eq 'FAIL') ("got=$($out.C008_real_fail)")
Add-R 'COLLAB-008 EXTERNAL_FREE_BUSY_ONLY -> PASS'       ($out.C008_real_pass -eq 'PASS') ("got=$($out.C008_real_pass)")
Add-R 'COLLAB-008 no policy -> OrgUnitPolicies FAIL'     ($out.C008_fb_fail -eq 'FAIL') ("got=$($out.C008_fb_fail)")
Add-R 'COLLAB-008 no policy + no OUP -> WARN (no throw)' ($out.C008_skip -eq 'WARN') ("got=$($out.C008_skip)")

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
