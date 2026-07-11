# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (OAuth & API Security): verifies the three converted OAuth checks
# (001/006/007) read real Cloud Identity policy values and grade correctly — PASS on the
# secure enum, FAIL on the insecure enum, WARN on an unrecognized enum (never PASS on an
# unknown value), multi-OU "weakest wins", and the unavailable -> SKIP path.
# OAUTH-005 (unverified apps) and OAUTH-009 (service-account keys) have no Cloud Identity
# policy mapping and remain manual-verify; the real OAuthApps/DWD checks are untouched.
# Run: pwsh -File Tests/verify-gws1-oauth-checks.ps1

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
    $def = @{ id = 'OAUTH-XXX'; name = 'x'; severity = 'High'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $r = @{}

    # ── OAUTH-001: unconfigured third-party apps (api_controls.unconfigured_third_party_apps / accessLevel) ──
    $r.O001_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'api_controls.unconfigured_third_party_apps' = @{ accessLevel = 'BLOCKED' } }) }) 'Test-FortificationOAUTH001'
    $r.O001_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'api_controls.unconfigured_third_party_apps' = @{ accessLevel = 'ALLOW_ALL' } }) }) 'Test-FortificationOAUTH001'
    $r.O001_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'api_controls.unconfigured_third_party_apps' = @{ accessLevel = 'SOMETHING_NEW' } }) }) 'Test-FortificationOAUTH001'
    # Weakest-OU-wins: one OU blocked, one OU allow-all -> FAIL.
    $r.O001_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'api_controls.unconfigured_third_party_apps' = @(@{ accessLevel = 'BLOCKED' }, @{ accessLevel = 'ALLOW_ALL' }) }) }) 'Test-FortificationOAUTH001'

    # ── OAUTH-006: app-access request workflow (api_controls.app_approval_requests / allowedForAll) ──
    # CONFIRMED (live + Google docs): ENABLED/true = request-and-approve workflow on (governance
    # positive, access still admin-gated) -> PASS. DISABLED/unknown -> WARN.
    $r.O006_pass  = St (@{ CloudIdentityPolicies = (New-Pol @{ 'api_controls.app_approval_requests' = @{ allowedForAll = 'ENABLED' } }) }) 'Test-FortificationOAUTH006'
    $r.O006_passT = St (@{ CloudIdentityPolicies = (New-Pol @{ 'api_controls.app_approval_requests' = @{ allowedForAll = $true } }) }) 'Test-FortificationOAUTH006'
    $r.O006_warn  = St (@{ CloudIdentityPolicies = (New-Pol @{ 'api_controls.app_approval_requests' = @{ allowedForAll = 'MAYBE' } }) }) 'Test-FortificationOAUTH006'

    # ── OAUTH-007: marketplace install restrictions (workspace_marketplace.apps_access_options / accessLevel) ──
    $r.O007_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'workspace_marketplace.apps_access_options' = @{ accessLevel = 'ALLOW_LISTED_APPS' } }) }) 'Test-FortificationOAUTH007'
    $r.O007_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'workspace_marketplace.apps_access_options' = @{ accessLevel = 'ALLOW_ALL' } }) }) 'Test-FortificationOAUTH007'
    $r.O007_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'workspace_marketplace.apps_access_options' = @{ accessLevel = 'FUTURE_ENUM' } }) }) 'Test-FortificationOAUTH007'

    # ── Type returned by API but absent for this tenant -> SKIP (not PASS/FAIL) ──
    $other = @{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }
    $r.O001_absent = St $other 'Test-FortificationOAUTH001'
    $r.O006_absent = St $other 'Test-FortificationOAUTH006'
    $r.O007_absent = St $other 'Test-FortificationOAUTH007'

    # ── Unavailable API -> SKIP ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.Skip001 = St $none 'Test-FortificationOAUTH001'
    $r.Skip006 = St $none 'Test-FortificationOAUTH006'
    $r.Skip007 = St $none 'Test-FortificationOAUTH007'

    # ── Untouched checks remain manual-verify (WARN) and real checks still work ──
    $empty = @{}
    $r.O005_manual = St $empty 'Test-FortificationOAUTH005'   # unverified apps: still manual
    $r.O009_manual = St $empty 'Test-FortificationOAUTH009'   # service account keys: still manual

    $r
}

Add-R 'OAUTH-001 blocked -> PASS'             ($out.O001_pass -eq 'PASS') ("got=$($out.O001_pass)")
Add-R 'OAUTH-001 allow-all -> FAIL'           ($out.O001_fail -eq 'FAIL') ("got=$($out.O001_fail)")
Add-R 'OAUTH-001 unknown enum -> WARN'        ($out.O001_warn -eq 'WARN') ("got=$($out.O001_warn)")
Add-R 'OAUTH-001 weakest OU -> FAIL'          ($out.O001_weak -eq 'FAIL') ("got=$($out.O001_weak)")
Add-R 'OAUTH-006 request workflow ENABLED -> PASS' ($out.O006_pass -eq 'PASS') ("got=$($out.O006_pass)")
Add-R 'OAUTH-006 allowedForAll=true -> PASS'       ($out.O006_passT -eq 'PASS') ("got=$($out.O006_passT)")
Add-R 'OAUTH-006 unrecognized value -> WARN'       ($out.O006_warn -eq 'WARN') ("got=$($out.O006_warn)")
Add-R 'OAUTH-007 allowlist -> PASS'           ($out.O007_pass -eq 'PASS') ("got=$($out.O007_pass)")
Add-R 'OAUTH-007 allow-all -> FAIL'           ($out.O007_fail -eq 'FAIL') ("got=$($out.O007_fail)")
Add-R 'OAUTH-007 unknown enum -> WARN'        ($out.O007_warn -eq 'WARN') ("got=$($out.O007_warn)")
Add-R 'OAUTH-001 type absent -> SKIP'         ($out.O001_absent -eq 'SKIP') ("got=$($out.O001_absent)")
Add-R 'OAUTH-006 type absent -> SKIP'         ($out.O006_absent -eq 'SKIP') ("got=$($out.O006_absent)")
Add-R 'OAUTH-007 type absent -> SKIP'         ($out.O007_absent -eq 'SKIP') ("got=$($out.O007_absent)")
Add-R 'Unavailable -> SKIP (001/006/007)'     ($out.Skip001 -eq 'SKIP' -and $out.Skip006 -eq 'SKIP' -and $out.Skip007 -eq 'SKIP') ("$($out.Skip001)/$($out.Skip006)/$($out.Skip007)")
Add-R 'OAUTH-005 left manual -> WARN'         ($out.O005_manual -eq 'WARN') ("got=$($out.O005_manual)")
Add-R 'OAUTH-009 left manual -> WARN'         ($out.O009_manual -eq 'WARN') ("got=$($out.O009_manual)")

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
