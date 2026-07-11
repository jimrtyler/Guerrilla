# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Logging/Alerting): verifies the two converted LOG checks
# (004 cloud-data-sharing, 005 system-defined alerts) read real Cloud Identity policy
# values and grade correctly — including the unavailable -> SKIP path. LOG-005 fixtures
# carry the .state field because real rule.system_defined_alerts value objects do.
# Run: pwsh -File Tests/verify-gws1-logging-checks.ps1

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
    $def = @{ id = 'LOG-XXX'; name = 'x'; severity = 'Medium'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $r = @{}

    # ── LOG-004: cloud data sharing (Takeout / data export proxy) ──
    $r.L004_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'cloud_sharing_options.cloud_data_sharing' = @{ sharingOptions = 'DISABLED' } }) }) 'Test-FortificationLOG004'
    $r.L004_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'cloud_sharing_options.cloud_data_sharing' = @{ sharingOptions = 'ENABLED' } }) }) 'Test-FortificationLOG004'
    $r.L004_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'cloud_sharing_options.cloud_data_sharing' = @{ sharingOptions = 'SOMETHING_NEW' } }) }) 'Test-FortificationLOG004'  # unknown enum -> WARN

    # ── LOG-005: system-defined alert rules (state-bearing value objects) ──
    $r.L005_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.system_defined_alerts' = @(
        @{ displayName = 'Suspicious login'; state = 'ACTIVE' },
        @{ displayName = 'Government attack';  state = 'INACTIVE' }) }) }) 'Test-FortificationLOG005'  # ≥1 ACTIVE -> PASS
    $r.L005_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.system_defined_alerts' = @(
        @{ displayName = 'Suspicious login'; state = 'INACTIVE' }) }) }) 'Test-FortificationLOG005'   # none ACTIVE, Medium sev -> WARN

    # ── LOG-005: none ACTIVE on a Critical-severity check -> FAIL ──
    $defCrit = @{ id = 'LOG-005'; name = 'x'; severity = 'Critical'; description = 'd' }
    $r.L005_critfail = (& 'Test-FortificationLOG005' -AuditData (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.system_defined_alerts' = @(
        @{ displayName = 'Suspicious login'; state = 'INACTIVE' }) }) }) -CheckDefinition $defCrit -OrgUnitPath '/').Status

    # ── Unavailable API -> SKIP ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.L004_skip = St $none 'Test-FortificationLOG004'
    $r.L005_skip = St $none 'Test-FortificationLOG005'

    # ── Type absent (API available, no policy of this type) -> SKIP ──
    $other = @{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }
    $r.L004_absent = St $other 'Test-FortificationLOG004'
    $r.L005_absent = St $other 'Test-FortificationLOG005'

    $r
}

Add-R 'LOG-004 sharing DISABLED -> PASS'   ($out.L004_pass -eq 'PASS') ("got=$($out.L004_pass)")
Add-R 'LOG-004 sharing ENABLED -> FAIL'    ($out.L004_fail -eq 'FAIL') ("got=$($out.L004_fail)")
Add-R 'LOG-004 unknown enum -> WARN'       ($out.L004_warn -eq 'WARN') ("got=$($out.L004_warn)")
Add-R 'LOG-005 >=1 ACTIVE alert -> PASS'   ($out.L005_pass -eq 'PASS') ("got=$($out.L005_pass)")
Add-R 'LOG-005 none ACTIVE (Med) -> WARN'  ($out.L005_warn -eq 'WARN') ("got=$($out.L005_warn)")
Add-R 'LOG-005 none ACTIVE (Crit) -> FAIL' ($out.L005_critfail -eq 'FAIL') ("got=$($out.L005_critfail)")
Add-R 'LOG-004 unavailable -> SKIP'        ($out.L004_skip -eq 'SKIP') ("got=$($out.L004_skip)")
Add-R 'LOG-005 unavailable -> SKIP'        ($out.L005_skip -eq 'SKIP') ("got=$($out.L005_skip)")
Add-R 'LOG-004 type absent -> SKIP'        ($out.L004_absent -eq 'SKIP') ("got=$($out.L004_absent)")
Add-R 'LOG-005 type absent -> SKIP'        ($out.L005_absent -eq 'SKIP') ("got=$($out.L005_absent)")

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
