# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Email Security, phase 2): verifies the two newly converted EMAIL
# checks (018 content-compliance, 019 DLP) read real Cloud Identity policy values and grade
# correctly — control-present PASS, none -> WARN, unavailable -> SKIP, and (019) an
# INACTIVE-only rule must NOT count as active.
# Run: pwsh -File Tests/verify-gws1-email-p2.ps1

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
    $def = @{ id = 'EMAIL-XXX'; name = 'x'; severity = 'High'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    $r = @{}

    # ── EMAIL-018: Content compliance rules present? ──
    # PASS: at least one configured content-compliance rule.
    $r.E018_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.content_compliance' = @{ contentComplianceRules = @(
        [PSCustomObject]@{ name = 'rule1' }, [PSCustomObject]@{ name = 'rule2' }) } }) }) 'Test-FortificationEMAIL018'
    # WARN: policy present but zero rules configured.
    $r.E018_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.content_compliance' = @{ contentComplianceRules = @() } }) }) 'Test-FortificationEMAIL018'

    # ── EMAIL-019: Active Gmail DLP rule present? ──
    # PASS: an ACTIVE rule whose action has a gmailAction.
    $r.E019_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.dlp' = @{ state = 'ACTIVE'; action = [PSCustomObject]@{ gmailAction = [PSCustomObject]@{ type = 'BLOCK' } } } }) }) 'Test-FortificationEMAIL019'
    # WARN: no DLP rules with a Gmail action (here an ACTIVE drive-only rule -> not Gmail-scoped).
    $r.E019_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.dlp' = @{ state = 'ACTIVE'; action = [PSCustomObject]@{ driveAction = [PSCustomObject]@{ type = 'WARN' } } } }) }) 'Test-FortificationEMAIL019'
    # INACTIVE Gmail rule -> WARN (anchored state; 'INACTIVE' must not count as active).
    $r.E019_inactive = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.dlp' = @{ state = 'INACTIVE'; action = [PSCustomObject]@{ gmailAction = [PSCustomObject]@{ type = 'BLOCK' } } } }) }) 'Test-FortificationEMAIL019'

    # ── Unavailable API -> SKIP ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.E018_skip = St $none 'Test-FortificationEMAIL018'
    $r.E019_skip = St $none 'Test-FortificationEMAIL019'

    $r
}

Add-R 'EMAIL-018 rules present -> PASS'        ($out.E018_pass -eq 'PASS') ("got=$($out.E018_pass)")
Add-R 'EMAIL-018 zero rules -> WARN'           ($out.E018_warn -eq 'WARN') ("got=$($out.E018_warn)")
Add-R 'EMAIL-018 unavailable -> SKIP'          ($out.E018_skip -eq 'SKIP') ("got=$($out.E018_skip)")
Add-R 'EMAIL-019 active Gmail DLP -> PASS'     ($out.E019_pass -eq 'PASS') ("got=$($out.E019_pass)")
Add-R 'EMAIL-019 no Gmail DLP -> WARN'         ($out.E019_warn -eq 'WARN') ("got=$($out.E019_warn)")
Add-R 'EMAIL-019 INACTIVE only -> WARN'        ($out.E019_inactive -eq 'WARN') ("got=$($out.E019_inactive)")
Add-R 'EMAIL-019 unavailable -> SKIP'          ($out.E019_skip -eq 'SKIP') ("got=$($out.E019_skip)")

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
