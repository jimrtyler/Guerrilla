# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Drive, phase 2): verifies DRIVE-010 (Drive DLP Rules Audit) reads
# real Cloud Identity rule.dlp policy values and grades correctly — an ACTIVE Drive-scoped DLP
# rule PASSes, no Drive-scoped rule (including an ACTIVE rule with only a gmailAction) WARNs,
# an INACTIVE driveAction rule WARNs (not PASS), and the unavailable API -> SKIP path.
# Run: pwsh -File Tests/verify-gws1-drive-p2.ps1

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
    $def = @{ id = 'DRIVE-010'; name = 'x'; severity = 'High'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }

    # Drive DLP rule value-object fixtures (PSCustomObject action objects, like ConvertFrom-Json).
    function DlpRule($state, [string[]]$actionKeys) {
        $action = [ordered]@{}
        foreach ($ak in $actionKeys) { $action[$ak] = [PSCustomObject]@{ note = $ak } }
        [PSCustomObject]@{ state = $state; action = [PSCustomObject]$action }
    }

    $r = @{}

    # ── PASS: at least one ACTIVE Drive-scoped DLP rule ──
    $r.D010_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.dlp' = @(
        (DlpRule 'ACTIVE' @('driveAction'))
    ) }) }) 'Test-FortificationDRIVE010'
    # PASS even when mixed with non-Drive / inactive rules, so long as one active Drive rule exists.
    $r.D010_passMixed = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.dlp' = @(
        (DlpRule 'ACTIVE' @('gmailAction')),
        (DlpRule 'INACTIVE' @('driveAction')),
        (DlpRule 'ACTIVE' @('driveAction', 'alertCenterAction'))
    ) }) }) 'Test-FortificationDRIVE010'

    # ── WARN: no Drive-scoped rule at all ──
    # An ACTIVE rule with only a gmailAction must NOT count as a Drive DLP rule.
    $r.D010_warnGmail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.dlp' = @(
        (DlpRule 'ACTIVE' @('gmailAction'))
    ) }) }) 'Test-FortificationDRIVE010'

    # ── WARN: INACTIVE driveAction (correct action, wrong state) must be WARN, not PASS ──
    $r.D010_warnInactive = St (@{ CloudIdentityPolicies = (New-Pol @{ 'rule.dlp' = @(
        (DlpRule 'INACTIVE' @('driveAction'))
    ) }) }) 'Test-FortificationDRIVE010'

    # ── SKIP: API unavailable ──
    $r.D010_skip = St (@{ CloudIdentityPolicies = $null }) 'Test-FortificationDRIVE010'
    # ── SKIP: API available but no rule.dlp policy returned ──
    $r.D010_skipAbsent = St (@{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }) 'Test-FortificationDRIVE010'

    $r
}

Add-R 'DRIVE-010 active Drive DLP rule -> PASS'          ($out.D010_pass -eq 'PASS') ("got=$($out.D010_pass)")
Add-R 'DRIVE-010 active Drive rule among mixed -> PASS'  ($out.D010_passMixed -eq 'PASS') ("got=$($out.D010_passMixed)")
Add-R 'DRIVE-010 ACTIVE gmail-only (no Drive) -> WARN'   ($out.D010_warnGmail -eq 'WARN') ("got=$($out.D010_warnGmail)")
Add-R 'DRIVE-010 INACTIVE driveAction -> WARN'           ($out.D010_warnInactive -eq 'WARN') ("got=$($out.D010_warnInactive)")
Add-R 'DRIVE-010 unavailable API -> SKIP'                ($out.D010_skip -eq 'SKIP') ("got=$($out.D010_skip)")
Add-R 'DRIVE-010 no rule.dlp policy -> SKIP'             ($out.D010_skipAbsent -eq 'SKIP') ("got=$($out.D010_skipAbsent)")

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
