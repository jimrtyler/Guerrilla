# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Drive Security): verifies the three converted DRIVE checks
# (001/004/008) read real Cloud Identity policy values from drive_and_docs.* and grade
# correctly — including weakest-OU-wins, unknown-enum -> WARN, and the unavailable -> SKIP path.
# Run: pwsh -File Tests/verify-gws1-drive-checks.ps1

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
    $def = @{ id = 'DRIVE-XXX'; name = 'x'; severity = 'High'; description = 'd' }
    # Some DRIVE checks consult OrgUnitPolicies first; supply an empty map so they fall through
    # to the Cloud Identity policy path under test.
    function St($ad, $fn) {
        if (-not $ad.ContainsKey('OrgUnitPolicies')) { $ad['OrgUnitPolicies'] = @{} }
        (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status
    }

    $r = @{}

    # ── DRIVE-001: external sharing mode (enum, weakest-OU-wins) ──
    $r.D001_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.external_sharing' = @{ externalSharingMode = 'ALLOWED' } }) }) 'Test-FortificationDRIVE001'
    $r.D001_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.external_sharing' = @{ externalSharingMode = 'DISALLOWED' } }) }) 'Test-FortificationDRIVE001'
    $r.D001_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.external_sharing' = @{ externalSharingMode = 'SOMETHING_NEW' } }) }) 'Test-FortificationDRIVE001'
    # weakest-OU-wins: one OU ALLOWED among restrictive ones -> FAIL
    $r.D001_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.external_sharing' = @(@{ externalSharingMode = 'DISALLOWED' }, @{ externalSharingMode = 'ALLOWED' }) }) }) 'Test-FortificationDRIVE001'

    # ── DRIVE-004: shared drive creation (bool, weakest-OU-wins) ──
    $r.D004_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.shared_drive_creation' = @{ allowSharedDriveCreation = $true } }) }) 'Test-FortificationDRIVE004'
    $r.D004_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.shared_drive_creation' = @{ allowSharedDriveCreation = $false } }) }) 'Test-FortificationDRIVE004'

    # ── DRIVE-008: drive for desktop (bool + restrictToAuthorizedDevices) ──
    $r.D008_pass_off = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.drive_for_desktop' = @{ allowDriveForDesktop = $false } }) }) 'Test-FortificationDRIVE008'
    $r.D008_warn     = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.drive_for_desktop' = @{ allowDriveForDesktop = $true; restrictToAuthorizedDevices = $false } }) }) 'Test-FortificationDRIVE008'
    $r.D008_pass_res = St (@{ CloudIdentityPolicies = (New-Pol @{ 'drive_and_docs.drive_for_desktop' = @{ allowDriveForDesktop = $true; restrictToAuthorizedDevices = $true } }) }) 'Test-FortificationDRIVE008'

    # ── Unavailable API -> SKIP (across the converted checks) ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.Skip001 = St $none 'Test-FortificationDRIVE001'
    $r.Skip004 = St $none 'Test-FortificationDRIVE004'
    $r.Skip008 = St $none 'Test-FortificationDRIVE008'

    # ── Available but type absent -> SKIP ──
    $other = @{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }
    $r.Absent001 = St $other 'Test-FortificationDRIVE001'
    $r.Absent004 = St $other 'Test-FortificationDRIVE004'
    $r.Absent008 = St $other 'Test-FortificationDRIVE008'

    $r
}

Add-R 'DRIVE-001 ALLOWED -> FAIL'             ($out.D001_fail -eq 'FAIL') ("got=$($out.D001_fail)")
Add-R 'DRIVE-001 DISALLOWED -> PASS'          ($out.D001_pass -eq 'PASS') ("got=$($out.D001_pass)")
Add-R 'DRIVE-001 unknown enum -> WARN'        ($out.D001_warn -eq 'WARN') ("got=$($out.D001_warn)")
Add-R 'DRIVE-001 weakest OU (ALLOWED) -> FAIL' ($out.D001_weak -eq 'FAIL') ("got=$($out.D001_weak)")
Add-R 'DRIVE-004 creation allowed -> WARN'    ($out.D004_warn -eq 'WARN') ("got=$($out.D004_warn)")
Add-R 'DRIVE-004 creation restricted -> PASS' ($out.D004_pass -eq 'PASS') ("got=$($out.D004_pass)")
Add-R 'DRIVE-008 disabled -> PASS'            ($out.D008_pass_off -eq 'PASS') ("got=$($out.D008_pass_off)")
Add-R 'DRIVE-008 enabled+unrestricted -> WARN' ($out.D008_warn -eq 'WARN') ("got=$($out.D008_warn)")
Add-R 'DRIVE-008 enabled+device-restricted -> PASS' ($out.D008_pass_res -eq 'PASS') ("got=$($out.D008_pass_res)")
Add-R 'Unavailable -> SKIP (001/004/008)'     ($out.Skip001 -eq 'SKIP' -and $out.Skip004 -eq 'SKIP' -and $out.Skip008 -eq 'SKIP') ("$($out.Skip001)/$($out.Skip004)/$($out.Skip008)")
Add-R 'Type absent -> SKIP (001/004/008)'     ($out.Absent001 -eq 'SKIP' -and $out.Absent004 -eq 'SKIP' -and $out.Absent008 -eq 'SKIP') ("$($out.Absent001)/$($out.Absent004)/$($out.Absent008)")

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
