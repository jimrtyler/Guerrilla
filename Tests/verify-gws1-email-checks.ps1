# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS-1 check conversions (Email Security): verifies the six converted EMAIL checks
# (013/015/016/017/020/021) read real Cloud Identity gmail.* policy values and grade
# correctly — including multi-OU "weakest wins" and the unavailable -> SKIP path.
# Run: pwsh -File Tests/verify-gws1-email-checks.ps1

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

    # ── EMAIL-013: enhanced pre-delivery message scanning ──
    $r.A013_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.enhanced_pre_delivery_message_scanning' = @{ enableImprovedSuspiciousContentDetection = $true } }) }) 'Test-FortificationEMAIL013'
    $r.A013_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.enhanced_pre_delivery_message_scanning' = @{ enableImprovedSuspiciousContentDetection = $false } }) }) 'Test-FortificationEMAIL013'
    $r.A013_weak = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.enhanced_pre_delivery_message_scanning' = @(@{ enableImprovedSuspiciousContentDetection = $true }, @{ enableImprovedSuspiciousContentDetection = $false }) }) }) 'Test-FortificationEMAIL013'  # weakest OU off -> FAIL

    # ── EMAIL-015: attachment safety (auto-apply future settings) ──
    $r.A015_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.email_attachment_safety' = @{ applyFutureRecommendedSettingsAutomatically = $true } }) }) 'Test-FortificationEMAIL015'
    $r.A015_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.email_attachment_safety' = @{ applyFutureRecommendedSettingsAutomatically = $false } }) }) 'Test-FortificationEMAIL015'

    # ── EMAIL-016: links and external images (both fields must be true) ──
    $r.A016_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.links_and_external_images' = @{ enableShortenerScanning = $true; enableExternalImageScanning = $true } }) }) 'Test-FortificationEMAIL016'
    $r.A016_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.links_and_external_images' = @{ enableShortenerScanning = $true; enableExternalImageScanning = $false } }) }) 'Test-FortificationEMAIL016'  # one field off -> FAIL

    # ── EMAIL-017: spoofing and authentication (three fields must be true) ──
    $r.A017_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.spoofing_and_authentication' = @{ detectDomainNameSpoofing = $true; detectEmployeeNameSpoofing = $true; detectUnauthenticatedEmails = $true } }) }) 'Test-FortificationEMAIL017'
    $r.A017_fail = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.spoofing_and_authentication' = @{ detectDomainNameSpoofing = $true; detectEmployeeNameSpoofing = $false; detectUnauthenticatedEmails = $true } }) }) 'Test-FortificationEMAIL017'  # one field off -> FAIL

    # ── EMAIL-020: confidential mode (WARN when enabled, PASS when off) ──
    $r.A020_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.confidential_mode' = @{ enableConfidentialMode = $true } }) }) 'Test-FortificationEMAIL020'
    $r.A020_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.confidential_mode' = @{ enableConfidentialMode = $false } }) }) 'Test-FortificationEMAIL020'

    # ── EMAIL-021: S/MIME user cert upload (WARN when allowed, PASS when restricted) ──
    $r.A021_warn = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.enhanced_smime_encryption' = @{ allowUserToUploadCertificates = $true } }) }) 'Test-FortificationEMAIL021'
    $r.A021_pass = St (@{ CloudIdentityPolicies = (New-Pol @{ 'gmail.enhanced_smime_encryption' = @{ allowUserToUploadCertificates = $false } }) }) 'Test-FortificationEMAIL021'

    # ── Unavailable API -> SKIP (every converted check) ──
    $none = @{ CloudIdentityPolicies = $null }
    $r.Skip013 = St $none 'Test-FortificationEMAIL013'
    $r.Skip015 = St $none 'Test-FortificationEMAIL015'
    $r.Skip016 = St $none 'Test-FortificationEMAIL016'
    $r.Skip017 = St $none 'Test-FortificationEMAIL017'
    $r.Skip020 = St $none 'Test-FortificationEMAIL020'
    $r.Skip021 = St $none 'Test-FortificationEMAIL021'

    # ── Available API but type absent -> SKIP (sampled) ──
    $other = @{ CloudIdentityPolicies = (New-Pol @{ 'security.password' = @{ minimumLength = 12 } }) }
    $r.Absent013 = St $other 'Test-FortificationEMAIL013'
    $r.Absent016 = St $other 'Test-FortificationEMAIL016'
    $r.Absent017 = St $other 'Test-FortificationEMAIL017'

    $r
}

Add-R 'EMAIL-013 scanning on -> PASS'         ($out.A013_pass -eq 'PASS') ("got=$($out.A013_pass)")
Add-R 'EMAIL-013 scanning off -> FAIL'        ($out.A013_fail -eq 'FAIL') ("got=$($out.A013_fail)")
Add-R 'EMAIL-013 weakest OU off -> FAIL'      ($out.A013_weak -eq 'FAIL') ("got=$($out.A013_weak)")
Add-R 'EMAIL-015 auto-apply on -> PASS'       ($out.A015_pass -eq 'PASS') ("got=$($out.A015_pass)")
Add-R 'EMAIL-015 auto-apply off -> WARN'      ($out.A015_warn -eq 'WARN') ("got=$($out.A015_warn)")
Add-R 'EMAIL-016 both on -> PASS'             ($out.A016_pass -eq 'PASS') ("got=$($out.A016_pass)")
Add-R 'EMAIL-016 one off -> FAIL'             ($out.A016_fail -eq 'FAIL') ("got=$($out.A016_fail)")
Add-R 'EMAIL-017 all on -> PASS'              ($out.A017_pass -eq 'PASS') ("got=$($out.A017_pass)")
Add-R 'EMAIL-017 one off -> FAIL'             ($out.A017_fail -eq 'FAIL') ("got=$($out.A017_fail)")
Add-R 'EMAIL-020 confidential on -> WARN'     ($out.A020_warn -eq 'WARN') ("got=$($out.A020_warn)")
Add-R 'EMAIL-020 confidential off -> PASS'    ($out.A020_pass -eq 'PASS') ("got=$($out.A020_pass)")
Add-R 'EMAIL-021 user upload on -> WARN'      ($out.A021_warn -eq 'WARN') ("got=$($out.A021_warn)")
Add-R 'EMAIL-021 user upload off -> PASS'     ($out.A021_pass -eq 'PASS') ("got=$($out.A021_pass)")
Add-R 'Unavailable -> SKIP (all six)'         ($out.Skip013 -eq 'SKIP' -and $out.Skip015 -eq 'SKIP' -and $out.Skip016 -eq 'SKIP' -and $out.Skip017 -eq 'SKIP' -and $out.Skip020 -eq 'SKIP' -and $out.Skip021 -eq 'SKIP') ("$($out.Skip013)/$($out.Skip015)/$($out.Skip016)/$($out.Skip017)/$($out.Skip020)/$($out.Skip021)")
Add-R 'Type absent -> SKIP (013/016/017)'     ($out.Absent013 -eq 'SKIP' -and $out.Absent016 -eq 'SKIP' -and $out.Absent017 -eq 'SKIP') ("$($out.Absent013)/$($out.Absent016)/$($out.Absent017)")

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
