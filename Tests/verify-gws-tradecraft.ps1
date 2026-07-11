# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# GWS Adversary Tradecraft category (GTRADE-001..006): detections for attack preconditions
# Google does not natively surface — DeleFriend DWD takeover, internet-readable / open-join
# groups, super-admin sprawl, super-admin-equivalent custom roles, persistent OAuth grants.
# Run: pwsh -File Tests/verify-gws-tradecraft.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$out = & $mod {
    $def = @{ id = 'GTRADE-XXX'; name = 'x'; severity = 'High'; description = 'd' }
    function St($ad, $fn) { (& $fn -AuditData $ad -CheckDefinition $def -OrgUnitPath '/').Status }
    function GS($map) {  # build a GroupSettings hashtable from email->@{view;join;ext}
        $h = @{}
        foreach ($e in $map.Keys) {
            $v = $map[$e]
            $h[$e] = [PSCustomObject]@{ email = $e; whoCanViewGroup = $v.view; whoCanJoin = $v.join; allowExternalMembers = $v.ext }
        }
        $h
    }
    function OAuthEv($name, $scope) { [PSCustomObject]@{ Params = [PSCustomObject]@{ app_name = $name; scope = $scope } } }

    $r = @{}

    # ── GTRADE-001: DWD takeover (empty/unenumerable must NEVER PASS — false-PASS regression) ──
    $r.G001_nokey = St @{} 'Test-FortificationGTRADE001'                              # no key -> WARN
    $r.G001_empty = St @{ DomainWideDelegation = @() } 'Test-FortificationGTRADE001'  # empty -> WARN (not PASS)
    $r.G001_narrow = St @{ DomainWideDelegation = @(@{ clientId = '1'; scopes = @('https://www.googleapis.com/auth/admin.directory.user.readonly') }) } 'Test-FortificationGTRADE001'
    $r.G001_mail = St @{ DomainWideDelegation = @(@{ clientId = '2'; scopes = @('https://mail.google.com/') }) } 'Test-FortificationGTRADE001'
    $r.G001_drive = St @{ DomainWideDelegation = @(@{ clientId = '3'; scopes = @('https://www.googleapis.com/auth/drive') }) } 'Test-FortificationGTRADE001'
    $r.G001_drivero = St @{ DomainWideDelegation = @(@{ clientId = '4'; scopes = @('https://www.googleapis.com/auth/drive.readonly') }) } 'Test-FortificationGTRADE001'

    # ── GTRADE-002 / 003: groups ──
    $r.G002_skip = St @{ GroupSettings = @{} } 'Test-FortificationGTRADE002'
    $r.G002_fail = St @{ GroupSettings = (GS @{ 'a@x.org' = @{ view = 'ANYONE_CAN_VIEW'; join = 'INVITED_CAN_JOIN'; ext = 'false' } }) } 'Test-FortificationGTRADE002'
    $r.G002_pass = St @{ GroupSettings = (GS @{ 'a@x.org' = @{ view = 'ALL_MEMBERS_CAN_VIEW'; join = 'INVITED_CAN_JOIN'; ext = 'false' } }) } 'Test-FortificationGTRADE002'
    $r.G003_warnjoin = St @{ GroupSettings = (GS @{ 'a@x.org' = @{ view = 'ALL_MEMBERS_CAN_VIEW'; join = 'ANYONE_CAN_JOIN'; ext = 'false' } }) } 'Test-FortificationGTRADE003'
    $r.G003_warnext = St @{ GroupSettings = (GS @{ 'a@x.org' = @{ view = 'ALL_MEMBERS_CAN_VIEW'; join = 'INVITED_CAN_JOIN'; ext = 'true' } }) } 'Test-FortificationGTRADE003'
    $r.G003_pass = St @{ GroupSettings = (GS @{ 'a@x.org' = @{ view = 'ALL_MEMBERS_CAN_VIEW'; join = 'INVITED_CAN_JOIN'; ext = 'false' } }) } 'Test-FortificationGTRADE003'

    # ── GTRADE-004: super-admin sprawl ──
    function Admins($n) { 1..$n | ForEach-Object { [PSCustomObject]@{ isAdmin = $true; suspended = $false; primaryEmail = "a$_@x.org" } } }
    $r.G004_skip = St @{ Users = @() } 'Test-FortificationGTRADE004'
    $r.G004_pass = St @{ Users = @(Admins 3) } 'Test-FortificationGTRADE004'
    $r.G004_warn = St @{ Users = @(Admins 7) } 'Test-FortificationGTRADE004'
    $r.G004_fail = St @{ Users = @(Admins 12) } 'Test-FortificationGTRADE004'

    # ── GTRADE-005: super-admin-equivalent custom roles ──
    $r.G005_skip = St @{ Roles = @() } 'Test-FortificationGTRADE005'
    # Real Google privilege vocabulary: _ALL / write verbs -> WARN; pure _RETRIEVE -> PASS (the over-match fix).
    $r.G005_warn     = St @{ Roles = @(@{ roleName = 'R1'; isSystemRole = $false; isSuperAdminRole = $false; rolePrivileges = @(@{ privilegeName = 'USERS_ALL' }) }) } 'Test-FortificationGTRADE005'
    $r.G005_write    = St @{ Roles = @(@{ roleName = 'R2'; isSystemRole = $false; isSuperAdminRole = $false; rolePrivileges = @(@{ privilegeName = 'USERS_CREATE' }, @{ privilegeName = 'GROUPS_RETRIEVE' }) }) } 'Test-FortificationGTRADE005'
    $r.G005_readonly = St @{ Roles = @(@{ roleName = 'R3'; isSystemRole = $false; isSuperAdminRole = $false; rolePrivileges = @(@{ privilegeName = 'USERS_RETRIEVE' }, @{ privilegeName = 'GROUPS_RETRIEVE' }, @{ privilegeName = 'ORGANIZATION_UNITS_RETRIEVE' }) }) } 'Test-FortificationGTRADE005'
    $r.G005_sys      = St @{ Roles = @(@{ roleName = '_SEED_ADMIN_ROLE'; isSystemRole = $true; rolePrivileges = @(@{ privilegeName = 'USERS_ALL' }) }) } 'Test-FortificationGTRADE005'  # system role ignored -> PASS

    # ── GTRADE-006: persistent/over-scoped OAuth ──
    $r.G006_skip = St @{ OAuthApps = @() } 'Test-FortificationGTRADE006'
    $r.G006_fail = St @{ OAuthApps = @((OAuthEv 'EvilApp' 'https://mail.google.com/')) } 'Test-FortificationGTRADE006'
    $r.G006_pass = St @{ OAuthApps = @((OAuthEv 'NiceApp' 'https://www.googleapis.com/auth/drive.readonly')) } 'Test-FortificationGTRADE006'

    $r
}

Add-R 'GTRADE-001 no DWD key -> WARN (not PASS)'   ($out.G001_nokey -eq 'WARN') ("got=$($out.G001_nokey)")
Add-R 'GTRADE-001 empty grants -> WARN (not PASS)' ($out.G001_empty -eq 'WARN') ("got=$($out.G001_empty)")
Add-R 'GTRADE-001 narrow readonly -> PASS'    ($out.G001_narrow -eq 'PASS') ("got=$($out.G001_narrow)")
Add-R 'GTRADE-001 full Gmail scope -> FAIL'   ($out.G001_mail -eq 'FAIL') ("got=$($out.G001_mail)")
Add-R 'GTRADE-001 full Drive scope -> FAIL'   ($out.G001_drive -eq 'FAIL') ("got=$($out.G001_drive)")
Add-R 'GTRADE-001 drive.readonly -> PASS'     ($out.G001_drivero -eq 'PASS') ("got=$($out.G001_drivero)")
Add-R 'GTRADE-002 no group settings -> SKIP'  ($out.G002_skip -eq 'SKIP') ("got=$($out.G002_skip)")
Add-R 'GTRADE-002 ANYONE_CAN_VIEW -> FAIL'    ($out.G002_fail -eq 'FAIL') ("got=$($out.G002_fail)")
Add-R 'GTRADE-002 members-only -> PASS'       ($out.G002_pass -eq 'PASS') ("got=$($out.G002_pass)")
Add-R 'GTRADE-003 open-join -> WARN'          ($out.G003_warnjoin -eq 'WARN') ("got=$($out.G003_warnjoin)")
Add-R 'GTRADE-003 external members -> WARN'   ($out.G003_warnext -eq 'WARN') ("got=$($out.G003_warnext)")
Add-R 'GTRADE-003 invited-only -> PASS'       ($out.G003_pass -eq 'PASS') ("got=$($out.G003_pass)")
Add-R 'GTRADE-004 no users -> SKIP'           ($out.G004_skip -eq 'SKIP') ("got=$($out.G004_skip)")
Add-R 'GTRADE-004 3 super admins -> PASS'     ($out.G004_pass -eq 'PASS') ("got=$($out.G004_pass)")
Add-R 'GTRADE-004 7 super admins -> WARN'     ($out.G004_warn -eq 'WARN') ("got=$($out.G004_warn)")
Add-R 'GTRADE-004 12 super admins -> FAIL'    ($out.G004_fail -eq 'FAIL') ("got=$($out.G004_fail)")
Add-R 'GTRADE-005 no roles -> SKIP'           ($out.G005_skip -eq 'SKIP') ("got=$($out.G005_skip)")
Add-R 'GTRADE-005 USERS_ALL -> WARN'                 ($out.G005_warn -eq 'WARN') ("got=$($out.G005_warn)")
Add-R 'GTRADE-005 write verb (USERS_CREATE) -> WARN' ($out.G005_write -eq 'WARN') ("got=$($out.G005_write)")
Add-R 'GTRADE-005 read-only role -> PASS (over-match fix)' ($out.G005_readonly -eq 'PASS') ("got=$($out.G005_readonly)")
Add-R 'GTRADE-005 system role ignored -> PASS' ($out.G005_sys -eq 'PASS') ("got=$($out.G005_sys)")
Add-R 'GTRADE-006 no OAuth data -> SKIP'      ($out.G006_skip -eq 'SKIP') ("got=$($out.G006_skip)")
Add-R 'GTRADE-006 full mail scope -> FAIL'    ($out.G006_fail -eq 'FAIL') ("got=$($out.G006_fail)")
Add-R 'GTRADE-006 readonly scope -> PASS'     ($out.G006_pass -eq 'PASS') ("got=$($out.G006_pass)")

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
