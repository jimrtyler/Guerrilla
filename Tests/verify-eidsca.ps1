# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# EIDSCA evaluator + dispatcher: Resolve-EidscaControl evaluates the 44-control catalog against the raw
# Graph policy objects our collectors store, across all source types/operators; missing data => SKIP
# ("Not Assessed", never PASS). Invoke-EntraEidscaChecks produces eidsca-tagged findings that flow through
# Get-ComplianceCrosswalk -Framework EIDSCA. Run: pwsh -File Tests/verify-eidsca.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

# A well-configured synthetic tenant (most controls should PASS) + deliberate gaps (some SKIP).
$goodAudit = @{
    AuthMethods = @{
        AuthorizationPolicy = [pscustomobject]@{
            allowedToUseSSPR = $false; allowInvitesFrom = 'none'; allowedToSignUpEmailBasedSubscriptions = $false
            allowEmailVerifiedUsersToJoinOrganization = $false; guestUserRoleId = '2af84b1e-32c8-42b7-82bc-daa82404023b'
            allowUserConsentForRiskyApps = $false
            permissionGrantPolicyIdsAssignedToDefaultUserRole = @('ManagePermissionGrantsForSelf.microsoft-user-default-low')
            defaultUserRolePermissions = [pscustomobject]@{ allowedToCreateApps = $false; allowedToReadOtherUsers = $true }
        }
        AuthMethodsPolicy = [pscustomobject]@{
            policyMigrationState = 'migrationComplete'
            reportSuspiciousActivitySettings = [pscustomobject]@{ state = 'enabled'; includeTarget = [pscustomobject]@{ id = 'all_users' } }
        }
        MethodConfigurations = @(
            [pscustomobject]@{ id = 'MicrosoftAuthenticator'; state = 'enabled'; isSoftwareOathEnabled = $false
                featureSettings = [pscustomobject]@{
                    numberMatchingRequiredState     = [pscustomobject]@{ state = 'enabled'; includeTarget = [pscustomobject]@{ id = 'all_users' } }
                    displayAppInformationRequiredState = [pscustomobject]@{ state = 'enabled'; includeTarget = [pscustomobject]@{ id = 'all_users' } }
                    displayLocationInformationRequiredState = [pscustomobject]@{ state = 'enabled'; includeTarget = [pscustomobject]@{ id = 'all_users' } }
                } }
            [pscustomobject]@{ id = 'Fido2'; state = 'enabled'; isSelfServiceRegistrationAllowed = $true; isAttestationEnforced = $true
                keyRestrictions = [pscustomobject]@{ isEnforced = $true; aaGuids = @('aaaa-bbbb'); enforcementType = 'allow' } }
            [pscustomobject]@{ id = 'TemporaryAccessPass'; state = 'enabled'; isUsableOnce = $true }
            [pscustomobject]@{ id = 'Voice'; state = 'disabled' }
            [pscustomobject]@{ id = 'Sms'; includeTargets = [pscustomobject]@{ isUsableForSignIn = $false } }
        )
        DirectorySettings = @(
            [pscustomobject]@{ values = @(
                [pscustomobject]@{ name = 'AllowGuestsToAccessGroups'; value = 'True' }
                [pscustomobject]@{ name = 'AllowGuestsToBeGroupOwner'; value = 'false' }
                [pscustomobject]@{ name = 'EnableBannedPasswordCheck'; value = 'True' }
            ) }
        )
    }
    TenantConfig = @{ AdminConsentRequestPolicy = [pscustomobject]@{ isEnabled = $true; notifyReviewers = $true; remindersEnabled = $true; requestDurationInDays = 14 } }
}

$out = & $mod {
    param($audit)
    # Load the catalog as the dispatcher does
    $cat = Get-Content (Join-Path (Split-Path (Get-Module Guerrilla).Path) 'Data/AuditChecks/EidscaChecks.json') -Raw | ConvertFrom-Json -AsHashtable
    $byId = @{}; foreach ($c in $cat.checks) { $byId[$c.id] = $c }
    $sources = @{
        AuthorizationPolicy = $audit.AuthMethods.AuthorizationPolicy
        AuthMethodsPolicy = $audit.AuthMethods.AuthMethodsPolicy
        MethodConfigurations = @($audit.AuthMethods.MethodConfigurations)
        DirectorySettings = @($audit.AuthMethods.DirectorySettings)
        AdminConsentRequestPolicy = $audit.TenantConfig.AdminConsentRequestPolicy
    }
    $ev = { param($id) (Resolve-EidscaControl -Control $byId["EIDSCA-$id"] -Sources $sources).Status }

    $r = @{}
    $r.CatalogCount = $cat.checks.Count
    # PASS cases across source types/operators
    $r.AP01 = & $ev 'AP01'   # authorizationPolicy eq false
    $r.AP04 = & $ev 'AP04'   # authorizationPolicy in (none)
    $r.AP10 = & $ev 'AP10'   # nested defaultUserRolePermissions.allowedToCreateApps eq false
    $r.AP08 = & $ev 'AP08'   # clike-any
    $r.AM03 = & $ev 'AM03'   # authMethodConfig nested featureSettings.*.state eq enabled
    $r.AV01 = & $ev 'AV01'   # Voice state eq disabled
    $r.AF05 = & $ev 'AF05'   # notempty aaGuids
    $r.AF06 = & $ev 'AF06'   # fido2-aaguid-enforced
    $r.ST09 = & $ev 'ST09'   # directorySetting eq True
    $r.CR04 = & $ev 'CR04'   # le 30
    # SKIP (Not Assessed): a directory setting we didn't include
    $r.PR01skip = & $ev 'PR01'  # BannedPasswordCheckOnPremisesMode not in DirectorySettings -> SKIP

    # FAIL case: flip SSPR-for-admins on
    $bad = $sources.Clone(); $bad.AuthorizationPolicy = [pscustomobject]@{ allowedToUseSSPR = $true }
    $r.AP01fail = (Resolve-EidscaControl -Control $byId['EIDSCA-AP01'] -Sources $bad).Status

    # SKIP when whole source object missing (Not Assessed, never PASS)
    $empty = @{ AuthorizationPolicy=$null; AuthMethodsPolicy=$null; MethodConfigurations=@(); DirectorySettings=@(); AdminConsentRequestPolicy=$null }
    $r.AP01missing = (Resolve-EidscaControl -Control $byId['EIDSCA-AP01'] -Sources $empty).Status

    # Dispatcher end-to-end
    $f = Invoke-EntraEidscaChecks -AuditData $audit
    $r.FindingCount = @($f).Count
    $r.AllTagged = (@($f | Where-Object { $_.Compliance.Eidsca.Count -gt 0 }).Count -eq @($f).Count)
    $r.NoFalsePass = (@($f | Where-Object { $_.Status -eq 'PASS' -and $_.CurrentValue -match 'Not Assessed' }).Count -eq 0)
    # crosswalk
    $cw = @(Get-ComplianceCrosswalk -Findings $f -Framework EIDSCA)
    $r.CrosswalkRows = $cw.Count
    $r
} $goodAudit

Add-R 'catalog has 44 controls'        ($out.CatalogCount -eq 44) "n=$($out.CatalogCount)"
Add-R 'AP01 authorizationPolicy eq'    ($out.AP01 -eq 'PASS') $out.AP01
Add-R 'AP04 in-operator'               ($out.AP04 -eq 'PASS') $out.AP04
Add-R 'AP10 nested property'           ($out.AP10 -eq 'PASS') $out.AP10
Add-R 'AP08 clike-any'                 ($out.AP08 -eq 'PASS') $out.AP08
Add-R 'AM03 authMethodConfig nested'   ($out.AM03 -eq 'PASS') $out.AM03
Add-R 'AV01 config state eq disabled'  ($out.AV01 -eq 'PASS') $out.AV01
Add-R 'AF05 notempty'                  ($out.AF05 -eq 'PASS') $out.AF05
Add-R 'AF06 fido2 compound'            ($out.AF06 -eq 'PASS') $out.AF06
Add-R 'ST09 directorySetting eq'       ($out.ST09 -eq 'PASS') $out.ST09
Add-R 'CR04 le-operator'              ($out.CR04 -eq 'PASS') $out.CR04
Add-R 'AP01 FAIL when misconfigured'   ($out.AP01fail -eq 'FAIL') $out.AP01fail
Add-R 'missing setting -> SKIP'        ($out.PR01skip -eq 'SKIP') $out.PR01skip
Add-R 'missing source obj -> SKIP'     ($out.AP01missing -eq 'SKIP') $out.AP01missing
Add-R 'dispatcher emits 44 findings'   ($out.FindingCount -eq 44) "n=$($out.FindingCount)"
Add-R 'all findings eidsca-tagged'     ($out.AllTagged) ''
Add-R 'no SKIP scored as PASS'         ($out.NoFalsePass) ''
Add-R 'crosswalk EIDSCA rows produced' ($out.CrosswalkRows -gt 0) "n=$($out.CrosswalkRows)"

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($x in $results) {
    $mark = if ($x.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($x.Name)"; if ($x.Detail) { $line += "  ($($x.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
