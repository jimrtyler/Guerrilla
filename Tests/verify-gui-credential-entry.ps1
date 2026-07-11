# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Verifies the GUI "Add Credential" modal's testable logic (the WPF dialog itself is
# render-validated separately): the entry builder, the field validator, and the
# non-interactive vault save helper. Run: pwsh -File Tests\verify-gui-credential-entry.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$guid1 = '11111111-1111-1111-1111-111111111111'
$guid2 = '22222222-2222-2222-2222-222222222222'

# ── New-AddCredentialEntries ──────────────────────────────────────────────────
$entra = & $mod {
    New-AddCredentialEntries -Environment 'microsoftGraph' -Fields @{
        TenantId = $args[0]; ClientId = $args[1]; ClientSecret = 'sekret'; Expiration = '2027-01-01' }
} $guid1 $guid2
$ek = @($entra | ForEach-Object { $_.VaultKey })
Add-R 'Entra -> 3 entries' ($entra.Count -eq 3) ("keys: " + ($ek -join ', '))
Add-R 'Entra keys correct' (($ek -contains 'GUERRILLA_GRAPH_TENANT') -and ($ek -contains 'GUERRILLA_GRAPH_CLIENTID') -and ($ek -contains 'GUERRILLA_GRAPH_SECRET')) ''
Add-R 'Entra secret carries expiry' (($entra | Where-Object VaultKey -eq 'GUERRILLA_GRAPH_SECRET').ExpirationDate -eq '2027-01-01') ''

$gws = & $mod {
    New-AddCredentialEntries -Environment 'googleWorkspace' -Fields @{
        ServiceAccountJson = '{"client_email":"svc@x.iam"}'; SaClientEmail = 'svc@x.iam'; AdminEmail = 'admin@x.org' }
}
$gk = @($gws | ForEach-Object { $_.VaultKey })
Add-R 'GWS -> 2 entries' ($gws.Count -eq 2) ("keys: " + ($gk -join ', '))
Add-R 'GWS keys correct' (($gk -contains 'GUERRILLA_GWS_SA') -and ($gk -contains 'GUERRILLA_GWS_SA_ADMIN_EMAIL')) ''
Add-R 'GWS SA identity from client_email' (($gws | Where-Object VaultKey -eq 'GUERRILLA_GWS_SA').Identity -eq 'svc@x.iam') ''

# ── Test-AddCredentialFields ──────────────────────────────────────────────────
$badEntra = & $mod { Test-AddCredentialFields -Environment 'microsoftGraph' -Fields @{ TenantId = 'nope'; ClientId = $args[0]; ClientSecret = '' } } $guid2
Add-R 'Entra validation catches bad GUID + empty secret' ($badEntra.Count -ge 2) ("errs=$($badEntra.Count)")
$okEntra = & $mod { Test-AddCredentialFields -Environment 'microsoftGraph' -Fields @{ TenantId = $args[0]; ClientId = $args[1]; ClientSecret = 's' } } $guid1 $guid2
Add-R 'Entra validation passes valid input' ($okEntra.Count -eq 0) ("errs=$($okEntra.Count)")
$badGws = & $mod { Test-AddCredentialFields -Environment 'googleWorkspace' -Fields @{ ServiceAccountJson = '{}'; SaClientEmail = $null; AdminEmail = 'not-an-email' } }
Add-R 'GWS validation catches no-client_email + bad email' ($badGws.Count -ge 2) ("errs=$($badGws.Count)")
$okGws = & $mod { Test-AddCredentialFields -Environment 'googleWorkspace' -Fields @{ ServiceAccountJson = '{...}'; SaClientEmail = 'svc@x.iam'; AdminEmail = 'admin@x.org' } }
Add-R 'GWS validation passes valid input' ($okGws.Count -eq 0) ("errs=$($okGws.Count)")

# ── Save-SafehouseCredentialSet (shadowed vault) ──────────────────────────────
$saved = & $mod {
    $script:__w = [System.Collections.Generic.List[string]]::new()
    $script:__meta = $null
    function Set-GuerrillaCredential { param($VaultKey, $Value, $VaultName) $script:__w.Add($VaultKey) }
    function Get-VaultMetadata { param($VaultName) @{ created = $null; lastModified = $null; credentials = @{} } }
    function Set-VaultMetadata { param($Metadata, $VaultName) $script:__meta = $Metadata }
    $entries = @(
        @{ VaultKey = 'GUERRILLA_GRAPH_TENANT'; Value = 'aaa'; Type = 'tenantId'; Environment = 'microsoftGraph'; Description = 'T'; Identity = 'aaa' }
        @{ VaultKey = 'GUERRILLA_GRAPH_SECRET'; Value = 'sek'; Type = 'clientSecret'; Environment = 'microsoftGraph'; Description = 'S'; ExpirationDate = '2027-01-01' }
        @{ VaultKey = 'GUERRILLA_EMPTY'; Value = ''; Type = 'x'; Environment = 'x'; Description = 'skip me' }   # must be skipped
    )
    $n = Save-SafehouseCredentialSet -Entries $entries -VaultName 'Guerrilla'
    [PSCustomObject]@{ Count = $n; Written = $script:__w; Meta = $script:__meta }
}
Add-R 'Save stored 2 (empty value skipped)' ($saved.Count -eq 2) ("count=$($saved.Count) written=$($saved.Written -join ',')")
Add-R 'Save did NOT write empty-value key' (-not ($saved.Written -contains 'GUERRILLA_EMPTY')) ''
Add-R 'Save registered metadata for both' ($saved.Meta.credentials.ContainsKey('GUERRILLA_GRAPH_TENANT') -and $saved.Meta.credentials.ContainsKey('GUERRILLA_GRAPH_SECRET')) ''
Add-R 'Save carried expiry into metadata' ($saved.Meta.credentials['GUERRILLA_GRAPH_SECRET'].expirationDate -eq '2027-01-01') ''
Add-R 'Save set created + lastModified' ($saved.Meta.created -and $saved.Meta.lastModified) ''

# ── Report ────────────────────────────────────────────────────────────────────
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
