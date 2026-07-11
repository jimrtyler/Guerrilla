# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Standalone verification of the GUI + Safehouse audit fixes:
#   SH-1  config migration also persists the GWS admin email to the vault
#   SH-4  config migration also persists Pushover + Twilio/SMS providers
#   SH-2  status surfaces reconcile metadata with the real secret store
# Run: pwsh -File Tests\verify-safehouse-fixes.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force

$mod = Get-Module Guerrilla
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result($name, $ok, $detail) { $results.Add([PSCustomObject]@{ Name = $name; Pass = [bool]$ok; Detail = $detail }) }

# ── SH-1 / SH-4: Invoke-CredentialMigration writes the right vault keys ────────
# Build a fake service-account JSON file so the Google branch runs.
$saPath = Join-Path ([System.IO.Path]::GetTempPath()) ('sa-' + [System.IO.Path]::GetRandomFileName() + '.json')
@{ type = 'service_account'; client_email = 'svc@proj.iam.gserviceaccount.com'; client_id = '123'; private_key = '-----BEGIN-----' } |
    ConvertTo-Json | Set-Content -Path $saPath -Encoding UTF8
$cfgPath = Join-Path ([System.IO.Path]::GetTempPath()) ('cfg-' + [System.IO.Path]::GetRandomFileName() + '.json')
'{}' | Set-Content -Path $cfgPath -Encoding UTF8

$writtenKeys = & $mod {
    param($SaPath, $CfgPath)
    # Capture every vault write by shadowing the real commands within this scope.
    $script:__written = [System.Collections.Generic.List[string]]::new()
    function Set-GuerrillaCredential { param($VaultKey, $Value, $VaultName) $script:__written.Add($VaultKey) }
    function Get-VaultMetadata { param($VaultName) @{ created = $null; lastModified = $null; credentials = @{} } }
    function Set-VaultMetadata { param($Metadata, $VaultName) }

    $config = @{
        google   = @{ serviceAccountKeyPath = $SaPath; adminEmail = 'admin@corp.com' }
        alerting = @{ providers = @{
            pushover = @{ apiToken = 'po-token'; userKey = 'po-user' }
            twilio   = @{ accountSid = 'AC1'; authToken = 'tw-token'; from = '+1'; to = '+2' }
        } }
    }
    Invoke-CredentialMigration -Config $config -VaultName 'Guerrilla' -ConfigPath $CfgPath 6>$null
    $script:__written
} $saPath $cfgPath

Remove-Item $saPath, $cfgPath -ErrorAction SilentlyContinue

Add-Result 'SH-1 admin email migrated' ($writtenKeys -contains 'GUERRILLA_GWS_SA_ADMIN_EMAIL') ("keys: " + ($writtenKeys -join ', '))
Add-Result 'SH-4 pushover migrated'    ($writtenKeys -contains 'GUERRILLA_PUSHOVER_KEY') ''
Add-Result 'SH-4 twilio migrated'      ($writtenKeys -contains 'GUERRILLA_TWILIO_KEY') ''
Add-Result 'SH-1 GWS SA still migrated' ($writtenKeys -contains 'GUERRILLA_GWS_SA') ''

# ── SH-2: Get-SafehouseCredentialView reconciles metadata with the store ──────
$view = & $mod {
    function Get-VaultMetadata { param($VaultName)
        @{ credentials = @{
            'GUERRILLA_GWS_SA'   = @{ description = 'Google Workspace service account'; environment = 'googleWorkspace' }
            'GUERRILLA_GRAPH_SECRET' = @{ description = 'Microsoft Graph Client Secret'; environment = 'microsoftGraph' }
        } }
    }
    function Get-SecretInfo { param($Vault, $ErrorAction)
        @(
            [PSCustomObject]@{ Name = 'GUERRILLA_GWS_SA' }
            [PSCustomObject]@{ Name = 'GUERRILLA_GRAPH_SECRET' }
            [PSCustomObject]@{ Name = 'GUERRILLA_VAULT_METADATA' }     # must be excluded
            [PSCustomObject]@{ Name = 'GUERRILLA_GWS_SA_ADMIN_EMAIL' } # present, unregistered
            [PSCustomObject]@{ Name = 'GUERRILLA_PUSHOVER_1' }         # present, unregistered (legacy)
        )
    }
    Get-SafehouseCredentialView -VaultName 'Guerrilla'
}

Add-Result 'SH-2 registered keys retained' ($view.ContainsKey('GUERRILLA_GWS_SA') -and $view.ContainsKey('GUERRILLA_GRAPH_SECRET')) ''
Add-Result 'SH-2 unregistered admin email surfaced' ($view.ContainsKey('GUERRILLA_GWS_SA_ADMIN_EMAIL')) ''
Add-Result 'SH-2 unregistered pushover surfaced'    ($view.ContainsKey('GUERRILLA_PUSHOVER_1')) ''
Add-Result 'SH-2 metadata key excluded'             (-not $view.ContainsKey('GUERRILLA_VAULT_METADATA')) ''
Add-Result 'SH-2 unregistered flagged' ($view['GUERRILLA_PUSHOVER_1'].unregistered -eq $true -and $view['GUERRILLA_PUSHOVER_1'].description -match 'Pushover') ("desc: " + $view['GUERRILLA_PUSHOVER_1'].description)
Add-Result 'SH-2 admin email labeled' ($view['GUERRILLA_GWS_SA_ADMIN_EMAIL'].description -match 'admin email') ("desc: " + $view['GUERRILLA_GWS_SA_ADMIN_EMAIL'].description)

# ── Report ────────────────────────────────────────────────────────────────────
$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($r in $results) {
    $mark = if ($r.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($r.Name)"
    if ($r.Detail) { $line += "  ($($r.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
