# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-Safehouse {
    <#
    .SYNOPSIS
        Retrieves Guerrilla configuration and vault status.

    .DESCRIPTION
        Returns the current runtime configuration. Credential values are stored in the
        SecretManagement vault and are not displayed unless -ShowSecrets is specified.
        Use Set-Safehouse -Status for a formatted vault status display.

    .PARAMETER ConfigPath
        Path to the Guerrilla runtime config file. Default: per-user data dir + \Guerrilla\config.json
        (Windows: $env:APPDATA; macOS: ~/Library/Application Support; Linux: $XDG_CONFIG_HOME or ~/.config)

    .PARAMETER ShowSecrets
        Include secret values from the vault in the output (use with caution).

    .PARAMETER VaultName
        Name of the SecretManagement vault. Default: Guerrilla

    .EXAMPLE
        Get-Safehouse
        # Returns config with vault credential status (no secret values)

    .EXAMPLE
        Get-Safehouse -ShowSecrets
        # Returns config including actual secret values from vault
    #>
    [CmdletBinding()]
    param(
        [Alias('RuntimeConfig')]
        [string]$ConfigPath,
        [switch]$ShowSecrets,
        [string]$VaultName = 'Guerrilla'
    )

    $path = if ($ConfigPath) { $ConfigPath } else { $script:ConfigPath }

    # Build result object
    $result = [ordered]@{}

    # Load runtime config if exists
    if ($path -and (Test-Path $path)) {
        $config = Get-Content -Path $path -Raw | ConvertFrom-Json
        if (-not $ShowSecrets) {
            Hide-ConfigSecret -InputObject $config
        }
        $result.config = $config
        $result.configPath = $path
    } else {
        Write-Warning "No configuration found at '$path'. Run Set-Safehouse to create one."
        $result.config = $null
        $result.configPath = $path
    }

    # Load vault status. SecretManagement may not be installed yet (Set-Safehouse
    # installs it on first run) — treat that the same as "no vault".
    $vault = if (Get-Command Get-SecretVault -ErrorAction SilentlyContinue) {
        Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    } else {
        $null
    }
    $result.vaultExists = [bool]$vault
    $result.vaultName = $VaultName

    if ($vault) {
        $metadata = Get-VaultMetadata -VaultName $VaultName
        $result.vaultMetadata = $metadata

        # Reconcile metadata with the real secret store so present-but-unregistered
        # secrets (e.g. the admin email, Pushover, a legacy bare key) are not hidden.
        $credView = Get-SafehouseCredentialView -VaultName $VaultName
        if ($credView -and $credView.Count -gt 0) {
            $credStatus = [ordered]@{}
            foreach ($key in $credView.Keys) {
                $cred = $credView[$key]
                $entry = [ordered]@{
                    description = $cred.description
                    environment = $cred.environment
                    type        = $cred.type
                    storedDate  = $cred.storedDate
                    status      = 'SECURED'
                }

                if ($cred.expirationDate) {
                    $entry.expirationDate = $cred.expirationDate
                    $daysLeft = ([datetime]$cred.expirationDate - [datetime]::UtcNow).TotalDays
                    if ($daysLeft -lt 0) { $entry.status = 'EXPIRED' }
                    elseif ($daysLeft -lt 30) { $entry.status = 'EXPIRES_SOON' }
                    elseif ($daysLeft -lt 90) { $entry.status = 'EXPIRING' }
                }

                if ($cred.identity) { $entry.identity = $cred.identity }
                if ($cred.unregistered) { $entry.unregistered = $true }

                if ($ShowSecrets) {
                    try {
                        $secret = Get-Secret -Name $key -Vault $VaultName -AsPlainText -ErrorAction Stop
                        if ($secret.Length -gt 50) {
                            $entry.value = $secret.Substring(0, 20) + '...[truncated]'
                        } else {
                            $entry.value = $secret
                        }
                    } catch {
                        $entry.value = '[ERROR: could not retrieve]'
                    }
                }

                $credStatus[$key] = $entry
            }
            $result.credentials = $credStatus
        }
    }

    [PSCustomObject]$result
}
