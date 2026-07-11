# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-SafehouseSecret {
    <#
    .SYNOPSIS
        Reads a secret from the safehouse vault, returning $null on any miss.
    .DESCRIPTION
        A graceful counterpart to Get-GuerrillaCredential. Where Get-GuerrillaCredential
        THROWS when a credential is missing (correct for the mission-config path, where a
        referenced key must exist), this returns $null when SecretManagement isn't
        installed, the vault doesn't exist, or the key isn't stored.

        It exists for "fall back to the safehouse" credential resolution: scan cmdlets
        call it for the default vault keys (GUERRILLA_GWS_SA, GUERRILLA_GRAPH_TENANT, …)
        as a last resort after parameters and config.json, where a miss is normal and
        should not be an error.
    .PARAMETER VaultKey
        The secret name to read (e.g. 'GUERRILLA_GWS_SA').
    .PARAMETER VaultName
        The SecretManagement vault. Default: Guerrilla.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultKey,

        [string]$VaultName = 'Guerrilla'
    )

    if (-not (Get-Command Get-SecretVault -ErrorAction SilentlyContinue)) { return $null }

    $tryVault = {
        param($v)
        if (-not (Get-SecretVault -Name $v -ErrorAction SilentlyContinue)) { return $null }
        try { Get-Secret -Name $VaultKey -Vault $v -AsPlainText -ErrorAction Stop } catch { $null }
    }

    $val = & $tryVault $VaultName
    if (-not [string]::IsNullOrEmpty($val)) { return $val }

    # Back-compat: the module was renamed PSGuerrilla -> Guerrilla, changing the default
    # vault name. If the current default vault has no value, fall back to a legacy
    # 'PSGuerrilla' vault so an existing install's safehouse credentials keep resolving.
    if ($VaultName -eq 'Guerrilla') {
        return (& $tryVault 'PSGuerrilla')
    }
    return $null
}
