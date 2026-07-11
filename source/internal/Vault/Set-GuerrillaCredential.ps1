# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Set-GuerrillaCredential {
    <#
    .SYNOPSIS
        Stores a credential in the Guerrilla SecretManagement vault.
    .DESCRIPTION
        Wrapper around Set-Secret that stores a value in the Guerrilla vault.
        Handles both string and SecureString values.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultKey,

        [Parameter(Mandatory)]
        [object]$Value,

        [Parameter()]
        [string]$VaultName = 'Guerrilla'
    )

    # Ensure vault exists
    $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if (-not $vault) {
        throw "Vault '$VaultName' not found. Run Initialize-GuerrillaVault first."
    }

    try {
        Set-Secret -Name $VaultKey -Secret $Value -Vault $VaultName -ErrorAction Stop
        Write-Verbose "Stored credential '$VaultKey' in vault '$VaultName'"
    } catch {
        throw "Failed to store credential '$VaultKey': $_"
    }
}
