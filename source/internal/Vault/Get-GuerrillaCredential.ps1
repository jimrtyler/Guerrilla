# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaCredential {
    <#
    .SYNOPSIS
        Resolves a credential from the Guerrilla SecretManagement vault.
    .DESCRIPTION
        Primary credential resolver used by all audit and monitoring functions.
        Retrieves secrets from the SecretManagement vault. Throws a helpful error
        if the credential is not found.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$VaultKey,

        [Parameter()]
        [string]$VaultName = 'Guerrilla'
    )

    # Check if vault exists
    $vault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if (-not $vault) {
        throw [System.Security.Authentication.AuthenticationException]::new(
            "Vault '$VaultName' not found. Run Set-Safehouse to configure credentials."
        )
    }

    try {
        $secret = Get-Secret -Name $VaultKey -Vault $VaultName -AsPlainText -ErrorAction Stop
        return $secret
    } catch {
        $msg = "Credential '$VaultKey' not found in vault '$VaultName'. " +
               'Run Set-Safehouse to configure credentials, or ' +
               'Set-Safehouse -ConfigFile .\guerrilla-config.json to set up from a config file.'
        throw [System.Security.Authentication.AuthenticationException]::new($msg)
    }
}
