# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Set-VaultMetadata {
    <#
    .SYNOPSIS
        Updates the Guerrilla vault metadata entry.
    .DESCRIPTION
        Stores or updates the GUERRILLA_VAULT_METADATA secret with JSON metadata
        about all credentials in the vault.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Metadata,

        [string]$VaultName = 'Guerrilla'
    )

    $metadataKey = 'GUERRILLA_VAULT_METADATA'

    # Ensure timestamps
    $now = [datetime]::UtcNow.ToString('o')
    if (-not $Metadata.created) {
        $Metadata.created = $now
    }
    $Metadata.lastModified = $now

    $json = $Metadata | ConvertTo-Json -Depth 10 -Compress
    Set-Secret -Name $metadataKey -Secret $json -Vault $VaultName -ErrorAction Stop
    Write-Verbose 'Vault metadata updated'
}
