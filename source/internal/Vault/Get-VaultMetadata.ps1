# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-VaultMetadata {
    <#
    .SYNOPSIS
        Reads the Guerrilla vault metadata entry.
    .DESCRIPTION
        Retrieves the GUERRILLA_VAULT_METADATA secret which stores JSON metadata
        about all credentials in the vault (stored dates, expiration, descriptions).
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'Guerrilla'
    )

    $metadataKey = 'GUERRILLA_VAULT_METADATA'

    try {
        $raw = Get-Secret -Name $metadataKey -Vault $VaultName -AsPlainText -ErrorAction Stop
        $metadata = $raw | ConvertFrom-Json -AsHashtable
        return $metadata
    } catch {
        # No metadata yet — return empty structure
        return @{
            created      = $null
            lastModified = $null
            credentials  = @{}
        }
    }
}
