# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Save-SafehouseCredentialSet {
    <#
    .SYNOPSIS
        Non-interactively stores a set of credential entries into the vault and registers
        their metadata in one pass. Backs the GUI "Add Credential" modal.
    .DESCRIPTION
        Each entry is a hashtable/object with: VaultKey, Value, Type, Environment,
        Description, and optionally Identity / ExpirationDate. For every entry this writes
        the secret (Set-GuerrillaCredential) and a matching metadata record, so the new
        credential shows up in every status surface (Get-SafehouseCredentialView reconciles
        anyway, but registering metadata keeps the description/date/identity rich).
        Returns the number of entries stored.
    .PARAMETER Entries
        One or more credential entries to store.
    .PARAMETER VaultName
        Target vault. Default: Guerrilla.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][object[]]$Entries,
        [string]$VaultName = 'Guerrilla'
    )

    $metadata = Get-VaultMetadata -VaultName $VaultName
    if (-not $metadata) { $metadata = @{ created = $null; lastModified = $null; credentials = @{} } }
    if (-not $metadata.credentials) { $metadata.credentials = @{} }

    $stored = 0
    foreach ($e in $Entries) {
        if (-not $e.VaultKey) { continue }
        if ($null -eq $e.Value -or "$($e.Value)" -eq '') { continue }
        if (-not $PSCmdlet.ShouldProcess($e.VaultKey, 'Store credential')) { continue }

        Set-GuerrillaCredential -VaultKey $e.VaultKey -Value $e.Value -VaultName $VaultName

        $meta = @{
            type        = $e.Type
            environment = $e.Environment
            storedDate  = [datetime]::UtcNow.ToString('o')
            description = $e.Description
        }
        if ($e.Identity)       { $meta.identity = $e.Identity }
        if ($e.ExpirationDate) { $meta.expirationDate = $e.ExpirationDate }
        $metadata.credentials[$e.VaultKey] = $meta
        $stored++
    }

    if ($stored -gt 0) {
        if (-not $metadata.created) { $metadata.created = [datetime]::UtcNow.ToString('o') }
        $metadata.lastModified = [datetime]::UtcNow.ToString('o')
        Set-VaultMetadata -Metadata $metadata -VaultName $VaultName
    }
    return $stored
}
