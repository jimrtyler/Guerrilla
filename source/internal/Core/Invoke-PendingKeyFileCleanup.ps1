# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Invoke-PendingKeyFileCleanup {
    <#
    .SYNOPSIS
        Offers to delete a credential source file after a successful vault write.
    .DESCRIPTION
        Read-CredentialValue stashes the path of a service-account key file the user
        pointed it at in $script:PendingKeySourceFile instead of deleting it inline.
        Callers invoke this immediately after Set-GuerrillaCredential succeeds so the
        only copy of a key is never destroyed before the vault actually holds it.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:PendingKeySourceFile) { return }

    $path = $script:PendingKeySourceFile
    $script:PendingKeySourceFile = $null

    if (-not (Test-Path $path)) { return }

    $deleteResponse = Read-Host "  Delete the original key file now that it's in the vault? [Y/n]"
    if (-not $deleteResponse -or $deleteResponse -match '^[Yy]') {
        try {
            Remove-Item -Path $path -Force -ErrorAction Stop
            Write-Host '  Original file deleted.'
        } catch {
            Write-Warning "Could not delete '$path': $_"
        }
    }
}
