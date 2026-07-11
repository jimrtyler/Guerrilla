# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Initialize-GuerrillaVault {
    <#
    .SYNOPSIS
        Ensures the Guerrilla SecretManagement vault exists and is configured.
    .DESCRIPTION
        Checks for required modules (SecretManagement + SecretStore), offers to
        install them if missing, registers the Guerrilla vault, and configures
        it for non-interactive use (DPAPI on Windows, encrypted file on Linux/macOS).
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'Guerrilla',
        [switch]$Force
    )

    # --- Check for required modules ---
    $smInstalled = Get-Module -ListAvailable -Name 'Microsoft.PowerShell.SecretManagement' -ErrorAction SilentlyContinue
    $ssInstalled = Get-Module -ListAvailable -Name 'Microsoft.PowerShell.SecretStore' -ErrorAction SilentlyContinue

    $missing = @()
    if (-not $smInstalled) { $missing += 'Microsoft.PowerShell.SecretManagement' }
    if (-not $ssInstalled) { $missing += 'Microsoft.PowerShell.SecretStore' }

    if ($missing.Count -gt 0) {
        $border = '=' * 60
        Write-Host ''
        Write-Host "  $($script:Palette.Amber)$border$($PSStyle.Reset)"
        Write-Host "  $($script:Palette.Parchment)  SAFEHOUSE PREREQUISITES$($PSStyle.Reset)"
        Write-Host "  $($script:Palette.Amber)$border$($PSStyle.Reset)"
        Write-Host ''
        Write-Host "  $($script:Palette.Khaki)  The following modules are required for secure credential$($PSStyle.Reset)"
        Write-Host "  $($script:Palette.Khaki)  storage and are not currently installed:$($PSStyle.Reset)"
        Write-Host ''
        foreach ($mod in $missing) {
            Write-Host "    $($script:Palette.Amber)* $mod$($PSStyle.Reset)"
        }
        Write-Host ''
        Write-Host "  $($script:Palette.Gray)  These are Microsoft's official credential management$($PSStyle.Reset)"
        Write-Host "  $($script:Palette.Gray)  modules from the PowerShell Gallery.$($PSStyle.Reset)"
        Write-Host "  $($script:Palette.Amber)$border$($PSStyle.Reset)"
        Write-Host ''

        if (-not $Force) {
            $response = Read-Host '  Install now? [Y/n]'
            if ($response -and $response -notmatch '^[Yy]') {
                throw 'SecretManagement modules are required. Install them manually or re-run with -Force.'
            }
        }

        foreach ($mod in $missing) {
            Write-Host "  Installing $mod..." -NoNewline
            try {
                Install-Module -Name $mod -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-Host " $($script:Palette.Sage)DONE$($PSStyle.Reset)"
            } catch {
                Write-Host " $($script:Palette.Amber)FAILED$($PSStyle.Reset)"
                throw "Failed to install $mod`: $_"
            }
        }

        # Import after install
        Import-Module Microsoft.PowerShell.SecretManagement -Force -ErrorAction Stop
        Import-Module Microsoft.PowerShell.SecretStore -Force -ErrorAction Stop
    } else {
        # Ensure modules are imported
        if (-not (Get-Module -Name 'Microsoft.PowerShell.SecretManagement')) {
            Import-Module Microsoft.PowerShell.SecretManagement -ErrorAction Stop
        }
        if (-not (Get-Module -Name 'Microsoft.PowerShell.SecretStore')) {
            Import-Module Microsoft.PowerShell.SecretStore -ErrorAction Stop
        }
    }

    # --- Register vault if not exists ---
    $existingVault = Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue
    if (-not $existingVault) {
        # Configure SecretStore BEFORE registering the vault so the store is created
        # with Authentication=None from the start, rather than defaulting to Password
        # and then needing the user to enter a password twice just to remove it.
        $needsConfig = $true
        try {
            $ssConfig = Get-SecretStoreConfiguration -ErrorAction Stop
            if ($ssConfig.Authentication -eq 'None') { $needsConfig = $false }
        } catch {
            # No store configured yet — Set-SecretStoreConfiguration below will create one.
        }
        if ($needsConfig) {
            try {
                Set-SecretStoreConfiguration -Authentication None -Interaction None `
                    -Password $null -Confirm:$false -Force -ErrorAction Stop
            } catch {
                Write-Warning "Could not auto-configure SecretStore for non-interactive use: $_"
                Write-Warning 'If prompted for a password next, it is from the Microsoft SecretStore module.'
            }
        }

        Write-Verbose "Registering vault '$VaultName' with SecretStore backend"
        Register-SecretVault -Name $VaultName -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault -ErrorAction Stop
        Write-Verbose "Vault '$VaultName' registered for non-interactive access"
    } else {
        Write-Verbose "Vault '$VaultName' already exists"
    }

    return @{
        VaultName = $VaultName
        Status    = 'Ready'
        Backend   = 'Microsoft.PowerShell.SecretStore'
        Protection = if ($IsWindows -or (-not (Test-Path variable:IsWindows))) { 'DPAPI (current user)' } else { 'Encrypted file (password-protected)' }
    }
}
