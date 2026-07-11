# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-GraphModuleAvailability {
    [CmdletBinding()]
    param()

    $availability = @{
        MSALPS                    = $false
        ExchangeOnlineManagement  = $false
        MicrosoftTeams            = $false
        PnPPowerShell             = $false
        PowerAppsAdmin            = $false
        AzAccounts                = $false
    }

    # MSAL.PS — token acquisition
    if (Get-Module -ListAvailable -Name 'MSAL.PS' -ErrorAction SilentlyContinue) {
        $availability.MSALPS = $true
    }

    # ExchangeOnlineManagement — Exchange Online, Defender for O365
    if (Get-Module -ListAvailable -Name 'ExchangeOnlineManagement' -ErrorAction SilentlyContinue) {
        $availability.ExchangeOnlineManagement = $true
    }

    # MicrosoftTeams — Teams admin
    if (Get-Module -ListAvailable -Name 'MicrosoftTeams' -ErrorAction SilentlyContinue) {
        $availability.MicrosoftTeams = $true
    }

    # PnP.PowerShell — SharePoint Online
    if (Get-Module -ListAvailable -Name 'PnP.PowerShell' -ErrorAction SilentlyContinue) {
        $availability.PnPPowerShell = $true
    }

    # Microsoft.PowerApps.Administration.PowerShell
    if (Get-Module -ListAvailable -Name 'Microsoft.PowerApps.Administration.PowerShell' -ErrorAction SilentlyContinue) {
        $availability.PowerAppsAdmin = $true
    }

    # Az.Accounts — Azure Resource Manager
    if (Get-Module -ListAvailable -Name 'Az.Accounts' -ErrorAction SilentlyContinue) {
        $availability.AzAccounts = $true
    }

    return $availability
}
