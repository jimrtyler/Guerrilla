# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADModuleAvailability {
    [CmdletBinding()]
    param()

    $result = @{
        ActiveDirectory = $false
        GroupPolicy     = $false
        DSInternals     = $false
        PSPKI           = $false
    }

    foreach ($moduleName in $result.Keys.Clone()) {
        try {
            $available = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
            $result[$moduleName] = ($null -ne $available -and @($available).Count -gt 0)
        } catch {
            $result[$moduleName] = $false
        }
    }

    return $result
}

function Assert-ADConnection {
    [CmdletBinding()]
    param(
        [string]$Server
    )

    try {
        $rootDsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }
        $rootDSE = [System.DirectoryServices.DirectoryEntry]::new($rootDsePath)
        [void]$rootDSE.Properties['defaultNamingContext']
        return $true
    } catch {
        return $false
    }
}
