# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-EntraRiskySignIn {
    [CmdletBinding()]
    param(
        [hashtable[]]$SignInEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    $riskyLevels = @('high', 'medium')

    foreach ($event in $SignInEvents) {
        $riskLevel = $event.RiskLevelDuringSignIn
        if (-not $riskLevel -or $riskLevel -eq 'none' -or $riskLevel -eq 'hidden') { continue }

        if ($riskLevel -in $riskyLevels) {
            $results.Add([PSCustomObject]@{
                Timestamp         = $event.Timestamp
                UserPrincipalName = $event.UserPrincipalName
                IpAddress         = $event.IpAddress
                RiskLevel         = $riskLevel
                RiskState         = $event.RiskState
                AppDisplayName    = $event.AppDisplayName
                ClientAppUsed     = $event.ClientAppUsed
                Location          = $event.Location
                IsInteractive     = $event.IsInteractive
            })
        }
    }

    return @($results)
}
