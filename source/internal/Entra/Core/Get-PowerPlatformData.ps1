# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-PowerPlatformData {
    <#
    .SYNOPSIS
        Collect Copilot Studio agents (the Dataverse `bots` table) across Power
        Platform environments for the AIAGENT checks.

    .DESCRIPTION
        Copilot Studio agents live in Dataverse, not Graph. Collection is two-stage:
        (1) discover environments via the Global Discovery Service
            (globaldisco.crm.dynamics.com/api/discovery/v2.0/Instances), and
        (2) query each environment's Dataverse Web API `bots` table for unmanaged
            agents and map the security-relevant fields.

        AUTH: Dataverse uses a DIFFERENT token audience than Graph, and each
        environment is its own audience. This mirrors how Invoke-Infiltration
        already acquires a separate management.azure.com token for the Azure
        collector. -GlobalDiscoToken authenticates discovery; -TokenFactory is a
        scriptblock that returns a per-environment Dataverse token given an env URL
        (built from the same credentials via Get-GraphAccessToken -ResourceUrl).

        LIVE-VALIDATION REQUIRED: the endpoints and the `bots` field names are taken
        from the documented Copilot Studio schema, but the per-environment auth flow
        and the authenticationmode -> UserAuthenticationType mapping have not been
        exercised against a live Power Platform tenant. Any failure is recorded in
        Errors so the AIAGENT checks report Not Assessed — never a fabricated verdict.
        When no auth context is supplied the collector returns empty and the checks
        SKIP.
    #>
    [CmdletBinding()]
    param(
        [string]$GlobalDiscoToken,
        [scriptblock]$TokenFactory,
        [string]$GlobalDiscoBaseUrl = 'https://globaldisco.crm.dynamics.com',
        [switch]$Quiet
    )

    $data = @{
        Agents       = @()
        Environments = @()
        Errors       = @{}
    }

    if (-not $GlobalDiscoToken -or -not $TokenFactory) {
        # No Dataverse auth context wired — nothing collected, checks Not Assessed.
        $data.Errors['Agents'] = 'Dataverse auth context not provided; Copilot Studio agents not collected.'
        return $data
    }

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE -Message 'Discovering Power Platform environments (Dataverse)'
    }

    # ── 1. Discover environments ─────────────────────────────────────────
    try {
        $gdsHeaders = @{ Authorization = "Bearer $GlobalDiscoToken"; Accept = 'application/json' }
        $gdsUri = "$GlobalDiscoBaseUrl/api/discovery/v2.0/Instances?`$select=ApiUrl,FriendlyName,State&`$filter=State eq 0"
        $gds = Invoke-RestMethod -TimeoutSec 30 -Uri $gdsUri -Headers $gdsHeaders -Method Get -ErrorAction Stop
        $data.Environments = @($gds.value | ForEach-Object { @{ ApiUrl = $_.ApiUrl; Name = $_.FriendlyName } })
    } catch {
        $data.Errors['Agents'] = "Environment discovery failed: $($_.Exception.Message)"
        return $data
    }

    # ── 2. Query each environment's bots table ───────────────────────────
    $select = 'botid,name,accesscontrolpolicy,authenticationmode,authenticationtrigger,authorizedsecuritygroupids,statecode,statuscode,modifiedon,publishedon,schemaname'
    $agents = [System.Collections.Generic.List[object]]::new()
    foreach ($env in $data.Environments) {
        $apiUrl = $env.ApiUrl
        if (-not $apiUrl) { continue }
        try {
            $envToken = & $TokenFactory $apiUrl
            $headers = @{ Authorization = "Bearer $envToken"; Accept = 'application/json' }
            $botsUri = "$apiUrl/api/data/v9.2/bots?`$filter=ismanaged eq false&`$select=$select"
            $resp = Invoke-RestMethod -TimeoutSec 30 -Uri $botsUri -Headers $headers -Method Get -ErrorAction Stop
            foreach ($bot in @($resp.value)) {
                $agents.Add([pscustomobject]@{
                    AIAgentId                  = $bot.botid
                    AIAgentName                = $bot.name
                    EnvironmentId              = $env.Name
                    AccessControlPolicy        = $bot.accesscontrolpolicy
                    # NOTE: authenticationmode -> UserAuthenticationType mapping is
                    # best-effort pending live confirmation of the mode enumeration.
                    UserAuthenticationType     = $bot.authenticationmode
                    AuthenticationTrigger      = $bot.authenticationtrigger
                    AuthorizedSecurityGroupIds = @($bot.authorizedsecuritygroupids)
                    LastPublishedTime          = $bot.publishedon
                    LastModifiedTime           = $bot.modifiedon
                    SchemaName                 = $bot.schemaname
                })
            }
        } catch {
            $data.Errors["Env:$($env.Name)"] = $_.Exception.Message
        }
    }
    $data.Agents = @($agents)

    if (-not $Quiet) {
        Write-ProgressLine -Phase INFILTRATE `
            -Message "Copilot Studio: $($data.Agents.Count) agents across $($data.Environments.Count) environment(s)"
    }

    return $data
}
