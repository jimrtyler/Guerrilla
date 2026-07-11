# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Read-MissionConfig {
    <#
    .SYNOPSIS
        Reads and validates a guerrilla-config.json file.
    .DESCRIPTION
        Parses the website-generated configuration file and returns a structured
        object with environment settings, credential requirements, and audit scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Configuration file not found: $Path"
    }

    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        $config = $raw | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    } catch {
        throw "Failed to parse configuration file '$Path': $_"
    }

    # Validate required fields
    if (-not $config.version) {
        throw "Invalid configuration file: missing 'version' field. Is this a guerrilla-config.json from the Guerrilla website?"
    }

    # Build credential requirements list
    $credentialRequirements = [System.Collections.Generic.List[hashtable]]::new()

    if ($config.credentials -and $config.credentials.references) {
        $refs = $config.credentials.references

        # Google Workspace
        if ($refs.googleWorkspace) {
            $gwsRef = $refs.googleWorkspace
            if (-not $gwsRef.vaultKey) {
                throw "Configuration file '$Path': credentials.references.googleWorkspace is missing required 'vaultKey'."
            }
            $credentialRequirements.Add(@{
                vaultKey    = $gwsRef.vaultKey
                type        = $gwsRef.type
                environment = 'googleWorkspace'
                description = 'Google Workspace service account'
                promptType  = 'serviceAccountJson'
            })
        }

        # Microsoft Graph
        if ($refs.microsoftGraph) {
            $graphRef = $refs.microsoftGraph

            if ($graphRef.tenantIdVaultKey) {
                $credentialRequirements.Add(@{
                    vaultKey    = $graphRef.tenantIdVaultKey
                    type        = 'tenantId'
                    environment = 'microsoftGraph'
                    description = 'Entra ID Tenant ID'
                    promptType  = 'guid'
                })
            }

            if ($graphRef.clientIdVaultKey) {
                $credentialRequirements.Add(@{
                    vaultKey    = $graphRef.clientIdVaultKey
                    type        = 'clientId'
                    environment = 'microsoftGraph'
                    description = 'App Registration Client ID'
                    promptType  = 'guid'
                })
            }

            if ($graphRef.vaultKey) {
                $promptType = if ($graphRef.authMethod -eq 'certificate') { 'certificateThumbprint' } else { 'secret' }
                $desc = if ($graphRef.authMethod -eq 'certificate') { 'Certificate Thumbprint' } else { 'Client Secret' }
                $credentialRequirements.Add(@{
                    vaultKey    = $graphRef.vaultKey
                    type        = 'clientSecret'
                    environment = 'microsoftGraph'
                    description = "Microsoft Graph $desc"
                    promptType  = $promptType
                })
            }
        }

        # Active Directory
        if ($refs.activeDirectory -and $refs.activeDirectory.type -eq 'serviceAccount') {
            $credentialRequirements.Add(@{
                vaultKey    = if ($refs.activeDirectory.vaultKey) { $refs.activeDirectory.vaultKey } else { 'GUERRILLA_AD_CREDENTIAL' }
                type        = 'serviceAccount'
                environment = 'activeDirectory'
                description = 'Active Directory service account'
                promptType  = 'psCredential'
            })
        }
    }

    # Alerting channel credentials
    if ($config.alerting -and $config.alerting.channels) {
        foreach ($channel in $config.alerting.channels) {
            if ($channel.vaultKey) {
                $desc = switch ($channel.type) {
                    'teams'     { 'Microsoft Teams webhook URL' }
                    'slack'     { 'Slack webhook URL' }
                    'email'     { 'Email configuration (SMTP or API key)' }
                    'sms'       { 'Twilio credentials' }
                    'webhook'   { 'Webhook URL' }
                    'syslog'    { 'Syslog server configuration' }
                    'pagerduty' { 'PagerDuty routing key' }
                    'pushover'  { 'Pushover push notification credentials' }
                    default     { "$($channel.type) credential" }
                }

                $promptType = switch ($channel.type) {
                    'teams'     { 'url' }
                    'slack'     { 'url' }
                    'email'     { 'emailConfig' }
                    'sms'       { 'twilioConfig' }
                    'webhook'   { 'url' }
                    'syslog'    { 'syslogConfig' }
                    'pagerduty' { 'secret' }
                    'pushover'  { 'pushoverConfig' }
                    default     { 'secret' }
                }

                $credentialRequirements.Add(@{
                    vaultKey    = $channel.vaultKey
                    type        = 'webhook'
                    environment = 'alerting'
                    description = $desc
                    promptType  = $promptType
                })
            }
        }
    }

    # Build enabled environments list
    $enabledEnvironments = @{}
    if ($config.environments) {
        foreach ($envKey in $config.environments.Keys) {
            $env = $config.environments[$envKey]
            if ($env.enabled) {
                $enabledEnvironments[$envKey] = @{
                    audit      = if ($env.audit) { $env.audit } else { @{ enabled = $true } }
                    monitoring = if ($env.monitoring) { $env.monitoring } else { $null }
                }
            }
        }
    }

    # Extract mission mode (defaults to both if not specified for backwards compatibility)
    $missionMode = @{ reporting = $true; monitoring = $true }
    if ($config.missionMode) {
        if ($null -ne $config.missionMode.reporting) { $missionMode.reporting = $config.missionMode.reporting }
        if ($null -ne $config.missionMode.monitoring) { $missionMode.monitoring = $config.missionMode.monitoring }
    }

    return @{
        Version                = $config.version
        Config                 = $config
        MissionMode            = $missionMode
        EnabledEnvironments    = $enabledEnvironments
        CredentialRequirements = @($credentialRequirements)
        Reporting              = if ($config.reporting) { $config.reporting } else { $null }
        Alerting               = if ($config.alerting) { $config.alerting } else { $null }
        CredentialStrategy     = if ($config.credentials) { $config.credentials.strategy } else { 'secretManagement' }
        VaultName              = if ($config.credentials -and $config.credentials.vaultName) { $config.credentials.vaultName } else { 'Guerrilla' }
    }
}
