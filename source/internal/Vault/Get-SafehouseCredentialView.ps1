# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-SafehouseCredentialView {
    <#
    .SYNOPSIS
        Returns the reconciled credential view for the vault.
    .DESCRIPTION
        The vault metadata (GUERRILLA_VAULT_METADATA) is the source of friendly
        descriptions/dates/expiry, but some store paths historically wrote a secret
        without registering metadata (the interactive admin-email write, Pushover, a
        bare MAILGUN key from an older version). Those secrets are present and working
        but invisible to any metadata-only status surface — a real troubleshooting blind
        spot ("are my creds loaded?" answered "no" when the secret is actually there).

        This helper enumerates the ACTUAL secret store (Get-SecretInfo) and reconciles it
        with the metadata, so every present secret shows up. Metadata-backed entries keep
        their rich fields; present-but-unregistered keys get a best-effort synthetic entry
        flagged with .unregistered = $true (so callers can surface "stored, no metadata").

        Returns a hashtable keyed by vault key name -> credential entry (hashtable).
    #>
    [CmdletBinding()]
    param(
        [string]$VaultName = 'Guerrilla'
    )

    $metadata = Get-VaultMetadata -VaultName $VaultName
    $view = @{}
    if ($metadata.credentials) {
        foreach ($k in $metadata.credentials.Keys) { $view[$k] = $metadata.credentials[$k] }
    }

    # Reconcile with the real store so present-but-unregistered keys are not hidden.
    if (Get-Command Get-SecretInfo -ErrorAction SilentlyContinue) {
        $actual = @()
        try { $actual = @(Get-SecretInfo -Vault $VaultName -ErrorAction Stop) } catch {}
        foreach ($info in $actual) {
            $name = [string]$info.Name
            if (-not $name -or $name -eq 'GUERRILLA_VAULT_METADATA') { continue }
            if ($view.ContainsKey($name)) { continue }
            $view[$name] = @{
                description  = (Resolve-SafehouseKeyLabel -Key $name)
                environment  = (Resolve-SafehouseKeyEnvironment -Key $name)
                type         = 'unregistered'
                storedDate   = $null
                unregistered = $true
            }
        }
    }

    return $view
}

function Resolve-SafehouseKeyLabel {
    # Best-effort friendly label for a vault key that has no metadata entry.
    [CmdletBinding()]
    param([string]$Key)
    switch -Regex ($Key) {
        '_ADMIN_EMAIL$'          { return 'Google Workspace admin email' }
        '^GUERRILLA_GWS_SA$'     { return 'Google Workspace service account' }
        '^GUERRILLA_GRAPH_TENANT$'   { return 'Entra ID Tenant ID' }
        '^GUERRILLA_GRAPH_CLIENTID$' { return 'App Registration Client ID' }
        '^GUERRILLA_GRAPH_SECRET$'   { return 'Microsoft Graph Client Secret' }
        'TEAMS'                  { return 'Microsoft Teams webhook' }
        'SLACK'                  { return 'Slack webhook' }
        'SENDGRID'               { return 'SendGrid API key' }
        'MAILGUN'                { return 'Mailgun email configuration' }
        'PAGERDUTY'              { return 'PagerDuty routing key' }
        'PUSHOVER'               { return 'Pushover alert credential' }
        default                  { return $Key }
    }
}

function Resolve-SafehouseKeyEnvironment {
    # Best-effort environment bucket for an unregistered vault key.
    [CmdletBinding()]
    param([string]$Key)
    switch -Regex ($Key) {
        'GWS|GOOGLE'                                  { return 'googleWorkspace' }
        'GRAPH'                                       { return 'microsoftGraph' }
        'TEAMS|SLACK|SENDGRID|MAILGUN|PAGERDUTY|PUSHOVER' { return 'alerting' }
        default                                       { return 'other' }
    }
}
