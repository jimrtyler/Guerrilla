# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Hide-ConfigSecret {
    <#
    .SYNOPSIS
        Masks sensitive values in a deserialized config object in place.
    .DESCRIPTION
        Credentials belong in the SecretManagement vault, but configs written before
        the vault migration (or hand-edited ones) can still carry plaintext secrets.
        Get-Safehouse calls this before returning the config so those values are not
        echoed to the console or transcripts unless -ShowSecrets is passed.

        Walks the PSCustomObject graph produced by ConvertFrom-Json and replaces any
        non-empty string property whose name matches a known sensitive pattern.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $InputObject
    )

    $sensitiveNames = '^(apiKey|authToken|accountSid|clientSecret|webhookUrl|routingKey|integrationKey|userKey|appToken|password|secret)$'

    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        foreach ($item in $InputObject) { Hide-ConfigSecret -InputObject $item }
        return
    }

    if ($InputObject -isnot [System.Management.Automation.PSCustomObject]) { return }

    foreach ($prop in $InputObject.PSObject.Properties) {
        if ($prop.Value -is [string]) {
            if ($prop.Name -match $sensitiveNames -and $prop.Value) {
                $prop.Value = '********'
            }
        } elseif ($null -ne $prop.Value) {
            Hide-ConfigSecret -InputObject $prop.Value
        }
    }
}
