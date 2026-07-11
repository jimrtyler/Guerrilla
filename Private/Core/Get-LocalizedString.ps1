# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-LocalizedString {
    <#
    .SYNOPSIS
        Returns a localized string by key from the current language table.
    .DESCRIPTION
        Looks up a string key in the loaded localization data. Falls back to en-US
        if the key is not found in the active locale. Supports format string placeholders.
    .PARAMETER Key
        The dot-notation key path (e.g., 'report.executive.title').
    .PARAMETER Arguments
        Optional format arguments for placeholder substitution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key,

        [object[]]$Arguments
    )

    # Load string table if not cached
    if (-not $script:LocalizationStrings) {
        $language = $script:ReportLanguage ?? 'en-US'
        $locPath = Join-Path $script:ModuleRoot 'Data/Localization' "$language.json"
        if (-not (Test-Path $locPath)) {
            $locPath = Join-Path $script:ModuleRoot 'Data/Localization/en-US.json'
        }
        if (Test-Path $locPath) {
            $script:LocalizationStrings = Get-Content -Path $locPath -Raw | ConvertFrom-Json -AsHashtable
        } else {
            $script:LocalizationStrings = @{}
        }
    }

    # Navigate dot-notation path
    $current = $script:LocalizationStrings
    $segments = $Key.Split('.')
    foreach ($segment in $segments) {
        if ($current -is [hashtable] -and $current.ContainsKey($segment)) {
            $current = $current[$segment]
        } else {
            # Key not found, return the key itself as fallback
            return $Key
        }
    }

    if ($current -isnot [string]) { return $Key }

    # Apply format arguments
    if ($Arguments -and $Arguments.Count -gt 0) {
        try {
            return [string]::Format($current, $Arguments)
        } catch {
            return $current
        }
    }

    return $current
}
