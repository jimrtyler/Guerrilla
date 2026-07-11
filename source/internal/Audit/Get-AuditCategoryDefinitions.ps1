# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-AuditCategoryDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Category
    )

    $dataDir = Join-Path $script:ModuleRoot 'Data/AuditChecks'
    if (-not $script:ModuleRoot) {
        $dataDir = Join-Path $PSScriptRoot '../../Data/AuditChecks'
    }
    $filePath = Join-Path $dataDir "$Category.json"

    if (-not (Test-Path $filePath)) {
        throw "Audit check definitions not found: $filePath"
    }

    $defs = Get-Content -Path $filePath -Raw | ConvertFrom-Json -AsHashtable

    # Inject category name into each check for convenience
    foreach ($check in $defs.checks) {
        $check['_categoryName'] = $defs.categoryName
    }

    return $defs
}
