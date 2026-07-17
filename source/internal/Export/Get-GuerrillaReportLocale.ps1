# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Report localization. Two catalog kinds, both under Data/Locales:
#
#   report.<code>.json          the report SHELL: section titles, table headers,
#                               labels, executive-summary prose, footer notes.
#                               English (report.en.json) is the source; other
#                               locales carry { value, status } entries, the same
#                               provenance convention the GUI and website use.
#
#   checks/<code>/<family>.json  the report CONTENT: per-check translations keyed
#                               by CheckId, each { name, description,
#                               recommendedValue, remediationSteps } with a
#                               status. One file per check family so a reviewer
#                               can review one family at a time.
#
# The honest boundary: only STATIC check-definition text is translated. Live
# collected evidence (a finding's CurrentValue, affected accounts, attack-path
# strings) is rendered as collected, because it is data the scan observed, not
# authored prose. A missing translation (whole language, one check, or one
# field) falls back to English, so a partial catalog degrades to mixed-language,
# never to a blank report.

function Get-GuerrillaReportLocaleRoot {
    [CmdletBinding()]
    param()
    $base = $null
    try { $base = $ExecutionContext.SessionState.Module.ModuleBase } catch { }
    if (-not $base) { $base = Join-Path $PSScriptRoot '..' '..' }
    return (Join-Path $base 'Data' 'Locales')
}

function Get-GuerrillaReportLanguages {
    # Languages that have a report SHELL catalog (report.<code>.json). English
    # first, the rest alphabetical. A report language must have at least the
    # shell; check content can lag and fall back per key.
    [CmdletBinding()]
    param()

    $root = Get-GuerrillaReportLocaleRoot
    $langs = [System.Collections.Generic.List[object]]::new()
    foreach ($f in (Get-ChildItem -Path $root -Filter 'report.*.json' -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $doc = Get-Content $f.FullName -Raw | ConvertFrom-Json -AsHashtable
            $meta = $doc['_language']
            if ($meta -and $meta.code -and $meta.name) {
                $dir = if ("$($meta.direction)" -eq 'rtl') { 'rtl' } else { 'ltr' }
                $langs.Add([PSCustomObject]@{ Code = [string]$meta.code; Name = [string]$meta.name; Direction = $dir })
            }
        } catch { }
    }
    return @(@($langs | Where-Object Code -eq 'en') + @($langs | Where-Object Code -ne 'en' | Sort-Object Code))
}

function Resolve-GuerrillaReportLanguage {
    # Report language: explicit choice if that shell catalog exists, else the
    # GUI language if it has a report catalog, else the OS UI culture, else en.
    [CmdletBinding()]
    param([string]$Configured)

    $available = @((Get-GuerrillaReportLanguages).Code)
    if ($Configured -and $Configured -in $available) { return $Configured }
    if ($script:GuerrillaGuiLanguage -and $script:GuerrillaGuiLanguage -in $available) { return $script:GuerrillaGuiLanguage }
    try {
        $os = [System.Globalization.CultureInfo]::CurrentUICulture.TwoLetterISOLanguageName
        if ($os -in $available) { return $os }
    } catch { }
    return 'en'
}

# Flattened dot-key -> string table for the report shell, English as the
# fallback for any key a language does not carry. Cached per language.
$script:GuerrillaReportStringCache = @{}
function Get-GuerrillaReportStringTable {
    [CmdletBinding()]
    param([string]$Language = 'en')

    if ($script:GuerrillaReportStringCache.ContainsKey($Language)) {
        return $script:GuerrillaReportStringCache[$Language]
    }
    $root = Get-GuerrillaReportLocaleRoot

    $flatten = {
        param($Node, $Prefix, $Table)
        foreach ($k in $Node.Keys) {
            if ($k -like '_*') { continue }
            $key = if ($Prefix) { "$Prefix.$k" } else { $k }
            $v = $Node[$k]
            if ($v -is [System.Collections.IDictionary]) {
                if ($v.Contains('value')) { $Table[$key] = [string]$v['value'] }
                else { & $flatten $v $key $Table }
            } else {
                $Table[$key] = [string]$v
            }
        }
    }
    $load = {
        param($Code)
        $path = Join-Path $root "report.$Code.json"
        if (-not (Test-Path $path)) { return $null }
        try { Get-Content $path -Raw | ConvertFrom-Json -AsHashtable } catch { $null }
    }

    $table = @{}
    $en = & $load 'en'
    if ($en) { & $flatten $en '' $table }
    if ($Language -and $Language -ne 'en') {
        $loc = & $load $Language
        if ($loc) { & $flatten $loc '' $table }
    }
    $script:GuerrillaReportStringCache[$Language] = $table
    return $table
}

# Convenience: a scriptblock that looks up a report-shell key and HTML-encodes
# the result. Exporters do:  $t = Get-GuerrillaReportStringResolver -Language es
# then  $(& $t 'ad.title')  in place of the old literal, and
# $(& $t 'ioe.affected' $count)  for format strings.
function Get-GuerrillaReportStringResolver {
    [CmdletBinding()]
    param([string]$Language = 'en', [switch]$Raw)

    $table = Get-GuerrillaReportStringTable -Language $Language
    if ($Raw) {
        return {
            param([string]$Key)
            $s = $table[$Key]
            if ($null -eq $s) { return $Key }
            if ($args.Count -gt 0) { return ($s -f $args) }
            return $s
        }.GetNewClosure()
    }
    return {
        param([string]$Key)
        $s = $table[$Key]
        if ($null -eq $s) { $s = $Key }
        elseif ($args.Count -gt 0) { $s = $s -f $args }
        return [System.Web.HttpUtility]::HtmlEncode($s)
    }.GetNewClosure()
}

# Load the per-check translation table for a language: CheckId -> hashtable of
# translated fields. Missing file/field falls back to English at apply time.
# Cached per language.
$script:GuerrillaCheckContentCache = @{}
function Get-GuerrillaCheckContentTable {
    [CmdletBinding()]
    param([string]$Language)

    if (-not $Language -or $Language -eq 'en') { return @{} }
    if ($script:GuerrillaCheckContentCache.ContainsKey($Language)) {
        return $script:GuerrillaCheckContentCache[$Language]
    }
    $dir = Join-Path (Get-GuerrillaReportLocaleRoot) 'checks' $Language
    $table = @{}
    if (Test-Path $dir) {
        foreach ($f in (Get-ChildItem -Path $dir -Filter '*.json' -ErrorAction SilentlyContinue)) {
            try {
                $doc = Get-Content $f.FullName -Raw | ConvertFrom-Json -AsHashtable
                foreach ($id in $doc.Keys) {
                    if ($id -like '_*') { continue }
                    $table[[string]$id] = $doc[$id]
                }
            } catch { }
        }
    }
    $script:GuerrillaCheckContentCache[$Language] = $table
    return $table
}

# Return a copy of the findings with their STATIC definition text swapped to the
# target language (CheckName, Description, RecommendedValue, RemediationSteps,
# Category), leaving live evidence (CurrentValue, Details, Severity, Status,
# Compliance, CheckId) untouched. English passes through unchanged. Each
# translated field falls back to the original when the catalog lacks it.
function Get-GuerrillaLocalizedFindings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowNull()][PSCustomObject[]]$Findings,
        [string]$Language = 'en'
    )

    if (-not $Findings -or $Findings.Count -eq 0) { return @($Findings) }
    if (-not $Language -or $Language -eq 'en') { return @($Findings) }

    $content = Get-GuerrillaCheckContentTable -Language $Language
    if ($content.Count -eq 0) { return @($Findings) }

    # Map catalog field name -> finding property name. Category is deliberately
    # NOT here: findings group by Category, so the grouping key stays English
    # (stable even with a partial catalog) and only the printed category LABEL is
    # localized, via Get-GuerrillaLocalizedCategoryName at the render site.
    $fieldMap = [ordered]@{
        name             = 'CheckName'
        description      = 'Description'
        recommendedValue = 'RecommendedValue'
        remediationSteps = 'RemediationSteps'
    }
    $pick = {
        param($Entry, $Key)
        if (-not $Entry) { return $null }
        $v = $Entry[$Key]
        if ($null -eq $v) { return $null }
        if ($v -is [System.Collections.IDictionary]) { $v = $v['value'] }
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { return $null }
        return $s
    }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $Findings) {
        $entry = $content["$($f.CheckId)"]
        if (-not $entry) { $out.Add($f); continue }
        $clone = $f.PSObject.Copy()
        foreach ($ck in $fieldMap.Keys) {
            $t = & $pick $entry $ck
            if ($null -ne $t) { $clone.($fieldMap[$ck]) = $t }
        }
        $out.Add($clone)
    }
    return @($out)
}

# Localize a category display name via the shell catalog's `category` namespace,
# keyed by the English category name lowercased with non-alphanumerics stripped
# (e.g. "AD ACL & Delegation" -> category.adacldelegation). Returns the English
# name unchanged when no translation exists, so grouping keys stay English and
# only the label localizes.
function Get-GuerrillaLocalizedCategoryName {
    [CmdletBinding()]
    param([string]$Name, [string]$Language = 'en')

    if (-not $Name -or -not $Language -or $Language -eq 'en') { return $Name }
    $table = Get-GuerrillaReportStringTable -Language $Language
    $slug = 'category.' + ([regex]::Replace($Name.ToLower(), '[^a-z0-9]', ''))
    $v = $table[$slug]
    if ([string]::IsNullOrWhiteSpace($v)) { return $Name }
    return $v
}
