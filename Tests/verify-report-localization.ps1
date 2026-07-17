# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Report-localization gate. Two catalogs back a translated report:
#   report.<code>.json          the shell (titles, labels, prose)
#   checks/<code>/<family>.json  per-check content keyed by CheckId
# This gate holds every shipped report language to the same bar the GUI gate
# holds the interface to: shell completeness + provenance + placeholder parity,
# full check-content coverage against the real check universe, correct
# field/placeholder shape, category coverage, live-evidence preservation, and a
# poison self-test proving the scanner can fail. Run: pwsh -File Tests/verify-report-localization.ps1

$ErrorActionPreference = 'Stop'
$env:PSGUERRILLA_QUIET = '1'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'source' 'Guerrilla.psd1') -Force
$mod = Get-Module Guerrilla

$results = [System.Collections.Generic.List[object]]::new()
function Add-R($n, $ok, $d) { $results.Add([PSCustomObject]@{ Name = $n; Pass = [bool]$ok; Detail = $d }) }

$localeDir = Join-Path $root 'source' 'Data' 'Locales'
$checkDir  = Join-Path $root 'source' 'Data' 'AuditChecks'

# ── Source-of-truth check universe: id -> which text fields it actually has ──
$srcFields = @{}      # id -> [hashtable] field -> source string
$srcCategories = [System.Collections.Generic.HashSet[string]]::new()
foreach ($f in (Get-ChildItem -Path $checkDir -Filter '*.json')) {
    $doc = Get-Content $f.FullName -Raw | ConvertFrom-Json -AsHashtable
    if ($doc.categoryName) { [void]$srcCategories.Add([string]$doc.categoryName) }
    foreach ($c in @($doc.checks)) {
        $id = [string]$c.id
        if (-not $id) { continue }
        $fields = @{}
        foreach ($fld in 'name', 'description', 'recommendedValue', 'remediationSteps') {
            if ($c.ContainsKey($fld) -and "$($c[$fld])".Trim()) { $fields[$fld] = [string]$c[$fld] }
        }
        $srcFields[$id] = $fields
    }
}
$allIds = @($srcFields.Keys)
Add-R 'source check universe loaded (600+ checks)' ($allIds.Count -ge 600) "got=$($allIds.Count)"

# ── Shell catalog: en parses + declares ──
$en = $null
try { $en = Get-Content (Join-Path $localeDir 'report.en.json') -Raw | ConvertFrom-Json -AsHashtable } catch { }
Add-R 'report.en.json parses' ($null -ne $en) ''
Add-R 'report.en declares _language en' ($en -and $en._language.code -eq 'en') ''

function Get-FlatKeys([hashtable]$Node, [string]$Prefix = '') {
    foreach ($k in $Node.Keys) {
        if ($k -like '_*') { continue }
        $key = if ($Prefix) { "$Prefix.$k" } else { $k }
        $v = $Node[$k]
        if ($v -is [System.Collections.IDictionary] -and -not $v.Contains('value')) { Get-FlatKeys $v $key }
        else { [PSCustomObject]@{ Key = $key; Value = $v } }
    }
}
$enFlat = @(Get-FlatKeys $en)
$enKeys = @($enFlat.Key)
$enByKey = @{}; foreach ($e in $enFlat) { $enByKey[$e.Key] = "$($e.Value)" }
Add-R 'report.en shell is non-trivial (60+ keys)' ($enKeys.Count -ge 60) "got=$($enKeys.Count)"

# Category coverage: every source categoryName has a category.<slug> shell key.
$missingCat = [System.Collections.Generic.List[string]]::new()
foreach ($cat in $srcCategories) {
    $slug = 'category.' + ([regex]::Replace($cat.ToLower(), '[^a-z0-9]', ''))
    if ($slug -notin $enKeys) { $missingCat.Add($cat) }
}
Add-R 'every source category has an en shell label' ($missingCat.Count -eq 0) (($missingCat | Select-Object -First 5) -join ', ')

# ── Discover shipped report translations (report.<code>.json except en) ──
$reportLangs = @(Get-ChildItem -Path $localeDir -Filter 'report.*.json' |
    Where-Object Name -ne 'report.en.json' |
    ForEach-Object { ($_.Name -replace '^report\.', '') -replace '\.json$', '' })
Add-R 'at least one report translation shipped' ($reportLangs.Count -ge 1) "got=$($reportLangs -join ',')"

foreach ($code in $reportLangs) {
    $loc = $null
    try { $loc = Get-Content (Join-Path $localeDir "report.$code.json") -Raw | ConvertFrom-Json -AsHashtable } catch { }
    Add-R "$code shell parses + declares" ($loc -and $loc._language.code -eq $code) ''
    if (-not $loc) { continue }
    $locFlat = @(Get-FlatKeys $loc)
    $locKeys = @($locFlat.Key)
    $missing = @($enKeys | Where-Object { $_ -notin $locKeys })
    Add-R "$code shell carries every en key" ($missing.Count -eq 0) (($missing | Select-Object -First 6) -join ', ')
    $extra = @($locKeys | Where-Object { $_ -notin $enKeys })
    Add-R "$code shell has no orphan keys" ($extra.Count -eq 0) (($extra | Select-Object -First 5) -join ', ')
    $badShape = @($locFlat | Where-Object {
        -not ($_.Value -is [System.Collections.IDictionary] -and $_.Value.Contains('value') -and
              "$($_.Value['status'])" -in @('machine-draft', 'human-reviewed') -and "$($_.Value['value'])".Trim())
    })
    Add-R "$code shell entries are { value, status }" ($badShape.Count -eq 0) (($badShape.Key | Select-Object -First 5) -join ', ')
    $ph = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $locFlat) {
        if (-not $enByKey.ContainsKey($e.Key)) { continue }
        $want = @([regex]::Matches($enByKey[$e.Key], '\{\d+\}') | ForEach-Object Value | Sort-Object -Unique)
        $have = @([regex]::Matches("$($e.Value['value'])", '\{\d+\}') | ForEach-Object Value | Sort-Object -Unique)
        if (($want -join ',') -ne ($have -join ',')) { $ph.Add($e.Key) }
    }
    Add-R "$code shell placeholders match en" ($ph.Count -eq 0) (($ph | Select-Object -First 5) -join ', ')

    # ── Check-content coverage for this language ──
    $cdir = Join-Path $localeDir 'checks' $code
    $content = @{}
    if (Test-Path $cdir) {
        foreach ($cf in (Get-ChildItem -Path $cdir -Filter '*.json')) {
            $cd = Get-Content $cf.FullName -Raw | ConvertFrom-Json -AsHashtable
            foreach ($id in $cd.Keys) { if ($id -notlike '_*') { $content[[string]$id] = $cd[$id] } }
        }
    }
    $missIds = @($allIds | Where-Object { $_ -notin $content.Keys })
    Add-R "$code check content covers every check" ($missIds.Count -eq 0) "missing=$($missIds.Count): $(($missIds | Select-Object -First 6) -join ', ')"
    $orphanIds = @($content.Keys | Where-Object { $_ -notin $allIds })
    Add-R "$code check content has no unknown ids" ($orphanIds.Count -eq 0) (($orphanIds | Select-Object -First 5) -join ', ')

    # Field shape + coverage + placeholder parity against the SOURCE fields.
    $shapeBad = [System.Collections.Generic.List[string]]::new()
    $fieldMiss = [System.Collections.Generic.List[string]]::new()
    $phBad = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $allIds) {
        $entry = $content[$id]
        if (-not $entry) { continue }
        foreach ($fld in $srcFields[$id].Keys) {
            $tv = $entry[$fld]
            if (-not $tv) { $fieldMiss.Add("$id.$fld"); continue }
            if (-not ($tv -is [System.Collections.IDictionary] -and $tv.Contains('value') -and
                      "$($tv['status'])" -in @('machine-draft', 'human-reviewed') -and "$($tv['value'])".Trim())) {
                $shapeBad.Add("$id.$fld"); continue
            }
            $want = @([regex]::Matches($srcFields[$id][$fld], '\{\d+\}') | ForEach-Object Value | Sort-Object -Unique)
            $have = @([regex]::Matches("$($tv['value'])", '\{\d+\}') | ForEach-Object Value | Sort-Object -Unique)
            if (($want -join ',') -ne ($have -join ',')) { $phBad.Add("$id.$fld") }
        }
    }
    Add-R "$code check fields cover every source field" ($fieldMiss.Count -eq 0) "missing=$($fieldMiss.Count): $(($fieldMiss | Select-Object -First 6) -join ', ')"
    Add-R "$code check fields are { value, status }" ($shapeBad.Count -eq 0) (($shapeBad | Select-Object -First 5) -join ', ')
    Add-R "$code check field placeholders match source" ($phBad.Count -eq 0) (($phBad | Select-Object -First 5) -join ', ')

    # Every source category has a translated shell label too.
    $catMiss = [System.Collections.Generic.List[string]]::new()
    foreach ($cat in $srcCategories) {
        $slug = 'category.' + ([regex]::Replace($cat.ToLower(), '[^a-z0-9]', ''))
        if ($slug -notin $locKeys) { $catMiss.Add($cat) }
    }
    Add-R "$code translates every category label" ($catMiss.Count -eq 0) (($catMiss | Select-Object -First 5) -join ', ')
}

# ── Loader behavior through the module (use es if present, else first translation) ──
$probe = if ('es' -in $reportLangs) { 'es' } elseif ($reportLangs.Count) { $reportLangs[0] } else { $null }
if ($probe) {
    $behav = & $mod {
        param($lang, $sampleId, $enName)
        $t  = Get-GuerrillaReportStringResolver -Language $lang -Raw
        $en = Get-GuerrillaReportStringResolver -Language 'en' -Raw
        $f = [pscustomobject]@{
            PSTypeName = 'Guerrilla.AuditFinding'; CheckId = $sampleId; CheckName = $enName
            Description = 'ENGLISH-DESC'; RecommendedValue = 'rec'; RemediationSteps = 'ENGLISH-REM'
            Category = 'PrivilegedAccounts'; CurrentValue = 'LIVE-EVIDENCE-42'; Severity = 'High'; Status = 'FAIL'; Details = @{}
        }
        $loc = Get-GuerrillaLocalizedFindings -Findings $f -Language $lang
        [pscustomobject]@{
            MissingKeyFallsBack = ((& $t 'no.such.key') -eq 'no.such.key')
            EvidenceStaysLive   = ($loc[0].CurrentValue -eq 'LIVE-EVIDENCE-42')
            NameChanged         = ($loc[0].CheckName -ne $enName -and "$($loc[0].CheckName)".Trim())
            EnglishUnchanged    = ((Get-GuerrillaLocalizedFindings -Findings $f -Language 'en')[0].CheckName -eq $enName)
        }
    } $probe ($allIds | Select-Object -First 1) ($srcFields[($allIds | Select-Object -First 1)]['name'])
    Add-R "loader: unknown shell key falls back" $behav.MissingKeyFallsBack ''
    Add-R "loader: live evidence not translated" $behav.EvidenceStaysLive ''
    Add-R "loader ($probe): check name is localized" $behav.NameChanged ''
    Add-R "loader: English findings pass through unchanged" $behav.EnglishUnchanged ''

    # Poison self-test: a finding with a bogus CheckId must be returned unchanged.
    $poison = & $mod {
        param($lang)
        $f = [pscustomobject]@{ PSTypeName = 'Guerrilla.AuditFinding'; CheckId = 'ZZZ-NOT-A-REAL-CHECK-999'; CheckName = 'PoisonName'; Description = 'd'; RecommendedValue = 'r'; RemediationSteps = 's'; Category = 'X'; CurrentValue = 'v'; Severity = 'Low'; Status = 'PASS'; Details = @{} }
        (Get-GuerrillaLocalizedFindings -Findings $f -Language $lang)[0].CheckName -eq 'PoisonName'
    } $probe
    Add-R 'poison: unknown CheckId is left untranslated (fallback proven)' $poison ''
}

$pass = @($results | Where-Object Pass).Count
$total = $results.Count
Write-Host ''
foreach ($x in $results) {
    $mark = if ($x.Pass) { '[PASS]' } else { '[FAIL]' }
    $line = "  $mark $($x.Name)"; if ($x.Detail) { $line += "  ($($x.Detail))" }
    Write-Host $line
}
Write-Host ''
Write-Host "  RESULT: $pass / $total passed"
if ($pass -ne $total) { exit 1 }
