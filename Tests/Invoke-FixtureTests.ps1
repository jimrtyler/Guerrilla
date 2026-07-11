#requires -version 7.0
<#
.SYNOPSIS
    Run the golden-fixture check suite, print a summary, and optionally publish
    the results to a local SQLite database for historical tracking.

.DESCRIPTION
    Executes every fixture under Tests/Fixtures/ against its real check function
    using the shared helpers in Tests/Helpers/TestHelpers.psm1 (the same code the
    Pester suite uses). Exits non-zero if any check's actual Status does not match
    its expected Status, so this can gate CI.

.PARAMETER Publish
    Also append the run + per-check rows to a local SQLite file (offline; no network).
    The database is created on first use. Override the location with -DbPath.

.PARAMETER DbPath
    SQLite file to publish to. Defaults to the migrated local copy under
    ~/Documents/Guerrilla-Data/ (see Tests/Local/Publish-GuerrillaTestResultsSqlite.ps1).

.EXAMPLE
    pwsh Tests/Invoke-FixtureTests.ps1

.EXAMPLE
    pwsh Tests/Invoke-FixtureTests.ps1 -Publish
#>
[CmdletBinding()]
param(
    [switch]$Publish,
    [string]$DbPath,
    # Write a machine-readable test-summary.json. This is the single artifact the
    # website renders every count from, so a public number can never be stale: the
    # only way it updates is a green run of this suite.
    [string]$EmitSummary
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

Import-Module (Join-Path $root 'Helpers' 'TestHelpers.psm1') -Force
Import-Guerrilla

$theaterByFamily = @{ AD = 'Reconnaissance'; Entra = 'Infiltration'; GoogleWorkspace = 'Fortification' }

$cases = Get-GuerrillaFixtureCases
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$results = foreach ($c in $cases) {
    $actual = 'ERROR'
    try {
        $finding = Invoke-GuerrillaCheckFixture -AuditData $c.AuditData -Definition $c.Definition -FunctionName $c.FunctionName
        $actual = "$($finding.Status)"
    } catch {
        $actual = "ERROR: $($_.Exception.Message)"
    }
    [PSCustomObject]@{
        CheckId        = $c.CheckId
        Family         = $c.Family
        Theater        = $theaterByFamily[$c.Family]
        Scenario       = $c.Scenario
        Severity       = $c.Definition.severity
        ExpectedStatus = $c.ExpectedStatus
        ActualStatus   = $actual
        Passed         = ($actual -eq $c.ExpectedStatus)
        FixtureFile    = $c.FixtureFile
        Description    = $c.Description
    }
}
$sw.Stop()

$results | Sort-Object Family, CheckId, Scenario |
    Format-Table CheckId, Scenario, ExpectedStatus, ActualStatus, Passed -AutoSize | Out-Host

$passed = @($results | Where-Object Passed).Count
$failed = @($results | Where-Object { -not $_.Passed }).Count
Write-Host ("`n{0} checks, {1} fixtures: {2} passed, {3} failed in {4} ms" -f `
    (@($results | Select-Object -Unique CheckId).Count), $results.Count, $passed, $failed, $sw.ElapsedMilliseconds)

if ($failed -gt 0) {
    Write-Host "FAILURES:" -ForegroundColor Red
    $results | Where-Object { -not $_.Passed } |
        ForEach-Object { Write-Host ("  {0} [{1}] expected {2} got {3}" -f $_.CheckId, $_.Scenario, $_.ExpectedStatus, $_.ActualStatus) -ForegroundColor Red }
}

# --- Branch-coverage assertion (opt-in per check via verdictPaths) -------------
# A scalar check has three verdict branches; a multi-field check has one per field
# it inspects, and three fixtures cover a third of it while wearing the same badge.
# A check that DECLARES its verdict paths (authored by reading the function, not the
# fixtures) must ship a fixture exercising each named path, or the run fails. This is
# how a multi-field check proves every branch instead of proving that some fixture
# passed. Checks that do not declare paths are not gated here; the catalog badges
# them by observed coverage so the claim on the page stays honest either way.
$defByCheck = @{}
foreach ($c in $cases) { if (-not $defByCheck.ContainsKey($c.CheckId)) { $defByCheck[$c.CheckId] = $c.Definition } }
$branchGaps = @()
foreach ($g in ($results | Group-Object CheckId)) {
    $declared = $defByCheck[$g.Name].verdictPaths
    if (-not $declared) { continue }
    $observed = @($g.Group.Scenario)
    foreach ($p in $declared) {
        if ($observed -notcontains $p) { $branchGaps += "  $($g.Name): declared verdict path '$p' has no fixture" }
    }
}
if ($branchGaps.Count -gt 0) {
    Write-Host "`nBRANCH-COVERAGE FAILURES (declared verdict path with no fixture):" -ForegroundColor Red
    $branchGaps | ForEach-Object { Write-Host $_ -ForegroundColor Red }
}

if ($EmitSummary) {
    # Universe of checks = the schema-tested definitions, counted here (not stored).
    $defIds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($jf in Get-ChildItem (Join-Path $root '..' 'source' 'Data' 'AuditChecks' '*.json')) {
        foreach ($c in (Get-Content $jf.FullName -Raw | ConvertFrom-Json).checks) { [void]$defIds.Add($c.id) }
    }
    # Fixtures on disk vs fixtures the run actually executed. Divergence means an
    # orphaned fixture file or a silently skipped fixture: fail rather than lie.
    $fixtureFilesOnDisk = @(Get-ChildItem (Join-Path $root 'Fixtures') -Recurse -Filter '*.json' -File).Count
    if ($fixtureFilesOnDisk -ne $results.Count) {
        Write-Host ("FATAL: {0} fixture files on disk but {1} executed (orphaned or skipped fixtures)" -f $fixtureFilesOnDisk, $results.Count) -ForegroundColor Red
        exit 2
    }

    $perCheck = [ordered]@{}
    foreach ($g in ($results | Group-Object CheckId | Sort-Object Name)) {
        # Guard the @($null) trap: a check with no verdictPaths must yield an EMPTY
        # array (count 0), not @($null) (count 1), or every check falsely reads 'declared'.
        $rawPaths = $defByCheck[$g.Name].verdictPaths
        $declared = if ($null -eq $rawPaths) { @() } else { @($rawPaths) }
        $perCheck[$g.Name] = [ordered]@{
            fixtureCount = $g.Count
            allPassed    = (@($g.Group | Where-Object { -not $_.Passed }).Count -eq 0)
            theater      = $g.Group[0].Theater
            severity     = "$($g.Group[0].Severity)"
            # branchCoverage: 'declared' means the check enumerated its verdict paths and
            # every one is fixture-proven (asserted above). 'observed' means we only know
            # the verdicts the existing fixtures happen to exercise. The badge must not
            # claim full branch coverage for 'observed'.
            declaredPaths  = $declared
            branchCoverage = ($declared.Count -gt 0 ? 'declared' : 'observed')
            verdictsProven = @($g.Group.ExpectedStatus | Sort-Object -Unique)
            scenarios    = @($g.Group | Sort-Object Scenario | ForEach-Object {
                [ordered]@{ scenario = $_.Scenario; expected = $_.ExpectedStatus; actual = $_.ActualStatus; passed = [bool]$_.Passed }
            })
        }
    }

    $artifact = [ordered]@{
        schemaVersion      = 1
        suite              = 'golden-fixtures'
        generatedAt        = (Get-Date).ToUniversalTime().ToString('o')
        moduleVersion      = "$((Import-PowerShellDataFile (Join-Path $root '..' 'source' 'Guerrilla.psd1')).ModuleVersion)"
        gitSha             = "$(git rev-parse --short HEAD 2>$null)"
        gitBranch          = "$(git rev-parse --abbrev-ref HEAD 2>$null)"
        checkDefinitions   = $defIds.Count          # the universe (618)
        checksTested       = @($results | Select-Object -Unique CheckId).Count
        fixtureFilesOnDisk = $fixtureFilesOnDisk
        fixtureCount       = $results.Count          # executed
        passed             = $passed
        failed             = $failed
        durationMs         = [int]$sw.ElapsedMilliseconds
        perCheck           = $perCheck
    }
    $dir = Split-Path -Parent $EmitSummary
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $artifact | ConvertTo-Json -Depth 8 | Set-Content -Path $EmitSummary -Encoding utf8
    Write-Host ("Wrote test-summary.json: {0} definitions, {1} tested, {2} fixtures, {3} failed -> {4}" -f `
        $artifact.checkDefinitions, $artifact.checksTested, $artifact.fixtureCount, $artifact.failed, $EmitSummary) -ForegroundColor Green
}

if ($Publish) {
    $gitSha    = (git rev-parse --short HEAD 2>$null)
    $gitBranch = (git rev-parse --abbrev-ref HEAD 2>$null)
    $summary = @{
        suite          = 'golden-fixtures'
        git_sha        = "$gitSha"
        git_branch     = "$gitBranch"
        host           = [System.Net.Dns]::GetHostName()
        runner         = $env:USER ?? $env:USERNAME
        total          = $results.Count
        passed         = $passed
        failed         = $failed
        duration_ms    = [int]$sw.ElapsedMilliseconds
        module_version = "$((Import-PowerShellDataFile (Join-Path $root '..' 'source' 'Guerrilla.psd1')).ModuleVersion)"
    }
    $publishArgs = @{ Summary = $summary; Results = $results }
    if ($DbPath) { $publishArgs.DbPath = $DbPath }
    & (Join-Path $root 'Local' 'Publish-GuerrillaTestResultsSqlite.ps1') @publishArgs
}

exit (($failed -gt 0 -or $branchGaps.Count -gt 0) ? 1 : 0)
