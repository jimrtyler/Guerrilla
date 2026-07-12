# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution

function Get-GuerrillaRunHistoryRoot {
    <#
    .SYNOPSIS
        The per-user run-history directory.
    .DESCRIPTION
        Product principle: the run history is created per-user on first run,
        lives on the user's machine under the user's data root, and involves
        zero telemetry and zero network. It is the user's file.
    #>
    [CmdletBinding()]
    param([string]$DataRoot)
    if (-not $DataRoot) { $DataRoot = Get-GuerrillaDataRoot }
    Join-Path $DataRoot 'RunHistory'
}

function Read-GuerrillaRunIndex {
    <#
    .SYNOPSIS
        Reads and validates the run-history index.json; $null when missing or invalid.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$IndexPath)
    if (-not (Test-Path $IndexPath)) { return $null }
    try {
        $idx = Get-Content -Path $IndexPath -Raw | ConvertFrom-Json
        if ($idx.schemaVersion -eq 1 -and $idx.store -eq 'guerrilla-run-history') { return $idx }
    } catch {
        Write-Verbose "RunHistory: index.json unreadable: $_"
    }
    return $null
}

function Write-GuerrillaRunIndex {
    <#
    .SYNOPSIS
        Persists the run-history index atomically (temp file + rename).
    .DESCRIPTION
        Every index write goes through here so a crash mid-write can never leave
        a truncated index.json — the same guarantee the run records already had.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$IndexPath,
        [Parameter(Mandatory)]$Index
    )
    $tmpPath = "$IndexPath.tmp"
    $Index | ConvertTo-Json -Depth 6 | Set-Content -Path $tmpPath -Encoding utf8
    Move-Item -Path $tmpPath -Destination $IndexPath -Force
}

function New-GuerrillaRunIndexEntry {
    <#
    .SYNOPSIS
        Builds the per-run index entry: everything Get-GuerrillaPreviousRun needs
        to locate the newest comparable baseline without parsing every record.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter(Mandatory)][string]$FileName
    )
    [ordered]@{
        file          = $FileName
        runId         = "$($Record.runId)"
        generatedAt   = "$($Record.generatedAt)"
        schemaVersion = $Record.schemaVersion
        targetHash    = "$($Record.scope.targetHash)"
        platforms     = @($Record.scope.platforms | Sort-Object | ForEach-Object { "$_" })
        ouScope       = Get-GuerrillaOuScopeString -TargetOu "$($Record.scope.targetOu)" `
            -StudentOu @($Record.scope.studentOus | ForEach-Object { "$_" })
    }
}

function Get-GuerrillaRunIndexEntriesFromRecords {
    <#
    .SYNOPSIS
        Rebuilds the index entry list deterministically from the run-*.json records
        on disk. Records are the source of truth; the index is only a locator.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Root)
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($file in (Get-ChildItem -Path $Root -Filter 'run-*.json' -File -ErrorAction SilentlyContinue | Sort-Object Name)) {
        try {
            $rec = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        } catch {
            Write-Verbose "RunHistory: skipping unreadable record $($file.Name) during index rebuild: $_"
            continue
        }
        if ($null -eq $rec.runId -or $null -eq $rec.generatedAt -or $null -eq $rec.scope) {
            Write-Verbose "RunHistory: skipping non-record file $($file.Name) during index rebuild."
            continue
        }
        $entries.Add((New-GuerrillaRunIndexEntry -Record $rec -FileName $file.Name))
    }
    return @($entries)
}

function Save-GuerrillaRunRecord {
    <#
    .SYNOPSIS
        Persist a completed run's record to the per-user run history.
    .DESCRIPTION
        Called only at the end of a COMPLETED assessment: a crashed or partial
        run writes nothing, so it can never become a comparison baseline.

        Index handling: the index.json carries a locator entry per record so
        baseline lookup does not have to parse every record. If records exist
        but the index is missing or unparseable (the anti-fork condition), the
        index is REBUILT from the records on disk with a loud warning instead
        of refusing forever — a permanent refusal would silently stop run
        recording while comparisons kept reading an ever-staler baseline.
        Records are the source of truth, so a rebuild cannot fork history; it
        re-derives the same locator data.

        All writes — records and every index write — are atomic (temp file +
        rename) so a crash mid-write cannot leave a truncated file that later
        parses as a baseline.

        Retention: after a successful write, each comparison series (target
        hash + platform set) is pruned to the most recent MaxRunsPerSeries
        records so the history cannot grow unbounded.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [string]$DataRoot,

        # Most recent records kept per comparison series (targetHash + platform set).
        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxRunsPerSeries = 200
    )

    foreach ($required in 'schemaVersion', 'generatedAt', 'runId', 'scope', 'checks') {
        if ($null -eq $Record.$required) {
            throw "Run record is missing '$required'; refusing to persist an incomplete record."
        }
    }

    $root = Get-GuerrillaRunHistoryRoot -DataRoot $DataRoot
    $indexPath = Join-Path $root 'index.json'

    if (-not (Test-Path $root)) {
        New-Item -ItemType Directory -Path $root -Force | Out-Null
    }

    $existingRuns = @(Get-ChildItem -Path $root -Filter 'run-*.json' -File -ErrorAction SilentlyContinue)
    $index = Read-GuerrillaRunIndex -IndexPath $indexPath

    $runsList = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $index) {
        if ($existingRuns.Count -gt 0) {
            # Records but no valid index. This used to refuse permanently (anti-fork
            # guard); the guard's intent — never silently start a second history next
            # to an existing one — is preserved by rebuilding the index FROM the
            # existing records, loudly, so the one true history continues.
            Write-Warning ("RunHistory at '$root' contains $($existingRuns.Count) run record(s) but no valid index.json " +
                '(missing, truncated, or corrupt). Rebuilding the index from the run records on disk — records are the ' +
                'source of truth, so no history is lost — and resuming run recording. If you did not expect this, ' +
                'check the directory for tampering or an interrupted write.')
        }
        foreach ($e in (Get-GuerrillaRunIndexEntriesFromRecords -Root $root)) { $runsList.Add($e) }
        $index = [ordered]@{
            schemaVersion = 1
            store         = 'guerrilla-run-history'
            createdAt     = [datetime]::UtcNow.ToString('o')
            principle     = 'Per-user local run history. Your file, your machine. No accounts, no telemetry, no network.'
        }
    } elseif ($null -eq $index.runs) {
        # Valid index from a version that did not keep per-run entries: backfill
        # the locator list from the records on disk.
        foreach ($e in (Get-GuerrillaRunIndexEntriesFromRecords -Root $root)) { $runsList.Add($e) }
    } elseif (@($index.runs).Count -ne $existingRuns.Count) {
        # Index disagrees with the directory (a record added or removed out of
        # band): re-derive the locator list from the records, which are the truth.
        Write-Verbose 'RunHistory: index entry count disagrees with the records on disk; rebuilding the locator list.'
        foreach ($e in (Get-GuerrillaRunIndexEntriesFromRecords -Root $root)) { $runsList.Add($e) }
    } else {
        foreach ($e in @($index.runs)) { $runsList.Add($e) }
    }

    # --- Write the record atomically. ---
    $stamp = ([datetime]$Record.generatedAt).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $idFragment = ("$($Record.runId)" -replace '[^A-Za-z0-9-]', '')
    if ($idFragment.Length -gt 12) { $idFragment = $idFragment.Substring(0, 12) }
    $finalPath = Join-Path $root "run-$stamp-$idFragment.json"

    $tmpPath = "$finalPath.tmp"
    $Record | ConvertTo-Json -Depth 8 | Set-Content -Path $tmpPath -Encoding utf8
    Move-Item -Path $tmpPath -Destination $finalPath -Force

    $runsList.Add((New-GuerrillaRunIndexEntry -Record $Record -FileName (Split-Path $finalPath -Leaf)))

    # --- Retention: prune each series to the most recent MaxRunsPerSeries. ---
    $bySeries = @{}
    foreach ($e in $runsList) {
        # Old index entries carry no ouScope; that reads as the whole-tenant
        # default, which is what those runs were.
        $entryOuScope = if ($null -ne $e.ouScope) { "$($e.ouScope)" } else { Get-GuerrillaOuScopeString }
        $seriesKey = "$($e.targetHash)|$(@($e.platforms | Sort-Object) -join ',')|$entryOuScope"
        if (-not $bySeries.ContainsKey($seriesKey)) {
            $bySeries[$seriesKey] = [System.Collections.Generic.List[object]]::new()
        }
        $bySeries[$seriesKey].Add($e)
    }
    $kept = [System.Collections.Generic.List[object]]::new()
    foreach ($seriesKey in $bySeries.Keys) {
        $series = @($bySeries[$seriesKey] | Sort-Object { [datetime]"$($_.generatedAt)" } -Descending)
        foreach ($e in ($series | Select-Object -First $MaxRunsPerSeries)) { $kept.Add($e) }
        foreach ($e in ($series | Select-Object -Skip $MaxRunsPerSeries)) {
            $prunePath = Join-Path $root "$($e.file)"
            try {
                if (Test-Path $prunePath) { Remove-Item -Path $prunePath -Force }
                Write-Verbose "RunHistory: retention pruned $($e.file) (series exceeds $MaxRunsPerSeries records)."
            } catch {
                # Keep the entry if the file could not be removed; the index must not
                # claim a record is gone while it still exists on disk.
                Write-Verbose "RunHistory: could not prune $($e.file): $_"
                $kept.Add($e)
            }
        }
    }

    # --- Persist the index (atomic, like every other write here). ---
    $newIndex = [ordered]@{
        schemaVersion = 1
        store         = 'guerrilla-run-history'
        createdAt     = "$($index.createdAt)"
        principle     = 'Per-user local run history. Your file, your machine. No accounts, no telemetry, no network.'
        runs          = @($kept | Sort-Object { [datetime]"$($_.generatedAt)" })
    }
    Write-GuerrillaRunIndex -IndexPath $indexPath -Index $newIndex

    return $finalPath
}

function Get-GuerrillaPreviousRun {
    <#
    .SYNOPSIS
        The newest recorded run comparable to the one about to be recorded.
    .DESCRIPTION
        Comparable means: same schema, same target (privacy-preserving hash),
        the same platform set, and the same OU scope (collection TargetOU plus
        the student-OU designation). An AD-only run is never diffed against a
        full campaign, and a student-scoped run is never diffed against a
        whole-tenant run; the checks that "vanished" or "drifted" would be
        scope, not drift. Returns $null when no comparable baseline exists
        (first run ever, or first run at this scope): the caller reports that
        plainly and fabricates nothing.

        Records and index entries written before OU scope existed carry no
        scope fields; they read as the whole-tenant default ('/', no student
        OUs), which is what those runs were, so pre-scope whole-tenant history
        keeps matching whole-tenant runs.

        Uses the index as a locator (newest matching entry first) so a lookup
        does not parse every record in the history; the chosen record is
        re-verified against the index entry because records, not the index,
        are the source of truth. Falls back to scanning every record when the
        index is missing, has no locator entries, or disagrees with the
        directory contents.

        Matching records skipped because of a schemaVersion mismatch are
        surfaced with a warning (once per lookup): a future schema bump must
        not silently reset everyone's baseline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Platforms,
        [Parameter(Mandatory)][string]$TargetHash,
        [string]$DataRoot,
        [string]$TargetOu = '/',
        [AllowNull()][AllowEmptyCollection()][string[]]$StudentOu = @()
    )

    $root = Get-GuerrillaRunHistoryRoot -DataRoot $DataRoot
    if (-not (Test-Path $root)) { return $null }

    $wanted = @($Platforms | Sort-Object) -join ','
    $wantedOuScope = Get-GuerrillaOuScopeString -TargetOu $TargetOu -StudentOu $StudentOu
    $recordOuScope = {
        param($scope)
        Get-GuerrillaOuScopeString -TargetOu "$($scope.targetOu)" `
            -StudentOu @($scope.studentOus | ForEach-Object { "$_" })
    }
    $indexPath = Join-Path $root 'index.json'

    $warnSchemaSkips = {
        param($count)
        if ($count -gt 0) {
            Write-Warning ("RunHistory: $count recorded run(s) at this scope use a different schemaVersion and were " +
                'skipped; the comparison baseline may be older than the most recent run, or absent. A schema bump ' +
                'does not delete history, but it does start a new comparison series.')
        }
    }

    # --- Fast path: locate the newest comparable run via the index. ---
    $index = Read-GuerrillaRunIndex -IndexPath $indexPath
    if ($null -ne $index -and $null -ne $index.runs) {
        $entries = @($index.runs)
        $onDiskCount = @(Get-ChildItem -Path $root -Filter 'run-*.json' -File -ErrorAction SilentlyContinue).Count
        if ($entries.Count -eq $onDiskCount) {
            $matching = @($entries | Where-Object {
                $entryOuScope = if ($null -ne $_.ouScope) { "$($_.ouScope)" } else { Get-GuerrillaOuScopeString }
                "$($_.targetHash)" -eq $TargetHash -and
                ((@($_.platforms | Sort-Object) -join ',') -eq $wanted) -and
                ($entryOuScope -eq $wantedOuScope)
            })
            $schemaSkips = @($matching | Where-Object { $_.schemaVersion -ne 1 }).Count
            $ordered = @($matching | Where-Object { $_.schemaVersion -eq 1 } |
                Sort-Object { [datetime]"$($_.generatedAt)" } -Descending)
            foreach ($entry in $ordered) {
                $path = Join-Path $root "$($entry.file)"
                if (-not (Test-Path $path)) { continue }
                try {
                    $rec = Get-Content -Path $path -Raw | ConvertFrom-Json
                } catch {
                    Write-Verbose "RunHistory: indexed record $($entry.file) unreadable, trying next: $_"
                    continue
                }
                # Re-verify against the record itself; the index is only a locator.
                if ($rec.schemaVersion -ne 1) { continue }
                if ("$($rec.scope.targetHash)" -ne $TargetHash) { continue }
                if ((@($rec.scope.platforms | Sort-Object) -join ',') -ne $wanted) { continue }
                if ((& $recordOuScope $rec.scope) -ne $wantedOuScope) { continue }
                & $warnSchemaSkips $schemaSkips
                return $rec
            }
            & $warnSchemaSkips $schemaSkips
            return $null
        }
        Write-Verbose 'RunHistory: index entry count disagrees with the records on disk; falling back to a full scan.'
    }

    # --- Fallback: scan every record (no usable index). ---
    $best = $null
    $schemaSkips = 0
    foreach ($file in (Get-ChildItem -Path $root -Filter 'run-*.json' -File -ErrorAction SilentlyContinue)) {
        try {
            $rec = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
        } catch {
            Write-Verbose "RunHistory: skipping unreadable record $($file.Name): $_"
            continue
        }
        if ("$($rec.scope.targetHash)" -ne $TargetHash) { continue }
        if ((@($rec.scope.platforms | Sort-Object) -join ',') -ne $wanted) { continue }
        if ((& $recordOuScope $rec.scope) -ne $wantedOuScope) { continue }
        if ($rec.schemaVersion -ne 1) { $schemaSkips++; continue }
        if ($null -eq $best -or ([datetime]$rec.generatedAt) -gt ([datetime]$best.generatedAt)) { $best = $rec }
    }
    & $warnSchemaSkips $schemaSkips
    return $best
}
