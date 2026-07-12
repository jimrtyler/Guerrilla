# Unit tests for the run-history store: record building (verdict
# normalization, evidence hashing), persistence (atomic write, index,
# anti-fork guard), and baseline selection (same target, same platform set).

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../../Helpers/TestHelpers.psm1') -Force
    Import-Guerrilla
}

Describe 'New-GuerrillaRunRecord' {
    It 'normalizes SKIP and ERROR to Not Assessed and keeps the raw status' {
        $findings = @(
            (New-MockAuditFinding -CheckId 'A-1' -Status 'PASS'),
            (New-MockAuditFinding -CheckId 'A-2' -Status 'SKIP'),
            (New-MockAuditFinding -CheckId 'A-3' -Status 'ERROR'),
            (New-MockAuditFinding -CheckId 'A-4' -Status 'FAIL')
        )
        $rec = InModuleScope Guerrilla -Parameters @{ f = $findings } {
            New-GuerrillaRunRecord -Findings $f -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 50
        }
        $verdicts = @($rec.checks | ForEach-Object { $_.verdict })
        $verdicts | Should -Be @('PASS', 'Not Assessed', 'Not Assessed', 'FAIL')
        @($rec.checks)[1].rawStatus | Should -Be 'SKIP'
        $rec.summary.notAssessed | Should -Be 2
        $rec.summary.total | Should -Be 4
    }

    It 'throws on an unknown status instead of guessing' {
        {
            InModuleScope Guerrilla {
                ConvertTo-GuerrillaRunVerdict -Status 'MAYBE'
            }
        } | Should -Throw -ExpectedMessage '*refusing to guess*'
    }

    It 'evidence hash is deterministic and order-insensitive over Details keys' {
        $h = InModuleScope Guerrilla {
            @(
                (Get-GuerrillaEvidenceHash -CurrentValue 'v' -Details @{ b = 2; a = 1 }),
                (Get-GuerrillaEvidenceHash -CurrentValue 'v' -Details @{ a = 1; b = 2 }),
                (Get-GuerrillaEvidenceHash -CurrentValue 'v' -Details @{ a = 1; b = 3 })
            )
        }
        $h[0] | Should -Be $h[1]
        $h[0] | Should -Not -Be $h[2]
        $h[0] | Should -Match '^[0-9a-f]{64}$'
    }

    It 'stores no raw evidence values, only hashes' {
        $secret = 'SuperSecretCurrentValue-9000'
        $finding = New-MockAuditFinding -CheckId 'A-1' -Status 'FAIL'
        $finding.CurrentValue = $secret
        $rec = InModuleScope Guerrilla -Parameters @{ f = @($finding) } {
            New-GuerrillaRunRecord -Findings $f -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 10
        }
        ($rec | ConvertTo-Json -Depth 8) | Should -Not -Match ([regex]::Escape($secret))
    }

    It 'target hash is stable across ordering and casing of identifiers' {
        $hashes = InModuleScope Guerrilla {
            @(
                (Get-GuerrillaTargetHash -TargetId @('Corp.Example.COM', 'tenant-b')),
                (Get-GuerrillaTargetHash -TargetId @('tenant-b', 'corp.example.com')),
                (Get-GuerrillaTargetHash -TargetId @('other.example.com'))
            )
        }
        $hashes[0] | Should -Be $hashes[1]
        $hashes[0] | Should -Not -Be $hashes[2]
    }
}

Describe 'Save-GuerrillaRunRecord / Get-GuerrillaPreviousRun' {
    BeforeEach {
        $script:root = Join-Path $TestDrive ("rh-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    It 'first save creates the store with an index and returns the record path' {
        $rec = InModuleScope Guerrilla {
            New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 90
        }
        $path = InModuleScope Guerrilla -Parameters @{ rec = $rec; root = $script:root } {
            Save-GuerrillaRunRecord -Record $rec -DataRoot $root
        }
        Test-Path $path | Should -BeTrue
        Test-Path (Join-Path $script:root 'RunHistory' 'index.json') | Should -BeTrue
        (Get-Content (Join-Path $script:root 'RunHistory' 'index.json') -Raw | ConvertFrom-Json).store |
            Should -Be 'guerrilla-run-history'
    }

    It 'rebuilds a missing or corrupt index from the records on disk instead of refusing forever' {
        # The old anti-fork guard threw here, which permanently disabled run
        # recording (callers warn-and-continue) while comparisons kept reading an
        # ever-staler baseline. Records are the source of truth: the index is
        # rebuilt from them, loudly, and recording resumes.
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $mk = {
                param($scanId, $when)
                $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                    -Platforms @('AD') -TargetId @('corp.example.com') -ScanId $scanId -OverallScore 90
                $rec.generatedAt = $when
                return $rec
            }
            Save-GuerrillaRunRecord -Record (& $mk 'first' '2026-07-01T10:00:00Z') -DataRoot $root | Out-Null

            # Corrupt the index after a legitimate save.
            $indexPath = Join-Path (Get-GuerrillaRunHistoryRoot -DataRoot $root) 'index.json'
            Set-Content -Path $indexPath -Value 'not json {{{'

            $wv = $null
            $path2 = Save-GuerrillaRunRecord -Record (& $mk 'second' '2026-07-05T10:00:00Z') -DataRoot $root `
                -WarningVariable wv -WarningAction SilentlyContinue
            Test-Path $path2 | Should -BeTrue
            (@($wv) -join ' ') | Should -Match 'Rebuilding the index'

            # The rebuilt index is valid again and carries a locator entry per record.
            $idx = Get-Content -Path $indexPath -Raw | ConvertFrom-Json
            $idx.store | Should -Be 'guerrilla-run-history'
            @($idx.runs).Count | Should -Be 2

            # And the baseline lookup still sees the full history.
            $target = Get-GuerrillaTargetHash -TargetId @('corp.example.com')
            (Get-GuerrillaPreviousRun -Platforms @('AD') -TargetHash $target -DataRoot $root).runId | Should -Be 'second'
        }
    }

    It 'index writes are atomic: no plain Set-Content path remains for index.json (source assertion)' {
        # Records were always temp+rename; the index used to be a bare Set-Content.
        # Assert every index write goes through Write-GuerrillaRunIndex, which
        # stages to a .tmp file and renames.
        $src = Get-Content -Raw (Join-Path $PSScriptRoot '../../../../source/internal/Audit/Save-GuerrillaRunRecord.ps1')
        $writes = [regex]::Matches($src, 'Set-Content\s+-Path\s+(\$\w+)')
        foreach ($w in $writes) {
            $w.Groups[1].Value | Should -Match '^\$tmpPath$' -Because 'every write must stage to a temp path and rename'
        }
        $src | Should -Match 'Move-Item -Path \$tmpPath -Destination \$IndexPath -Force'
    }

    It 'leaves no temp files behind after a save' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 90
            Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null
            @(Get-ChildItem -Path (Get-GuerrillaRunHistoryRoot -DataRoot $root) -Filter '*.tmp').Count | Should -Be 0
        }
    }

    It 'retention prunes each series to the most recent N records and spares other series' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $mk = {
                param($scanId, $when, $platforms)
                $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                    -Platforms $platforms -TargetId @('corp.example.com') -ScanId $scanId -OverallScore 80
                $rec.generatedAt = $when
                Save-GuerrillaRunRecord -Record $rec -DataRoot $root -MaxRunsPerSeries 3 | Out-Null
            }
            & $mk 'r1' '2026-07-01T10:00:00Z' @('AD')
            & $mk 'r2' '2026-07-02T10:00:00Z' @('AD')
            & $mk 'other' '2026-07-02T11:00:00Z' @('GWS')   # different series, must survive
            & $mk 'r3' '2026-07-03T10:00:00Z' @('AD')
            & $mk 'r4' '2026-07-04T10:00:00Z' @('AD')
            & $mk 'r5' '2026-07-05T10:00:00Z' @('AD')

            $rh = Get-GuerrillaRunHistoryRoot -DataRoot $root
            @(Get-ChildItem -Path $rh -Filter 'run-*.json').Count | Should -Be 4 -Because '3 kept in the AD series + 1 in the GWS series'

            $target = Get-GuerrillaTargetHash -TargetId @('corp.example.com')
            (Get-GuerrillaPreviousRun -Platforms @('AD') -TargetHash $target -DataRoot $root).runId | Should -Be 'r5'
            (Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root).runId | Should -Be 'other'

            $idx = Get-Content -Path (Join-Path $rh 'index.json') -Raw | ConvertFrom-Json
            @($idx.runs).Count | Should -Be 4
            @($idx.runs | ForEach-Object runId) | Should -Not -Contain 'r1'
            @($idx.runs | ForEach-Object runId) | Should -Not -Contain 'r2'
        }
    }

    It 'warns (once per lookup) when matching records are skipped for a schemaVersion mismatch' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $mk = {
                param($scanId, $when, $schema)
                $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                    -Platforms @('AD') -TargetId @('corp.example.com') -ScanId $scanId -OverallScore 80
                $rec.generatedAt = $when
                $rec.schemaVersion = $schema
                Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null
            }
            & $mk 'v1-run' '2026-07-01T10:00:00Z' 1
            & $mk 'v2-run' '2026-07-05T10:00:00Z' 2   # newer but future-schema

            $target = Get-GuerrillaTargetHash -TargetId @('corp.example.com')
            $wv = $null
            $best = Get-GuerrillaPreviousRun -Platforms @('AD') -TargetHash $target -DataRoot $root `
                -WarningVariable wv -WarningAction SilentlyContinue
            $best.runId | Should -Be 'v1-run' -Because 'the v2 record is not comparable, but must not be skipped silently'
            @($wv).Count | Should -Be 1
            (@($wv) -join ' ') | Should -Match 'schemaVersion'

            # Same warning on the full-scan fallback path (no index).
            Remove-Item -Path (Join-Path (Get-GuerrillaRunHistoryRoot -DataRoot $root) 'index.json')
            $wv2 = $null
            $best2 = Get-GuerrillaPreviousRun -Platforms @('AD') -TargetHash $target -DataRoot $root `
                -WarningVariable wv2 -WarningAction SilentlyContinue
            $best2.runId | Should -Be 'v1-run'
            @($wv2).Count | Should -Be 1
        }
    }

    It 'refuses to persist an incomplete record' {
        {
            InModuleScope Guerrilla -Parameters @{ root = $script:root } {
                Save-GuerrillaRunRecord -Record ([ordered]@{ schemaVersion = 1; runId = 'x' }) -DataRoot $root
            }
        } | Should -Throw -ExpectedMessage '*incomplete*'
    }

    It 'previous-run selection matches target and platform set and picks the newest' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $mk = {
                param($scanId, $when, $platforms, $target)
                $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                    -Platforms $platforms -TargetId $target -ScanId $scanId -OverallScore 80
                $rec.generatedAt = $when
                Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null
            }
            & $mk 'ad-old'    '2026-07-01T10:00:00Z' @('AD') @('corp.example.com')
            & $mk 'ad-new'    '2026-07-05T10:00:00Z' @('AD') @('corp.example.com')
            & $mk 'campaign'  '2026-07-06T10:00:00Z' @('AD', 'Entra', 'GWS') @('corp.example.com')
            & $mk 'other-org' '2026-07-07T10:00:00Z' @('AD') @('other.example.com')

            $target = Get-GuerrillaTargetHash -TargetId @('corp.example.com')
            $best = Get-GuerrillaPreviousRun -Platforms @('AD') -TargetHash $target -DataRoot $root
            $best.runId | Should -Be 'ad-new'

            # A different platform set is a different comparison series.
            $bestCampaign = Get-GuerrillaPreviousRun -Platforms @('GWS', 'AD', 'Entra') -TargetHash $target -DataRoot $root
            $bestCampaign.runId | Should -Be 'campaign'

            # No comparable baseline: null, not a guess.
            Get-GuerrillaPreviousRun -Platforms @('Entra') -TargetHash $target -DataRoot $root | Should -BeNullOrEmpty
        }
    }

    It 'campaign series: a failed platform keys on the requested set and surfaces as lost visibility' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            # Baseline: full campaign (AD + Entra + GWS), every platform assessed.
            $prevRec = New-GuerrillaRunRecord -Findings @(
                (New-MockAuditFinding -CheckId 'AD-1' -Status 'PASS'),
                (New-MockAuditFinding -CheckId 'ENT-1' -Status 'PASS'),
                (New-MockAuditFinding -CheckId 'GWS-1' -Status 'PASS')
            ) -Platforms @('AD', 'Entra', 'GWS') `
                -TargetId @('corp.example.com', 'tenant-1', 'ws.example.com') -ScanId 'c1' -OverallScore 90
            $prevRec.generatedAt = '2026-07-01T10:00:00Z'
            Save-GuerrillaRunRecord -Record $prevRec -DataRoot $root | Out-Null

            # Next campaign: the GWS sub-audit failed outright. The record is still
            # keyed on the REQUESTED platform set (same series, not a false first
            # run), and the failed platform's checks are synthesized Not-Assessed
            # (ERROR) findings instead of vanishing.
            $currRec = New-GuerrillaRunRecord -Findings @(
                (New-MockAuditFinding -CheckId 'AD-1' -Status 'PASS'),
                (New-MockAuditFinding -CheckId 'ENT-1' -Status 'PASS'),
                (New-MockAuditFinding -CheckId 'GWS-1' -Status 'ERROR')
            ) -Platforms @('AD', 'Entra', 'GWS') `
                -TargetId @('corp.example.com', 'tenant-1', 'ws.example.com') -ScanId 'c2' -OverallScore 92

            $prev = Get-GuerrillaPreviousRun -Platforms @('AD', 'Entra', 'GWS') `
                -TargetHash $currRec.scope.targetHash -DataRoot $root
            $prev | Should -Not -BeNullOrEmpty -Because 'one failed platform must not move the campaign to a new series'
            $prev.runId | Should -Be 'c1'

            $diff = Compare-GuerrillaRun -Previous $prev -Current $currRec
            @($diff.LostVisibility | ForEach-Object CheckId) | Should -Contain 'GWS-1'
            @($diff.RetiredChecks).Count | Should -Be 0 -Because 'a failed platform is lost visibility, never a benign retirement'
        }
    }

    It 'round-trips a record through disk and diffs cleanly against itself' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $rec = New-GuerrillaRunRecord -Findings @(
                (New-MockAuditFinding -CheckId 'A-1' -Status 'PASS'),
                (New-MockAuditFinding -CheckId 'A-2' -Status 'SKIP')
            ) -Platforms @('AD') -TargetId @('corp.example.com') -ScanId 'scan-1' -OverallScore 75
            Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null

            $loaded = Get-GuerrillaPreviousRun -Platforms @('AD') `
                -TargetHash (Get-GuerrillaTargetHash -TargetId @('corp.example.com')) -DataRoot $root
            $loaded | Should -Not -BeNullOrEmpty

            $diff = Compare-GuerrillaRun -Previous $loaded -Current $rec
            $diff.BaselineRun | Should -BeFalse
            $diff.UnchangedCount | Should -Be 1 -Because 'the stable PASS'
            @($diff.StillNotAssessed).Count | Should -Be 1 -Because 'the SKIP is dark in both runs — enumerated, never unchanged'
            $diff.TotalClassified | Should -Be 2
            $diff.ScoreDelta | Should -Be 0
        }
    }
}

Describe 'OU scope in the comparison-series identity' {
    BeforeEach {
        $script:root = Join-Path $TestDrive ("rh-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }

    It 'normalizes the student-OU list: trims, deduplicates, sorts, adds the leading slash' {
        InModuleScope Guerrilla {
            $out = ConvertTo-GuerrillaStudentOuList -StudentOu @(' /Students ', 'Students', '/Alumni/', '', $null) -EnsureLeadingSlash
            $out | Should -Be @('/Alumni', '/Students')
            (Get-GuerrillaOuScopeString -TargetOu '' -StudentOu @()) |
                Should -Be (Get-GuerrillaOuScopeString -TargetOu '/' -StudentOu $null) `
                -Because 'absent scope fields on old records must read as the whole-tenant default'
        }
    }

    It 'a student-scoped run is never diffed against a whole-tenant run, in either direction' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $mk = {
                param($scanId, $when, $studentOus)
                $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                    -Platforms @('GWS') -TargetId @('district.example.org') -ScanId $scanId -OverallScore 80 `
                    -StudentOu $studentOus
                $rec.generatedAt = $when
                Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null
            }
            & $mk 'tenantwide' '2026-07-01T10:00:00Z' @()
            & $mk 'scoped'     '2026-07-02T10:00:00Z' @('/Students')

            $target = Get-GuerrillaTargetHash -TargetId @('district.example.org')

            # Whole-tenant lookup must find the whole-tenant run, not the newer scoped one.
            (Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root).runId |
                Should -Be 'tenantwide'

            # Scoped lookup must find the scoped run, not the whole-tenant one.
            (Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root `
                -StudentOu @('/Students')).runId | Should -Be 'scoped'

            # A different student-OU set is a different series: null, not a guess.
            Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root `
                -StudentOu @('/HighSchool') | Should -BeNullOrEmpty
        }
    }

    It 'scope matching holds on the full-scan fallback path too (no index)' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $mk = {
                param($scanId, $when, $studentOus)
                $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                    -Platforms @('GWS') -TargetId @('district.example.org') -ScanId $scanId -OverallScore 80 `
                    -StudentOu $studentOus
                $rec.generatedAt = $when
                Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null
            }
            & $mk 'tenantwide' '2026-07-01T10:00:00Z' @()
            & $mk 'scoped'     '2026-07-02T10:00:00Z' @('/Students')
            Remove-Item (Join-Path $root 'RunHistory' 'index.json') -Force

            $target = Get-GuerrillaTargetHash -TargetId @('district.example.org')
            (Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root).runId |
                Should -Be 'tenantwide'
            (Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root `
                -StudentOu @('/Students')).runId | Should -Be 'scoped'
        }
    }

    It 'TargetOu (collection scope) separates series: an OU-narrowed run never baselines a whole-tenant run' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                -Platforms @('GWS') -TargetId @('district.example.org') -ScanId 'narrowed' -OverallScore 80 `
                -TargetOu '/Engineering'
            Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null

            $target = Get-GuerrillaTargetHash -TargetId @('district.example.org')
            Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root |
                Should -BeNullOrEmpty -Because 'a -TargetOU run must not become the whole-tenant baseline'
            (Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root `
                -TargetOu '/Engineering').runId | Should -Be 'narrowed'
        }
    }

    It 'pre-scope records (no scope fields) keep matching whole-tenant lookups' {
        InModuleScope Guerrilla -Parameters @{ root = $script:root } {
            $rec = New-GuerrillaRunRecord -Findings @((New-MockAuditFinding -CheckId 'A-1' -Status 'PASS')) `
                -Platforms @('GWS') -TargetId @('district.example.org') -ScanId 'legacy' -OverallScore 80
            Save-GuerrillaRunRecord -Record $rec -DataRoot $root | Out-Null

            # Strip the scope fields from the persisted record and index entry to
            # simulate a record written before OU scope existed.
            $rhRoot = Join-Path $root 'RunHistory'
            $file = Get-ChildItem $rhRoot -Filter 'run-*.json' | Select-Object -First 1
            $legacy = Get-Content $file.FullName -Raw | ConvertFrom-Json
            $legacy.scope.PSObject.Properties.Remove('targetOu')
            $legacy.scope.PSObject.Properties.Remove('studentOus')
            $legacy | ConvertTo-Json -Depth 8 | Set-Content $file.FullName -Encoding utf8
            Remove-Item (Join-Path $rhRoot 'index.json') -Force

            $target = Get-GuerrillaTargetHash -TargetId @('district.example.org')
            (Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root).runId |
                Should -Be 'legacy' -Because 'a schema addition must not silently reset whole-tenant baselines'
            Get-GuerrillaPreviousRun -Platforms @('GWS') -TargetHash $target -DataRoot $root `
                -StudentOu @('/Students') | Should -BeNullOrEmpty
        }
    }
}
