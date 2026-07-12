#requires -version 7.0
# Schema gate: the K12 baseline DOCUMENT is the source of truth and the checks derive
# from it. Two failure modes must be RED builds: a check claiming a baselineId that the
# document does not define (a check inventing authority), and a document control whose
# Checks field disagrees with the checks that actually claim it (the document lying
# about coverage, in either direction). The guerrillaBaseline field is deliberately NOT
# an external framework mapping; this gate also keeps its shape too small to become one.

BeforeAll {
    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path

    # Parse the baseline document into { Version, Controls[] }. Controls are
    # '### K12-<DOMAIN>-<NNN>: Title' headings followed by bold bullet fields.
    # Kept as a scriptblock so the poison self-tests can feed it synthetic text.
    $script:parseBaselineDoc = {
        param([string]$Text)
        $version = $null
        if ($Text -match '(?m)^\*\*Version:\*\*\s+(\S+)') { $version = $Matches[1] }
        $controls = @{}
        $pattern = '(?ms)^### (K12-[A-Z]+-\d{3}):[^\r\n]*\r?\n(.*?)(?=^### |^## |\z)'
        foreach ($m in [regex]::Matches($Text, $pattern)) {
            $id = $m.Groups[1].Value
            $body = $m.Groups[2].Value
            $field = {
                param($name)
                if ($body -match "(?m)^- \*\*${name}:\*\*\s+(.+?)\s*$") { $Matches[1] } else { $null }
            }
            $controls[$id] = [pscustomobject]@{
                Id         = $id
                Scope      = & $field 'Scope'
                Assessment = & $field 'Assessment'
                Posture    = & $field 'Verdict posture'
                Checks     = & $field 'Checks'
                Status     = & $field 'Status'
            }
        }
        [pscustomobject]@{ Version = $version; Controls = $controls }
    }

    # Cross-check parsed doc against check definitions. Pure: returns violation strings.
    $script:findViolations = {
        param($Doc, $AllChecks)
        $violations = [System.Collections.Generic.List[string]]::new()
        $validScopes = @('OU-scoped', 'Tenant-wide')
        $validAssessments = @('Machine-assessable', 'Machine-assisted + policy review', 'Policy review')
        $validPostures = @('Standard', 'Context-dependent')
        $validStatuses = @('candidate', 'adopted', 'deprecated')

        if (-not $Doc.Version) { $violations.Add('baseline doc: missing **Version:** field') }
        if ($Doc.Controls.Count -eq 0) { $violations.Add('baseline doc: no controls parsed') }

        foreach ($ctl in $Doc.Controls.Values) {
            if ($ctl.Scope -notin $validScopes) { $violations.Add("$($ctl.Id): missing/invalid Scope '$($ctl.Scope)'") }
            if ($ctl.Assessment -notin $validAssessments) { $violations.Add("$($ctl.Id): missing/invalid Assessment '$($ctl.Assessment)'") }
            if ($ctl.Posture -notin $validPostures) { $violations.Add("$($ctl.Id): missing/invalid Verdict posture '$($ctl.Posture)'") }
            if ($ctl.Status -notin $validStatuses) { $violations.Add("$($ctl.Id): missing/invalid Status '$($ctl.Status)'") }
            if (-not $ctl.Checks) { $violations.Add("$($ctl.Id): missing Checks field") }
        }

        # Index the checks claiming each baselineId.
        $claims = @{}
        foreach ($c in $AllChecks) {
            $gb = $c.guerrillaBaseline
            if ($null -eq $gb) { continue }

            $keys = @($gb.PSObject.Properties.Name | Sort-Object)
            $expectedKeys = @('baselineId', 'baselineVersion', 'status')
            if (($keys -join '|') -ne ($expectedKeys -join '|')) {
                $violations.Add("$($c.id): guerrillaBaseline must have exactly keys {baselineId, baselineVersion, status}, got {$($keys -join ', ')}")
            }
            if ($gb.baselineId -notmatch '^K12-[A-Z]+-\d{3}$') {
                $violations.Add("$($c.id): malformed baselineId '$($gb.baselineId)'")
                continue
            }
            if ($c.provenance -ne 'original') {
                $violations.Add("$($c.id): claims $($gb.baselineId) but provenance is '$($c.provenance)' (Guerrilla-authored controls are provenance 'original')")
            }
            if ($null -eq $c.ouScoped) {
                $violations.Add("$($c.id): claims $($gb.baselineId) but does not declare ouScoped (true/false)")
            }
            $ctl = $Doc.Controls[$gb.baselineId]
            if ($null -eq $ctl) {
                $violations.Add("$($c.id): claims baselineId '$($gb.baselineId)' which the baseline document does not define")
                continue
            }
            if ($gb.baselineVersion -ne $Doc.Version) {
                $violations.Add("$($c.id): baselineVersion '$($gb.baselineVersion)' does not match document version '$($Doc.Version)'")
            }
            if ($gb.status -ne $ctl.Status) {
                $violations.Add("$($c.id): status '$($gb.status)' does not match document status '$($ctl.Status)' for $($gb.baselineId)")
            }
            if ($ctl.Scope -eq 'OU-scoped' -and $c.ouScoped -ne $true) {
                $violations.Add("$($c.id): $($gb.baselineId) is OU-scoped in the document but the check does not declare ouScoped=true")
            }
            if ($ctl.Scope -eq 'Tenant-wide' -and $c.ouScoped -eq $true) {
                $violations.Add("$($c.id): $($gb.baselineId) is Tenant-wide in the document but the check declares ouScoped=true")
            }
            if (-not $claims.ContainsKey($gb.baselineId)) { $claims[$gb.baselineId] = [System.Collections.Generic.List[string]]::new() }
            $claims[$gb.baselineId].Add($c.id)
        }

        # The document's Checks field must equal the actual claim set, both directions.
        foreach ($ctl in $Doc.Controls.Values) {
            $actual = if ($claims.ContainsKey($ctl.Id)) { @($claims[$ctl.Id] | Sort-Object) } else { @() }
            $documented = if ($ctl.Checks -and $ctl.Checks -ne 'Not yet covered') {
                @(($ctl.Checks -split ',').Trim() | Where-Object { $_ } | Sort-Object)
            } else { @() }
            if (($documented -join '|') -ne ($actual -join '|')) {
                $docSays = if ($documented.Count) { $documented -join ', ' } else { 'Not yet covered' }
                $isSays = if ($actual.Count) { $actual -join ', ' } else { 'no check claims it' }
                $violations.Add("$($ctl.Id): document says Checks = [$docSays] but $isSays")
            }
        }

        $violations
    }

    $script:loadAllChecks = {
        param([string]$RepoRoot)
        $dataDir = Join-Path $RepoRoot 'source' 'Data' 'AuditChecks'
        $all = [System.Collections.Generic.List[object]]::new()
        foreach ($file in Get-ChildItem -Path $dataDir -Filter *.json) {
            $json = Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
            foreach ($c in @($json.checks)) { if ($c.id) { $all.Add($c) } }
        }
        $all
    }
}

Describe 'K12 baseline document / check consistency' {

    It 'poison: the parser and detector go red on fabricated mismatches before we trust green' {
        $poisonDoc = @'
**Version:** 9.9.9

### K12-TEST-001: A control with a check the definitions do not have

- **Scope:** OU-scoped
- **Assessment:** Machine-assessable
- **Verdict posture:** Standard
- **Checks:** GWS-K12-999
- **Status:** candidate
'@
        $doc = & $parseBaselineDoc $poisonDoc
        $doc.Version | Should -Be '9.9.9'
        $doc.Controls.Count | Should -Be 1

        # Case 1: document claims coverage that does not exist.
        $v1 = & $findViolations $doc @()
        @($v1 | Where-Object { $_ -match 'K12-TEST-001: document says' }).Count | Should -Be 1

        # Case 2: a check claims a baselineId the document does not define.
        $ghost = [pscustomobject]@{
            id = 'GWS-K12-998'; provenance = 'original'; ouScoped = $true
            guerrillaBaseline = [pscustomobject]@{ baselineId = 'K12-GHOST-001'; baselineVersion = '9.9.9'; status = 'candidate' }
        }
        $v2 = & $findViolations $doc @($ghost)
        @($v2 | Where-Object { $_ -match "does not define" }).Count | Should -Be 1

        # Case 3: wrong version, wrong status, missing ouScoped, extra key all flagged.
        $bad = [pscustomobject]@{
            id = 'GWS-K12-997'; provenance = 'baseline'
            guerrillaBaseline = [pscustomobject]@{ baselineId = 'K12-TEST-001'; baselineVersion = '1.0.0'; status = 'adopted'; extra = 'x' }
        }
        $v3 = & $findViolations $doc @($bad)
        @($v3 | Where-Object { $_ -match 'GWS-K12-997' }).Count | Should -BeGreaterOrEqual 4
    }

    It 'the baseline document parses and every guerrillaBaseline claim reconciles with it, both directions' {
        $docPath = Join-Path $repoRoot 'docs' 'baselines' 'k12-secure-configuration-baseline.md'
        Test-Path $docPath | Should -BeTrue -Because 'the K12 baseline document is the source of truth for guerrillaBaseline claims'
        $doc = & $parseBaselineDoc (Get-Content -Path $docPath -Raw)
        $allChecks = & $loadAllChecks $repoRoot
        $violations = & $findViolations $doc $allChecks
        if ($violations.Count) {
            throw "K12 baseline consistency violations ($($violations.Count)):`n" + ($violations -join "`n")
        }
        $violations.Count | Should -Be 0
    }
}
