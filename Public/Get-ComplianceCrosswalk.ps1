# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ComplianceCrosswalk {
    <#
    .SYNOPSIS
        Maps audit findings to compliance framework requirements.
    .DESCRIPTION
        Cross-references audit check IDs against FERPA, COPPA, CIPA, NIST SP 800-171,
        and state education technology privacy requirements. Returns findings grouped
        by compliance framework with citations.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER Framework
        Filter to a specific compliance framework. If not specified, returns all frameworks.
    .PARAMETER FailOnly
        Only include findings with FAIL status (exclude WARN and PASS).
    .PARAMETER ConfigPath
        Override config file path.
    .EXAMPLE
        Get-ComplianceCrosswalk -Framework FERPA
        Returns all findings mapped to FERPA requirements.
    .EXAMPLE
        Get-ComplianceCrosswalk -FailOnly
        Returns only failing checks mapped to compliance frameworks.
    .EXAMPLE
        $findings = Invoke-Reconnaissance -PassThru; Get-ComplianceCrosswalk -Findings $findings -Framework COPPA
        Maps specific findings to COPPA requirements.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,

        [ValidateSet('FERPA', 'COPPA', 'CIPA', 'NIST-171', 'STATE-EDTECH', 'NIST-800-53', 'MITRE-ATTACK', 'CIS', 'SCUBA', 'EIDSCA')]
        [string]$Framework,

        [switch]$FailOnly,
        [Alias('RuntimeConfig')]
        [string]$ConfigPath
    )

    # Load findings from state if not provided
    if (-not $Findings -or $Findings.Count -eq 0) {
        $dataDir = Get-GuerrillaDataRoot
        $findingsFiles = @()
        if (Test-Path $dataDir) {
            $findingsFiles = @(Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)
        }
        if ($findingsFiles.Count -gt 0) {
            $Findings = @()
            foreach ($f in $findingsFiles) {
                try {
                    $data = Get-Content -Path $f.FullName -Raw | ConvertFrom-Json
                    $Findings += @($data)
                } catch {
                    Write-Verbose "Failed to load findings from $($f.Name): $_"
                }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return @()
    }

    # Load crosswalk data
    $crosswalkPath = Join-Path $script:ModuleRoot 'Data/ComplianceCrosswalk.json'
    if (-not (Test-Path $crosswalkPath)) {
        Write-Warning "ComplianceCrosswalk.json not found at $crosswalkPath"
        return @()
    }
    $crosswalk = Get-Content -Path $crosswalkPath -Raw | ConvertFrom-Json -AsHashtable

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Technical frameworks are built directly from each finding's own compliance map
    # (NIST 800-53 / MITRE ATT&CK / CIS are already carried on every check definition),
    # not from the education-focused ComplianceCrosswalk.json.
    $technicalFrameworks = [ordered]@{
        'NIST-800-53'  = @{ Name = 'NIST SP 800-53';  Props = @('NistSp80053') }
        'MITRE-ATTACK' = @{ Name = 'MITRE ATT&CK';    Props = @('MitreAttack') }
        'CIS'          = @{ Name = 'CIS Benchmarks';  Props = @('CisBenchmark', 'CisAd', 'CisM365', 'CisAzure') }
        'SCUBA'        = @{ Name = 'CISA SCuBA Secure Configuration Baselines'; Props = @('Scuba') }
        'EIDSCA'       = @{ Name = 'Entra ID Security Config Analyzer';          Props = @('Eidsca') }
    }

    foreach ($finding in $Findings) {
        if ($FailOnly -and $finding.Status -ne 'FAIL') { continue }
        # ERROR = the check failed to run (no signal). SKIP = the control was not assessed (e.g. the
        # data source / admin module wasn't connected). We KEEP SKIP rows so a compliance crosswalk
        # distinguishes "passed" from "not looked at" instead of silently under-reporting coverage —
        # the row carries Status='SKIP' (render as "Not Assessed"). Only ERROR is dropped.
        if ($finding.Status -eq 'ERROR') { continue }

        $checkId   = $finding.CheckId ?? $finding.Id ?? ''
        $checkName = $finding.CheckName ?? $finding.Name ?? $checkId

        # --- Technical frameworks (from the finding's own compliance mappings) ---
        foreach ($tfKey in $technicalFrameworks.Keys) {
            if ($Framework -and $Framework -ne $tfKey) { continue }
            $controls = [System.Collections.Generic.List[string]]::new()
            foreach ($prop in $technicalFrameworks[$tfKey].Props) {
                foreach ($v in @($finding.Compliance.$prop)) {
                    if ($v) { [void]$controls.Add([string]$v) }
                }
            }
            $controls = @($controls | Select-Object -Unique)
            if ($controls.Count -eq 0) { continue }
            $results.Add([PSCustomObject]@{
                PSTypeName       = 'Guerrilla.ComplianceMapping'
                CheckId          = $checkId
                CheckName        = $checkName
                Status           = $finding.Status
                Severity         = $finding.Severity ?? 'Medium'
                Framework        = $tfKey
                FrameworkName    = $technicalFrameworks[$tfKey].Name
                Requirement      = ($controls -join ', ')
                Citation         = ($controls -join ', ')
                Category         = $finding.Category ?? ''
                RemediationSteps = $finding.RemediationSteps ?? ''
            })
        }

        # --- Education frameworks (FERPA / COPPA / CIPA / NIST-171 / STATE-EDTECH) ---
        $mapping = $crosswalk.mappings.$checkId
        if ($mapping -and $mapping.frameworks) {
            $frameworks = $mapping.frameworks
            if ($Framework) {
                $frameworks = if ($frameworks.$Framework) { @{ $Framework = $frameworks.$Framework } } else { @{} }
            }
            foreach ($fw in $frameworks.GetEnumerator()) {
                $results.Add([PSCustomObject]@{
                    PSTypeName       = 'Guerrilla.ComplianceMapping'
                    CheckId          = $checkId
                    CheckName        = $mapping.checkName ?? $checkName
                    Status           = $finding.Status
                    Severity         = $finding.Severity ?? 'Medium'
                    Framework        = $fw.Key
                    FrameworkName    = $crosswalk.frameworks.($fw.Key).fullName ?? $fw.Key
                    Requirement      = $fw.Value.requirement ?? ''
                    Citation         = $fw.Value.citation ?? ''
                    Category         = $finding.Category ?? ''
                    RemediationSteps = $finding.RemediationSteps ?? ''
                })
            }
        }
    }

    return @($results | Sort-Object -Property Framework, Severity, CheckId)
}
