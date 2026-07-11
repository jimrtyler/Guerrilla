# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-GuerrillaJUnit {
    <#
    .SYNOPSIS
        Exports Guerrilla findings as JUnit XML — the format GitHub Actions, Azure DevOps, and GitLab
        render natively as pass/fail — so Guerrilla results show up in CI/CD pipelines.

    .DESCRIPTION
        Turns any theater's findings (AD / Entra / M365 / Google Workspace) into a JUnit test report:
        one <testsuite> per category, one <testcase> per check. FAIL -> <failure>; SKIP/ERROR -> <skipped>
        (Not Assessed); WARN -> passing with output, or <failure type="warning"> when -WarningsAsFailures.
        Returns the counts so a pipeline can gate on them (exit non-zero on Failures).

    .PARAMETER Findings
        Audit findings, e.g. (Invoke-Infiltration -PassThru).Findings.

    .PARAMETER OutputPath
        Destination .xml. Default ./Guerrilla-results.xml.

    .PARAMETER SuiteName
        Top-level <testsuites> name. Default 'Guerrilla'.

    .PARAMETER WarningsAsFailures
        Treat WARN findings as failures (so CI gates on them too).

    .EXAMPLE
        $r = Invoke-Infiltration -PassThru
        Export-GuerrillaJUnit -Findings $r.Findings -OutputPath ./results.xml
        if ((Export-GuerrillaJUnit -Findings $r.Findings).Failures) { exit 1 }   # gate the pipeline
    #>
    [CmdletBinding()]
    [OutputType('Guerrilla.JUnitExport')]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [string]$OutputPath = (Join-Path (Get-Location) 'Guerrilla-results.xml'),
        [string]$SuiteName = 'Guerrilla',
        [switch]$WarningsAsFailures
    )

    $esc = {
        param([string]$s)
        if ($null -eq $s) { return '' }
        $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&apos;')
    }

    $all = @($Findings)
    $totalTests = $all.Count
    $totalFail = 0; $totalSkip = 0

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<?xml version="1.0" encoding="UTF-8"?>')
    # placeholder for root attributes — counts are patched in after we tally
    $suiteXml = [System.Text.StringBuilder]::new()

    $groups = $all | Group-Object -Property { "$($_.Category)" } | Sort-Object Name
    foreach ($g in $groups) {
        $cases = @($g.Group)
        $sFail = 0; $sSkip = 0
        $caseXml = [System.Text.StringBuilder]::new()
        foreach ($f in $cases) {
            $cls = & $esc "$($g.Name)"
            $name = & $esc ("$($f.CheckId): $($f.CheckName)")
            $sev = & $esc "$($f.Severity)"
            $status = "$($f.Status)"
            $detail = & $esc ("$($f.CurrentValue)" + $(if ($f.RemediationSteps) { " | Remediation: $($f.RemediationSteps)" } else { '' }))

            $isFailure = ($status -eq 'FAIL') -or ($WarningsAsFailures -and $status -eq 'WARN')
            $isSkipped = $status -in @('SKIP', 'ERROR')

            [void]$caseXml.Append("    <testcase classname=`"$cls`" name=`"$name`" time=`"0`">")
            if ($isFailure) {
                $totalFail++; $sFail++
                [void]$caseXml.Append("<failure message=`"$detail`" type=`"$sev`">$detail</failure>")
            } elseif ($isSkipped) {
                $totalSkip++; $sSkip++
                [void]$caseXml.Append("<skipped message=`"Not Assessed: $detail`"/>")
            } elseif ($status -eq 'WARN') {
                [void]$caseXml.Append("<system-out>WARN: $detail</system-out>")
            }
            [void]$caseXml.AppendLine('</testcase>')
        }
        [void]$suiteXml.AppendLine("  <testsuite name=`"$(& $esc $g.Name)`" tests=`"$($cases.Count)`" failures=`"$sFail`" skipped=`"$sSkip`" time=`"0`">")
        [void]$suiteXml.Append($caseXml.ToString())
        [void]$suiteXml.AppendLine('  </testsuite>')
    }

    [void]$sb.AppendLine("<testsuites name=`"$(& $esc $SuiteName)`" tests=`"$totalTests`" failures=`"$totalFail`" skipped=`"$totalSkip`" time=`"0`">")
    [void]$sb.Append($suiteXml.ToString())
    [void]$sb.AppendLine('</testsuites>')

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -Path $OutputPath -Value $sb.ToString() -Encoding UTF8

    [PSCustomObject]@{
        PSTypeName = 'Guerrilla.JUnitExport'
        Path       = $OutputPath
        Tests      = $totalTests
        Failures   = $totalFail
        Skipped    = $totalSkip
        Passed     = ($totalTests - $totalFail - $totalSkip)
    }
}
