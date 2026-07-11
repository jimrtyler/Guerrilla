# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GuerrillaCIGate {
    <#
    .SYNOPSIS
        Decides whether a CI/CD build should fail based on the findings and a severity threshold.

    .DESCRIPTION
        The gating primitive behind the Guerrilla GitHub Action / pipeline templates. Given findings
        and a -FailOn threshold, returns whether the build should fail and how many findings triggered it.
        Only FAIL findings gate (plus WARN when -WarningsAsFailures); SKIP / "Not Assessed" never gate.

    .PARAMETER Findings
        Audit findings, e.g. (Invoke-Infiltration -PassThru).Findings.

    .PARAMETER FailOn
        Minimum severity that fails the build: Critical, High, Medium, Low (severity-or-higher),
        Any (any FAIL), or None (never fail). Default High.

    .PARAMETER WarningsAsFailures
        Count WARN findings toward the gate.

    .EXAMPLE
        $g = Get-GuerrillaCIGate -Findings $r.Findings -FailOn High
        if ($g.ShouldFail) { exit 1 }
    #>
    [CmdletBinding()]
    [OutputType('Guerrilla.CIGate')]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Findings,

        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Any', 'None')]
        [string]$FailOn = 'High',

        [switch]$WarningsAsFailures
    )

    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $gating = @()
    if ($FailOn -ne 'None') {
        $fails = @($Findings | Where-Object { $_.Status -eq 'FAIL' -or ($WarningsAsFailures -and $_.Status -eq 'WARN') })
        if ($FailOn -eq 'Any') {
            $gating = $fails
        } else {
            $threshold = $rank[$FailOn]
            $gating = @($fails | Where-Object { ($rank["$($_.Severity)"] ?? 9) -le $threshold })
        }
    }

    [PSCustomObject]@{
        PSTypeName  = 'Guerrilla.CIGate'
        FailOn      = $FailOn
        ShouldFail  = ($gating.Count -gt 0)
        GatingCount = $gating.Count
        GatingCheckIds = @($gating | ForEach-Object { $_.CheckId })
    }
}
