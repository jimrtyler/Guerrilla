#requires -version 7.0
<#
.SYNOPSIS
    Prove that each release gate can fail: an injected failure must surface as a
    non-zero exit code through the SAME invocation shape the gate uses.

.DESCRIPTION
    A gate that cannot demonstrate its ability to fail proves nothing — a green
    light is only meaningful if red is reachable. Gate C carries its poison
    self-test inside its own test file (Tests/Unit/ZeroTrustSchema.Tests.ps1);
    this script covers the other three:

      A: golden-fixture suite  — run Invoke-FixtureTests.ps1 -PoisonSelfTest
         (one expected verdict flipped in memory) and require a non-zero exit.
      B: collector contracts   — run the gate-B wrapper form against a poisoned
         contract-shaped Pester file and require a non-zero exit.
      D: full unit suite       — run the gate-D wrapper form against a poisoned
         unit-test directory and require a non-zero exit.

    Each poison run replicates the literal command shape used by
    Publish-Release.ps1 (child pwsh, Invoke-Pester -PassThru, exit FailedCount),
    so a break in exit-code propagation anywhere along that path turns THIS
    script red. Exits 0 only when every gate proved it can fail.

.EXAMPLE
    pwsh Tests/Invoke-GatePoisonSelfTests.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot   # repo root (this script lives in Tests/)
$failures = [System.Collections.Generic.List[string]]::new()

function Assert-PoisonRed {
    param([string]$Gate, [int]$ExitCode)
    if ($ExitCode -eq 0) {
        Write-Host ("  [FAIL] gate {0}: poisoned input exited 0 — the gate has lost the ability to fail." -f $Gate) -ForegroundColor Red
        $script:failures.Add($Gate)
    } else {
        Write-Host ("  [ok] gate {0}: poisoned input exited {1} (red reachable)" -f $Gate, $ExitCode) -ForegroundColor Green
    }
}

# --- Gate A: golden-fixture suite with one expected verdict flipped ---------------
Write-Host '-- poison gate A: fixture suite with an impossible expected verdict --'
& pwsh -NoProfile -File (Join-Path $root 'Tests' 'Invoke-FixtureTests.ps1') -PoisonSelfTest *> $null
Assert-PoisonRed -Gate 'A' -ExitCode $LASTEXITCODE

# --- Gates B and D: the Invoke-Pester wrapper forms against poisoned suites -------
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) ("guerrilla-gate-poison-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
try {
    # Gate B shape: Invoke-Pester -Path <single file>; exit FailedCount.
    # The poison is contract-shaped: an asserted request URI that cannot match.
    $poisonB = Join-Path $scratch 'PoisonContract.Tests.ps1'
    @'
Describe 'poison collector contract' {
    It 'a collector requesting the wrong endpoint must turn this suite red' {
        $requestedUri = '/poison/wrong/endpoint'
        $requestedUri | Should -Be '/v1.0/expected/endpoint'
    }
}
'@ | Set-Content -Path $poisonB -Encoding utf8
    Write-Host '-- poison gate B: contract wrapper against a failing contract test --'
    & pwsh -NoProfile -c "`$r = Invoke-Pester -Path '$poisonB' -Output None -PassThru; exit `$r.FailedCount" *> $null
    Assert-PoisonRed -Gate 'B' -ExitCode $LASTEXITCODE

    # Gate D shape: Invoke-Pester -Path <directory>; exit FailedCount.
    $poisonDir = Join-Path $scratch 'unit'
    New-Item -ItemType Directory -Path $poisonDir -Force | Out-Null
    @'
Describe 'poison unit test' {
    It 'an injected failing unit test must turn the suite red' {
        1 | Should -Be 2
    }
}
'@ | Set-Content -Path (Join-Path $poisonDir 'Poison.Tests.ps1') -Encoding utf8
    Write-Host '-- poison gate D: unit-suite wrapper against a failing test directory --'
    & pwsh -NoProfile -c "`$r = Invoke-Pester -Path '$poisonDir' -Output None -PassThru; exit `$r.FailedCount" *> $null
    Assert-PoisonRed -Gate 'D' -ExitCode $LASTEXITCODE
} finally {
    Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

if ($failures.Count -gt 0) {
    Write-Host ("POISON SELF-TEST RED: gate(s) {0} did not fail on poisoned input." -f ($failures -join ', ')) -ForegroundColor Red
    exit 1
}
Write-Host 'All gates proved they can fail (A, B, D poison-verified; C self-tests in-file).' -ForegroundColor Green
exit 0
