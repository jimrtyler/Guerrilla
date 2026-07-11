# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-RemediationPlaybook {
    <#
    .SYNOPSIS
        Generates a step-by-step remediation guide grouped by category and priority.
    .DESCRIPTION
        Produces an HTML playbook organized into phases (critical first, then high, medium, low).
        Each finding includes prerequisites, step-by-step remediation, validation steps,
        effort estimates, and cost tier information.
    .PARAMETER Findings
        Array of audit finding objects. If not provided, reads from latest state.
    .PARAMETER OutputPath
        File path for the HTML output. Default: Guerrilla-Remediation-Playbook.html
    .PARAMETER OrganizationName
        Organization name for the report header.
    .PARAMETER MaxCostTier
        Maximum cost tier to include. Default: Medium.
    .EXAMPLE
        Export-RemediationPlaybook -OrganizationName 'Springfield USD'
    .EXAMPLE
        Export-RemediationPlaybook -MaxCostTier Free -OutputPath ./free-fixes.html
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$Findings,
        [string]$OutputPath,
        [string]$OrganizationName = 'Organization',
        [ValidateSet('Free', 'Low', 'Medium', 'High', 'Enterprise')]
        [string]$MaxCostTier = 'Medium'
    )

    if (-not $OutputPath) { $OutputPath = Join-Path (Get-Location) 'Guerrilla-Remediation-Playbook.html' }

    $dataDir = Get-GuerrillaDataRoot
    if (-not $Findings -or $Findings.Count -eq 0) {
        if (Test-Path $dataDir) {
            foreach ($f in (Get-ChildItem -Path $dataDir -Filter '*.findings.json' -ErrorAction SilentlyContinue)) {
                try { $Findings += @(Get-Content $f.FullName -Raw | ConvertFrom-Json) } catch { }
            }
        }
    }

    if (-not $Findings -or $Findings.Count -eq 0) {
        Write-Warning 'No audit findings available. Run a scan first.'
        return [PSCustomObject]@{ Success = $false; Message = 'No findings'; Path = $null }
    }

    # Load remediation costs
    $remPath = Join-Path $script:ModuleRoot 'Data/RemediationCosts.json'
    $remData = $null
    if (Test-Path $remPath) {
        $remData = Get-Content -Path $remPath -Raw | ConvertFrom-Json -AsHashtable
    }

    $tierOrder = @{ 'Free' = 0; 'Low' = 1; 'Medium' = 2; 'High' = 3; 'Enterprise' = 4 }
    $maxTierIndex = $tierOrder[$MaxCostTier] ?? 2

    $esc = { param([string]$s) [System.Web.HttpUtility]::HtmlEncode($s) }
    $timestamp = [datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss')
    $html = [System.Text.StringBuilder]::new(65536)

    # Filter to actionable findings with cost lookup
    $actionable = @($Findings | Where-Object Status -in @('FAIL', 'WARN') | ForEach-Object {
        $checkId = $_.CheckId ?? $_.Id ?? ''
        $prefix = if ($checkId -match '^([A-Z0-9]+)-') { $Matches[1] } else { '' }
        $costInfo = $remData.overrides.$checkId ?? $remData.categoryDefaults.$prefix
        $tier = $costInfo.costTier ?? 'Medium'
        if ($tierOrder[$tier] -le $maxTierIndex) {
            $_ | Add-Member -NotePropertyName '_CostTier' -NotePropertyValue $tier -PassThru -Force |
                 Add-Member -NotePropertyName '_Effort' -NotePropertyValue ($costInfo.effort ?? 'Medium') -PassThru -Force |
                 Add-Member -NotePropertyName '_Notes' -NotePropertyValue ($costInfo.notes ?? '') -PassThru -Force
        }
    })

    # Group by severity phase
    $phases = @(
        @{ Name = 'Phase 1: Critical Fixes'; Severity = 'Critical'; Color = 'var(--dark-red)' }
        @{ Name = 'Phase 2: High Priority'; Severity = 'High'; Color = 'var(--deep-orange)' }
        @{ Name = 'Phase 3: Medium Priority'; Severity = 'Medium'; Color = 'var(--gold)' }
        @{ Name = 'Phase 4: Low Priority'; Severity = 'Low'; Color = 'var(--sage)' }
    )

    [void]$html.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Remediation Playbook - $(& $esc $OrganizationName)</title>
<style>
:root { --bg:#1a1f16; --surface:#242b1e; --surface-alt:#2d3526; --border:#3d4a35; --text:#d4c9a8; --text-muted:#8a8468; --olive:#a8b58b; --amber:#d4883a; --sage:#6b9b6b; --parchment:#d4c4a0; --gold:#c9a84c; --dim:#6b6b5a; --deep-orange:#c75c2e; --dark-red:#8b2500; }
body { font-family:'Segoe UI',Tahoma,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:20px; }
.container { max-width:900px; margin:0 auto; }
h1 { color:var(--olive); border-bottom:2px solid var(--border); padding-bottom:10px; }
h2 { margin-top:30px; padding:8px 12px; border-radius:4px; }
.item { background:var(--surface); border:1px solid var(--border); border-radius:6px; margin:12px 0; padding:15px; }
.item-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; }
.item-header .title { font-weight:bold; }
.meta { display:flex; gap:12px; color:var(--text-muted); font-size:0.85em; }
.steps { margin:8px 0; padding-left:20px; }
.steps li { margin:6px 0; }
pre { background:var(--surface-alt); padding:8px; border-radius:4px; font-size:0.85em; overflow-x:auto; }
.badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:0.75em; font-weight:bold; }
.footer { color:var(--dim); font-size:0.8em; margin-top:40px; border-top:1px solid var(--border); padding-top:10px; }
@media print { body { background:#fff; color:#333; } .item { page-break-inside:avoid; } :root { --bg:#fff; --surface:#f9f9f9; --surface-alt:#eee; --border:#ccc; --text:#333; --text-muted:#666; --olive:#5a6b3a; --sage:#3a7a3a; --gold:#8a7a2a; --amber:#aa6a1a; --deep-orange:#aa3a0a; --dark-red:#7a1a00; --dim:#999; } }
</style>
</head>
<body>
<div class="container">
<h1>Remediation Playbook</h1>
<p>$(& $esc $OrganizationName) | $($actionable.Count) actionable item(s) | Max cost: $MaxCostTier | $timestamp UTC</p>
"@)

    $itemNum = 0
    foreach ($phase in $phases) {
        $phaseItems = @($actionable | Where-Object Severity -eq $phase.Severity |
            Sort-Object @{Expression={$tierOrder[$_._CostTier]}}, CheckId)
        if ($phaseItems.Count -eq 0) { continue }

        [void]$html.Append("<h2 style='background:var(--surface);border-left:4px solid $($phase.Color);color:$($phase.Color);'>$($phase.Name) ($($phaseItems.Count) items)</h2>`n")

        foreach ($item in $phaseItems) {
            $itemNum++
            $checkId = $item.CheckId ?? $item.Id ?? ''
            $effortHours = switch ($item._Effort) { 'Minimal' { '~15min' } 'Low' { '~1h' } 'Medium' { '~4h' } 'High' { '~2d' } 'Major' { '~2w' } default { '~4h' } }

            [void]$html.Append(@"
<div class="item">
<div class="item-header">
<div class="title">$itemNum. $(& $esc ($item.Name ?? $item.CheckName ?? $checkId))</div>
<div><span class="badge" style="background:$($phase.Color);color:#fff;">$($item.Severity)</span></div>
</div>
<div class="meta">
<span>ID: $checkId</span>
<span>Cost: $($item._CostTier)</span>
<span>Effort: $effortHours</span>
<span>Category: $(& $esc ($item.Category ?? ''))</span>
</div>
$(if ($item.Description) { "<p style='margin:8px 0;'>$(& $esc $item.Description)</p>" })
$(if ($item.RemediationSteps) {
    "<p style='margin:8px 0;'><strong>Steps:</strong> $(& $esc $item.RemediationSteps)</p>"
})
$(if ($item.RecommendedValue) { "<p style='margin:4px 0;color:var(--text-muted);'><strong>Target:</strong> $(& $esc $item.RecommendedValue)</p>" })
$(if ($item._Notes) { "<p style='margin:4px 0;color:var(--text-muted);font-style:italic;'>Note: $(& $esc $item._Notes)</p>" })
$(if ($item.RemediationUrl) { "<p style='margin:4px 0;'><a href='$(& $esc $item.RemediationUrl)' style='color:var(--olive);font-size:0.85em;'>$(& $esc $item.RemediationUrl)</a></p>" })
</div>
"@)
        }
    }

    [void]$html.Append(@"
<div class="footer">
<p>Generated by Guerrilla v2.1.0 | $timestamp UTC</p>
<p style="font-style:italic;">Review each remediation step before implementing. Test changes in a non-production environment first.</p>
</div>
</div>
</body>
</html>
"@)

    $html.ToString() | Set-Content -Path $OutputPath -Encoding UTF8

    return [PSCustomObject]@{
        PSTypeName = 'Guerrilla.RemediationPlaybook'
        Success    = $true
        Path       = (Resolve-Path $OutputPath).Path
        Message    = "Remediation playbook exported to $OutputPath"
        ItemCount  = $itemNum
    }
}
