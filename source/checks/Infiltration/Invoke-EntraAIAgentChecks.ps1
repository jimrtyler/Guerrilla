# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Copilot Studio AI-agent governance dispatcher + checks. Collector:
# Get-PowerPlatformData -> $AuditData.AIAgents (the Dataverse `bots` table per Power
# Platform environment). A failed collection is Not Assessed; a tenant with no agents
# passes (nothing to govern). Field semantics mirror the Copilot Studio bots schema
# (AccessControlPolicy / UserAuthenticationType / AuthenticationTrigger /
# LastPublishedTime / LastModifiedTime / AuthorizedSecurityGroupIds).
function Invoke-EntraAIAgentChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$AuditData
    )

    $checkDefs = Get-AuditCategoryDefinitions -Category 'EntraAIAgentChecks'
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($check in $checkDefs.checks) {
        $funcName = "Test-Infiltration$($check.id -replace '-', '')"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            try {
                $finding = & $funcName -AuditData $AuditData -CheckDefinition $check
                if ($finding) { $findings.Add($finding) }
            } catch {
                Write-Warning "Check $($check.id) failed: $($_.Exception.Message)"
            }
        }
    }

    return @($findings)
}

# Shared Not-Assessed guard + agent-list resolver for the AI-agent checks.
function Get-AIAgentList {
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)
    $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
        -ErrorMap @($AuditData.Errors, $AuditData.AIAgents.Errors) `
        -SourceKey @('AIAgents', 'Agents') -Subject 'Copilot Studio agent (Dataverse) data'
    if ($na) { return @{ Na = $na } }
    return @{ Agents = @($AuditData.AIAgents.Agents) }
}

# ── AIAGENT-001: Restrict who can interact (no broad access) ──────────────
function Test-InfiltrationAIAGENT001 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $r = Get-AIAgentList -AuditData $AuditData -CheckDefinition $CheckDefinition
    if ($r.Na) { return $r.Na }
    $agents = $r.Agents
    if ($agents.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Copilot Studio agents found (nothing to govern)' -Details @{ AgentCount = 0 }
    }

    $broad = @($agents | Where-Object { $_.AccessControlPolicy -in @('Any', 'Any multitenant') })
    $status = if ($broad.Count -eq 0) { 'PASS' } else { 'FAIL' }
    $cv = if ($status -eq 'PASS') {
        "All $($agents.Count) agents restrict who can interact"
    } else {
        "$($broad.Count) of $($agents.Count) agents allow broad access (Any / Any multitenant)"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{ AgentCount = $agents.Count; BroadAccessCount = $broad.Count; BroadAgents = @($broad | ForEach-Object { $_.AIAgentName }) }
}

# ── AIAGENT-002: Require authentication ──────────────────────────────────
function Test-InfiltrationAIAGENT002 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $r = Get-AIAgentList -AuditData $AuditData -CheckDefinition $CheckDefinition
    if ($r.Na) { return $r.Na }
    $agents = $r.Agents
    if ($agents.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Copilot Studio agents found (nothing to govern)' -Details @{ AgentCount = 0 }
    }

    $noAuth = @($agents | Where-Object { $_.UserAuthenticationType -eq 'None' })
    $optionalAuth = @($agents | Where-Object { $_.UserAuthenticationType -ne 'None' -and $_.AuthenticationTrigger -eq 'As Needed' })

    if ($noAuth.Count -gt 0) {
        $status = 'FAIL'
        $cv = "$($noAuth.Count) of $($agents.Count) agents accept anonymous (unauthenticated) interaction"
    } elseif ($optionalAuth.Count -gt 0) {
        $status = 'WARN'
        $cv = "$($optionalAuth.Count) of $($agents.Count) agents make authentication optional (triggered As Needed)"
    } else {
        $status = 'PASS'
        $cv = "All $($agents.Count) agents require authentication"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{
            AgentCount        = $agents.Count
            NoAuthCount       = $noAuth.Count
            OptionalAuthCount = $optionalAuth.Count
            NoAuthAgents      = @($noAuth | ForEach-Object { $_.AIAgentName })
        }
}

# ── AIAGENT-003: Published agents not dormant ────────────────────────────
function Test-InfiltrationAIAGENT003 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $r = Get-AIAgentList -AuditData $AuditData -CheckDefinition $CheckDefinition
    if ($r.Na) { return $r.Na }
    $agents = $r.Agents
    # Only PUBLISHED agents can be dormant-but-exposed.
    $published = @($agents | Where-Object { $_.LastPublishedTime })
    if ($published.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No published Copilot Studio agents to review' -Details @{ PublishedCount = 0 }
    }

    $thresholdDays = 90
    $threshold = (Get-Date).AddDays(-$thresholdDays)
    $dormant = @($published | Where-Object {
        $dt = [datetime]::MinValue
        [datetime]::TryParse("$($_.LastModifiedTime)", [ref]$dt) -and $dt -lt $threshold
    })
    $status = if ($dormant.Count -eq 0) { 'PASS' } else { 'WARN' }
    $cv = if ($status -eq 'PASS') {
        "All $($published.Count) published agents modified within $thresholdDays days"
    } else {
        "$($dormant.Count) of $($published.Count) published agents are dormant (>$thresholdDays days since modification)"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{ PublishedCount = $published.Count; DormantCount = $dormant.Count; DormantAgents = @($dormant | ForEach-Object { $_.AIAgentName }) }
}

# ── AIAGENT-004: Access scoped to security groups ────────────────────────
function Test-InfiltrationAIAGENT004 {
    [CmdletBinding()]
    param([hashtable]$AuditData, [hashtable]$CheckDefinition)

    $r = Get-AIAgentList -AuditData $AuditData -CheckDefinition $CheckDefinition
    if ($r.Na) { return $r.Na }
    $agents = $r.Agents
    if ($agents.Count -eq 0) {
        return New-AuditFinding -CheckDefinition $CheckDefinition -Status 'PASS' `
            -CurrentValue 'No Copilot Studio agents found (nothing to govern)' -Details @{ AgentCount = 0 }
    }

    # Authenticated agents with no authorized security groups are reachable by any
    # authenticated user in the tenant.
    $authenticated = @($agents | Where-Object { $_.UserAuthenticationType -ne 'None' })
    $unscoped = @($authenticated | Where-Object { @($_.AuthorizedSecurityGroupIds | Where-Object { $_ }).Count -eq 0 })
    $status = if ($unscoped.Count -eq 0) { 'PASS' } else { 'WARN' }
    $cv = if ($status -eq 'PASS') {
        "All authenticated agents are scoped to security groups (or there are none)"
    } else {
        "$($unscoped.Count) of $($authenticated.Count) authenticated agents are open to all authenticated users (no security-group scope)"
    }
    return New-AuditFinding -CheckDefinition $CheckDefinition -Status $status -CurrentValue $cv `
        -Details @{ AuthenticatedCount = $authenticated.Count; UnscopedCount = $unscoped.Count; UnscopedAgents = @($unscoped | ForEach-Object { $_.AIAgentName }) }
}
