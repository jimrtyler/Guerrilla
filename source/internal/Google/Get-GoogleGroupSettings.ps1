# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GoogleGroupSettings {
    <#
    .SYNOPSIS
        Enriches directory groups with their Groups Settings (visibility, join policy, external
        membership) — the data needed to detect internet-readable and open-join groups.
    .DESCRIPTION
        The directory groups.list endpoint returns group identity but NOT the exposure-relevant
        settings (whoCanViewGroup, whoCanJoin, allowExternalMembers). Those live in the Groups
        Settings API (https://www.googleapis.com/auth/apps.groups.settings, already in the
        requested scope set). This collector calls that API once per group and returns a hashtable
        keyed by group email.

        Token isolation: the apps.groups.settings scope is requested in its OWN token so a tenant
        that hasn't delegated it degrades gracefully — the collector returns $null and the
        dependent Tradecraft checks SKIP, instead of breaking the Google scan.

        Per-group calls are O(groups); to bound wall-clock on very large tenants the collector
        caps at MaxGroups (default 1000) and logs when it truncates (never silently).
    .PARAMETER ServiceAccountKeyPath
        Path to the service-account JSON key.
    .PARAMETER AdminEmail
        Delegated super-admin to impersonate.
    .PARAMETER Groups
        The directory groups (each must expose an .email).
    .PARAMETER MaxGroups
        Cap on groups inspected (0 = no cap). Default 1000.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceAccountKeyPath,
        [Parameter(Mandatory)][string]$AdminEmail,
        [object[]]$Groups = @(),
        [int]$MaxGroups = 1000,
        [switch]$Quiet
    )

    $scope = 'https://www.googleapis.com/auth/apps.groups.settings'
    $token = $null
    try {
        $token = Get-GoogleAccessToken -ServiceAccountKeyPath $ServiceAccountKeyPath `
            -AdminEmail $AdminEmail -Scopes @($scope)
    } catch {
        Write-Verbose "Groups Settings API unavailable (scope not delegated): $($_.Exception.Message)"
        return $null
    }
    if (-not $token) { return $null }

    $list = @($Groups | Where-Object { $_.email -or $_.Email })
    $truncated = $false
    if ($MaxGroups -gt 0 -and $list.Count -gt $MaxGroups) {
        if (-not $Quiet) { Write-Warning "Get-GoogleGroupSettings: $($list.Count) groups exceeds cap $MaxGroups — inspecting the first $MaxGroups (group-exposure coverage is partial)." }
        $list = $list[0..($MaxGroups - 1)]
        $truncated = $true
    }

    $result = @{}
    foreach ($g in $list) {
        $email = $g.email ?? $g.Email
        if (-not $email) { continue }
        try {
            $s = Invoke-GoogleAdminApi -AccessToken $token `
                -Uri "https://www.googleapis.com/groups/v1/groups/$([uri]::EscapeDataString($email))?alt=json" `
                -Quiet:$Quiet
            if ($s) {
                $result[$email] = [PSCustomObject]@{
                    email                = $email
                    whoCanViewGroup      = $s.whoCanViewGroup
                    whoCanJoin           = $s.whoCanJoin
                    whoCanPostMessage    = $s.whoCanPostMessage
                    whoCanViewMembership = $s.whoCanViewMembership
                    allowExternalMembers = $s.allowExternalMembers
                }
            }
        } catch {
            Write-Verbose "Group settings unavailable for $email : $($_.Exception.Message)"
        }
    }

    if ($result.Count -gt 0 -and $truncated) { $result['__truncated'] = $true }
    return $result
}
