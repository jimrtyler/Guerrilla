# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-GoogleCloudIdentityPolicies {
    <#
    .SYNOPSIS
        Collects Google Workspace setting policies from the Cloud Identity Policy API and
        indexes them by setting type.
    .DESCRIPTION
        policies.list (https://cloudidentity.googleapis.com/v1/policies) returns the full
        set of effective Workspace settings (Gmail, Drive, Chat, Meet, Calendar, security,
        DLP rules, service on/off, …) — the data that previously could only be "verified in
        the Admin Console". This is what turns those placeholder checks into real ones.

        IMPORTANT: the cloud-identity.policies.readonly scope is requested in its OWN token,
        deliberately isolated from the main Google scan token. On a tenant that has NOT
        granted that domain-wide-delegation scope (or hasn't enabled the Cloud Identity API),
        the token exchange fails with unauthorized_client — we catch that and return $null so
        the rest of the Google scan is unaffected and the policy-backed checks simply SKIP.
        (Adding the scope to the shared token set would break Google auth for every tenant
        that hasn't delegated it — hence the isolation.)

        Returns an object: { All = <all policies>; ByType = @{ '<type>' = @(policies…) };
        Count = <n> }, or $null when the API is unavailable. Each policy carries
        setting.type (e.g. 'settings/gmail.auto_forwarding'), setting.value (the per-type
        value struct), and policyQuery (the OU/group it applies to).
    .PARAMETER ServiceAccountKeyPath
        Path to the service-account JSON key.
    .PARAMETER AdminEmail
        Delegated super-admin to impersonate.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceAccountKeyPath,
        [Parameter(Mandatory)][string]$AdminEmail,
        [switch]$Quiet
    )

    $scope = 'https://www.googleapis.com/auth/cloud-identity.policies.readonly'

    $token = $null
    try {
        $token = Get-GoogleAccessToken -ServiceAccountKeyPath $ServiceAccountKeyPath `
            -AdminEmail $AdminEmail -Scopes @($scope)
    } catch {
        Write-Verbose "Cloud Identity Policy API unavailable (scope not delegated or API not enabled): $($_.Exception.Message)"
        return $null
    }
    if (-not $token) { return $null }

    $policies = @(Invoke-GoogleAdminApi -AccessToken $token `
            -Uri 'https://cloudidentity.googleapis.com/v1/policies' `
            -Paginate -ItemsProperty 'policies' -Quiet:$Quiet)

    # Index by bare setting type ('settings/gmail.auto_forwarding' -> 'gmail.auto_forwarding').
    # A type can appear multiple times (one policy per targeted OU/group).
    $byType = @{}
    foreach ($p in $policies) {
        if (-not $p.setting -or -not $p.setting.type) { continue }
        $type = ([string]$p.setting.type) -replace '^settings/', ''
        if (-not $type) { continue }
        if (-not $byType.ContainsKey($type)) {
            $byType[$type] = [System.Collections.Generic.List[object]]::new()
        }
        $byType[$type].Add($p)
    }

    return [PSCustomObject]@{
        All    = $policies
        ByType = $byType
        Count  = @($policies).Count
    }
}

function Get-GooglePolicySetting {
    <#
    .SYNOPSIS
        Looks up a Cloud Identity setting type and returns its value object(s).
    .DESCRIPTION
        Returns an array of setting.value objects (one per matching policy / targeted OU),
        or @() when the type isn't present. Checks read individual fields off these values
        and should SKIP when an expected field is absent — so an unexpected value shape can
        never produce a wrong PASS/FAIL.
    .PARAMETER Policies
        The object returned by Get-GoogleCloudIdentityPolicies (or $auditData.CloudIdentityPolicies).
    .PARAMETER Type
        The bare setting type, e.g. 'gmail.auto_forwarding'.
    #>
    [CmdletBinding()]
    param(
        $Policies,
        [Parameter(Mandatory)][string]$Type
    )
    if (-not $Policies -or -not $Policies.ByType) { return @() }
    $list = $Policies.ByType[$Type]
    if (-not $list) { return @() }
    return @($list | ForEach-Object { $_.setting.value })
}
