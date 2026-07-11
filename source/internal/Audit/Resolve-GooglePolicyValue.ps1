# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Resolve-GooglePolicyValue {
    <#
    .SYNOPSIS
        Reads a Cloud Identity policy setting for a Fortification check, returning per-OU
        field values in a shape that is immune to how Get-GooglePolicySetting hands them back.
    .DESCRIPTION
        The GWS-1 placeholder->real-check conversions all need the same three-way answer:

          $null   the Cloud Identity Policy API was unavailable (scope not delegated / API
                  disabled -> the collector returned $null). The check should SKIP with a
                  "scope not delegated" message — it is NOT a pass or a fail.
          @()     the API was available but returned no policy of this type for the tenant
                  (or the requested field is absent from the value shape). The check should
                  SKIP — never invent a PASS/FAIL from a missing value.
          @(...)  one entry per targeting OU / group. With -Field, each entry is that field's
                  value; without -Field, each entry is the whole setting.value object.

        Shape immunity: the committed Get-GooglePolicySetting returns setting.value objects,
        but a live-validation note described callers reading .setting.value off a returned
        *policy* object. Rather than bet 60 checks on one shape, this normalizer accepts
        either — if an entry still looks like a policy (has a .setting.value), it unwraps it;
        otherwise it treats the entry as the value object directly.
    .PARAMETER Policies
        $AuditData.CloudIdentityPolicies (the object from Get-GoogleCloudIdentityPolicies).
    .PARAMETER Type
        Bare setting type, e.g. 'security.less_secure_apps'.
    .PARAMETER Field
        Optional field name to extract from each value object, e.g. 'allowLessSecureApps'.
        Entries missing the field are dropped (so the result can be @() -> SKIP).
    #>
    [CmdletBinding()]
    param(
        $Policies,
        [Parameter(Mandatory)][string]$Type,
        [string]$Field
    )

    # API unavailable -> $null (caller SKIPs distinctly from "type absent").
    if (-not $Policies -or -not $Policies.ByType) { return $null }

    $raw = Get-GooglePolicySetting -Policies $Policies -Type $Type

    # Normalize each entry to its value object regardless of which shape we were handed.
    $values = foreach ($item in @($raw)) {
        if ($null -eq $item) { continue }
        $props = $item.PSObject.Properties.Name
        if (($props -contains 'setting') -and $item.setting -and $item.setting.value) {
            $item.setting.value
        } else {
            $item
        }
    }
    $values = @($values | Where-Object { $null -ne $_ })

    if (-not $PSBoundParameters.ContainsKey('Field') -or [string]::IsNullOrEmpty($Field)) {
        return @($values)
    }

    $fieldVals = foreach ($v in $values) {
        if ($v.PSObject.Properties.Name -contains $Field) { $v.$Field }
    }
    return @($fieldVals)
}

function ConvertFrom-GoogleDurationSeconds {
    <#
    .SYNOPSIS
        Parses a Cloud Identity duration string ("1209600s", "0s") to an integer of seconds.
        Returns $null if the value isn't a recognizable "<n>s" duration.
    #>
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$Duration)
    process {
        if ($null -eq $Duration) { return $null }
        $s = [string]$Duration
        if ($s -match '^\s*(\d+(?:\.\d+)?)s\s*$') { return [double]$Matches[1] }
        # Some shapes already deserialize to a number of seconds.
        $n = 0.0
        if ([double]::TryParse($s, [ref]$n)) { return $n }
        return $null
    }
}
