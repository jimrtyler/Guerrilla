# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
#
# Pure evaluator for EIDSCA (Entra ID Security Config Analyzer) controls. Given a control accessor
# (source object + dotted property path + operator + expected value, from Data/AuditChecks/EidscaChecks.json)
# and the collected Graph policy objects, returns PASS / FAIL / SKIP. SKIP == "Not Assessed": the source
# object or property wasn't collected (e.g. scope/module not connected) — never scored as PASS.
# Offline-testable; no Graph calls. Property paths mirror the live Graph objects our collectors store raw.

function Get-EidscaPropertyValue {
    [CmdletBinding()]
    param($Object, [string]$Path)
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Path)) { return $null }
    $cur = $Object
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        $cur = $cur.$seg
    }
    return $cur
}

function Resolve-EidscaControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Control,
        [Parameter(Mandatory)][hashtable]$Sources
        # Sources keys: AuthorizationPolicy, AuthMethodsPolicy, MethodConfigurations[], AdminConsentRequestPolicy, DirectorySettings[]
    )

    $op = "$($Control.op)"

    # ── Resolve the actual value from the right source object ──
    $parentPresent = $true
    $actual = $null
    switch ("$($Control.source)") {
        'directorySetting' {
            # find a value by name across all collected directory settings
            $found = $false
            foreach ($s in @($Sources.DirectorySettings)) {
                $v = @($s.values) | Where-Object { "$($_.name)" -eq "$($Control.path)" } | Select-Object -First 1
                if ($v) { $actual = $v.value; $found = $true; break }
            }
            if (-not $found) { return @{ Status = 'SKIP'; Actual = $null } }
        }
        'authMethodConfig' {
            $cfg = @($Sources.MethodConfigurations) | Where-Object {
                "$($_.id)" -eq "$($Control.configId)" -or "$($_.'@odata.type')" -match "$($Control.configId)"
            } | Select-Object -First 1
            if ($null -eq $cfg) { return @{ Status = 'SKIP'; Actual = $null } }
            $actual = Get-EidscaPropertyValue -Object $cfg -Path $Control.path
            $obj = $cfg
        }
        default {
            $obj = switch ("$($Control.source)") {
                'authorizationPolicy'       { $Sources.AuthorizationPolicy }
                'authMethodsPolicy'         { $Sources.AuthMethodsPolicy }
                'adminConsentRequestPolicy' { $Sources.AdminConsentRequestPolicy }
                default { $null }
            }
            if ($null -eq $obj) { return @{ Status = 'SKIP'; Actual = $null } }
            $actual = Get-EidscaPropertyValue -Object $obj -Path $Control.path
        }
    }

    # For simple comparisons, an unresolved property == Not Assessed. For the "presence" operators
    # (notempty / fido2) the parent object WAS present, so absence is a real FAIL, not a SKIP.
    if ($null -eq $actual -and $op -notin @('notempty', 'fido2-aaguid-enforced')) {
        return @{ Status = 'SKIP'; Actual = $null }
    }

    $exp = $Control.expected
    $pass = switch ($op) {
        'eq' { "$actual".ToLower() -eq "$exp".ToLower() }
        'ne' { "$actual".ToLower() -ne "$exp".ToLower() }
        'in' { @(@($exp) | ForEach-Object { "$_".ToLower() }) -contains "$actual".ToLower() }
        'ge' { $n = $actual -as [double]; if ($null -eq $n) { $null } else { $n -ge ([double]$exp) } }
        'le' { $n = $actual -as [double]; if ($null -eq $n) { $null } else { $n -le ([double]$exp) } }
        'clike-any' { (@($actual) | Where-Object { "$_" -like "$exp*" }).Count -gt 0 }
        'notempty'  { (@($actual) | Where-Object { $_ }).Count -gt 0 }
        'fido2-aaguid-enforced' {
            $aa = Get-EidscaPropertyValue -Object $obj -Path 'keyRestrictions.aaGuids'
            $et = Get-EidscaPropertyValue -Object $obj -Path 'keyRestrictions.enforcementType'
            ((@($aa) | Where-Object { $_ }).Count -gt 0) -and ("$et" -in @('allow', 'block'))
        }
        default { $null }
    }

    if ($null -eq $pass) { return @{ Status = 'SKIP'; Actual = $actual } }  # couldn't evaluate -> Not Assessed
    return @{ Status = ($(if ($pass) { 'PASS' } else { 'FAIL' })); Actual = $actual }
}
