# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-NotAssessedFinding {
    <#
    .SYNOPSIS
        Returns a SKIP ("Not Assessed") finding when the data a check depends on
        failed to collect — so absence of evidence is never scored as PASS.
    .DESCRIPTION
        A check must call this BEFORE it returns a PASS-on-empty verdict. If a
        collector recorded a failure for any of the named source keys (i.e. the
        data was never successfully gathered), an empty result is indistinguishable
        from a genuinely clean tenant — and scoring it PASS manufactures false
        confidence. In that case this returns a SKIP finding, which the posture
        scorer (Get-AuditPostureScore) excludes from the score entirely rather than
        crediting as 100.

        Returns $null when none of the named sources failed — meaning the data WAS
        collected and an empty result is a legitimate PASS the caller can proceed to.

        Collector failures are recorded in a hashtable Errors map keyed by source
        name (e.g. $AuditData.Errors['TrustRelationships'], or a nested
        $AuditData.Federation.Errors['Domains']). Pass every Errors map that could
        carry the dependency. Non-hashtable Errors (a few AD sub-collectors use an
        array of strings for fine-grained partial failures) are ignored here.
    .EXAMPLE
        $na = Get-NotAssessedFinding -CheckDefinition $CheckDefinition `
            -ErrorMap $AuditData.Errors -SourceKey 'TrustRelationships' `
            -Subject 'trust relationships'
        if ($na) { return $na }
        # ... safe to treat an empty $AuditData.Trusts as a real PASS below ...
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$CheckDefinition,

        # One or more collector Errors maps to inspect. $null entries are ignored,
        # so callers can pass an optional nested map without guarding it first.
        [AllowNull()]
        [object[]]$ErrorMap,

        # The collector source key(s) this check depends on. If ANY is present in
        # ANY supplied Errors map, the dependency could not be assessed. May be empty
        # when only prefix matching is used.
        [string[]]$SourceKey = @(),

        # Prefix(es) for collectors that record per-entity error keys (e.g. Google
        # records 'GmailSettings:user@x' / 'DnsRecords:contoso.com'). Any error key
        # that starts with a supplied prefix trips the guard.
        [string[]]$SourceKeyPrefix = @(),

        # Human-readable subject for the message, e.g. 'trust relationships'.
        [Parameter(Mandatory)]
        [string]$Subject
    )

    foreach ($map in $ErrorMap) {
        if ($map -isnot [System.Collections.IDictionary]) { continue }

        # Exact source-key match
        foreach ($key in $SourceKey) {
            if ($map.Contains($key)) {
                return New-NotAssessedSkip -CheckDefinition $CheckDefinition -Subject $Subject `
                    -FailedSource $key -Reason $map[$key]
            }
        }

        # Prefix match for per-entity error keys
        foreach ($prefix in $SourceKeyPrefix) {
            foreach ($k in $map.Keys) {
                if ("$k".StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    return New-NotAssessedSkip -CheckDefinition $CheckDefinition -Subject $Subject `
                        -FailedSource "$k" -Reason $map[$k]
                }
            }
        }
    }

    return $null
}

function New-NotAssessedSkip {
    # Internal: builds the standard "Not Assessed" SKIP finding for Get-NotAssessedFinding.
    [CmdletBinding()]
    param([hashtable]$CheckDefinition, [string]$Subject, [string]$FailedSource, $Reason)

    New-AuditFinding -CheckDefinition $CheckDefinition -Status 'SKIP' `
        -CurrentValue "Not Assessed — could not collect $Subject ($Reason). This control was not evaluated; absence of evidence is not compliance." `
        -Details @{
            NotAssessed     = $true
            FailedSource    = $FailedSource
            CollectionError = "$Reason"
        }
}
