# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-WiretapReportCsv {
    <#
    .SYNOPSIS
        Exports Wiretap flagged changes to CSV format.

    .DESCRIPTION
        Converts all flagged M365 security changes into a flat CSV format suitable for
        import into SIEM tools, spreadsheets, or ticketing systems.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$FlaggedChanges,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $rows = foreach ($change in $FlaggedChanges) {
        $d = $change.Details

        # Normalize detection-specific fields into common columns
        $targetName = switch ($change.DetectionType) {
            'm365TransportRuleChange'    { $d.TargetName ?? '' }
            'm365ForwardingRule'         { $d.TargetMailbox ?? '' }
            'm365EDiscoverySearch'       { $d.SearchName ?? '' }
            'm365DLPPolicyChange'        { $d.PolicyName ?? '' }
            'm365ExternalSharingChange'  { $d.TargetSite ?? '' }
            'm365TeamsExternalAccess'    { $d.PolicyName ?? '' }
            'm365BulkFileExfiltration'   { "[$($d.FileCount) files]" }
            'm365PowerAutomateFlow'      { $d.FlowName ?? '' }
            'm365DefenderAlertChange'    { $d.PolicyName ?? '' }
            'm365AuditLogDisablement'    { $d.AffectedScope ?? '' }
            default                      { '' }
        }

        $changeNotes = if ($d -is [hashtable] -and $d.ChangeNotes) {
            @($d.ChangeNotes) -join ' | '
        } elseif ($d -is [hashtable] -and $d.ModificationNotes) {
            @($d.ModificationNotes) -join ' | '
        } else { '' }

        $activity = if ($d -is [hashtable]) { $d.Activity ?? $d.OperationType ?? '' } else { '' }

        [PSCustomObject]@{
            Timestamp       = $change.Timestamp
            DetectionType   = $change.DetectionType
            Severity        = $change.Severity ?? ''
            Actor           = $change.Actor ?? ''
            TargetName      = $targetName
            Activity        = $activity
            Description     = $change.Description ?? ''
            ChangeNotes     = $changeNotes
            # Type-specific columns from Details hashtable
            IsExternal      = if ($d -is [hashtable] -and $null -ne $d.IsExternal) { $d.IsExternal } else { '' }
            IsServerSide    = if ($d -is [hashtable] -and $null -ne $d.IsServerSide) { $d.IsServerSide } else { '' }
            IsDisabling     = if ($d -is [hashtable] -and $null -ne $d.IsDisabling) { $d.IsDisabling } else { '' }
            IsRemoved       = if ($d -is [hashtable] -and $null -ne $d.IsRemoved) { $d.IsRemoved } else { '' }
            IsWeakened      = if ($d -is [hashtable] -and ($null -ne $d.IsWeakened -or $null -ne $d.SharingWeakened -or $null -ne $d.AccessWeakened)) {
                                  $d.IsWeakened -or $d.SharingWeakened -or $d.AccessWeakened
                              } else { '' }
            ForwardingDest  = if ($d -is [hashtable]) { $d.ForwardingDestination ?? '' } else { '' }
            FileCount       = if ($d -is [hashtable]) { $d.FileCount ?? '' } else { '' }
            AffectedScope   = if ($d -is [hashtable]) { $d.AffectedScope ?? '' } else { '' }
        }
    }

    $rows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
