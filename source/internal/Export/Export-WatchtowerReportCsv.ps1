# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-WatchtowerReportCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject[]]$FlaggedChanges,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $rows = foreach ($c in $FlaggedChanges) {
        # Flatten details hashtable for CSV consumption
        $detailStr = ''
        if ($c.Details -and $c.Details -is [hashtable]) {
            $detailParts = [System.Collections.Generic.List[string]]::new()
            foreach ($key in ($c.Details.Keys | Sort-Object)) {
                $val = $c.Details[$key]
                if ($val -is [array]) {
                    $detailParts.Add("$key=$($val -join ';')")
                } elseif ($val -is [hashtable]) {
                    $subParts = $val.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
                    $detailParts.Add("$key={$($subParts -join ';')}")
                } elseif ($null -ne $val) {
                    $detailParts.Add("$key=$val")
                }
            }
            $detailStr = $detailParts -join ' | '
        }

        [PSCustomObject]@{
            DetectionId   = $c.DetectionId
            DetectionName = $c.DetectionName
            Severity      = $c.Severity
            Score         = '{0:N1}' -f $c.Score
            IsNew         = if ($c.IsNew) { 'YES' } else { '' }
            Description   = $c.Description
            Details       = $detailStr
        }
    }

    $rows | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}
