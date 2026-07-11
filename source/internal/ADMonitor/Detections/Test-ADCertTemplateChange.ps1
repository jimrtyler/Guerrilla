# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADCertTemplateChange {
    [CmdletBinding()]
    param(
        [array]$CertTemplateChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($CertTemplateChanges.Count -eq 0) { return @() }

    foreach ($change in $CertTemplateChanges) {
        $description = switch ($change.ChangeType) {
            'Added' {
                $extra = @()
                if ($change.ContainsKey('EnrolleeSuppliesSubject') -and $change.EnrolleeSuppliesSubject) {
                    $extra += 'ENROLLEE_SUPPLIES_SUBJECT (ESC1 risk)'
                }
                if ($change.ContainsKey('AllowsAuthentication') -and $change.AllowsAuthentication) {
                    $extra += 'allows authentication'
                }
                $extraStr = if ($extra.Count -gt 0) { " [$($extra -join ', ')]" } else { '' }
                "New certificate template: $($change.Name)$extraStr"
            }
            'Modified' {
                "Certificate template modified: $($change.Details)"
            }
            'Removed' {
                "Certificate template removed: $($change.Name)"
            }
            default { $change.Details }
        }

        $detectionId = "adCertTemplateChange_$($change.Name -replace '\s+', '_')_$($change.ChangeType)"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Certificate Template $($change.ChangeType): $($change.Name)"
            DetectionType = 'adCertTemplateChange'
            Description   = "CERT TEMPLATE CHANGE - $description"
            Details       = @{
                Name                    = $change.Name
                ChangeType              = $change.ChangeType
                EnrolleeSuppliesSubject = if ($change.ContainsKey('EnrolleeSuppliesSubject')) { $change.EnrolleeSuppliesSubject } else { $false }
                AllowsAuthentication    = if ($change.ContainsKey('AllowsAuthentication')) { $change.AllowsAuthentication } else { $false }
            }
            Count         = 1
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
