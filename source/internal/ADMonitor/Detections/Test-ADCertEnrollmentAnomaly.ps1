# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADCertEnrollmentAnomaly {
    [CmdletBinding()]
    param(
        [array]$CertTemplateChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($CertTemplateChanges.Count -eq 0) { return @() }

    # Detect templates that were modified to enable ESC1/ESC2/ESC3 attack paths
    $dangerousChanges = @($CertTemplateChanges | Where-Object {
        $_.ChangeType -eq 'Modified' -and (
            ($_.ContainsKey('EnrolleeSuppliesSubject') -and $_.EnrolleeSuppliesSubject) -or
            ($_.ContainsKey('AllowsAuthentication') -and $_.AllowsAuthentication)
        )
    })

    # Also check for new templates with dangerous configurations
    $dangerousNew = @($CertTemplateChanges | Where-Object {
        $_.ChangeType -eq 'Added' -and
        $_.ContainsKey('EnrolleeSuppliesSubject') -and $_.EnrolleeSuppliesSubject -and
        $_.ContainsKey('AllowsAuthentication') -and $_.AllowsAuthentication
    })

    $allDangerous = @($dangerousChanges) + @($dangerousNew)

    if ($allDangerous.Count -eq 0) { return @() }

    foreach ($change in $allDangerous) {
        $riskFactors = [System.Collections.Generic.List[string]]::new()
        if ($change.ContainsKey('EnrolleeSuppliesSubject') -and $change.EnrolleeSuppliesSubject) {
            $riskFactors.Add('ENROLLEE_SUPPLIES_SUBJECT enabled (ESC1)')
        }
        if ($change.ContainsKey('AllowsAuthentication') -and $change.AllowsAuthentication) {
            $riskFactors.Add('allows domain authentication')
        }

        $riskStr = $riskFactors -join ', '
        $detectionId = "adCertEnrollmentAnomaly_$($change.Name -replace '\s+', '_')"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = "Certificate Enrollment Anomaly: $($change.Name)"
            DetectionType = 'adCertEnrollmentAnomaly'
            Description   = "CERT ENROLLMENT ANOMALY - Template '$($change.Name)' has dangerous configuration: $riskStr. This could enable certificate-based privilege escalation."
            Details       = @{
                TemplateName            = $change.Name
                ChangeType              = $change.ChangeType
                RiskFactors             = @($riskFactors)
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
