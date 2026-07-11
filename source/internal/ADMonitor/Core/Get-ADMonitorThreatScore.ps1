# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Get-ADMonitorThreatScore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Profile,

        [hashtable]$Weights
    )

    # Default weights for AD monitoring detections
    if (-not $Weights) {
        $Weights = @{
            adDomainAdminChange       = 90
            adEnterpriseAdminChange   = 95
            adPrivilegedGroupChange   = 70
            adAdminSDHolderChange     = 80
            adGPOModification         = 50
            adGPOLinkChange           = 45
            adNewTrust                = 85
            adTrustModified           = 75
            adDCSyncPermission        = 95
            adKrbtgtPasswordChange    = 70
            adServiceAccountCreation  = 30
            adSensitivePasswordChange = 40
            adComputerAccountCreation = 20
            adCertTemplateChange      = 65
            adCertEnrollmentAnomaly   = 55
            adDelegationChange        = 60
            adOUPermissionChange      = 50
            adDnsRecordChange         = 35
            adSchemaChange            = 80
            adReplicationAnomaly      = 70
            adLdapQueryAnomaly        = 25
        }
    }

    $totalScore = 0.0

    # Score each indicator based on its detection type
    foreach ($indicator in $Profile.Indicators) {
        $detectionType = $indicator.DetectionType
        $weight = if ($Weights.ContainsKey($detectionType)) { $Weights[$detectionType] } else { 25 }

        # Apply multiplier for multiple items of the same type
        $multiplier = 1.0
        if ($indicator.Count -gt 1) {
            # Diminishing returns: additional items add 20% each
            $multiplier = 1.0 + (([Math]::Min($indicator.Count, 10) - 1) * 0.2)
        }

        $indicatorScore = [Math]::Round($weight * $multiplier, 1)
        $indicator | Add-Member -NotePropertyName 'Score' -NotePropertyValue $indicatorScore -Force

        # Map weight to severity
        $severity = switch ($true) {
            ($weight -ge 90)  { 'CRITICAL'; break }
            ($weight -ge 60)  { 'HIGH'; break }
            ($weight -ge 35)  { 'MEDIUM'; break }
            default           { 'LOW' }
        }
        $indicator | Add-Member -NotePropertyName 'Severity' -NotePropertyValue $severity -Force

        $totalScore += $indicatorScore
    }

    # Assign overall threat level
    $threatLevel = switch ($true) {
        ($totalScore -ge 150) { 'CRITICAL'; break }
        ($totalScore -ge 80)  { 'HIGH'; break }
        ($totalScore -ge 35)  { 'MEDIUM'; break }
        ($totalScore -gt 0)   { 'LOW'; break }
        default               { 'Clean' }
    }

    $Profile.ThreatScore = $totalScore
    $Profile.ThreatLevel = $threatLevel

    return $Profile
}
