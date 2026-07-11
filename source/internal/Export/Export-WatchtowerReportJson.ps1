# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Export-WatchtowerReportJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$ChangeProfile,

        [Parameter(Mandatory)]
        [PSCustomObject[]]$FlaggedChanges,

        [Parameter(Mandatory)]
        [string]$DomainName,

        [Parameter(Mandatory)]
        [string]$ScanId,

        [Parameter(Mandatory)]
        [datetime]$Timestamp,

        [Parameter(Mandatory)]
        [string]$FilePath
    )

    $report = @{
        metadata = @{
            reportType  = 'WatchtowerReport'
            scanId      = $ScanId
            timestamp   = $Timestamp.ToString('o')
            theater     = 'ActiveDirectory'
            domainName  = $DomainName
            generator   = 'Guerrilla.Watchtower'
        }
        summary = @{
            threatLevel          = $ChangeProfile.ThreatLevel
            threatScore          = $ChangeProfile.ThreatScore
            totalChangesDetected = $FlaggedChanges.Count
            criticalCount        = @($FlaggedChanges | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
            highCount            = @($FlaggedChanges | Where-Object { $_.Severity -eq 'HIGH' }).Count
            mediumCount          = @($FlaggedChanges | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
            lowCount             = @($FlaggedChanges | Where-Object { $_.Severity -eq 'LOW' }).Count
            newThreatsCount      = @($FlaggedChanges | Where-Object { $_.IsNew }).Count
        }
        changes = @{
            groupChanges         = @($ChangeProfile.GroupChanges)
            gpoChanges           = @($ChangeProfile.GPOChanges)
            gpoLinkChanges       = @($ChangeProfile.GPOLinkChanges)
            trustChanges         = @($ChangeProfile.TrustChanges)
            aclChanges           = @($ChangeProfile.ACLChanges)
            adminSDHolderChanged = $ChangeProfile.AdminSDHolderChanged
            krbtgtChanged        = $ChangeProfile.KrbtgtChanged
            certTemplateChanges  = @($ChangeProfile.CertTemplateChanges)
            delegationChanges    = @($ChangeProfile.DelegationChanges)
            dnsChanges           = @($ChangeProfile.DNSChanges)
            schemaChanges        = @($ChangeProfile.SchemaChanges)
            newComputers         = @($ChangeProfile.NewComputers)
            newServiceAccounts   = @($ChangeProfile.NewServiceAccounts)
        }
        detections = @($FlaggedChanges | ForEach-Object {
            @{
                detectionId   = $_.DetectionId
                detectionName = $_.DetectionName
                severity      = $_.Severity
                score         = $_.Score
                isNew         = $_.IsNew
                description   = $_.Description
                details       = $_.Details
            }
        })
    }

    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $FilePath -Encoding UTF8
}
