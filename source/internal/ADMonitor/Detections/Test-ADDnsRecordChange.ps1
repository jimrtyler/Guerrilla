# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-ADDnsRecordChange {
    [CmdletBinding()]
    param(
        [array]$DNSChanges = @()
    )

    $indicators = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($DNSChanges.Count -eq 0) { return @() }

    # Separate added from removed
    $added = @($DNSChanges | Where-Object { $_.ChangeType -eq 'Added' })
    $removed = @($DNSChanges | Where-Object { $_.ChangeType -eq 'Removed' })

    # Check for suspicious patterns in added records
    $suspiciousPatterns = @(
        'wpad',          # Web Proxy Auto-Discovery (WPAD poisoning)
        'isatap',        # ISATAP tunnel interface
        '_msdcs',        # Domain controller SRV records
        '_ldap',         # LDAP service records
        '_kerberos',     # Kerberos service records
        '_gc',           # Global catalog records
        'burp',          # Common pentesting tools
        'proxy',         # Proxy-related names
        'vpn'            # VPN-related names
    )

    $suspiciousAdded = @($added | Where-Object {
        $name = $_.Name.ToLower()
        $isSuspicious = $false
        foreach ($pattern in $suspiciousPatterns) {
            if ($name -match $pattern) {
                $isSuspicious = $true
                break
            }
        }
        $isSuspicious
    })

    if ($added.Count -gt 0) {
        $description = "$($added.Count) DNS record(s) added"
        if ($suspiciousAdded.Count -gt 0) {
            $suspiciousNames = @($suspiciousAdded | ForEach-Object { "$($_.Name) ($($_.Zone))" })
            $description += " - SUSPICIOUS: $($suspiciousNames -join ', ')"
        }

        $addedNames = @($added | ForEach-Object { "$($_.Name) ($($_.Zone))" }) | Select-Object -First 10
        $description += ": $($addedNames -join ', ')"
        if ($added.Count -gt 10) { $description += " (and $($added.Count - 10) more)" }

        $detectionId = "adDnsRecordChange_added_$([datetime]::UtcNow.ToString('yyyyMMddHHmm'))"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = 'DNS Records Added'
            DetectionType = 'adDnsRecordChange'
            Description   = "DNS RECORD CHANGE - $description"
            Details       = @{
                AddedCount     = $added.Count
                SuspiciousCount = $suspiciousAdded.Count
                Records        = @($added | Select-Object -First 20)
            }
            Count         = $added.Count
            Score         = 0
            Severity      = ''
        })
    }

    if ($removed.Count -gt 0) {
        $removedNames = @($removed | ForEach-Object { "$($_.Name) ($($_.Zone))" }) | Select-Object -First 10
        $description = "$($removed.Count) DNS record(s) removed: $($removedNames -join ', ')"
        if ($removed.Count -gt 10) { $description += " (and $($removed.Count - 10) more)" }

        $detectionId = "adDnsRecordChange_removed_$([datetime]::UtcNow.ToString('yyyyMMddHHmm'))"

        $indicators.Add([PSCustomObject]@{
            DetectionId   = $detectionId
            DetectionName = 'DNS Records Removed'
            DetectionType = 'adDnsRecordChange'
            Description   = "DNS RECORD CHANGE - $description"
            Details       = @{
                RemovedCount = $removed.Count
                Records      = @($removed | Select-Object -First 20)
            }
            Count         = $removed.Count
            Score         = 0
            Severity      = ''
        })
    }

    return @($indicators)
}
