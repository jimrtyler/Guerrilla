# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Resolve-DomainMailSecurity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Domain,

        [string]$DkimSelector = 'google'
    )

    $result = @{
        Domain = $Domain
        SPF    = @{ Record = ''; Valid = $false; Details = '' }
        DKIM   = @{ Record = ''; Valid = $false; Selector = $DkimSelector; Details = '' }
        DMARC  = @{ Record = ''; Valid = $false; Policy = ''; Details = '' }
        MTASTS = @{ Record = ''; Valid = $false; Details = '' }
        MX     = @{ Records = @(); Details = '' }
    }

    # --- SPF ---
    try {
        $spfRecords = Resolve-DnsNameSafe -Name $Domain -Type 'TXT' |
            Where-Object { $_ -match '^v=spf1\s' }
        if ($spfRecords.Count -gt 0) {
            $result.SPF.Record = $spfRecords[0]
            $result.SPF.Valid = $true
            if ($spfRecords.Count -gt 1) {
                $result.SPF.Details = 'Multiple SPF records found (RFC 7208 violation)'
                $result.SPF.Valid = $false
            } elseif ($spfRecords[0] -match '\+all') {
                $result.SPF.Details = 'SPF uses +all (permits any sender)'
                $result.SPF.Valid = $false
            } elseif ($spfRecords[0] -match '\?all') {
                $result.SPF.Details = 'SPF uses ?all (neutral, no enforcement)'
            }
        } else {
            $result.SPF.Details = 'No SPF record found'
        }
    } catch {
        $result.SPF.Details = "SPF lookup failed: $_"
    }

    # --- DKIM ---
    try {
        $dkimName = "$DkimSelector._domainkey.$Domain"
        $dkimRecords = Resolve-DnsNameSafe -Name $dkimName -Type 'TXT'
        if ($dkimRecords.Count -gt 0) {
            $result.DKIM.Record = $dkimRecords[0]
            if ($dkimRecords[0] -match 'v=DKIM1' -or $dkimRecords[0] -match 'p=') {
                $result.DKIM.Valid = $true
            } else {
                $result.DKIM.Details = 'DKIM record found but does not contain valid key'
            }
        } else {
            $result.DKIM.Details = "No DKIM record found for selector '$DkimSelector'"
        }
    } catch {
        $result.DKIM.Details = "DKIM lookup failed: $_"
    }

    # --- DMARC ---
    try {
        $dmarcName = "_dmarc.$Domain"
        $dmarcRecords = Resolve-DnsNameSafe -Name $dmarcName -Type 'TXT' |
            Where-Object { $_ -match '^v=DMARC1' }
        if ($dmarcRecords.Count -gt 0) {
            $result.DMARC.Record = $dmarcRecords[0]
            $result.DMARC.Valid = $true

            if ($dmarcRecords[0] -match 'p=reject') {
                $result.DMARC.Policy = 'reject'
            } elseif ($dmarcRecords[0] -match 'p=quarantine') {
                $result.DMARC.Policy = 'quarantine'
            } elseif ($dmarcRecords[0] -match 'p=none') {
                $result.DMARC.Policy = 'none'
                $result.DMARC.Details = 'DMARC policy is none (monitoring only, no enforcement)'
            }
        } else {
            $result.DMARC.Details = 'No DMARC record found'
        }
    } catch {
        $result.DMARC.Details = "DMARC lookup failed: $_"
    }

    # --- MTA-STS ---
    try {
        $mtaStsName = "_mta-sts.$Domain"
        $mtaStsRecords = Resolve-DnsNameSafe -Name $mtaStsName -Type 'TXT' |
            Where-Object { $_ -match '^v=STSv1' }
        if ($mtaStsRecords.Count -gt 0) {
            $result.MTASTS.Record = $mtaStsRecords[0]
            $result.MTASTS.Valid = $true
        } else {
            $result.MTASTS.Details = 'No MTA-STS TXT record found'
        }
    } catch {
        $result.MTASTS.Details = "MTA-STS lookup failed: $_"
    }

    # --- MX ---
    try {
        $mxRecords = Resolve-DnsNameSafe -Name $Domain -Type 'MX'
        $result.MX.Records = @($mxRecords)
    } catch {
        $result.MX.Details = "MX lookup failed: $_"
    }

    return $result
}

function Resolve-DnsNameSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [ValidateSet('TXT', 'MX', 'A', 'AAAA', 'CNAME')]
        [string]$Type
    )

    # Try Resolve-DnsName (Windows PowerShell / PS7 on Windows)
    if (Get-Command 'Resolve-DnsName' -ErrorAction SilentlyContinue) {
        $records = Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop
        if ($Type -eq 'TXT') {
            return @($records | Where-Object { $_.Strings } | ForEach-Object { $_.Strings -join '' })
        } elseif ($Type -eq 'MX') {
            return @($records | Where-Object { $_.NameExchange } | ForEach-Object {
                "$($_.Preference) $($_.NameExchange)"
            })
        }
        return @($records)
    }

    # Fallback: dig (Linux/macOS)
    if (Get-Command 'dig' -ErrorAction SilentlyContinue) {
        $output = dig +short $Name $Type 2>/dev/null
        if ($LASTEXITCODE -eq 0 -and $output) {
            $lines = @($output -split "`n" | Where-Object { $_.Trim() })
            if ($Type -eq 'TXT') {
                return @($lines | ForEach-Object { $_.Trim('"') })
            }
            return @($lines)
        }
        return @()
    }

    # Fallback: nslookup
    if (Get-Command 'nslookup' -ErrorAction SilentlyContinue) {
        $output = nslookup -type=$Type $Name 2>/dev/null
        if ($output) {
            $lines = @($output -split "`n" | Where-Object { $_.Trim() })
            if ($Type -eq 'TXT') {
                return @($lines | Where-Object { $_ -match 'text\s*=' } | ForEach-Object {
                    ($_ -replace '.*text\s*=\s*', '').Trim('"')
                })
            }
            return @($lines)
        }
        return @()
    }

    throw "No DNS resolution tool available (Resolve-DnsName, dig, or nslookup)"
}
