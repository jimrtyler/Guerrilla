# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Update-ThreatIntelData {
    [CmdletBinding()]
    param(
        [switch]$Force
    )

    $dataDir = Join-Path $script:ModuleRoot 'Data'
    $ipRangesPath = Join-Path $dataDir 'CloudIpRanges.json'
    $currentData = Get-Content -Path $ipRangesPath -Raw | ConvertFrom-Json -AsHashtable

    $lastUpdated = if ($currentData.metadata -and $currentData.metadata.lastUpdated) {
        try { [datetime]::Parse($currentData.metadata.lastUpdated) } catch { [datetime]::MinValue }
    } else { [datetime]::MinValue }

    $staleDays = 7
    $cfgPath = $script:ConfigPath
    if (Test-Path $cfgPath) {
        $config = Get-Content -Path $cfgPath -Raw | ConvertFrom-Json -AsHashtable
        if ($config.detection -and $config.detection.autoUpdateIntelDays) {
            $staleDays = $config.detection.autoUpdateIntelDays
        }
    }

    if ($staleDays -eq 0 -and -not $Force) {
        Write-Verbose 'Auto-update disabled (autoUpdateIntelDays = 0)'
        return @{ Updated = $false; Reason = 'Disabled' }
    }

    $daysSinceUpdate = ([datetime]::UtcNow - $lastUpdated).TotalDays
    if ($daysSinceUpdate -lt $staleDays -and -not $Force) {
        Write-Verbose "Intel data is $([Math]::Round($daysSinceUpdate, 1)) days old (threshold: $staleDays). Skipping update."
        return @{ Updated = $false; Reason = "Fresh ($([Math]::Round($daysSinceUpdate, 1)) days old)" }
    }

    Write-Verbose "Intel data is $([Math]::Round($daysSinceUpdate, 1)) days old. Updating..."

    $updated = $false
    $errors = [System.Collections.Generic.List[string]]::new()
    $providers = if ($currentData.providers) { $currentData.providers } else { @{} }

    # --- AWS ---
    try {
        Write-Verbose 'Fetching AWS IP ranges...'
        $awsData = Invoke-RestMethod -TimeoutSec 30 -Uri 'https://ip-ranges.amazonaws.com/ip-ranges.json' -ErrorAction Stop
        $awsCidrs = @($awsData.prefixes | Where-Object { $_.service -eq 'EC2' } | ForEach-Object { $_.ip_prefix } | Sort-Object -Unique)
        if ($awsCidrs.Count -gt 10) {
            $providers['aws'] = $awsCidrs
            $updated = $true
            Write-Verbose "AWS: $($awsCidrs.Count) EC2 CIDRs"
        }
    } catch {
        $errors.Add("AWS: $_")
        Write-Warning "Failed to fetch AWS ranges: $_"
    }

    # --- GCP ---
    try {
        Write-Verbose 'Fetching GCP IP ranges...'
        $gcpData = Invoke-RestMethod -TimeoutSec 30 -Uri 'https://www.gstatic.com/ipranges/cloud.json' -ErrorAction Stop
        $gcpCidrs = @($gcpData.prefixes | Where-Object { $_.ipv4Prefix } | ForEach-Object { $_.ipv4Prefix } | Sort-Object -Unique)
        if ($gcpCidrs.Count -gt 10) {
            $providers['gcp'] = $gcpCidrs
            $updated = $true
            Write-Verbose "GCP: $($gcpCidrs.Count) CIDRs"
        }
    } catch {
        $errors.Add("GCP: $_")
        Write-Warning "Failed to fetch GCP ranges: $_"
    }

    # --- Cloudflare ---
    try {
        Write-Verbose 'Fetching Cloudflare IP ranges...'
        $cfText = Invoke-RestMethod -TimeoutSec 30 -Uri 'https://www.cloudflare.com/ips-v4' -ErrorAction Stop
        $cfCidrs = @($cfText -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d' })
        if ($cfCidrs.Count -gt 5) {
            $providers['cloudflare'] = $cfCidrs
            $updated = $true
            Write-Verbose "Cloudflare: $($cfCidrs.Count) CIDRs"
        }
    } catch {
        $errors.Add("Cloudflare: $_")
        Write-Warning "Failed to fetch Cloudflare ranges: $_"
    }

    if ($updated) {
        $newData = @{
            metadata = @{
                version     = '2.0.0'
                lastUpdated = [datetime]::UtcNow.ToString('yyyy-MM-dd')
                description = 'Cloud provider IP CIDR ranges for compromise detection'
            }
            providers = $providers
        }
        $newData | ConvertTo-Json -Depth 5 | Set-Content -Path $ipRangesPath -Encoding UTF8
        Write-Verbose "Updated $ipRangesPath"
    }

    return @{
        Updated = $updated
        Errors  = @($errors)
        Reason  = if ($updated) { 'Data refreshed' } else { 'No updates available' }
    }
}
