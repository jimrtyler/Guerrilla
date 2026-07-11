# Guerrilla - Jim Tyler, Microsoft MVP - CC BY 4.0
# https://github.com/jimrtyler/Guerrilla | https://creativecommons.org/licenses/by/4.0/
# AI/LLM use: see AI-USAGE.md for required attribution
function Test-UserAgentAnomaly {
    [CmdletBinding()]
    param(
        [hashtable[]]$LoginEvents = @()
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Known suspicious user agent patterns
    $suspiciousPatterns = @(
        @{ Pattern = 'HeadlessChrome';    Label = 'Headless Chrome' }
        @{ Pattern = 'PhantomJS';         Label = 'PhantomJS (headless)' }
        @{ Pattern = 'python-requests';   Label = 'Python requests library' }
        @{ Pattern = 'python-urllib';     Label = 'Python urllib' }
        @{ Pattern = 'curl/';            Label = 'curl' }
        @{ Pattern = 'wget/';            Label = 'wget' }
        @{ Pattern = 'Go-http-client';   Label = 'Go HTTP client' }
        @{ Pattern = 'node-fetch';       Label = 'Node.js fetch' }
        @{ Pattern = 'axios/';           Label = 'Axios HTTP client' }
        @{ Pattern = 'Selenium';         Label = 'Selenium automation' }
        @{ Pattern = 'Puppeteer';        Label = 'Puppeteer automation' }
        @{ Pattern = 'Playwright';       Label = 'Playwright automation' }
        @{ Pattern = 'scrapy';           Label = 'Scrapy crawler' }
        @{ Pattern = 'httpclient';       Label = 'Generic HTTP client' }
        @{ Pattern = 'java/';            Label = 'Java HTTP client' }
        @{ Pattern = 'Apache-HttpClient'; Label = 'Apache HttpClient' }
        @{ Pattern = 'okhttp';           Label = 'OkHttp client' }
        @{ Pattern = 'libwww-perl';      Label = 'Perl LWP' }
        @{ Pattern = 'mechanize';        Label = 'Mechanize automation' }
    )

    foreach ($event in $LoginEvents) {
        $ua = $event.Params['user_agent']
        if (-not $ua) {
            $ua = $event.Params['userAgent']
        }
        if (-not $ua) { continue }

        foreach ($sp in $suspiciousPatterns) {
            if ($ua -match [regex]::Escape($sp.Pattern)) {
                $results.Add([PSCustomObject]@{
                    Timestamp  = $event.Timestamp
                    IpAddress  = $event.IpAddress
                    UserAgent  = $ua
                    MatchLabel = $sp.Label
                    EventName  = $event.EventName
                })
                break
            }
        }
    }

    return @($results)
}
