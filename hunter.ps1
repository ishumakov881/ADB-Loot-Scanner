# ========== CONFIG ========== 

$device = "adb-R5CY84FR39K-GZWkml._adb-tls-connect._tcp"
$logDir = "hunter_logs"
$burpFile = "hunter_burp.txt" # Global file for all findings

# ========== SETUP ========== 

# Create log directory if it does not exist
if (-not (Test-Path -Path $logDir -PathType Container)) {
    New-Item -Path $logDir -ItemType Directory | Out-Null
}

# Clear old log files in the directory and the global burp file
Get-ChildItem -Path $logDir -Filter "*.txt" | Remove-Item
if (Test-Path $burpFile) {
    Clear-Content -Path $burpFile
} else {
    New-Item -ItemType File -Path $burpFile | Out-Null
}


# ========== REGEX PATTERNS ========== 

# Use a hashtable to group patterns by name
$quote = "'"
$patternGroups = @{
    "url"            = 'https?://[^ \t\r\n"' + $quote + ']+';
    "content_uri"    = 'content://[^\s"' + $quote + ']+';
    "email"          = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}';
    "jwt"            = 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+';
    "firebase_key"   = 'AIza[0-9A-Za-z\-_]{35}';
    "bearer_token"   = 'Bearer\s+[A-Za-z0-9._-]+';
    "auth_header"    = 'Authorization:\s*\S+';
    "domain"         = '\b([a-zA-Z0-9-]{2,63}\.)+(com|net|org|io|dev|app|cloud|store)\b';
    "aws_key"        = 'AKIA[0-9A-Z]{16}';
    "multipart"      = '----WebKitFormBoundary[a-zA-Z0-9]+';
    "base64"         = '(?:[A-Za-z0-9+/]{20,}={0,2})'; # Post-filtered in the main loop
    "keyword_token"  = '(token|key|apiKey|secret|session|auth|authorization|access|refresh)[=:\s]+([A-Za-z0-9._-]+)';
    "graphql"        = "/graphql(?:\?|/|`$)";
    "internal_ip"    = 'https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)[^ \t\r\n"' + $quote + '<>]+';
    "oauth_token"    = '(?:access_token|refresh_token)["' + $quote + '=:\s]+([A-Za-z0-9\-._~+/]+)';
    "cookies"        = '(Set-Cookie|Cookie):\s*[A-Za-z0-9._-]+=[A-Za-z0-9._-]+';
    "passwords"      = '(password|pwd|pass)["' + $quote + '=:\s]+([^\s"' + $quote + '<>]+)';
    "s3_url"         = 'https?://[A-Za-z0-9.-]+\.amazonaws\.com/[^ \t\r\n"' + $quote + ']+';
    "gcs_url"        = 'https?://storage\.googleapis\.com/[^ \t\r\n"' + $quote + ']+';
    "azure_url"      = 'https?://[A-Za-z0-9.-]+\.blob\.core\.windows\.net/[^ \t\r\n"' + $quote + ']+';
    "json_auth"      = '"authorization"\s*:\s*"[A-Za-z0-9._-]+"'
}

# ========== EXCLUSION PATTERNS ========== 
$exclusionPatterns = @(
    'android\.app',
    'com\.samsung\.android\.app',
    'vendor\.',
    'service-id',
    'request-id',
    'session-id',
    'job-id',
    'worker-id',
    'task-id',
    'com\.android\.'
)

# ========== UNIQUE CHECK SETUP ========== 
# Create a hashtable of HashSets, one for each pattern group
$uniqueSets = @{}
foreach ($key in $patternGroups.Keys) {
    $uniqueSets[$key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $uniqueLogFile = Join-Path -Path $logDir -ChildPath ($key + "_unique.txt")
    if(Test-Path $uniqueLogFile){
        Get-Content $uniqueLogFile | ForEach-Object {
            $uniqueSets[$key].Add($_) | Out-Null
        }
    }
}


# ========== MAIN LOOP ========== 

Write-Host "?? BugBounty Hunter started..." -ForegroundColor Cyan
Write-Host "?? Listening ADB logcat for: $device"
Write-Host "?? Saving categorized logs to: $logDir"
Write-Host "?? Saving all findings for Burp to: $burpFile"
Write-Host "-------------------------------------`n"

adb -s $device logcat | ForEach-Object {
    $line = $_

    # Filter noisy lines
    $shouldExclude = $false
    foreach ($excludePattern in $exclusionPatterns) {
        if ($line -match $excludePattern) {
            $shouldExclude = $true
            break
        }
    }
    if ($shouldExclude) { return }

    # Iterate through each pattern group
    foreach ($group in $patternGroups.GetEnumerator()) {
        $groupName = $group.Name
        $pattern = $group.Value
        
        try {
            $matches = [regex]::Matches($line, $pattern)
        }
        catch {
            Write-Warning "? Regex error: $($_.Exception.Message) Pattern: $pattern"
            continue
        }

        if ($matches.Count -gt 0) {
            $logFile = Join-Path -Path $logDir -ChildPath ($groupName + ".txt")
            $uniqueLogFile = Join-Path -Path $logDir -ChildPath ($groupName + "_unique.txt")
            $currentUniqueSet = $uniqueSets[$groupName]

            foreach ($match in $matches) {
                $value = $match.Value.Trim()

                # Post-filter for specific noisy groups
                if ($groupName -eq "base64" -and $value -notmatch '\d') {
                    continue # Skip Base64 matches that do not contain any digits
                }

                $outputLine = "MATCH: $value   LINE: $line"

                Write-Host "[FOUND][$groupName] $outputLine" -ForegroundColor Green

                # Write to the specific log file for this group
                Add-Content -Path $logFile -Value $outputLine

                # Write to the global burp file (only the value)
                Add-Content -Path $burpFile -Value $value

                # Write to the specific unique log file for this group
                if ($currentUniqueSet.Add($value)) {
                    Add-Content -Path $uniqueLogFile -Value $outputLine
                }
            }
        }
    }
}