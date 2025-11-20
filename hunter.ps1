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

# Use a hashtable to group patterns by name and risk level
$quote = "'"
$patternGroups = @{
    # HIGH risk patterns
    "passwords"      = @{ Regex = '(password|pwd|pass)"\' + $quote + '=:\s]+([^\s"\' + $quote + '<>]+)';                            Level = 'HIGH' };
    "aws_key"        = @{ Regex = 'AKIA[0-9A-Z]{16}';                                                                           Level = 'HIGH' };
    "firebase_key"   = @{ Regex = 'AIza[0-9A-Za-z\-_]{35}';                                                                     Level = 'HIGH' };
    "jwt"            = @{ Regex = 'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+';                                            Level = 'HIGH' };
    "bearer_token"   = @{ Regex = 'Bearer\s+[A-Za-z0-9._-]+';                                                                  Level = 'HIGH' };
    "auth_header"    = @{ Regex = 'Authorization:\s*\S+';                                                                     Level = 'HIGH' };
    "keyword_token"  = @{ Regex = '(token|key|apiKey|secret|session|auth|authorization|access|refresh)[=:\s]+([A-Za-z0-9._-]{8,})'; Level = 'HIGH' };
    "oauth_token"    = @{ Regex = '(?:access_token|refresh_token)"\' + $quote + '=:\s]+([A-Za-z0-9\-._~+/]+)';                   Level = 'HIGH' };
    "json_auth"      = @{ Regex = '"authorization"\s*:\s*"[A-Za-z0-9._-]+"';                                                    Level = 'HIGH' };

    # MEDIUM risk patterns
    "email"          = @{ Regex = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}';                                              Level = 'MEDIUM' };
    "phone_number"   = @{ Regex = '\+?(\d[ -]?){9,15}\d';                                                                       Level = 'MEDIUM' };
    "internal_ip"    = @{ Regex = 'https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)[^ \t\r\n"\' + $quote + '<>]+'; Level = 'MEDIUM' };
    "s3_url"         = @{ Regex = 'https?://[A-Za-z0-9.-]+\.amazonaws\.com/[^ \t\r\n"\' + $quote + ']+';                           Level = 'MEDIUM' };
    "gcs_url"        = @{ Regex = 'https?://storage\.googleapis\.com/[^ \t\r\n"\' + $quote + ']+';                                Level = 'MEDIUM' };
    "azure_url"      = @{ Regex = 'https?://[A-Za-z0-9.-]+\.blob\.core\.windows\.net/[^ \t\r\n"\' + $quote + ']+';                 Level = 'MEDIUM' };
    "content_uri"    = @{ Regex = 'content://[^\s"\' + $quote + ']+';                                                             Level = 'MEDIUM' };
    "cookies"        = @{ Regex = '(Set-Cookie|Cookie):\s*[A-Za-z0-9._-]+=[A-Za-z0-9._-]+';                                     Level = 'MEDIUM' };
    
    # LOW risk patterns
    "graphql"        = @{ Regex = "/graphql(?:\?|/|`$)";                                                                        Level = 'LOW' };
    "url"            = @{ Regex = 'https?://[^ \t\r\n"\' + $quote + ']+';                                                         Level = 'LOW' };
    "base64"         = @{ Regex = '(?:[A-Za-z0-9+/]{20,}={0,2})';                                                              Level = 'LOW' }; # Post-filtered
    "domain"         = @{ Regex = '\b([a-zA-Z0-9-]{2,63}\.)+(com|net|org|io|dev|app|cloud|store)\b';                             Level = 'LOW' };
    "mac_address"    = @{ Regex = '([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})';                                                     Level = 'LOW' };

    # NOISE risk patterns
    "multipart"      = @{ Regex = '----WebKitFormBoundary[a-zA-Z0-9]+';                                                         Level = 'NOISE' };
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
    'com\.android\.',
    '\bSDHMS\b:'
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

adb -s $device logcat '*:V' 'SDHMS:S' | ForEach-Object {
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
        $patternData = $group.Value
        $pattern = $patternData.Regex
        $level = $patternData.Level
        
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
                if ($groupName -eq "base64") {
                    # Skip if the value doesn't contain a mix of lower, upper, and digits
                    if (($value -notmatch '[a-z]') -or ($value -notmatch '[A-Z]') -or ($value -notmatch '\d')) {
                        continue
                    }
                }

                $outputLine = "[$level] MATCH: $value   LINE: $line"

                Write-Host "[$level][$groupName] $value" -ForegroundColor Green

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
