# ========== CONFIG ==========

$device = "adb-R5CY84FR39K-GZWkml._adb-tls-connect._tcp"

$outFile = "hunter_output.txt"
$uniqueFile = "hunter_unique.txt"
$burpFile = "hunter_burp.txt"

# Create files if they do not exist, and clear them
foreach ($file in @($outFile, $uniqueFile, $burpFile)) {
    if (-not (Test-Path $file)) {
        New-Item -ItemType File -Path $file | Out-Null
    } else {
        Clear-Content -Path $file -ErrorAction SilentlyContinue
    }
}

# ========== REGEX PATTERNS ==========
# Construct the URL pattern by concatenating the quote to avoid parsing issues
$quote = "'"
$pattern_url = 'https?://[^ \t\r\n"' + $quote + ']+'
$pattern_email = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

$patterns = @(
    $pattern_url, # URL pattern
    $pattern_email # Email pattern
)

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

# ========== MAIN LOOP ==========

Write-Host "?? BugBounty Hunter started..." -ForegroundColor Cyan
Write-Host "?? Listening ADB logcat for: $device"
Write-Host "?? Saving to: $outFile"
Write-Host "?? Unique results: $uniqueFile"
Write-Host "?? Burp Intruder payloads: $burpFile"
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

    foreach ($pattern in $patterns) {
        try {
            $matches = [regex]::Matches($line, $pattern)
        }
        catch {
            Write-Warning "? Regex error: $($_.Exception.Message) Pattern: $pattern"
            continue
        }

        foreach ($match in $matches) {
            $value = $match.Value.Trim()

            Write-Host "[FOUND] $value @@ $line" -ForegroundColor Green

            # Write all
            Add-Content -Path $outFile -Value "$value"

            # Write unique
            # This part will be enhanced later with HashSet if basic parsing works
            if (-not (Select-String -Path $uniqueFile -Pattern ([regex]::Escape($value)) -Quiet)) {
                Add-Content -Path $uniqueFile -Value "$value"
            }

            # Burp Intruder
            Add-Content -Path $burpFile -Value "$value"
        }
    }
}
