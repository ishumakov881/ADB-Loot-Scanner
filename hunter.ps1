# ========== CONFIG ==========

$device = "adb-R5CY84FR39K-GZWkml._adb-tls-connect._tcp"

$outFile = "hunter_output.txt"
$uniqueFile = "hunter_unique.txt"
$burpFile = "hunter_burp.txt"

# Создаём файлы, если их нет
foreach ($file in @($outFile, $uniqueFile, $burpFile)) {
    if (-not (Test-Path $file)) {
        New-Item -ItemType File -Path $file | Out-Null
    } else {
        Clear-Content -Path $file -ErrorAction SilentlyContinue
    }
}

# ========== REGEX PATTERNS ==========
$patterns = @(
    # URLs
    "https?://[^ \t\r\n""']+",

    # JWT tokens
    "eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",

    # Google/Firebase API key
    "AIza[0-9A-Za-z\-_]{35}",

    # Bearer tokens
    "Bearer\s+[A-Za-z0-9._-]+",

    # Authorization header
    "Authorization:\s*\S+",

    # ONLY real domains — НЕ ЛОВИТ android.app, com.samsung.android.app
    "\\b([a-zA-Z0-9-]{2,63}\.)+(com|net|org|io|dev|app|cloud|store)\\b",

    # AWS keys
    "AKIA[0-9A-Z]{16}",

    # UUIDs
    # "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",

    # Multipart boundaries
    "----WebKitFormBoundary[a-zA-Z0-9]+"
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

    foreach ($pattern in $patterns) {
        try {
            $matches = [regex]::Matches($line, $pattern)
        }
        catch {
            Write-Warning "? Regex error: $pattern"
            continue
        }

        foreach ($match in $matches) {
            $value = $match.Value.Trim()

            Write-Host "[FOUND] $value @@ $line" -ForegroundColor Green

            # Write all
            Add-Content -Path $outFile -Value "$value"

            # Write unique
            if (-not (Select-String -Path $uniqueFile -Pattern ([regex]::Escape($value)) -Quiet)) {
                Add-Content -Path $uniqueFile -Value "$value"
            }

            # Burp Intruder
            Add-Content -Path $burpFile -Value "$value"
        }
    }
}
