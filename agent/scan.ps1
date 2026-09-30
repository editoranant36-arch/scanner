# Windows Endpoint Leftover Folder Scanner Agent
# Zero-dependency PowerShell script for scanning Windows systems
param (
    [string]$ServerUrl = "http://192.168.0.139:8090"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Application Leftover Folder Scanner - Windows Agent    " -ForegroundColor Cyan
Write-Host "  Reporting to Central Dashboard: $ServerUrl             " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$Hostname = $env:COMPUTERNAME
$NodeId = "win_" + ($env:COMPUTERNAME -replace '\W','_')
$StartTime = Get-Date

Write-Host "[1/4] Detecting installed applications from Windows Registry..." -ForegroundColor Yellow
$InstalledApps = @{}

$UninstallKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($keyPath in $UninstallKeys) {
    if (Test-Path (Split-Path $keyPath)) {
        Get-ItemProperty $keyPath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.DisplayName) {
                $clean = ($_.DisplayName -replace '[^a-zA-Z0-9]','').ToLower()
                if ($clean -and -not $InstalledApps.ContainsKey($clean)) {
                    $InstalledApps[$clean] = @{
                        DisplayName = $_.DisplayName
                        Version = $_.DisplayVersion
                        Publisher = $_.Publisher
                        InstallLocation = $_.InstallLocation
                    }
                }
            }
        }
    }
}

Write-Host "  -> Found $($InstalledApps.Count) installed applications." -ForegroundColor Green

Write-Host "[2/4] Inspecting running processes to protect active applications..." -ForegroundColor Yellow
$RunningProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName -Unique | ForEach-Object { $_.ToLower() }

Write-Host "[3/4] Scanning application directories for potential leftovers..." -ForegroundColor Yellow

$CandidateRoots = @(
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)},
    $env:ProgramData,
    $env:LOCALAPPDATA,
    $env:APPDATA
) | Where-Object { $_ -and (Test-Path $_) }

$ProtectedNames = @("system32", "syswow64", "winsxs", "windowsapps", "system volume information", "recovery", "boot", "microsoft", "windows defender", "common files")

$Items = @()
$LeftoversDetected = 0
$TotalRecoverableBytes = 0
$ProtectedCount = 0
$ActiveCount = 0

foreach ($root in $CandidateRoots) {
    Get-ChildItem -Path $root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $folderName = $_.Name
        $folderPath = $_.FullName
        $cleanName = ($folderName -replace '[^a-zA-Z0-9]','').ToLower()

        # Check size (quick sum up to 1000 files)
        $files = Get-ChildItem -Path $folderPath -File -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1000
        $sizeBytes = ($files | Measure-Object -Property Length -Sum).Sum
        if (-not $sizeBytes) { $sizeBytes = 0 }
        
        $sizeMb = [math]::Round($sizeBytes / 1MB, 1)
        $sizeFormatted = "$sizeMb MB"
        if ($sizeBytes -lt 1MB) { $sizeFormatted = "$([math]::Round($sizeBytes / 1KB, 1)) KB" }
        if ($sizeBytes -gt 1GB) { $sizeFormatted = "$([math]::Round($sizeBytes / 1GB, 2)) GB" }

        # Correlation Checks
        $isProtected = $false
        $decision = "Unknown / Uncertain"
        $reason = ""
        $associatedApp = $folderName

        # 1. Protected Check
        if ($ProtectedNames -contains $folderName.ToLower() -or $folderPath.ToLower() -like "*\windows\*") {
            $isProtected = $true
            $decision = "System Protected"
            $reason = "System critical protected directory."
            $ProtectedCount++
        }
        # 2. Running process lock
        elseif ($RunningProcesses -contains $folderName.ToLower()) {
            $decision = "Application Exists"
            $reason = "Active running process detected locking this application folder."
            $ActiveCount++
        }
        # 3. Installed app match
        elseif ($InstalledApps.ContainsKey($cleanName)) {
            $matched = $InstalledApps[$cleanName]
            $decision = "Application Exists"
            $associatedApp = $matched.DisplayName
            $reason = "Application '$($matched.DisplayName)' (v$($matched.Version)) is currently installed."
            $ActiveCount++
        }
        else {
            # Check partial match
            $matchedApp = $null
            foreach ($k in $InstalledApps.Keys) {
                if ($cleanName.Length -gt 4 -and ($k -like "*$cleanName*" -or $cleanName -like "*$k*")) {
                    $matchedApp = $InstalledApps[$k]
                    break
                }
            }
            if ($matchedApp) {
                $decision = "Application Exists"
                $associatedApp = $matchedApp.DisplayName
                $reason = "Application '$($matchedApp.DisplayName)' is currently installed."
                $ActiveCount++
            } else {
                # LEFTOVER FOUND!
                $decision = "Application Deleted"
                $reason = "Application is not installed in the Windows registry or system list."
                $LeftoversDetected++
                $TotalRecoverableBytes += $sizeBytes
            }
        }

        $Items += @{
            path = $folderPath
            name = $folderName
            size_bytes = $sizeBytes
            size_formatted = $sizeFormatted
            associated_app_name = $associatedApp
            decision = $decision
            decision_reason = $reason
            is_protected = $isProtected
            running_processes = @()
        }
    }
}

$Duration = [math]::Round(((Get-Date) - $StartTime).TotalSeconds, 2)
$RecMb = [math]::Round($TotalRecoverableBytes / 1MB, 1)

Write-Host "`nScan Complete in $Duration seconds!" -ForegroundColor Cyan
Write-Host "  -> Leftover Folders: $LeftoversDetected" -ForegroundColor Red
Write-Host "  -> Recoverable Space: $RecMb MB" -ForegroundColor Green
Write-Host "  -> Active Applications: $ActiveCount" -ForegroundColor Green
Write-Host "  -> System Protected: $ProtectedCount" -ForegroundColor Yellow

$Payload = @{
    node_id = $NodeId
    hostname = $Hostname
    os_type = "Windows ($([System.Environment]::OSVersion.VersionString))"
    ip_address = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike "127.*" } | Select-Object -First 1).IPAddress
    scan_data = @{
        timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        duration_seconds = $Duration
        total_folders_scanned = $Items.Count
        installed_apps_count = $InstalledApps.Count
        leftovers_detected = $LeftoversDetected
        system_protected_count = $ProtectedCount
        active_apps_count = $ActiveCount
        uncertain_count = 0
        total_space_recoverable_bytes = $TotalRecoverableBytes
        total_space_recoverable_formatted = "$RecMb MB"
        items = $Items
    }
} | ConvertTo-Json -Depth 6

Write-Host "`n[4/4] Sending results to central dashboard ($ServerUrl)..." -ForegroundColor Yellow
try {
    $Response = Invoke-RestMethod -Uri "$ServerUrl/api/nodes/report" -Method Post -Body $Payload -ContentType "application/json"
    Write-Host "✓ Successfully registered node with central scanner dashboard!" -ForegroundColor Green
    Write-Host "Open $ServerUrl on any device to view and manage this machine's folders." -ForegroundColor Cyan
} catch {
    Write-Host "✗ Error uploading report to server: $_" -ForegroundColor Red
}
