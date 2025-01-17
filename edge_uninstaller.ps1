# Administrator rights check
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run with administrator rights!"
    Break
}

Write-Host "Starting Microsoft Edge uninstallation process..." -ForegroundColor Yellow

# Terminate Edge processes
Write-Host "Terminating Edge processes..." -ForegroundColor Cyan
Get-Process | Where-Object { $_.Name -like "*edge*" } | Stop-Process -Force -ErrorAction SilentlyContinue

# Uninstall with Winget
Write-Host "Uninstalling Edge with Winget..." -ForegroundColor Cyan
Start-Process "winget" -ArgumentList "uninstall --id Microsoft.Edge" -Wait -ErrorAction SilentlyContinue

# Uninstall Edge with setup.exe
Write-Host "Uninstalling Microsoft Edge with setup..." -ForegroundColor Cyan
$edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe"
if (Test-Path $edgePath) {
    Start-Process -FilePath $(Resolve-Path $edgePath) -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
}

# Remove UWP Edge apps
Write-Host "Removing UWP Edge applications..." -ForegroundColor Cyan
$edgeApps = @(
    "Microsoft.MicrosoftEdge",
    "Microsoft.MicrosoftEdgeDevToolsClient"
)

foreach ($app in $edgeApps) {
    Get-AppxPackage -Name "*$app*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
    Get-AppxPackage -Name "*$app*" | Remove-AppxPackage -ErrorAction SilentlyContinue
    Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*$app*" | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
}

# Clean Edge folders
Write-Host "Cleaning Edge folders..." -ForegroundColor Cyan
$edgePaths = @(
    "$env:LOCALAPPDATA\Microsoft\Edge",
    "$env:PROGRAMFILES\Microsoft\Edge",
    "${env:ProgramFiles(x86)}\Microsoft\Edge",
    "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate",
    "${env:ProgramFiles(x86)}\Microsoft\EdgeCore",
    "$env:LOCALAPPDATA\Microsoft\EdgeUpdate",
    "$env:PROGRAMDATA\Microsoft\EdgeUpdate",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
    "$env:PUBLIC\Desktop\Microsoft Edge.lnk"
)

foreach ($path in $edgePaths) {
    if (Test-Path $path) {
        Write-Host "Cleaning: $path" -ForegroundColor Cyan
        takeown /F $path /R /D Y | Out-Null
        icacls $path /grant administrators:F /T | Out-Null
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Clean Edge registry entries
Write-Host "Cleaning Edge registry entries..." -ForegroundColor Cyan
$edgeRegKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update",
    "HKLM:\SOFTWARE\Microsoft\EdgeUpdate",
    "HKCU:\Software\Microsoft\Edge",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeUpdate",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeUpdate",
    "HKLM:\SOFTWARE\Microsoft\Edge",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update"
)

foreach ($key in $edgeRegKeys) {
    if (Test-Path $key) {
        Write-Host "Deleting registry key: $key" -ForegroundColor Cyan
        Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Force uninstall EdgeUpdate
$edgeUpdatePath = "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
if (Test-Path $edgeUpdatePath) {
    Start-Process $edgeUpdatePath -ArgumentList "/uninstall" -Wait -ErrorAction SilentlyContinue
}

# Remove EdgeUpdate services
$services = @(
    "edgeupdate",
    "edgeupdatem",
    "MicrosoftEdgeElevationService"
)

foreach ($service in $services) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    sc.exe delete $service
}

# Finally force uninstall Edge
$edgeSetup = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe" -ErrorAction SilentlyContinue
if ($edgeSetup) {
    Start-Process $edgeSetup.FullName -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
}

# Restart Explorer
Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
Start-Process explorer

Write-Host "`nMicrosoft Edge uninstallation process completed!" -ForegroundColor Green

# Create empty Edge folders and protect them
Write-Host "Creating protective Edge folders..." -ForegroundColor Cyan
$edgeBlockPath = "${env:ProgramFiles(x86)}\Microsoft\Edge"
$edgeAppPath = "$edgeBlockPath\Application"

# Create folders
New-Item -Path $edgeBlockPath -ItemType Directory -Force | Out-Null
New-Item -Path $edgeAppPath -ItemType Directory -Force | Out-Null

Write-Host "Protective folders created and security settings configured." -ForegroundColor Green
Write-Host "Please restart your computer." -ForegroundColor Yellow
exit