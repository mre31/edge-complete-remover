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
$folderPath = "${env:ProgramFiles(x86)}\Microsoft\Edge"
$edgeAppPath = "$folderPath\Application"

# Create folders
New-Item -Path $folderPath -ItemType Directory -Force | Out-Null
New-Item -Path $edgeAppPath -ItemType Directory -Force | Out-Null

# Get current username
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Process all items recursively including subfolders and files
Get-ChildItem -Path $folderPath -Recurse | ForEach-Object {
    try {
        # Create new empty security object
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        
        # Set ownership
        $acl.SetOwner([System.Security.Principal.NTAccount]$currentUser)
        
        # Disable inheritance
        $acl.SetAccessRuleProtection($true, $false)

        # Add full control permission including take ownership permission
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser, 
            "FullControl,TakeOwnership,ChangePermissions", 
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

        # Add security permissions
        $acl.AddAccessRule($accessRule)

        # Block take ownership permission for SYSTEM, Administrators and Trusted Installer
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
        $adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $trustedInstallerSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
        $authenticatedUsersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
        
        $denyRule1 = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemSid,
            "TakeOwnership,ChangePermissions",
            "ContainerInherit,ObjectInherit",
            "None",
            "Deny"
        )
        
        $denyRule2 = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminsSid,
            "TakeOwnership,ChangePermissions",
            "ContainerInherit,ObjectInherit",
            "None",
            "Deny"
        )

        $denyRule3 = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $trustedInstallerSid,
            "TakeOwnership,ChangePermissions",
            "ContainerInherit,ObjectInherit",
            "None",
            "Deny"
        )

        $denyRule4 = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $authenticatedUsersSid,
            "TakeOwnership,ChangePermissions",
            "ContainerInherit,ObjectInherit",
            "None",
            "Deny"
        )

        # Add deny rules
        $acl.AddAccessRule($denyRule1)
        $acl.AddAccessRule($denyRule2)
        $acl.AddAccessRule($denyRule3)
        $acl.AddAccessRule($denyRule4)

        # Apply security permissions
        Set-Acl $_.FullName $acl -ErrorAction Stop
        Write-Host "Success: $($_.FullName)" -ForegroundColor Green
    }
    catch {
        Write-Host "Error occurred: $($_.FullName) - $_" -ForegroundColor Red
    }
}

Write-Host "Protective folders created and security settings configured." -ForegroundColor Green
Write-Host "Please restart your computer." -ForegroundColor Yellow
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')