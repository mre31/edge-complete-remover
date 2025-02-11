# Administrator rights check
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run with administrator rights!" -ForegroundColor Red
    Break
}

Write-Host "Edge Vanisher started" -ForegroundColor Yellow
Write-Host "Starting Microsoft Edge uninstallation process..." -ForegroundColor Yellow

# Terminate Edge processes
Write-Host "Terminating Edge processes..." -ForegroundColor Cyan
$processes = Get-Process | Where-Object { $_.Name -like "*edge*" }
if ($processes) {
    $processes | ForEach-Object {
        Write-Host "Terminated process: $($_.Name) (PID: $($_.Id))" -ForegroundColor Cyan
    }
    $processes | Stop-Process -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "No running Edge processes found." -ForegroundColor Cyan
}

# Uninstall Edge with setup.exe
Write-Host "Uninstalling Edge with setup..." -ForegroundColor Cyan
$edgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe"
if (Test-Path $edgePath) {
    Start-Process -FilePath $(Resolve-Path $edgePath) -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
}

# Remove Start Menu shortcuts
Write-Host "Removing Start Menu shortcuts..." -ForegroundColor Cyan
$startMenuPaths = @(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
    "$env:ALLUSERSPROFILE\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
)

foreach ($path in $startMenuPaths) {
    if (Test-Path $path) {
        Write-Host "Deleting: $path" -ForegroundColor Cyan
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
        if (!(Test-Path $path)) {
            Write-Host "Successfully deleted: $path" -ForegroundColor Green
        } else {
            Write-Host "Failed to delete: $path" -ForegroundColor Red
        }
    }
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
        if (!(Test-Path $key)) {
            Write-Host "Successfully deleted registry key: $key" -ForegroundColor Green
        } else {
            Write-Host "Failed to delete registry key: $key" -ForegroundColor Red
        }
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
$protectiveFolders = @(
    @{
        Base = "${env:ProgramFiles(x86)}\Microsoft\Edge"
        App = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
        CreateSubFolder = $true
    },
    @{
        Base = "${env:ProgramFiles(x86)}\Microsoft\EdgeCore"
        CreateSubFolder = $false
    }
)

foreach ($folder in $protectiveFolders) {
    # Create folders
    New-Item -Path $folder.Base -ItemType Directory -Force | Out-Null
    if ($folder.CreateSubFolder) {
        New-Item -Path $folder.App -ItemType Directory -Force | Out-Null
    }

    Write-Host "Processing protective folder: $($folder.Base)" -ForegroundColor Cyan

    # Get current username
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # Apply permissions to the base folder only for EdgeCore
    if (!$folder.CreateSubFolder) {
        try {
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
            Set-Acl $folder.Base $acl -ErrorAction Stop
            Write-Host "Success: $($folder.Base)" -ForegroundColor Green
        }
        catch {
            Write-Host "Error occurred: $($folder.Base) - $_" -ForegroundColor Red
        }
    }
    else {
        # Process all items recursively for Edge folder
        Get-ChildItem -Path $folder.Base -Recurse | ForEach-Object {
            try {
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
    }
}

Write-Host "Protective folders created and security settings configured for Edge and EdgeCore." -ForegroundColor Green