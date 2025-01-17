# Set the folder paths
$folderPaths = @(
    "C:\Program Files (x86)\Microsoft\Edge",
    "C:\Program Files (x86)\Microsoft\EdgeCore"
)

# Get current username
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Process each folder
foreach ($folderPath in $folderPaths) {
    Write-Host "`nProcessing folder: $folderPath" -ForegroundColor Cyan
    
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
}

Write-Host "`nOperation completed. File ownership and permissions are locked for both Edge and EdgeCore folders." -ForegroundColor Green
exit 