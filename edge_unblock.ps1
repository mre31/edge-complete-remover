# Edge folder paths
$folderPaths = @(
    "C:\Program Files (x86)\Microsoft\Edge",
    "C:\Program Files (x86)\Microsoft\EdgeCore"
)

# Create new ACL object
$acl = New-Object System.Security.AccessControl.DirectorySecurity

# Set ownership to Administrators group
$administratorsGroup = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$acl.SetOwner($administratorsGroup)

# Enable inheritance
$acl.SetAccessRuleProtection($false, $true)

# Define required SIDs
$trustedInstallerSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
$systemSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-18")
$adminsSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
$usersSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-545")
$creatorOwnerSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-3-0")
$allAppPackagesSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-15-2-1")
$restrictedAppPackagesSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-15-2-2")

# Define and add permissions
$rules = @(
    # Permissions for TrustedInstaller
    [PSCustomObject]@{
        Identity = $trustedInstallerSid
        Rights = "FullControl"
        InheritanceFlags = "ContainerInherit,ObjectInherit"
        PropagationFlags = "None"
        Type = "Allow"
    },
    # Permissions for SYSTEM
    [PSCustomObject]@{
        Identity = $systemSid
        Rights = "FullControl"
        InheritanceFlags = "ContainerInherit,ObjectInherit"
        PropagationFlags = "None"
        Type = "Allow"
    },
    # Permissions for Administrators
    [PSCustomObject]@{
        Identity = $adminsSid
        Rights = "FullControl"
        InheritanceFlags = "ContainerInherit,ObjectInherit"
        PropagationFlags = "None"
        Type = "Allow"
    },
    # Permissions for Users
    [PSCustomObject]@{
        Identity = $usersSid
        Rights = "ReadAndExecute"
        InheritanceFlags = "ContainerInherit,ObjectInherit"
        PropagationFlags = "None"
        Type = "Allow"
    },
    # Permissions for ALL APPLICATION PACKAGES
    [PSCustomObject]@{
        Identity = $allAppPackagesSid
        Rights = "ReadAndExecute"
        InheritanceFlags = "ContainerInherit,ObjectInherit"
        PropagationFlags = "None"
        Type = "Allow"
    },
    # Permissions for RESTRICTED APPLICATION PACKAGES
    [PSCustomObject]@{
        Identity = $restrictedAppPackagesSid
        Rights = "ReadAndExecute"
        InheritanceFlags = "ContainerInherit,ObjectInherit"
        PropagationFlags = "None"
        Type = "Allow"
    },
    # Permissions for CREATOR OWNER
    [PSCustomObject]@{
        Identity = $creatorOwnerSid
        Rights = "FullControl"
        InheritanceFlags = "ContainerInherit,ObjectInherit"
        PropagationFlags = "None"
        Type = "Allow"
    }
)

# Add permissions to ACL
foreach ($rule in $rules) {
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $rule.Identity,
        $rule.Rights,
        $rule.InheritanceFlags,
        $rule.PropagationFlags,
        $rule.Type
    )
    $acl.AddAccessRule($accessRule)
}

# Process each folder
foreach ($folderPath in $folderPaths) {
    Write-Host "`nProcessing folder: $folderPath" -ForegroundColor Cyan
    
    try {
        # Apply permissions to all folders and subitems
        Get-ChildItem -Path $folderPath -Recurse | ForEach-Object {
            Set-Acl $_.FullName $acl -ErrorAction Stop
            Write-Host "Success: $($_.FullName)" -ForegroundColor Green
        }
        
        # Apply permissions to main folder
        Set-Acl $folderPath $acl -ErrorAction Stop
        Write-Host "Main folder permissions successfully updated: $folderPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Error occurred while processing $folderPath : $_" -ForegroundColor Red
    }
}

Write-Host "`nOperation completed. Edge and EdgeCore folder permissions have been restored to default." -ForegroundColor Green
exit 