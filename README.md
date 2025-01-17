# Edge Complete Remover Tool

This tool completely removes Microsoft Edge from Windows and prevents its automatic reinstallation.

## Features

- Complete removal of Microsoft Edge browser
- Removes all Edge-related services and registry entries
- Cleans up Edge folders and files
- Creates protected folders to prevent automatic reinstallation
- Supports both user and system-level uninstallation

## Requirements

- Windows 11
- Administrator privileges
- PowerShell 5.1 or higher

## Files

- `edge_uninstaller.ps1` - Main PowerShell script that performs the uninstallation
- `edge_block.ps1` - PowerShell script that blocks the installation of Edge again by anyone other than the current user.
- `edge_unblock.ps1` - PowerShell script that restores defaults for the folders for Edge.
- `edge_vanisher.ps1` Combine script of scripts above
- `run_edge_vanisher.bat` - Batch file to run the combined script with admin privileges

## Usage

1. Download all files to a folder
2. Right-click `run_edge_vanisher.bat`
3. Select "Run as administrator"
4. Wait for the process to complete
5. Restart your computer when prompted

## What the Tool Does

1. Checks for administrator privileges
2. Terminates all Edge processes
3. Uninstalls Edge using multiple methods:
   - Winget
   - Setup.exe
   - UWP app removal
4. Removes Edge-related folders and registry entries
5. Removes Edge update services
6. Creates protected folders to prevent reinstallation
7. Cleans up remaining components

## Important Notes

- Always backup your data before using this tool
- The script requires administrator privileges to run
- A system restart is required after uninstallation
- Some Windows updates might try to reinstall Edge
- The tool creates protected folders to prevent automatic reinstallation

## Troubleshooting

If you encounter any issues:
1. Make sure you're running as administrator
2. Check if Windows Update is not running
3. Ensure all Edge processes are closed
4. Try restarting your computer and running the tool again

## Disclaimer

This tool is provided as-is without any warranty. Use at your own risk. The authors are not responsible for any damage caused by the use of this tool. Microsoft Edge WebView2 should work but it might not. You have been warned.

## License

This project is licensed under the BSD-3-Clause license. By using our software, you acknowledge and agree to the terms of the license.
