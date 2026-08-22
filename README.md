# CyberGuard Pro

Windows Security Assistant powered by AI.

## Building the Installer

This repository uses GitHub Actions to automatically build a professional Windows MSI installer.

**No manual steps needed** - just push to main branch and the installer builds itself in the cloud.

### How it works

1. Push code to GitHub
2. GitHub Actions runs on a Windows cloud machine
3. Builds `CyberGuard Pro.exe` using PyInstaller
4. Builds `CyberGuard_Pro_Setup.msi` using WiX Toolset 4
5. Releases are automatically created with download links

### Download

Go to the **Releases** section of this repository to download the latest `CyberGuard_Pro_Setup.msi` installer.

## Features

- AI-powered security chatbot (Claude)
- One-click Windows security tools (18 tools)
- Website security scanner
- Professional MSI installer with your logo
