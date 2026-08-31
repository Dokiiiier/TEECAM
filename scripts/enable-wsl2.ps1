#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -All -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -All -NoRestart

Write-Host 'WSL2 components are enabled. Restart Windows, then run:'
Write-Host '  wsl --set-default-version 2'
Write-Host '  wsl --install -d Ubuntu-22.04'

