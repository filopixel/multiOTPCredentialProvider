@echo off
:: Uninstall.bat - Run Uninstall-CredentialProvider.ps1 as Administrator
:: Double-click this file to uninstall the Credential Provider

echo Requesting Administrator privileges...
powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"%~dp0Uninstall-CredentialProvider.ps1\"' -Verb RunAs"
