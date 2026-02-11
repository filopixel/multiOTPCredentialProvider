@echo off
:: Install.bat - Run Install-CredentialProvider.ps1 as Administrator
:: Double-click this file to install the Credential Provider

echo Requesting Administrator privileges...
powershell -Command "Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File \"%~dp0Install-CredentialProvider.ps1\"' -Verb RunAs"
