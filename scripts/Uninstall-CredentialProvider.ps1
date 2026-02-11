# Uninstall-CredentialProvider.ps1
# Uninstalls the Das Credential Provider and Filter DLLs
# Must be run as Administrator

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Installation directory
$installDir = "$env:SystemRoot\System32"

# CLSIDs for registry cleanup
$providerClsid = "{07B5C3C1-5E97-4CAE-855B-84966AC4132F}"
$filterClsid = "{D1CA3136-738F-4466-A973-1C46BD9F0385}"

# Installed DLL paths
$providerInstallPath = "$installDir\DasCredentialProvider.dll"
$filterInstallPath = "$installDir\DasCredentialProviderFilter.dll"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " Das Credential Provider Uninstaller" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Unregister and remove Filter first
if (Test-Path $filterInstallPath) {
    Write-Host "Filter DLL found: $filterInstallPath" -ForegroundColor Green
    Write-Host "Unregistering Filter DLL..." -ForegroundColor Cyan

    try {
        $result = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/u /s `"$filterInstallPath`"" -Wait -PassThru

        if ($result.ExitCode -eq 0) {
            Write-Host "  Filter unregistered successfully." -ForegroundColor Green
        }
        else {
            Write-Host "  WARNING: regsvr32 returned exit code $($result.ExitCode) for Filter" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  WARNING: Filter unregistration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "Removing Filter DLL..." -ForegroundColor Cyan
    try {
        Remove-Item -Path $filterInstallPath -Force
        Write-Host "  Filter DLL removed." -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: Failed to remove Filter DLL: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Filter DLL not found in System32, cleaning up registry entries..." -ForegroundColor Yellow
}

# Always try to clean up Filter registry entries
try {
    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\$filterClsid" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\CLSID\$filterClsid" -Recurse -Force -ErrorAction SilentlyContinue
}
catch {
    # Ignore errors - entries may not exist
}

# Unregister and remove Provider
if (Test-Path $providerInstallPath) {
    Write-Host "Provider DLL found: $providerInstallPath" -ForegroundColor Green
    Write-Host "Unregistering Provider DLL..." -ForegroundColor Cyan

    try {
        $result = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/u /s `"$providerInstallPath`"" -Wait -PassThru

        if ($result.ExitCode -eq 0) {
            Write-Host "  Provider unregistered successfully." -ForegroundColor Green
        }
        else {
            Write-Host "  WARNING: regsvr32 returned exit code $($result.ExitCode) for Provider" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  WARNING: Provider unregistration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "Removing Provider DLL..." -ForegroundColor Cyan
    try {
        Remove-Item -Path $providerInstallPath -Force
        Write-Host "  Provider DLL removed." -ForegroundColor Green
    }
    catch {
        Write-Host "  WARNING: Failed to remove Provider DLL: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Provider DLL not found in System32, cleaning up registry entries..." -ForegroundColor Yellow
}

# Always try to clean up Provider registry entries
try {
    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$providerClsid" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "Registry::HKEY_CLASSES_ROOT\CLSID\$providerClsid" -Recurse -Force -ErrorAction SilentlyContinue
}
catch {
    # Ignore errors - entries may not exist
}

Write-Host ""
Write-Host "SUCCESS: Credential Provider and Filter uninstalled!" -ForegroundColor Green
Write-Host ""
Write-Host "The Windows logon screen will now use the default credential providers." -ForegroundColor White
