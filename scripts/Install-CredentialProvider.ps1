# Install-CredentialProvider.ps1
# Installs the Das Credential Provider and Filter DLLs
# Must be run as Administrator

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Installation directory
$installDir = "$env:SystemRoot\System32"

# Find the Provider DLL - check multiple possible locations
$providerPaths = @(
    "$PSScriptRoot\..\CredentialProvider\bin\ARM64\Release\DasCredentialProvider.dll",
    "$PSScriptRoot\..\CredentialProvider\bin\x64\Release\DasCredentialProvider.dll",
    "$PSScriptRoot\..\ARM64\Release\DasCredentialProvider.dll",
    "$PSScriptRoot\..\x64\Release\DasCredentialProvider.dll"
)

# Find the Filter DLL - check multiple possible locations
$filterPaths = @(
    "$PSScriptRoot\..\CredentialProviderFilter\bin\ARM64\Release\DasCredentialProviderFilter.dll",
    "$PSScriptRoot\..\CredentialProviderFilter\bin\x64\Release\DasCredentialProviderFilter.dll",
    "$PSScriptRoot\..\ARM64\Release\DasCredentialProviderFilter.dll",
    "$PSScriptRoot\..\x64\Release\DasCredentialProviderFilter.dll"
)

$providerDllPath = $null
foreach ($path in $providerPaths) {
    $resolved = Resolve-Path $path -ErrorAction SilentlyContinue
    if ($resolved) {
        $providerDllPath = $resolved.Path
        break
    }
}

$filterDllPath = $null
foreach ($path in $filterPaths) {
    $resolved = Resolve-Path $path -ErrorAction SilentlyContinue
    if ($resolved) {
        $filterDllPath = $resolved.Path
        break
    }
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Das Credential Provider Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not $providerDllPath) {
    Write-Host "ERROR: Could not find DasCredentialProvider.dll" -ForegroundColor Red
    Write-Host "Please build the solution first in Visual Studio." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Searched locations:" -ForegroundColor Gray
    foreach ($path in $providerPaths) {
        Write-Host "  - $path" -ForegroundColor Gray
    }
    exit 1
}

Write-Host "Provider DLL found: $providerDllPath" -ForegroundColor Green

if ($filterDllPath) {
    Write-Host "Filter DLL found: $filterDllPath" -ForegroundColor Green
} else {
    Write-Host "Filter DLL not found (optional - will skip)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "DLLs will be copied to: $installDir" -ForegroundColor Cyan
Write-Host ""

# Confirm installation
Write-Host "WARNING: Installing a credential provider can affect Windows logon." -ForegroundColor Yellow
Write-Host "Make sure you have a backup admin account or recovery method." -ForegroundColor Yellow
Write-Host ""
$confirm = Read-Host "Do you want to continue? (yes/no)"

if ($confirm -ne "yes") {
    Write-Host "Installation cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Host ""

# Copy and register Provider DLL
$providerInstallPath = "$installDir\DasCredentialProvider.dll"
Write-Host "Copying Provider DLL to System32..." -ForegroundColor Cyan

try {
    Copy-Item -Path $providerDllPath -Destination $providerInstallPath -Force
    Write-Host "  Copied to: $providerInstallPath" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to copy Provider DLL: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "Registering Provider DLL..." -ForegroundColor Cyan

try {
    $result = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s `"$providerInstallPath`"" -Wait -PassThru

    if ($result.ExitCode -eq 0) {
        Write-Host "  Provider registered successfully." -ForegroundColor Green
    }
    else {
        Write-Host "ERROR: regsvr32 failed for Provider with exit code $($result.ExitCode)" -ForegroundColor Red
        Write-Host "Try running regsvr32 manually to see the error:" -ForegroundColor Yellow
        Write-Host "  regsvr32 `"$providerInstallPath`"" -ForegroundColor White
        exit 1
    }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Copy and register Filter if found
if ($filterDllPath) {
    $filterInstallPath = "$installDir\DasCredentialProviderFilter.dll"
    Write-Host "Copying Filter DLL to System32..." -ForegroundColor Cyan

    try {
        Copy-Item -Path $filterDllPath -Destination $filterInstallPath -Force
        Write-Host "  Copied to: $filterInstallPath" -ForegroundColor Green
    }
    catch {
        Write-Host "WARNING: Failed to copy Filter DLL: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    Write-Host "Registering Filter DLL..." -ForegroundColor Cyan

    try {
        $result = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s `"$filterInstallPath`"" -Wait -PassThru

        if ($result.ExitCode -eq 0) {
            Write-Host "  Filter registered successfully." -ForegroundColor Green
        }
        else {
            Write-Host "WARNING: regsvr32 failed for Filter with exit code $($result.ExitCode)" -ForegroundColor Yellow
            Write-Host "The Provider is installed but the Filter failed." -ForegroundColor Yellow
            Write-Host "Try running regsvr32 manually to see the error:" -ForegroundColor Yellow
            Write-Host "  regsvr32 `"$filterInstallPath`"" -ForegroundColor White
        }
    }
    catch {
        Write-Host "WARNING: Filter registration failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Disable Win+L (lock workstation) - forces users through LOGON instead of UNLOCK
# UNLOCK is handled as a fallback (all fields editable) if screensaver/timeout triggers lock
Write-Host "Disabling Win+L (lock workstation)..." -ForegroundColor Cyan
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "DisableLockWorkstation" -Value 1 -Type DWord
    Write-Host "  Win+L disabled successfully." -ForegroundColor Green
}
catch {
    Write-Host "  WARNING: Failed to disable Win+L: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "SUCCESS: Credential Provider installed!" -ForegroundColor Green
Write-Host ""
Write-Host "Installed files:" -ForegroundColor Cyan
Write-Host "  - $providerInstallPath" -ForegroundColor White
if ($filterDllPath) {
    Write-Host "  - $filterInstallPath" -ForegroundColor White
}
Write-Host ""
Write-Host "To test:" -ForegroundColor Cyan
Write-Host "  1. Log off or restart to reach the logon screen" -ForegroundColor White
Write-Host "  2. 'Das Credential Provider' should be the only available option" -ForegroundColor White
Write-Host "  3. Enter username, password, and OTP" -ForegroundColor White
Write-Host "  4. OTP ending in EVEN digit (e.g., 1234) = SUCCESS" -ForegroundColor White
Write-Host "  5. OTP ending in ODD digit (e.g., 1235) = FAILURE" -ForegroundColor White
Write-Host "  6. Win+L is disabled (lock workstation disabled by policy)" -ForegroundColor White
Write-Host ""
Write-Host "To uninstall, run: .\Uninstall-CredentialProvider.ps1" -ForegroundColor Gray
