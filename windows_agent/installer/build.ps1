# Windows DLP Agent Build Script
# Cibershield R.L. 2025
#
# Usage:
#   .\build.ps1              # Build for current architecture
#   .\build.ps1 -Arch x64    # Build for x64
#   .\build.ps1 -Arch arm64  # Build for ARM64
#   .\build.ps1 -Clean       # Clean build artifacts first

param(
    [ValidateSet('x64', 'arm64', 'auto')]
    [string]$Arch = 'auto',

    [switch]$Clean,

    [switch]$Debug
)

# Script configuration
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$DistDir = Join-Path $ProjectDir "dist"
$BuildDir = Join-Path $ProjectDir "build"

# Detect architecture if auto
if ($Arch -eq 'auto') {
    $processor = $env:PROCESSOR_ARCHITECTURE
    switch ($processor) {
        'AMD64' { $Arch = 'x64' }
        'ARM64' { $Arch = 'arm64' }
        default { $Arch = 'x64' }
    }
    Write-Host "Detected architecture: $Arch" -ForegroundColor Cyan
}

# Banner
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Windows DLP Agent Build Script" -ForegroundColor Green
Write-Host "  Target: $Arch" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""

# Clean if requested
if ($Clean) {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Yellow
    if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
    if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
    Write-Host "Clean complete." -ForegroundColor Green
}

# Check Python
Write-Host "Checking Python installation..." -ForegroundColor Cyan
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Python not found. Please install Python 3.8+" -ForegroundColor Red
    exit 1
}

# Check/Install dependencies
Write-Host "`nInstalling dependencies..." -ForegroundColor Cyan
Set-Location $ProjectDir

try {
    pip install -r requirements.txt --quiet
    Write-Host "Dependencies installed." -ForegroundColor Green
} catch {
    Write-Host "WARNING: Some dependencies may have failed to install." -ForegroundColor Yellow
}

# Ensure PyInstaller is installed
Write-Host "`nChecking PyInstaller..." -ForegroundColor Cyan
try {
    $pyiVersion = pyinstaller --version 2>&1
    Write-Host "Found: PyInstaller $pyiVersion" -ForegroundColor Green
} catch {
    Write-Host "Installing PyInstaller..." -ForegroundColor Yellow
    pip install pyinstaller
}

# Select spec file
$specFile = Join-Path $ScriptDir "dlp_agent_$Arch.spec"
if (-not (Test-Path $specFile)) {
    Write-Host "ERROR: Spec file not found: $specFile" -ForegroundColor Red
    exit 1
}

# Build
Write-Host "`nBuilding DLP Agent for $Arch..." -ForegroundColor Cyan
Write-Host "Spec file: $specFile" -ForegroundColor Gray

$buildArgs = @(
    $specFile,
    "--distpath", $DistDir,
    "--workpath", $BuildDir,
    "--noconfirm"
)

if ($Debug) {
    $buildArgs += "--debug", "all"
}

try {
    Set-Location $ScriptDir
    & pyinstaller @buildArgs

    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller returned exit code $LASTEXITCODE"
    }
} catch {
    Write-Host "`nERROR: Build failed!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Verify output
$exeName = "DLPAgent_$($Arch.ToUpper()).exe"
$exePath = Join-Path $DistDir $exeName

if (Test-Path $exePath) {
    $fileInfo = Get-Item $exePath
    $sizeMB = [math]::Round($fileInfo.Length / 1MB, 2)

    Write-Host "`n============================================" -ForegroundColor Green
    Write-Host "  BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Output: $exePath" -ForegroundColor Cyan
    Write-Host "Size: $sizeMB MB" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To test:" -ForegroundColor Yellow
    Write-Host "  $exePath --status" -ForegroundColor Gray
    Write-Host "  $exePath --debug" -ForegroundColor Gray
    Write-Host ""
} else {
    Write-Host "`nERROR: Output file not found!" -ForegroundColor Red
    exit 1
}

# Copy config file to dist
$configSrc = Join-Path $ProjectDir "config.yaml"
$configDst = Join-Path $DistDir "config.yaml"
if (Test-Path $configSrc) {
    Copy-Item $configSrc $configDst -Force
    Write-Host "Config file copied to dist folder." -ForegroundColor Green
}

Write-Host "Build complete!" -ForegroundColor Green
