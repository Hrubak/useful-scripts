#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Installs IIS + FTP Server Windows features required by New-SmartZoneIisFtp.ps1.

.DESCRIPTION
    Windows Server 2016/2019/2022/2025. Uses Install-WindowsFeature.
    Idempotent: already-installed features are skipped.
    Starts FTPSVC and sets StartType Automatic.

.NOTES
    Run elevated, then run New-SmartZoneIisFtp.ps1.
    -DumpOnly lists current install state and exits.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$IncludeWebMgmtService,
    [switch]$DumpOnly
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "    OK  $Message" -ForegroundColor Green }
function Write-Warn2{ param([string]$Message) Write-Host "    !!  $Message" -ForegroundColor Yellow }

$FeatureNames = @(
    'Web-Server',
    'Web-WebServer',
    'Web-Common-Http',
    'Web-Default-Doc',
    'Web-Dir-Browsing',
    'Web-Http-Errors',
    'Web-Static-Content',
    'Web-Health',
    'Web-Http-Logging',
    'Web-Performance',
    'Web-Stat-Compression',
    'Web-Security',
    'Web-Filtering',
    'Web-Mgmt-Tools',
    'Web-Mgmt-Console',
    'Web-Scripting-Tools',
    'Web-Ftp-Server',
    'Web-Ftp-Service',
    'Web-Ftp-Ext'
)

if ($IncludeWebMgmtService) {
    $FeatureNames += 'Web-Mgmt-Service'
}

if (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) {
    throw 'Install-WindowsFeature not found. This script is for Windows Server, not client Windows / DISM-only SKUs.'
}

Write-Host 'IIS + FTP feature installer' -ForegroundColor White

$states = foreach ($name in $FeatureNames) {
    $f = Get-WindowsFeature -Name $name -ErrorAction SilentlyContinue
    if (-not $f) {
        [pscustomobject]@{ Name = $name; Installed = $false; Present = $false }
    } else {
        [pscustomobject]@{ Name = $name; Installed = [bool]$f.Installed; Present = $true }
    }
}

$states | Format-Table Name, Installed, Present -AutoSize

if ($DumpOnly) {
    Write-Host 'DumpOnly set - no changes applied.' -ForegroundColor Yellow
    return
}

$missing = @($states | Where-Object { $_.Present -and -not $_.Installed } | Select-Object -ExpandProperty Name)
$unknown = @($states | Where-Object { -not $_.Present } | Select-Object -ExpandProperty Name)

if ($unknown.Count -gt 0) {
    Write-Warn2 ('Feature names not on this SKU (skipped): {0}' -f ($unknown -join ', '))
}

if ($missing.Count -eq 0) {
    Write-Ok 'All requested features already installed.'
} else {
    Write-Step ('Installing: {0}' -f ($missing -join ', '))
    $result = Install-WindowsFeature -Name $missing -IncludeManagementTools
    if ($result.Success) {
        Write-Ok 'Install-WindowsFeature reported Success'
    } else {
        throw ('Install-WindowsFeature failed. ExitCode={0}' -f $result.ExitCode)
    }
    if ($result.RestartNeeded -eq 'Yes') {
        Write-Warn2 'A reboot is required before FTPSVC / IIS Manager will be clean. Reboot, then rerun.'
    }
}

Write-Step 'FTP service'
$svc = Get-Service -Name FTPSVC -ErrorAction SilentlyContinue
if (-not $svc) {
    throw 'FTPSVC still missing after feature install. Reboot and rerun this script.'
}
Set-Service -Name FTPSVC -StartupType Automatic
if ($svc.Status -ne 'Running') {
    Start-Service -Name FTPSVC
} else {
    Write-Ok 'FTPSVC already running'
}
Write-Ok 'FTPSVC Automatic + running'

Write-Host ''
Write-Host 'DONE. Next: New-SmartZoneIisFtp.ps1 -DumpConfig' -ForegroundColor Green
Write-Host '  Default Web Site on :80 is created with the IIS role. Stop or bind it if this host should not serve HTTP.'
