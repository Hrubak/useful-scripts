#Requires -Version 5.1
<#
.SYNOPSIS
    Check PHP and Node.js versions against Oct 21 2026 security releases and optionally update.

.DESCRIPTION
    Detects installed PHP and Node.js versions (PATH + common locations).
    Reports whether the Oct 21 2026 critical advisories apply:
      - PHP: CVE-2026-109618 / CVE-2026-109619 (php2shell) - fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35
      - Node.js: October 2026 security releases - fixed in 22.23.4, 24.22.1, 26.12.1
    Not installed = not vulnerable.
    Provides an interactive update option via winget when available.

.NOTES
    Run elevated for system-wide updates.
    Always confirm before applying updates on production systems.
    Restart web servers / services after PHP updates.
#>

[CmdletBinding()]
param(
    [switch]$Update,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

# Fixed version thresholds
$PhpFixed = @{
    '8.5' = [version]'8.5.12'
    '8.4' = [version]'8.4.27'
    '8.3' = [version]'8.3.36'
    '8.2' = [version]'8.2.35'
}

$NodeFixed = @{
    '22' = [version]'22.23.4'
    '24' = [version]'24.22.1'
    '26' = [version]'26.12.1'
}

function Get-VersionFromExe {
    param([string]$ExePath)
    if (-not (Test-Path $ExePath)) { return $null }
    try {
        $output = & $ExePath -v 2>$null | Select-Object -First 1
        if ($output -match '([0-9]+\.[0-9]+\.[0-9]+)') {
            return [version]$Matches[1]
        }
    } catch {}
    return $null
}

function Get-InstalledVersion {
    param([string]$Command)
    try {
        $output = & $Command -v 2>$null | Select-Object -First 1
        if ($output -match '([0-9]+\.[0-9]+\.[0-9]+)') {
            return [version]$Matches[1]
        }
    } catch {}
    return $null
}

function Test-PhpVulnerable {
    param([version]$Ver)
    if (-not $Ver) { return $false }   # not installed
    $majorMinor = "$($Ver.Major).$($Ver.Minor)"
    if ($PhpFixed.ContainsKey($majorMinor)) {
        return $Ver -lt $PhpFixed[$majorMinor]
    }
    # 8.1 and older, or unknown branches
    return $true
}

function Test-NodeVulnerable {
    param([version]$Ver)
    if (-not $Ver) { return $false }   # not installed
    $major = "$($Ver.Major)"
    if ($NodeFixed.ContainsKey($major)) {
        return $Ver -lt $NodeFixed[$major]
    }
    # EOL lines (20 and below) or unknown
    return $true
}

function Show-Status {
    param(
        [string]$Name,
        [version]$Version,
        [bool]$Vulnerable,
        [string]$FixedInfo
    )
    Write-Host ""
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    if (-not $Version) {
        Write-Host "STATUS: Not installed" -ForegroundColor DarkGray
        return
    }
    Write-Host "Detected version: $Version"
    if ($Vulnerable) {
        Write-Host "STATUS: VULNERABLE - update required" -ForegroundColor Red
        Write-Host "Advisory applies. $FixedInfo" -ForegroundColor Red
    } else {
        Write-Host "STATUS: OK (patched)" -ForegroundColor Green
    }
}

# --- Detection ---
Write-Host "PHP / Node.js Security Check (Oct 21 2026 releases)" -ForegroundColor White
Write-Host "====================================================" -ForegroundColor White

# PATH first
$phpVer = Get-InstalledVersion -Command 'php'
$nodeVer = Get-InstalledVersion -Command 'node'

# Common PHP locations
$phpCandidates = @(
    'C:\php\php.exe',
    'C:\xampp\php\php.exe',
    'C:\laragon\bin\php\*\php.exe',
    'C:\Program Files\PHP\*\php.exe',
    'C:\Program Files (x86)\PHP\*\php.exe',
    "$env:ProgramFiles\PHP\*\php.exe",
    "$env:LOCALAPPDATA\Programs\PHP\*\php.exe"
)

# Common Node locations
$nodeCandidates = @(
    'C:\Program Files\nodejs\node.exe',
    'C:\Program Files (x86)\nodejs\node.exe',
    "$env:ProgramFiles\nodejs\node.exe",
    "$env:LOCALAPPDATA\Programs\nodejs\node.exe",
    "$env:APPDATA\nvm\*\node.exe",
    'C:\nvm\*\node.exe',
    "$env:USERPROFILE\AppData\Roaming\nvm\*\node.exe"
)

Write-Host ""
Write-Host "Scanning common install locations..." -ForegroundColor DarkGray

$foundPhp = @()
foreach ($pattern in $phpCandidates) {
    Get-Item $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        $ver = Get-VersionFromExe $_.FullName
        if ($ver) {
            $foundPhp += [pscustomobject]@{ Path = $_.FullName; Version = $ver }
            if (-not $phpVer) { $phpVer = $ver }
        }
    }
}

$foundNode = @()
foreach ($pattern in $nodeCandidates) {
    Get-Item $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        $ver = Get-VersionFromExe $_.FullName
        if ($ver) {
            $foundNode += [pscustomobject]@{ Path = $_.FullName; Version = $ver }
            if (-not $nodeVer) { $nodeVer = $ver }
        }
    }
}

# Report all found installs
if ($foundPhp.Count -gt 0) {
    Write-Host "PHP installs found:" -ForegroundColor DarkGray
    $foundPhp | ForEach-Object {
        $vuln = Test-PhpVulnerable $_.Version
        $status = if ($vuln) { 'VULNERABLE' } else { 'OK' }
        $color = if ($vuln) { 'Yellow' } else { 'Green' }
        Write-Host "  $($_.Path) -> $($_.Version) [$status]" -ForegroundColor $color
    }
}
if ($foundNode.Count -gt 0) {
    Write-Host "Node.js installs found:" -ForegroundColor DarkGray
    $foundNode | ForEach-Object {
        $vuln = Test-NodeVulnerable $_.Version
        $status = if ($vuln) { 'VULNERABLE' } else { 'OK' }
        $color = if ($vuln) { 'Yellow' } else { 'Green' }
        Write-Host "  $($_.Path) -> $($_.Version) [$status]" -ForegroundColor $color
    }
}

$phpVuln = Test-PhpVulnerable -Ver $phpVer
$nodeVuln = Test-NodeVulnerable -Ver $nodeVer

Show-Status -Name 'PHP' -Version $phpVer -Vulnerable $phpVuln -FixedInfo 'Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. Older branches need vendor backports or upgrade.'
Show-Status -Name 'Node.js' -Version $nodeVer -Vulnerable $nodeVuln -FixedInfo 'Fixed in 22.23.4 / 24.22.1 / 26.12.1. EOL lines are affected.'

# --- Update feature ---
$needsUpdate = $phpVuln -or $nodeVuln
if (-not $needsUpdate) {
    Write-Host "`nNo vulnerable PHP or Node.js installations detected." -ForegroundColor Green
    exit 0
}

if (-not $Update -and -not $Force) {
    Write-Host "`nVulnerable components detected." -ForegroundColor Yellow
    $reply = Read-Host "Attempt update via winget? (y/N)"
    if ($reply -notmatch '^[Yy]') {
        Write-Host "No update performed. Manual update recommended." -ForegroundColor Yellow
        Write-Host "  Node: https://nodejs.org/en/download/"
        Write-Host "  PHP:  https://windows.php.net/download/"
        exit 0
    }
}

# winget check
$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
    Write-Host "`nwinget not found. Install App Installer from Microsoft Store or update manually." -ForegroundColor Red
    exit 1
}

Write-Host "`n=== Update via winget ===" -ForegroundColor Cyan
Write-Host "WARNING: This will modify system packages. Confirm on production hosts." -ForegroundColor Yellow
Write-Host "Restart IIS / Apache / PHP-FPM / services after PHP update." -ForegroundColor Yellow

if ($nodeVuln -and $nodeVer) {
    Write-Host "`nUpdating Node.js..."
    winget upgrade --id OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements -h
    if ($LASTEXITCODE -ne 0) {
        winget upgrade --id OpenJS.NodeJS --accept-package-agreements --accept-source-agreements -h
    }
}

if ($phpVuln) {
    Write-Host "`nUpdating PHP..."
    winget upgrade --id PHP.PHP.8.3 --accept-package-agreements --accept-source-agreements -h
    if ($LASTEXITCODE -ne 0) {
        winget search php | Select-Object -First 10
        Write-Host "Multiple PHP packages may exist. Choose the matching major version and re-run, or update manually." -ForegroundColor Yellow
    }
}

Write-Host "`nUpdate complete. Re-run this script to verify versions." -ForegroundColor Green
Write-Host "Remember to restart any web servers or services using the updated runtimes." -ForegroundColor Yellow
