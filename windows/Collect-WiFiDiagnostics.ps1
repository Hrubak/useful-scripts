#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Collect Wi-Fi diagnostics for intermittent connection drops on Windows 10/11.
.DESCRIPTION
    Generates the native WLAN report (netsh wlan show wlanreport), captures
    netsh state, exports relevant event logs, and writes a timestamped folder
    on the Desktop. No passwords or PSK material is collected.
.NOTES
    Run elevated. Primary artifact is wlan-report.html.
#>

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $env:USERPROFILE "Desktop\WiFi-Diagnostics-$timestamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host "Collecting Wi-Fi diagnostics to:`n  $outDir`n" -ForegroundColor Cyan

# --- 1. Native WLAN report ---
Write-Host "[1/4] Generating WLAN report..." -ForegroundColor Yellow
& netsh wlan show wlanreport | Out-Null
$reportSrc = 'C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html'
if (Test-Path $reportSrc) {
    Copy-Item $reportSrc -Destination (Join-Path $outDir 'wlan-report.html') -Force
    Write-Host "  WLAN report copied." -ForegroundColor Green
} else {
    Write-Warning "  WLAN report not found at expected path."
}

# --- 2. Current state snapshots ---
Write-Host "[2/4] Capturing current adapter / driver / profile state..." -ForegroundColor Yellow
$netshCmds = @(
    @{ File = 'interfaces.txt'; Args = @('wlan', 'show', 'interfaces') }
    @{ File = 'drivers.txt';    Args = @('wlan', 'show', 'drivers') }
    @{ File = 'profiles.txt';   Args = @('wlan', 'show', 'profiles') }
    @{ File = 'networks.txt';   Args = @('wlan', 'show', 'networks', 'mode=bssid') }
    @{ File = 'settings.txt';   Args = @('wlan', 'show', 'settings') }
)
foreach ($cmd in $netshCmds) {
    $outFile = Join-Path $outDir $cmd.File
    & netsh @($cmd.Args) | Out-File -FilePath $outFile -Encoding utf8
}

Get-NetAdapter -IncludeHidden |
    Where-Object { $_.Name -match 'Wi-?Fi|WLAN' -or $_.InterfaceDescription -match 'Wireless|Wi-Fi' } |
    Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, DriverVersion, DriverDate |
    Format-List | Out-File (Join-Path $outDir 'Get-NetAdapter.txt') -Encoding utf8

Get-NetAdapterAdvancedProperty -Name * -ErrorAction SilentlyContinue |
    Where-Object { $_.RegistryKeyword -match 'Power|Sleep|Roaming|Band|Channel' } |
    Select-Object Name, DisplayName, DisplayValue, RegistryKeyword |
    Format-Table -AutoSize | Out-File (Join-Path $outDir 'Advanced-Power-Roaming.txt') -Encoding utf8

# --- 3. Event logs (last 3 days) ---
Write-Host "[3/4] Exporting event logs (last 3 days)..." -ForegroundColor Yellow
$startTime = (Get-Date).AddDays(-3)

$wlanLog = 'Microsoft-Windows-WLAN-AutoConfig/Operational'
try {
    Get-WinEvent -FilterHashtable @{ LogName = $wlanLog; StartTime = $startTime } -ErrorAction Stop |
        Export-Csv -Path (Join-Path $outDir 'WLAN-AutoConfig-Operational.csv') -NoTypeInformation -Encoding UTF8
} catch {
    Write-Warning "  Could not export $wlanLog : $($_.Exception.Message)"
}

try {
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-NCSI/Operational'; StartTime = $startTime } -ErrorAction Stop |
        Export-Csv -Path (Join-Path $outDir 'NCSI-Operational.csv') -NoTypeInformation -Encoding UTF8
} catch { }

Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $startTime; Level = 2,3 } -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.ProviderName -match 'NDIS|Kernel-Power|Netwtw|Intel|Realtek|Qualcomm|Broadcom|Wi-Fi|WLAN' -or
        $_.Message -match 'wireless|Wi-Fi|WLAN|adapter'
    } |
    Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
    Export-Csv -Path (Join-Path $outDir 'System-Relevant.csv') -NoTypeInformation -Encoding UTF8

# --- 4. Summary ---
Write-Host "[4/4] Writing summary..." -ForegroundColor Yellow
@"
Wi-Fi Diagnostics collected: $timestamp
Output folder: $outDir

Primary artifact:
  wlan-report.html  <-- open this first

What to look for in the WLAN report:
  - Timeline chart (red = error)
  - Disconnect Reasons table (plain-English causes + counts)
  - Sessions with very short duration
  - "Wireless adapter entered a low power state" events
  - Driver disconnect / association failures

Other files:
  interfaces.txt / drivers.txt / profiles.txt / networks.txt
  WLAN-AutoConfig-Operational.csv   (Event IDs 8001/8002/8003 are key)
  System-Relevant.csv
  Advanced-Power-Roaming.txt

Next steps after review:
  - Disable "Allow the computer to turn off this device to save power" on the Wi-Fi adapter
  - Update the wireless driver from the laptop OEM (not just Windows Update)
  - Note signal % and channel at the time of drops (visible in the report and interfaces.txt)
"@ | Out-File (Join-Path $outDir 'README.txt') -Encoding UTF8

Write-Host "`nDone." -ForegroundColor Green
Write-Host "Open: $outDir\wlan-report.html" -ForegroundColor Cyan
Start-Process (Join-Path $outDir 'wlan-report.html')
