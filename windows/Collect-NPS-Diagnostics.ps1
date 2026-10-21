#Requires -Version 4.0
# NPS Diagnostic Collection - 2012 R2 compatible
# Run elevated on the NPS server.
# Collects NPS config, certificates, Security 6272/6273/6274, and IAS logs.
# Shared secrets and password-like values are redacted before write.

param(
    [string]$OutputRoot = "$env:USERPROFILE\Desktop",
    [int]$EventHours = 48,
    [switch]$NoZip
)

$ErrorActionPreference = 'Continue'
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $OutputRoot "NPS-Diag-$timestamp"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

function Save-Text($Name, $Content) {
    $path = Join-Path $outDir $Name
    if ($null -eq $Content) { $Content = "(null)" }
    if ($Content -isnot [string]) { $Content = $Content | Out-String }
    $Content = Redact-Secrets $Content
    Set-Content -Path $path -Value $Content -Encoding UTF8
    Write-Host "  $Name"
}

function Redact-Secrets([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    # netsh nps dump: sharedsecret = "value"
    $Text = [regex]::Replace($Text, '(sharedsecret\s*=\s*")[^"]*(")', '$1***REDACTED***$2', 'IgnoreCase')
    # Get-NpsRadiusClient Format-List: SharedSecret : value
    $Text = [regex]::Replace($Text, '(SharedSecret\s*:\s*)\S+', '$1***REDACTED***', 'IgnoreCase')
    # Generic password / psk lines
    $Text = [regex]::Replace($Text, '(password|passwd|psk|secret)\s*[:=]\s*\S+', '$1 = ***REDACTED***', 'IgnoreCase')
    return $Text
}

Write-Host "Collecting NPS diagnostics to $outDir" -ForegroundColor Cyan

# --- System ---
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$sys = @"
ComputerName : $env:COMPUTERNAME
FQDN         : $([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName)
OS           : $($os.Caption)
Version      : $($os.Version)
Domain       : $($cs.Domain)
PartOfDomain : $($cs.PartOfDomain)
Time         : $(Get-Date)
"@
Save-Text "00-System.txt" $sys

# --- Service ---
$svc = Get-Service IAS -ErrorAction SilentlyContinue
if ($svc) {
    Save-Text "01-IAS-Service.txt" ($svc | Format-List Name, Status, StartType, DisplayName | Out-String)
} else {
    Save-Text "01-IAS-Service.txt" "IAS service not found"
}

# --- Full NPS config via netsh (correct syntax for 2012 R2) ---
$dump = netsh nps dump exportpsk=yes 2>&1 | Out-String
Save-Text "10-netsh-nps-dump.txt" $dump

# --- RADIUS clients (cmdlet exists) ---
$clients = Get-NpsRadiusClient -ErrorAction SilentlyContinue
if ($clients) {
    Save-Text "11-RadiusClients.txt" ($clients | Format-List * | Out-String)
} else {
    Save-Text "11-RadiusClients.txt" "(Get-NpsRadiusClient returned nothing)"
}

# --- Policies via netsh show (fallback when Get-Nps* missing) ---
$npShow = netsh nps show np 2>&1 | Out-String
Save-Text "12-NetworkPolicies-netsh.txt" $npShow

$crpShow = netsh nps show crp 2>&1 | Out-String
Save-Text "13-ConnectionRequestPolicies-netsh.txt" $crpShow

# --- Certificates ---
$certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.HasPrivateKey }
if ($certs) {
    $certText = $certs | ForEach-Object {
        $eku = ($_.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ', '
        @"
Subject     : $($_.Subject)
Issuer      : $($_.Issuer)
NotBefore   : $($_.NotBefore)
NotAfter    : $($_.NotAfter)
Thumbprint  : $($_.Thumbprint)
EKU         : $eku
HasPrivKey  : $($_.HasPrivateKey)
---
"@
    }
    Save-Text "20-Computer-Personal-Certs.txt" ($certText -join "`r`n")
} else {
    Save-Text "20-Computer-Personal-Certs.txt" "No certs with private key in LocalMachine\My"
}

# --- Event logs: full 6272/6273 messages ---
$start = (Get-Date).AddHours(-$EventHours)
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 6272,6273,6274
        StartTime = $start
    } -MaxEvents 200 -ErrorAction SilentlyContinue

    if ($events) {
        $lines = $events | ForEach-Object {
            "==== $($_.TimeCreated)  Id=$($_.Id) ====`r`n$($_.Message)`r`n"
        }
        Save-Text "30-Security-NPS-Events.txt" ($lines -join "`r`n")

        # Summary counts
        $summary = $events | Group-Object Id | ForEach-Object { "$($_.Name) : $($_.Count)" }
        Save-Text "31-Event-Counts.txt" ($summary -join "`r`n")
    } else {
        Save-Text "30-Security-NPS-Events.txt" "No 6272/6273/6274 in last $EventHours hours"
    }
} catch {
    Save-Text "30-Security-NPS-Events.txt" "Event query failed: $_"
}

# --- IAS file logs (check both default and custom path) ---
$logPaths = @(
    "$env:windir\System32\LogFiles",
    "C:\RADIUS Accounting Logs"
)
$found = $false
foreach ($p in $logPaths) {
    if (Test-Path $p) {
        $files = Get-ChildItem $p -Filter "IN*.log" -ErrorAction SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 3
        if ($files) {
            $found = $true
            $logDir = Join-Path $outDir "IAS-Logs"
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            foreach ($f in $files) {
                Copy-Item $f.FullName -Destination (Join-Path $logDir $f.Name) -Force
            }
            Save-Text "40-IAS-Log-Note.txt" "Copied $($files.Count) files from $p"
        }
    }
}
if (-not $found) {
    Save-Text "40-IAS-Log-Note.txt" "No IN*.log found in default or C:\RADIUS Accounting Logs"
}

# --- Domain Computers group members sample (if AD available) ---
try {
    $dc = Get-ADGroupMember "Domain Computers" -ErrorAction SilentlyContinue | Select-Object -First 20 Name, SamAccountName, ObjectClass
    if ($dc) {
        Save-Text "50-DomainComputers-Sample.txt" ($dc | Format-Table -AutoSize | Out-String)
    } else {
        Save-Text "50-DomainComputers-Sample.txt" "Domain Computers group empty or AD cmdlets unavailable"
    }
} catch {
    Save-Text "50-DomainComputers-Sample.txt" "AD query failed: $_"
}

# --- README ---
$readme = @"
NPS Diagnostic Collection
Server: $env:COMPUTERNAME
Generated: $(Get-Date)
Window: last $EventHours hours

Key files:
  10-netsh-nps-dump.txt          full config (policies, clients; secrets redacted)
  12-NetworkPolicies-netsh.txt
  30-Security-NPS-Events.txt     full 6272/6273 messages
  20-Computer-Personal-Certs.txt

Review 10-netsh-nps-dump.txt and 30-Security-NPS-Events.txt first.
Computer identity (host/computer$) matching Domain Computers hits the machine policy.
User identity hits the user policy.
"@
Save-Text "README.txt" $readme

Write-Host "`nDone: $outDir" -ForegroundColor Green

if (-not $NoZip) {
    $zip = "$outDir.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outDir, $zip)
    Write-Host "Zip: $zip" -ForegroundColor Green
}
