#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a locked-down IIS FTP drop site for SmartZone / SonicWall config exports.
.NOTES
    Edit New-SmartZoneIisFtp.settings.json next to this script.
    CLI parameters override the JSON. -DumpConfig prints the merged config and exits.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SettingsFile,
    [string]$SiteName,
    [string]$BindIp,
    [int]$ControlPort,
    [string]$PhysicalPath,
    [string]$FtpUser,
    [string]$FtpGroup,
    [SecureString]$FtpPassword,
    [int]$PasvLow,
    [int]$PasvHigh,
    [string]$ExternalIp,
    [ValidateSet('None','Allow','Require')]
    [string]$SslMode,
    [string]$SslCertThumbprint,
    [switch]$EnableUserIsolation,
    [switch]$RecreateSite,
    [switch]$DumpConfig
)

$Config = @{
    SiteName            = 'SmartZone-Backup'
    BindIp              = '10.0.0.10'
    ControlPort         = 21
    PhysicalPath        = 'D:\FTP\SmartZone'
    FtpUser             = 'szbackup'
    FtpGroup            = 'FTP-SZBackup'
    FtpPasswordPlain    = ''
    PasvLow             = 50000
    PasvHigh            = 50050
    ExternalIp          = ''
    SslMode             = 'None'
    SslCertThumbprint   = ''
    EnableUserIsolation = $false
    RecreateSite        = $false
}

function Get-DefaultSettingsPath { Join-Path $PSScriptRoot 'New-SmartZoneIisFtp.settings.json' }

function Import-SettingsFile {
    param([hashtable]$Config, [string]$Path)
    if (-not $Path) { $Path = Get-DefaultSettingsPath }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "    !!  Settings file not found: $Path" -ForegroundColor Yellow
        return $Config
    }
    Write-Host "    Settings: $Path" -ForegroundColor DarkGray
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $raw = [regex]::Replace($raw, '\\(?![\\/"bfnrtu])', '\\')
    try { $json = $raw | ConvertFrom-Json }
    catch { throw "Settings JSON is invalid: $Path" }
    foreach ($p in $json.PSObject.Properties) { $Config[$p.Name] = $p.Value }
    return $Config
}

function Resolve-Config {
    param($Config, $Bound)
    $map = @{
        SiteName=$SiteName; BindIp=$BindIp; ControlPort=$ControlPort; PhysicalPath=$PhysicalPath
        FtpUser=$FtpUser; FtpGroup=$FtpGroup; PasvLow=$PasvLow; PasvHigh=$PasvHigh
        ExternalIp=$ExternalIp; SslMode=$SslMode; SslCertThumbprint=$SslCertThumbprint
        EnableUserIsolation=$EnableUserIsolation; RecreateSite=$RecreateSite
    }
    foreach ($k in $map.Keys) {
        if ($Bound.ContainsKey($k) -and $null -ne $map[$k] -and $map[$k] -ne '' -and $map[$k] -ne 0) {
            $Config[$k] = $map[$k]
        }
    }
    if ($Bound.ContainsKey('EnableUserIsolation')) { $Config.EnableUserIsolation = [bool]$EnableUserIsolation }
    if ($Bound.ContainsKey('RecreateSite'))        { $Config.RecreateSite        = [bool]$RecreateSite }
    if ($Bound.ContainsKey('ControlPort') -and $ControlPort -gt 0) { $Config.ControlPort = $ControlPort }
    if ($Bound.ContainsKey('PasvLow') -and $PasvLow -gt 0) { $Config.PasvLow = $PasvLow }
    if ($Bound.ContainsKey('PasvHigh') -and $PasvHigh -gt 0) { $Config.PasvHigh = $PasvHigh }
    if ([string]::IsNullOrWhiteSpace($Config.ExternalIp) -and $Config.BindIp -ne '*') {
        $Config.ExternalIp = $Config.BindIp
    }
    $Config.PhysicalPath = [IO.Path]::GetFullPath($Config.PhysicalPath)
    return $Config
}

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "    OK  $Message" -ForegroundColor Green }
function Write-Warn2{ param([string]$Message) Write-Host "    !!  $Message" -ForegroundColor Yellow }

function Assert-Prereq {
    $missing = @()
    foreach ($f in @('Web-Ftp-Server','Web-Ftp-Service','Web-Mgmt-Console')) {
        $st = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
        if (-not $st -or -not $st.Installed) { $missing += $f }
    }
    if ($missing.Count -gt 0) { throw "Missing Windows features: $($missing -join ', '). Install IIS + FTP first." }
    Import-Module WebAdministration -ErrorAction Stop
    if (-not (Get-Service -Name FTPSVC -ErrorAction SilentlyContinue)) { throw 'FTPSVC is not present.' }
}

function Get-OrSetPassword {
    param([SecureString]$FromParam, [string]$PlainFromConfig)
    if ($FromParam) { return $FromParam }
    if (-not [string]::IsNullOrWhiteSpace($PlainFromConfig)) {
        Write-Warn2 'FtpPasswordPlain is set in settings JSON. Clear it after first run.'
        return (ConvertTo-SecureString $PlainFromConfig -AsPlainText -Force)
    }
    return (Read-Host -AsSecureString -Prompt 'Password for FTP user')
}

function Ensure-LocalPrincipal {
    param([string]$User, [string]$Group, [SecureString]$Password)
    if (-not (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $Group -Description 'IIS FTP writers for SmartZone backups' | Out-Null
        Write-Ok "Created group $Group"
    } else { Write-Ok "Group $Group exists" }
    $existing = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-LocalUser -Name $User -Password $Password -FullName 'SmartZone FTP drop' `
            -Description 'SmartZone backup export only' -PasswordNeverExpires `
            -UserMayNotChangePassword -AccountNeverExpires | Out-Null
        Write-Ok "Created user $User"
    } else {
        Write-Warn2 "User $User already exists - password not changed."
        if ($existing.Enabled -eq $false) { Enable-LocalUser -Name $User }
    }
    $members = Get-LocalGroupMember -Group $Group -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    $needle = "$env:COMPUTERNAME\$User"
    if ($members -notcontains $needle -and $members -notcontains $User) {
        Add-LocalGroupMember -Group $Group -Member $User
        Write-Ok "Added $User to $Group"
    }
}

function Ensure-DropFolder {
    param([string]$Path, [string]$Group, [bool]$Isolate, [string]$User)
    $target = $Path
    if ($Isolate) { $target = Join-Path $Path "LocalUser\$User" }
    if (-not (Test-Path -LiteralPath $target)) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Write-Ok "Created $target"
    }
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null }
    foreach ($p in @($Path, $target) | Select-Object -Unique) {
        $acl = Get-Acl -LiteralPath $p
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($r in @(
            (New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')),
            (New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')),
            (New-Object System.Security.AccessControl.FileSystemAccessRule($Group,'Modify','ContainerInherit,ObjectInherit','None','Allow'))
        )) { $acl.AddAccessRule($r) | Out-Null }
        Set-Acl -LiteralPath $p -AclObject $acl
        Write-Ok 'NTFS ACL applied'
    }
    return $target
}

function Remove-FtpAuthRules {
    param([string]$SiteName)
    $filter = '/system.ftpServer/security/authorization'
    $cfg = Get-WebConfiguration -Filter $filter -PSPath IIS:\ -Location $SiteName -ErrorAction SilentlyContinue
    if ($cfg) { Clear-WebConfiguration -Filter $filter -PSPath IIS:\ -Location $SiteName -ErrorAction SilentlyContinue }
}

function Ensure-FtpSite {
    param($Cfg)
    $sitePath = "IIS:\Sites\$($Cfg.SiteName)"
    $exists = Test-Path $sitePath
    if ($exists -and $Cfg.RecreateSite) {
        Write-Warn2 "Removing existing site $($Cfg.SiteName)"
        Stop-WebItem $sitePath -ErrorAction SilentlyContinue
        Remove-Website -Name $Cfg.SiteName
        $exists = $false
    }
    $ip = if ($Cfg.BindIp -eq '*') { '*' } else { $Cfg.BindIp }
    if (-not $exists) {
        New-WebFtpSite -Name $Cfg.SiteName -IPAddress $ip -Port $Cfg.ControlPort -PhysicalPath $Cfg.PhysicalPath -Force | Out-Null
        Write-Ok "Created FTP site $($Cfg.SiteName)"
    } else {
        Write-Ok "Site $($Cfg.SiteName) exists - updating"
        Set-ItemProperty $sitePath -Name physicalPath -Value $Cfg.PhysicalPath
        Get-WebBinding -Name $Cfg.SiteName -Protocol ftp -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-WebBinding -Name $Cfg.SiteName -BindingInformation $_.bindingInformation -Protocol ftp
        }
        New-WebBinding -Name $Cfg.SiteName -Protocol ftp -IPAddress $ip -Port $Cfg.ControlPort | Out-Null
    }
    Set-ItemProperty $sitePath -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    Set-ItemProperty $sitePath -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false
    switch ($Cfg.SslMode) {
        'Require' {
            if ([string]::IsNullOrWhiteSpace($Cfg.SslCertThumbprint)) { throw 'SslMode Require needs SslCertThumbprint.' }
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslRequire'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.dataChannelPolicy -Value 'SslRequire'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertStoreName -Value 'My'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash -Value ($Cfg.SslCertThumbprint -replace '\s','')
        }
        'Allow' {
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslAllow'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.dataChannelPolicy -Value 'SslAllow'
            if ($Cfg.SslCertThumbprint) {
                Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertStoreName -Value 'My'
                Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash -Value ($Cfg.SslCertThumbprint -replace '\s','')
            } else { Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash -Value '' }
        }
        default {
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslAllow'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.dataChannelPolicy -Value 'SslAllow'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash -Value ''
        }
    }
    if ($Cfg.EnableUserIsolation) {
        Set-ItemProperty $sitePath -Name ftpServer.userIsolation.mode -Value 'IsolateAllDirectories'
    } else {
        Set-ItemProperty $sitePath -Name ftpServer.userIsolation.mode -Value 'None'
    }
    Remove-FtpAuthRules -SiteName $Cfg.SiteName
    Add-WebConfiguration '/system.ftpServer/security/authorization' -PSPath IIS:\ -Location $Cfg.SiteName `
        -Value @{ accessType = 'Allow'; roles = $Cfg.FtpGroup; permissions = 'Read,Write' }
    if ($Cfg.ExternalIp) {
        Set-ItemProperty $sitePath -Name ftpServer.firewallSupport.externalIp4Address -Value $Cfg.ExternalIp
    }
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.ftpServer/firewallSupport' -Name lowDataChannelPort -Value $Cfg.PasvLow
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.ftpServer/firewallSupport' -Name highDataChannelPort -Value $Cfg.PasvHigh
    Write-Ok 'FTP site configured'
}

function Ensure-Firewall {
    param($Cfg)
    foreach ($r in @(
        @{ Name = 'FTP-SZ-Control'; Port = "$($Cfg.ControlPort)" },
        @{ Name = 'FTP-SZ-Passive'; Port = "$($Cfg.PasvLow)-$($Cfg.PasvHigh)" }
    )) {
        if (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -DisplayName $r.Name
        }
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol TCP -LocalPort $r.Port -Action Allow -Profile Any | Out-Null
        Write-Ok "Firewall $($r.Name)"
    }
    Get-NetFirewallRule -DisplayGroup 'FTP Server' -ErrorAction SilentlyContinue | Enable-NetFirewallRule -ErrorAction SilentlyContinue
}

function Start-FtpStack {
    param([string]$SiteName)
    $svc = Get-Service FTPSVC
    if ($svc.Status -ne 'Running') { Start-Service FTPSVC } else { Restart-Service FTPSVC -Force }
    try { (Get-Website -Name $SiteName).ftpServer.stop() | Out-Null } catch { }
    (Get-Website -Name $SiteName).ftpServer.start() | Out-Null
    Write-Ok "FTP site $SiteName started"
}

$ErrorActionPreference = 'Stop'
Write-Host 'SmartZone IIS FTP provisioner' -ForegroundColor White
$Config = Import-SettingsFile -Config $Config -Path $SettingsFile
$Cfg = Resolve-Config -Config $Config -Bound $PSBoundParameters
Write-Host 'Merged config:' -ForegroundColor DarkGray
$Cfg.GetEnumerator() | Sort-Object Name | ForEach-Object {
    $val = $_.Value
    if ($_.Name -eq 'FtpPasswordPlain' -and $val) { $val = '***' }
    Write-Host ('  {0,-22} {1}' -f $_.Name, $val) -ForegroundColor DarkGray
}
if ($DumpConfig) { Write-Host 'DumpConfig set - no changes applied.' -ForegroundColor Yellow; return }

if ($Cfg.BindIp -eq '*') { Write-Warn2 'BindIp is *. Prefer a dedicated management IP.' }
if ($Cfg.SslMode -eq 'None') { Write-Warn2 'Plain FTP. Restrict source to SmartZone management IPs.' }

Assert-Prereq
Write-Step 'Local user / group'
$securePass = Get-OrSetPassword -FromParam $FtpPassword -PlainFromConfig $Cfg.FtpPasswordPlain
Ensure-LocalPrincipal -User $Cfg.FtpUser -Group $Cfg.FtpGroup -Password $securePass
Write-Step 'Drop folder + NTFS'
Ensure-DropFolder -Path $Cfg.PhysicalPath -Group $Cfg.FtpGroup -Isolate $Cfg.EnableUserIsolation -User $Cfg.FtpUser | Out-Null
Write-Step 'IIS FTP site'
Ensure-FtpSite -Cfg $Cfg
Write-Step 'Windows Firewall'
Ensure-Firewall -Cfg $Cfg
Write-Step 'Start services'
Start-FtpStack -SiteName $Cfg.SiteName

Write-Host ''
Write-Host 'DONE. SmartZone External Services > FTP' -ForegroundColor Green
Write-Host "  Protocol        : FTP"
Write-Host "  Host            : $(if ($Cfg.ExternalIp) { $Cfg.ExternalIp } else { $Cfg.BindIp })"
Write-Host "  Port            : $($Cfg.ControlPort)"
Write-Host "  User            : $($Cfg.FtpUser)"
Write-Host '  Remote Directory: /'
Write-Host "  Verify: ftp $($Cfg.BindIp)"
