#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Creates a locked-down IIS FTP drop site for SmartZone / SonicWall config exports.

.DESCRIPTION
    Standalone Windows Server 2019+ (local accounts).
    Creates local user + group, NTFS ACL, FTP site, Basic auth, authorization,
    passive data-port range, Windows Firewall rules, optional user isolation.

    SmartZone External Services > FTP expects:
      Protocol FTP, port 21, path starting with /, writable account.

    SAFETY: plain FTP is cleartext. Bind to a management NIC only. Do not publish to WAN.
    If your SZ build supports SFTP, use OpenSSH instead of this script.

.NOTES
    Edit the CONFIG block, then:
      Set-ExecutionPolicy -Scope Process Bypass
      .\New-SmartZoneIisFtp.ps1
    Or override any value:
      .\New-SmartZoneIisFtp.ps1 -BindIp '10.20.30.40' -PhysicalPath 'E:\Backups\SZ'
#>

[CmdletBinding(SupportsShouldProcess)]
param(
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
    [switch]$RecreateSite
)

# =============================================================================
# CONFIG — edit these. Any -Parameter on the command line overrides the same key.
# =============================================================================
$Config = @{
    # IIS FTP site name
    SiteName           = 'SmartZone-Backup'

    # NIC SmartZone reaches. Use '*' only if this box has a single IP.
    BindIp             = '10.0.0.10'

    ControlPort        = 21

    # Drop folder. Created if missing.
    PhysicalPath       = 'D:\FTP\SmartZone'

    FtpUser            = 'szbackup'
    FtpGroup           = 'FTP-SZBackup'

    # Leave blank to be prompted at runtime. Do not commit a real password.
    FtpPasswordPlain   = ''

    # Passive data ports. Open the same range on any firewall in front of this host.
    PasvLow            = 50000
    PasvHigh           = 50050

    # IP SmartZone uses as the destination (this host's IP on same L3, or NAT IP if PAT'd).
    # Empty = BindIp (or omitted if BindIp is '*').
    ExternalIp         = ''

    # None  = no certificate, SSL allowed-but-unused  (SZ plain FTP)
    # Allow = optional FTPS if a cert thumbprint is set
    # Require = FTPS only — SZ will fail Test unless it speaks explicit FTPS
    SslMode            = 'None'
    SslCertThumbprint  = ''

    # $true = isolate to PhysicalPath\LocalUser\<FtpUser>
    EnableUserIsolation = $false

    # $true = delete and rebuild the FTP site if it already exists
    RecreateSite        = $false
}
# =============================================================================

function Resolve-Config {
    param($Config, $Bound)

    $map = @{
        SiteName              = $SiteName
        BindIp                = $BindIp
        ControlPort           = $ControlPort
        PhysicalPath          = $PhysicalPath
        FtpUser               = $FtpUser
        FtpGroup              = $FtpGroup
        PasvLow               = $PasvLow
        PasvHigh              = $PasvHigh
        ExternalIp            = $ExternalIp
        SslMode               = $SslMode
        SslCertThumbprint     = $SslCertThumbprint
        EnableUserIsolation   = $EnableUserIsolation
        RecreateSite          = $RecreateSite
    }

    foreach ($k in $map.Keys) {
        if ($Bound.ContainsKey($k) -and $null -ne $map[$k] -and $map[$k] -ne '' -and $map[$k] -ne 0) {
            $Config[$k] = $map[$k]
        }
    }

    if ($Bound.ContainsKey('EnableUserIsolation')) { $Config.EnableUserIsolation = [bool]$EnableUserIsolation }
    if ($Bound.ContainsKey('RecreateSite'))        { $Config.RecreateSite        = [bool]$RecreateSite }
    if ($Bound.ContainsKey('ControlPort') -and $ControlPort -gt 0) { $Config.ControlPort = $ControlPort }
    if ($Bound.ContainsKey('PasvLow')     -and $PasvLow     -gt 0) { $Config.PasvLow     = $PasvLow }
    if ($Bound.ContainsKey('PasvHigh')    -and $PasvHigh    -gt 0) { $Config.PasvHigh    = $PasvHigh }

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
    $features = @('Web-Ftp-Server', 'Web-Ftp-Service', 'Web-Mgmt-Console')
    $missing = @()
    foreach ($f in $features) {
        $st = Get-WindowsFeature -Name $f -ErrorAction SilentlyContinue
        if (-not $st -or -not $st.Installed) { $missing += $f }
    }
    if ($missing.Count -gt 0) {
        throw "Missing Windows features: $($missing -join ', '). Install IIS + FTP first."
    }

    Import-Module WebAdministration -ErrorAction Stop

    if (-not (Get-Service -Name FTPSVC -ErrorAction SilentlyContinue)) {
        throw 'FTPSVC is not present. FTP Service role is not installed.'
    }
}

function Get-OrSetPassword {
    param([SecureString]$FromParam, [string]$PlainFromConfig)

    if ($FromParam) { return $FromParam }
    if (-not [string]::IsNullOrWhiteSpace($PlainFromConfig)) {
        Write-Warn2 'FtpPasswordPlain is set in CONFIG. Clear it after first run.'
        return (ConvertTo-SecureString $PlainFromConfig -AsPlainText -Force)
    }
    return (Read-Host -AsSecureString -Prompt 'Password for FTP user')
}

function Ensure-LocalPrincipal {
    param([string]$User, [string]$Group, [SecureString]$Password)

    if (-not (Get-LocalGroup -Name $Group -ErrorAction SilentlyContinue)) {
        New-LocalGroup -Name $Group -Description 'IIS FTP writers for SmartZone backups' | Out-Null
        Write-Ok "Created group $Group"
    } else {
        Write-Ok "Group $Group exists"
    }

    $existing = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-LocalUser -Name $User `
            -Password $Password `
            -FullName 'SmartZone FTP drop' `
            -Description 'SmartZone / SonicWall backup export only' `
            -PasswordNeverExpires `
            -UserMayNotChangePassword `
            -AccountNeverExpires | Out-Null
        Write-Ok "Created user $User"
    } else {
        Write-Warn2 "User $User already exists — password not changed. Use Set-LocalUser to rotate."
        if ($existing.Enabled -eq $false) {
            Enable-LocalUser -Name $User
            Write-Ok "Re-enabled $User"
        }
    }

    $members = Get-LocalGroupMember -Group $Group -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    $needle  = "$env:COMPUTERNAME\$User"
    if ($members -notcontains $needle -and $members -notcontains $User) {
        Add-LocalGroupMember -Group $Group -Member $User
        Write-Ok "Added $User to $Group"
    } else {
        Write-Ok "$User already in $Group"
    }
}

function Ensure-DropFolder {
    param([string]$Path, [string]$Group, [bool]$Isolate, [string]$User)

    $target = $Path
    if ($Isolate) {
        $target = Join-Path $Path "LocalUser\$User"
    }

    if (-not (Test-Path -LiteralPath $target)) {
        New-Item -ItemType Directory -Path $target -Force | Out-Null
        Write-Ok "Created $target"
    } else {
        Write-Ok "Folder exists $target"
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }

    foreach ($p in @($Path, $target) | Select-Object -Unique) {
        $acl = Get-Acl -LiteralPath $p
        $acl.SetAccessRuleProtection($true, $false)

        $rules = @(
            New-Object System.Security.AccessControl.FileSystemAccessRule('SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'),
            New-Object System.Security.AccessControl.FileSystemAccessRule('Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'),
            New-Object System.Security.AccessControl.FileSystemAccessRule($Group,'Modify','ContainerInherit,ObjectInherit','None','Allow')
        )
        foreach ($r in $rules) { $acl.AddAccessRule($r) | Out-Null }
        Set-Acl -LiteralPath $p -AclObject $acl
        Write-Ok "NTFS ACL set on $p (SYSTEM, Administrators, $Group:Modify)"
    }

    return $target
}

function Remove-FtpAuthRules {
    param([string]$SiteName)
    $filter = '/system.ftpServer/security/authorization'
    $cfg = Get-WebConfiguration -Filter $filter -PSPath IIS:\ -Location $SiteName -ErrorAction SilentlyContinue
    if ($cfg) {
        Clear-WebConfiguration -Filter $filter -PSPath IIS:\ -Location $SiteName -ErrorAction SilentlyContinue
    }
}

function Ensure-FtpSite {
    param($Cfg)

    $sitePath = "IIS:\Sites\$($Cfg.SiteName)"
    $exists   = Test-Path $sitePath

    if ($exists -and $Cfg.RecreateSite) {
        Write-Warn2 "Removing existing site $($Cfg.SiteName)"
        Stop-WebItem $sitePath -ErrorAction SilentlyContinue
        Remove-Website -Name $Cfg.SiteName
        $exists = $false
    }

    $ip = if ($Cfg.BindIp -eq '*') { '*' } else { $Cfg.BindIp }

    if (-not $exists) {
        New-WebFtpSite -Name $Cfg.SiteName -IPAddress $ip -Port $Cfg.ControlPort -PhysicalPath $Cfg.PhysicalPath -Force | Out-Null
        Write-Ok "Created FTP site $($Cfg.SiteName) on ${ip}:$($Cfg.ControlPort)"
    } else {
        Write-Ok "Site $($Cfg.SiteName) exists — updating settings"
        Set-ItemProperty $sitePath -Name physicalPath -Value $Cfg.PhysicalPath
        Get-WebBinding -Name $Cfg.SiteName -Protocol ftp -ErrorAction SilentlyContinue | ForEach-Object {
            Remove-WebBinding -Name $Cfg.SiteName -BindingInformation $_.bindingInformation -Protocol ftp
        }
        New-WebBinding -Name $Cfg.SiteName -Protocol ftp -IPAddress $ip -Port $Cfg.ControlPort | Out-Null
    }

    Set-ItemProperty $sitePath -Name ftpServer.security.authentication.basicAuthentication.enabled     -Value $true
    Set-ItemProperty $sitePath -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false
    Write-Ok 'Basic auth ON, anonymous OFF'

    switch ($Cfg.SslMode) {
        'Require' {
            if ([string]::IsNullOrWhiteSpace($Cfg.SslCertThumbprint)) {
                throw 'SslMode Require needs SslCertThumbprint.'
            }
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslRequire'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.dataChannelPolicy    -Value 'SslRequire'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertStoreName  -Value 'My'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash       -Value ($Cfg.SslCertThumbprint -replace '\s','')
            Write-Ok 'SSL Require + certificate bound'
        }
        'Allow' {
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslAllow'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.dataChannelPolicy    -Value 'SslAllow'
            if ($Cfg.SslCertThumbprint) {
                Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertStoreName -Value 'My'
                Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash      -Value ($Cfg.SslCertThumbprint -replace '\s','')
            } else {
                Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash -Value ''
            }
            Write-Ok 'SSL Allow'
        }
        default {
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslAllow'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.dataChannelPolicy    -Value 'SslAllow'
            Set-ItemProperty $sitePath -Name ftpServer.security.ssl.serverCertHash       -Value ''
            Write-Ok 'SSL None (no certificate; plain FTP)'
        }
    }

    if ($Cfg.EnableUserIsolation) {
        Set-ItemProperty $sitePath -Name ftpServer.userIsolation.mode -Value 'IsolateAllDirectories'
        Write-Ok 'User isolation IsolateAllDirectories (LocalUser\<user>)'
    } else {
        Set-ItemProperty $sitePath -Name ftpServer.userIsolation.mode -Value 'None'
        Write-Ok 'User isolation off — session starts at site root'
    }

    Remove-FtpAuthRules -SiteName $Cfg.SiteName
    Add-WebConfiguration '/system.ftpServer/security/authorization' `
        -PSPath IIS:\ `
        -Location $Cfg.SiteName `
        -Value @{ accessType = 'Allow'; roles = $Cfg.FtpGroup; permissions = 'Read,Write' }
    Write-Ok "Authorization Allow Read+Write for group $($Cfg.FtpGroup)"

    if ($Cfg.ExternalIp) {
        Set-ItemProperty $sitePath -Name ftpServer.firewallSupport.externalIp4Address -Value $Cfg.ExternalIp
        Write-Ok "PASV advertised IP = $($Cfg.ExternalIp)"
    }

    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
        -Filter 'system.ftpServer/firewallSupport' -Name lowDataChannelPort  -Value $Cfg.PasvLow
    Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
        -Filter 'system.ftpServer/firewallSupport' -Name highDataChannelPort -Value $Cfg.PasvHigh
    Write-Ok "PASV data ports $($Cfg.PasvLow)-$($Cfg.PasvHigh) (server-wide)"
}

function Ensure-Firewall {
    param($Cfg)

    $rules = @(
        @{ Name = 'FTP-SZ-Control'; Port = "$($Cfg.ControlPort)";     Desc = "FTP control $($Cfg.ControlPort)" },
        @{ Name = 'FTP-SZ-Passive'; Port = "$($Cfg.PasvLow)-$($Cfg.PasvHigh)"; Desc = "FTP PASV $($Cfg.PasvLow)-$($Cfg.PasvHigh)" }
    )

    foreach ($r in $rules) {
        $existing = Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue
        if ($existing) { Remove-NetFirewallRule -DisplayName $r.Name }
        New-NetFirewallRule -DisplayName $r.Name `
            -Description $r.Desc `
            -Direction Inbound -Protocol TCP -LocalPort $r.Port `
            -Action Allow -Profile Any | Out-Null
        Write-Ok "Firewall inbound TCP $($r.Port) ($($r.Name))"
    }

    Get-NetFirewallRule -DisplayGroup 'FTP Server' -ErrorAction SilentlyContinue |
        Enable-NetFirewallRule -ErrorAction SilentlyContinue
}

function Start-FtpStack {
    param([string]$SiteName)

    $svc = Get-Service FTPSVC
    if ($svc.Status -ne 'Running') {
        Start-Service FTPSVC
    } else {
        Restart-Service FTPSVC -Force
    }
    Write-Ok 'FTPSVC running'

    try {
        (Get-Website -Name $SiteName).ftpServer.stop()  | Out-Null
    } catch { }
    (Get-Website -Name $SiteName).ftpServer.start() | Out-Null
    Write-Ok "FTP site $SiteName started"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
$ErrorActionPreference = 'Stop'
$Cfg = Resolve-Config -Config $Config -Bound $PSBoundParameters

Write-Host 'SmartZone IIS FTP provisioner' -ForegroundColor White
Write-Host ("  Site {0}  {1}:{2}" -f $Cfg.SiteName, $Cfg.BindIp, $Cfg.ControlPort)
Write-Host ("  Path {0}" -f $Cfg.PhysicalPath)
Write-Host ("  User {0}  Group {1}  SSL {2}  Isolate {3}" -f $Cfg.FtpUser, $Cfg.FtpGroup, $Cfg.SslMode, $Cfg.EnableUserIsolation)

if ($Cfg.BindIp -eq '*') {
    Write-Warn2 'BindIp is *. Prefer a dedicated management IP.'
}
if ($Cfg.SslMode -eq 'None') {
    Write-Warn2 'Plain FTP. Restrict source to SmartZone management IPs at the firewall.'
}

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

$remoteDir = '/'

Write-Host ''
Write-Host 'DONE. SmartZone External Services > FTP' -ForegroundColor Green
Write-Host "  Protocol        : FTP"
Write-Host "  Host            : $(if ($Cfg.ExternalIp) { $Cfg.ExternalIp } else { $Cfg.BindIp })"
Write-Host "  Port            : $($Cfg.ControlPort)"
Write-Host "  User            : $($Cfg.FtpUser)"
Write-Host "  Remote Directory: $remoteDir   (must start with /)"
Write-Host ''
Write-Host 'Verify from another host:'
Write-Host "  ftp $($Cfg.BindIp)"
Write-Host "  # login as $($Cfg.FtpUser), then: put test.txt"
Write-Host "  # file should land in $($Cfg.PhysicalPath)$(if ($Cfg.EnableUserIsolation) { \"\\LocalUser\\$($Cfg.FtpUser)\" })"
Write-Host ''
Write-Host 'If SZ Test fails with 425: PASV advertised IP or ports 50000-50050 blocked, or FTP ALG on the path.'
Write-Host 'Rotate the password with: Set-LocalUser -Name szbackup -Password (Read-Host -AsSecureString)'
