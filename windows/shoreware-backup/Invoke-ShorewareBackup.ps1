#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Dump Shoreware / Mitel MySQL databases, gzip them, upload to SharePoint via Graph.
.NOTES
    Config: Invoke-ShorewareBackup.settings.json
    Secrets: CredFile (Export-Clixml). Never store secrets in JSON.
    .\Invoke-ShorewareBackup.ps1 -DumpConfig
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$SettingsFile,
    [switch]$DumpConfig,
    [switch]$SkipBackup,
    [switch]$SkipUpload,
    [switch]$ResetCredentials
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Message) Write-Host "    OK  $Message" -ForegroundColor Green }
function Write-Warn2{ param([string]$Message) Write-Host "    !!  $Message" -ForegroundColor Yellow }

function Get-DefaultSettingsPath { Join-Path $PSScriptRoot 'Invoke-ShorewareBackup.settings.json' }

function Import-SettingsFile {
    param([string]$Path)
    if (-not $Path) { $Path = Get-DefaultSettingsPath }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Settings file not found: $Path" }
    Write-Host "    Settings: $Path" -ForegroundColor DarkGray
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $raw = [regex]::Replace($raw, '\\(?![\\/"bfnrtu])', '\\')
    $json = $raw | ConvertFrom-Json
    $cfg = @{}
    foreach ($p in $json.PSObject.Properties) {
        if ($p.Name -eq 'Databases') { $cfg.Databases = @($p.Value) }
        else { $cfg[$p.Name] = $p.Value }
    }
    if ([string]::IsNullOrWhiteSpace($cfg.ServerName)) { $cfg.ServerName = $env:COMPUTERNAME }
    if ([string]::IsNullOrWhiteSpace($cfg.MysqlHost)) { $cfg.MysqlHost = '127.0.0.1' }
    if ([string]::IsNullOrWhiteSpace($cfg.MysqlUser)) { $cfg.MysqlUser = 'root' }
    $cfg.BackupRoot = [IO.Path]::GetFullPath($cfg.BackupRoot)
    $cfg.CredFile   = [IO.Path]::GetFullPath($cfg.CredFile)
    if ($cfg.ChunkSizeMB) { $cfg.ChunkSize = [int]$cfg.ChunkSizeMB * 1MB }
    if (-not $cfg.ChunkSize) { $cfg.ChunkSize = 10MB }
    return $cfg
}

function Get-EncryptedCredentials {
    param([string]$CredFile, [switch]$Reset)
    if ($Reset -and (Test-Path -LiteralPath $CredFile)) {
        Remove-Item -LiteralPath $CredFile -Force
        Write-Warn2 "Removed $CredFile"
    }
    $dir = Split-Path $CredFile -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    if (-not (Test-Path -LiteralPath $CredFile)) {
        Write-Warn2 'Credential file missing. Interactive prompt (run as the scheduled-task account).'
        $db  = Read-Host 'MySQL password' -AsSecureString
        $sec = Read-Host 'Graph client secret' -AsSecureString
        @{ DBPassword = $db; ClientSecret = $sec } | Export-Clixml -Path $CredFile
        Write-Ok "Saved DPAPI creds to $CredFile"
    }
    $creds = Import-Clixml -Path $CredFile
    $dbBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($creds.DBPassword)
    $scBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($creds.ClientSecret)
    try {
        return @{
            DBPassword   = [Runtime.InteropServices.Marshal]::PtrToStringAuto($dbBstr)
            ClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($scBstr)
        }
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($dbBstr)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($scBstr)
    }
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
}

function Resolve-MysqlDump {
    param($Cfg, $Db)
    if ($Db.MysqlDumpPath -and (Test-Path -LiteralPath $Db.MysqlDumpPath)) { return $Db.MysqlDumpPath }
    if ($Cfg.MysqlDumpPath -and (Test-Path -LiteralPath $Cfg.MysqlDumpPath)) { return $Cfg.MysqlDumpPath }
    $regPath = $Cfg.MysqlRegistryPath
    if (-not $regPath) { $regPath = 'HKLM:\SOFTWARE\Wow6432Node\MySQL AB\MySQL Server' }
    $valName = $Db.RegistryValueName
    if (-not $valName) { $valName = 'Location' }
    $root = Get-RegistryValue -Path $regPath -Name $valName
    $dump = Join-Path $root 'bin\mysqldump.exe'
    if (-not (Test-Path -LiteralPath $dump)) { throw "mysqldump.exe not found at $dump" }
    return $dump
}

function Compress-GZipFile {
    param([string]$InputFile)
    $output = "$InputFile.gz"
    $in = [IO.File]::OpenRead($InputFile)
    $out = [IO.File]::Create($output)
    $gz = New-Object IO.Compression.GZipStream($out, [IO.Compression.CompressionMode]::Compress)
    try { $in.CopyTo($gz) } finally { $gz.Dispose(); $in.Dispose(); $out.Dispose() }
    Remove-Item -LiteralPath $InputFile -Force
    return $output
}

function Invoke-DatabaseBackup {
    param($Cfg, $Secrets, $Db, [string]$WorkFolder)
    $name = $Db.Name
    $port = [int]$Db.Port
    $file = $Db.OutputFile
    if (-not $file) { $file = "$name.sql" }
    Write-Step ('Dump {0} port {1}' -f $name, $port)
    $mysqldump = Resolve-MysqlDump -Cfg $Cfg -Db $Db
    $outPath = Join-Path $WorkFolder $file
    $errPath = "$outPath.err"
    $cnfPath = Join-Path $WorkFolder ('mysql_{0}.cnf' -f $name)
    @"
[client]
user=$($Cfg.MysqlUser)
password=$($Secrets.DBPassword)
host=$($Cfg.MysqlHost)
port=$port
"@ | Set-Content -LiteralPath $cnfPath -Encoding ASCII
    $dumpArgs = @(
        "--defaults-extra-file=$cnfPath",
        '--add-drop-database', '--routines', '--quick', '--single-transaction',
        '--databases', $name
    )
    $p = Start-Process -FilePath $mysqldump -ArgumentList $dumpArgs `
        -RedirectStandardOutput $outPath -RedirectStandardError $errPath `
        -NoNewWindow -Wait -PassThru
    Remove-Item -LiteralPath $cnfPath -Force -ErrorAction SilentlyContinue
    if ($p.ExitCode -ne 0) {
        $err = if (Test-Path $errPath) { Get-Content $errPath -Raw } else { '' }
        throw ('mysqldump failed for {0} exit {1} {2}' -f $name, $p.ExitCode, $err)
    }
    if (-not (Select-String -Path $outPath -Pattern 'Dump completed' -Quiet)) {
        throw "Validation failed: Dump completed not found in $outPath"
    }
    $mb = [math]::Round((Get-Item $outPath).Length / 1MB, 2)
    Write-Ok ('{0}  {1} MB' -f $outPath, $mb)
    $gz = Compress-GZipFile -InputFile $outPath
    Write-Ok ('gzip {0}' -f $gz)
    return $gz
}

function Get-GraphHeaders {
    param($Cfg, $Secrets)
    $body = @{
        grant_type    = 'client_credentials'
        client_id     = $Cfg.ClientId
        client_secret = $Secrets.ClientSecret
        scope         = 'https://graph.microsoft.com/.default'
    }
    $tok = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$($Cfg.TenantId)/oauth2/v2.0/token" `
        -Body $body -ContentType 'application/x-www-form-urlencoded'
    return @{ Authorization = "Bearer $($tok.access_token)" }
}

function Get-GraphDrive {
    param($Cfg, $Headers)
    $sitePath = $Cfg.GraphSitePath
    if (-not $sitePath) { $sitePath = "root:/sites/$($Cfg.SiteName)" }
    $site = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$sitePath" -Headers $Headers
    $drives = Invoke-RestMethod -Method GET -Uri "https://graph.microsoft.com/v1.0/sites/$($site.id)/drives" -Headers $Headers
    $drive = $drives.value | Where-Object { $_.name -eq $Cfg.LibraryName }
    if (-not $drive) { throw "Drive not found: $($Cfg.LibraryName)" }
    return $drive
}

function Add-GraphFolder {
    param($Headers, [string]$DriveId, [string]$ParentPath, [string]$Name)
    $uri = if ([string]::IsNullOrWhiteSpace($ParentPath)) {
        "https://graph.microsoft.com/v1.0/drives/$DriveId/root/children"
    } else {
        $enc = ($ParentPath -replace '\\', '/')
        "https://graph.microsoft.com/v1.0/drives/$DriveId/root:/${enc}:/children"
    }
    $body = @{ name = $Name; folder = @{}; '@microsoft.graph.conflictBehavior' = 'replace' } | ConvertTo-Json
    Invoke-RestMethod -Method POST -Uri $uri -Headers $Headers -Body $body -ContentType 'application/json' | Out-Null
}

function Ensure-GraphFolders {
    param($Headers, [string]$DriveId, [string]$FolderPath)
    $parts = @($FolderPath -split '[\\/]' | Where-Object { $_ })
    $built = ''
    foreach ($part in $parts) {
        Add-GraphFolder -Headers $Headers -DriveId $DriveId -ParentPath $built -Name $part
        $built = if ($built) { "$built/$part" } else { $part }
    }
}

function Send-GraphFile {
    param($Cfg, $Headers, $Drive, [string]$FilePath, [string]$UploadPath)
    $sessionUri = "https://graph.microsoft.com/v1.0/drives/$($Drive.id)/root:/${UploadPath}:/createUploadSession"
    $sessionBody = @{ item = @{ '@microsoft.graph.conflictBehavior' = 'replace'; name = (Split-Path $FilePath -Leaf) } } | ConvertTo-Json
    $session = Invoke-RestMethod -Method POST -Uri $sessionUri -Headers $Headers -Body $sessionBody -ContentType 'application/json'
    $uploadUrl = $session.uploadUrl
    $fileSize = (Get-Item -LiteralPath $FilePath).Length
    $fs = [IO.File]::OpenRead($FilePath)
    try {
        $buffer = New-Object byte[] $Cfg.ChunkSize
        $pos = 0
        while (($read = $fs.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $chunkHeaders = @{
                'Content-Length' = $read
                'Content-Range'  = "bytes $pos-$($pos + $read - 1)/$fileSize"
            }
            $chunk = New-Object IO.MemoryStream($buffer, 0, $read)
            Invoke-RestMethod -Method PUT -Uri $uploadUrl -Headers $chunkHeaders -Body $chunk -ContentType 'application/octet-stream' | Out-Null
            $pos += $read
            Write-Host ('    upload {0}%' -f [math]::Round(($pos / $fileSize) * 100, 1)) -ForegroundColor DarkGray
        }
    } finally { $fs.Dispose() }
}

function Invoke-SharePointRetention {
    param($Cfg, $Headers, $Drive, [string]$ServerFolder)
    $days = [int]$Cfg.RetentionDays
    if ($days -le 0) { Write-Warn2 'RetentionDays <= 0 - skip cleanup'; return }
    $cutoff = (Get-Date).AddDays(-$days)
    Write-Step ('SharePoint retention older than {0:yyyy-MM-dd} under {1}' -f $cutoff, $ServerFolder)
    $listUri = "https://graph.microsoft.com/v1.0/drives/$($Drive.id)/root:/${ServerFolder}:/children"
    try { $kids = Invoke-RestMethod -Method GET -Uri $listUri -Headers $Headers }
    catch { Write-Warn2 "Could not list $ServerFolder"; return }
    foreach ($item in $kids.value) {
        $stamp = $null
        if ($item.folder -and $item.name -match '^\d{4}-\d{2}-\d{2}$') {
            $stamp = [datetime]::ParseExact($item.name, 'yyyy-MM-dd', $null)
        } elseif ($item.file -and $item.lastModifiedDateTime) {
            $stamp = [datetime]$item.lastModifiedDateTime
        }
        if ($stamp -and $stamp -lt $cutoff) {
            Write-Warn2 ('Delete {0}' -f $item.name)
            Invoke-RestMethod -Method DELETE -Uri "https://graph.microsoft.com/v1.0/drives/$($Drive.id)/items/$($item.id)" -Headers $Headers | Out-Null
        }
    }
}

$Cfg = Import-SettingsFile -Path $SettingsFile
Write-Host 'Shoreware / Mitel MySQL backup' -ForegroundColor White
Write-Host ('  Server   {0}' -f $Cfg.ServerName) -ForegroundColor DarkGray
Write-Host ('  Root     {0}' -f $Cfg.BackupRoot) -ForegroundColor DarkGray
Write-Host ('  Graph    {0} / {1}' -f $Cfg.SiteName, $Cfg.LibraryName) -ForegroundColor DarkGray
Write-Host ('  DBs      {0}' -f (($Cfg.Databases | ForEach-Object { $_.Name }) -join ', ')) -ForegroundColor DarkGray
if ($DumpConfig) {
    $Cfg.GetEnumerator() | Sort-Object Name | ForEach-Object {
        if ($_.Name -eq 'Databases') {
            Write-Host ('  {0,-22} {1}' -f 'Databases', (($_.Value | ForEach-Object { $_.Name }) -join ', '))
        } else {
            Write-Host ('  {0,-22} {1}' -f $_.Name, $_.Value)
        }
    }
    return
}

New-Item -ItemType Directory -Path $Cfg.BackupRoot -Force | Out-Null
$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$dateFolder = Get-Date -Format 'yyyy-MM-dd'
$workFolder = Join-Path $Cfg.BackupRoot $timestamp
$logFile    = Join-Path $Cfg.BackupRoot 'Backup.log'
$transcript = Join-Path $Cfg.BackupRoot ('{0}-Transcript_{1}.log' -f $Cfg.ServerName, $timestamp)
New-Item -ItemType Directory -Path $workFolder -Force | Out-Null
Start-Transcript -Path $transcript -Force | Out-Null

function Write-Log {
    param([string]$Message)
    $line = '{0} - {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    Add-Content -Path $logFile -Value $line
}

try {
    $secrets = Get-EncryptedCredentials -CredFile $Cfg.CredFile -Reset:$ResetCredentials
    $compressed = @()
    if (-not $SkipBackup) {
        foreach ($db in $Cfg.Databases) {
            $compressed += Invoke-DatabaseBackup -Cfg $Cfg -Secrets $secrets -Db $db -WorkFolder $workFolder
        }
    } else { Write-Warn2 'SkipBackup' }

    if (-not $SkipUpload -and $compressed.Count -gt 0) {
        Write-Step 'SharePoint upload'
        $headers = Get-GraphHeaders -Cfg $Cfg -Secrets $secrets
        $drive   = Get-GraphDrive -Cfg $Cfg -Headers $headers
        $relRoot = ($Cfg.FolderPath.Trim('/\') + '/' + $Cfg.ServerName + '/' + $dateFolder) -replace '\\', '/'
        Ensure-GraphFolders -Headers $headers -DriveId $drive.id -FolderPath $relRoot
        foreach ($file in $compressed) {
            $leaf = Split-Path $file -Leaf
            $upload = "$relRoot/$leaf"
            Write-Log "Uploading $leaf -> $upload"
            Send-GraphFile -Cfg $Cfg -Headers $headers -Drive $drive -FilePath $file -UploadPath $upload
            Write-Ok $leaf
        }
        $serverFolder = ($Cfg.FolderPath.Trim('/\') + '/' + $Cfg.ServerName) -replace '\\', '/'
        Invoke-SharePointRetention -Cfg $Cfg -Headers $headers -Drive $drive -ServerFolder $serverFolder
    } else { Write-Warn2 'SkipUpload or nothing to send' }

    Write-Log 'BACKUP JOB COMPLETED SUCCESSFULLY'
}
catch {
    Write-Log ('BACKUP JOB FAILED: {0}' -f $_.Exception.Message)
    throw
}
finally {
    if (-not $Cfg.KeepLocalFiles) {
        Remove-Item -Path $workFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
    Stop-Transcript | Out-Null
}
