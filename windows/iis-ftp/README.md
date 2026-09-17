# IIS FTP drop site (SmartZone / SonicWall)

Two scripts:

| File | Role |
|---|---|
| `Install-IisFtpFeatures.ps1` | Installs IIS + FTP Windows features and starts `FTPSVC`. |
| `New-SmartZoneIisFtp.ps1` | Creates the locked-down FTP drop site (user, NTFS, site, PASV, firewall). |
| `New-SmartZoneIisFtp.settings.json` | **Your** site config. Do not overwrite when updating scripts. |

Run order on a clean Server 2019+ box: features script, then (if it asked for a reboot) reboot, then site script.

## 1. Install IIS + FTP features

Elevated PowerShell 5.1+. Server SKU only (`Install-WindowsFeature`).

```powershell
Set-Location "$env:USERPROFILE\Desktop\FTPServer"
curl.exe -L "https://raw.githubusercontent.com/Hrubak/useful-scripts/main/windows/iis-ftp/Install-IisFtpFeatures.ps1" -o ".\Install-IisFtpFeatures.ps1"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Install-IisFtpFeatures.ps1 -DumpOnly
.\Install-IisFtpFeatures.ps1
```

Features installed when missing:

- IIS core: `Web-Server`, common HTTP, logging, static compression, request filtering
- Management: `Web-Mgmt-Console`, `Web-Scripting-Tools`
- FTP: `Web-Ftp-Server`, `Web-Ftp-Service`, `Web-Ftp-Ext`

Optional remote IIS management service:

```powershell
.\Install-IisFtpFeatures.ps1 -IncludeWebMgmtService
```

Idempotent. Sets `FTPSVC` to Automatic and starts it. The IIS role also creates **Default Web Site** on port 80 — stop or rebind that site if this host should not serve HTTP.

## 2. Provision the SmartZone drop site

- Windows Server 2019+ (local accounts)
- Features from step 1 already installed
- Elevated PowerShell 5.1+

## Safety

Plain FTP sends credentials and backup files in the clear. Bind to a management NIC. Do not publish port 21 to WAN. IIS FTP is **not** SFTP.

Do not put a real password in `FtpPasswordPlain` on a machine that is backed up or copied. Leave it empty and type the password at the prompt. Rotate if it ever leaked.

Load order for the site script: script defaults → settings JSON → `-Parameter` (last wins).

## Settings JSON

Prefer forward slashes in paths. JSON treats `C:\FTP` as an illegal escape (`\F`).

```json
{
  "SiteName": "SmartZone-Backup",
  "BindIp": "10.1.20.56",
  "ControlPort": 21,
  "PhysicalPath": "C:/FTP/SmartZone",
  "FtpUser": "szbackup",
  "FtpGroup": "FTP-SZBackup",
  "FtpPasswordPlain": "",
  "PasvLow": 50000,
  "PasvHigh": 50050,
  "ExternalIp": "",
  "SslMode": "None",
  "SslCertThumbprint": "",
  "EnableUserIsolation": false,
  "RecreateSite": false
}
```

| Key | Meaning |
|---|---|
| `BindIp` | Exact IPv4 the FTP site listens on. Must be the address SmartZone and `ftp.exe` use. `*` listens on all IPv4 addresses. A specific IP **rejects** `127.0.0.1` and other NICs — you get Connected then Connection closed by remote host. |
| `PhysicalPath` | Drop folder. Use `C:/FTP/SmartZone`. |
| `FtpUser` | Login name. **This** is what you type at the FTP prompt. |
| `FtpGroup` | Authorization + NTFS group. **Not** a login. |
| `FtpPasswordPlain` | Leave empty. |
| `PasvLow` / `PasvHigh` | Passive data ports. |
| `ExternalIp` | IP advertised in PASV. Blank = `BindIp`. |
| `SslMode` | `None` for SZ plain FTP. |
| `EnableUserIsolation` | Files land under `PhysicalPath/LocalUser/<user>` when true. |
| `RecreateSite` | Delete and rebuild the IIS site. |

## Download / update scripts only

```powershell
$dir = Join-Path $env:USERPROFILE 'Desktop\FTPServer'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Set-Location $dir
$base = 'https://raw.githubusercontent.com/Hrubak/useful-scripts/main/windows/iis-ftp'
curl.exe -L "$base/Install-IisFtpFeatures.ps1" -o ".\Install-IisFtpFeatures.ps1"
curl.exe -L "$base/New-SmartZoneIisFtp.ps1" -o ".\New-SmartZoneIisFtp.ps1"
```

Do not redownload the JSON after you have edited it. Use `curl.exe` on one line.

## Run the site script

```powershell
Set-Location "$env:USERPROFILE\Desktop\FTPServer"
Set-ExecutionPolicy -Scope Process Bypass -Force
.\New-SmartZoneIisFtp.ps1 -DumpConfig
.\New-SmartZoneIisFtp.ps1
```

Rebuild: `.\New-SmartZoneIisFtp.ps1 -RecreateSite`

## Test

Use the **same IP as `BindIp`**. Login as `szbackup`, not `FTP-SZBackup`.

```text
ftp 10.1.20.56
User: szbackup
```

## SmartZone

Protocol FTP, Host = BindIp, Port 21, User `szbackup`, Remote Directory `/`.

## Failure modes

| Symptom | Cause |
|---|---|
| `Install-WindowsFeature not found` | Client Windows / wrong SKU. This installer is Server-only. |
| Feature install asks for reboot | Reboot, rerun `Install-IisFtpFeatures.ps1`, then the site script. |
| `ConvertFrom-Json : Unrecognized escape sequence` | Path used `C:\FTP\...`. Change to `C:/FTP/SmartZone`. |
| `ftp 127.0.0.1` → Connected, then connection closed | Site bound to a specific NIC IP. Use that IP. |
| `530` user name or password incorrect | Logged in as the **group**, wrong password, or user disabled. |
| `530` home directory inaccessible | Folder missing or NTFS. |
| `425` after login | PASV IP wrong or ports `50000-50050` blocked. |
| SZ Test fails, `ftp.exe` works | SZ host/user mismatch, or SZ pointed at SFTP/22. |
