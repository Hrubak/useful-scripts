# IIS FTP drop site (SmartZone / SonicWall)

`New-SmartZoneIisFtp.ps1` provisions a locked-down IIS FTP site on standalone Windows Server 2019+ for SmartZone configuration backup exports.

## Requirements

- Windows Server 2019+ (local accounts)
- Roles already installed: IIS + FTP Server (`Web-Ftp-Server`, `Web-Ftp-Service`, `Web-Mgmt-Console`)
- Elevated PowerShell 5.1+

## Safety

Plain FTP sends credentials and backup files in the clear. Bind to a management NIC. Do not publish port 21 to WAN. IIS FTP is **not** SFTP.

Do not put a real password in `FtpPasswordPlain` on a machine that is backed up or copied. Leave it empty and type the password at the prompt. Rotate if it ever leaked.

## Files

Keep these in the same folder:

| File | Role |
|---|---|
| `New-SmartZoneIisFtp.ps1` | Provisioner. Safe to redownload from GitHub. |
| `New-SmartZoneIisFtp.settings.json` | **Your** config. Do not overwrite when updating the script. |

Load order: script defaults → settings JSON → `-Parameter` (last wins).

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

## Download / update the script only

```powershell
$dir = Join-Path $env:USERPROFILE 'Desktop\FTPServer'
New-Item -ItemType Directory -Path $dir -Force | Out-Null
Set-Location $dir
curl.exe -L "https://raw.githubusercontent.com/Hrubak/useful-scripts/main/windows/iis-ftp/New-SmartZoneIisFtp.ps1" -o ".\New-SmartZoneIisFtp.ps1"
```

Do not redownload the JSON after you have edited it. Use `curl.exe` on one line.

## Run

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
| `ConvertFrom-Json : Unrecognized escape sequence` | Path used `C:\FTP\...`. Change to `C:/FTP/SmartZone`. |
| `ftp 127.0.0.1` → Connected, then connection closed | Site bound to a specific NIC IP. Use that IP. |
| `530` user name or password incorrect | Logged in as the **group**, wrong password, or user disabled. |
| `530` home directory inaccessible | Folder missing or NTFS. |
| `425` after login | PASV IP wrong or ports `50000-50050` blocked. |
| SZ Test fails, `ftp.exe` works | SZ host/user mismatch, or SZ pointed at SFTP/22. |
