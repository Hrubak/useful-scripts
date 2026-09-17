# IIS FTP drop site (SmartZone / SonicWall)

`New-SmartZoneIisFtp.ps1` provisions a locked-down IIS FTP site on standalone Windows Server 2019+ for SmartZone configuration backup exports.

## Requirements

- Windows Server 2019+ (local accounts, not domain-joined required)
- Roles already installed: IIS + FTP Server (`Web-Ftp-Server`, `Web-Ftp-Service`, `Web-Mgmt-Console`)
- Elevated PowerShell 5.1+

## Safety

Plain FTP sends credentials and backup files in the clear. Bind to a management NIC. Do not publish port 21 to WAN. If the SmartZone build offers **SFTP**, use OpenSSH instead — IIS FTP is not SFTP.

`SslMode = Require` only works if SmartZone speaks explicit FTPS. The SZ External Services UI documents **FTP or SFTP**.

## Configure

Edit `New-SmartZoneIisFtp.settings.json` in the same folder as the script. Do not put passwords in the JSON if the file may be copied off-box.

Load order: built-in defaults → settings JSON → command-line parameters (last wins).

```powershell
.\New-SmartZoneIisFtp.ps1 -DumpConfig
.\New-SmartZoneIisFtp.ps1 -SettingsFile 'C:\FTP\sz.settings.json'
```

| Key | Meaning |
|---|---|
| `BindIp` | IP SmartZone reaches. Avoid `*` on multi-homed hosts. |
| `PhysicalPath` | Drop folder (created if missing). |
| `FtpUser` / `FtpGroup` | Local account and group. |
| `FtpPasswordPlain` | Leave empty; you are prompted. Do not commit a password. |
| `PasvLow` / `PasvHigh` | Passive data range. Open the same range on any firewall in front. |
| `ExternalIp` | IP advertised in PASV. Blank = `BindIp`. Use the NAT IP only if SZ is across PAT. |
| `SslMode` | `None` (SZ plain FTP), `Allow`, or `Require` (needs `SslCertThumbprint`). |
| `EnableUserIsolation` | `$true` stores files under `PhysicalPath\LocalUser\<user>`. |
| `RecreateSite` | `$true` deletes and rebuilds the IIS site. |

## Run

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\New-SmartZoneIisFtp.ps1
```
