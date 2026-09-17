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

Edit the `CONFIG` hashtable at the top of the script, or override on the command line.

| Key | Meaning |
|---|---|
| `BindIp` | IP SmartZone reaches. Avoid `*` on multi-homed hosts. |
| `PhysicalPath` | Drop folder (created if missing). |
| `FtpUser` / `FtpGroup` | Local account and group. |
| `FtpPasswordPlain` | Leave empty; you are prompted. Do not commit a password. |
| `PasvLow` / `PasvHigh` | Passive data range. Open the same range on any firewall in front. |
| `ExternalIp` | IP advertised in PASV. Blank = `BindIp`. Use the NAT IP only if SZ is across PAT. |
| `SslMode` | `None` (SZ plain FTP), `Allow`, or `Require` (needs `SslCertThumbprint`). |
| `EnableUserIsolation` | `$true` stores files under `PhysicalPath\\LocalUser\\<user>`. |
| `RecreateSite` | `$true` deletes and rebuilds the IIS site. |

## Run

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\New-SmartZoneIisFtp.ps1
```

```powershell
.\New-SmartZoneIisFtp.ps1 -BindIp '10.20.30.40' -PhysicalPath 'E:\\Backups\\SZ' -FtpUser 'szbackup'
```

```powershell
.\New-SmartZoneIisFtp.ps1 -RecreateSite
```

Re-runs are idempotent for group, folder, site settings, and firewall rules. An existing local user is **not** password-rotated.

```powershell
Set-LocalUser -Name szbackup -Password (Read-Host -AsSecureString)
```

## What it creates

1. Local group + user (`PasswordNeverExpires`, user cannot change password)
2. Drop folder with NTFS: SYSTEM + Administrators Full, group Modify, inheritance broken
3. IIS FTP site: Basic auth on, anonymous off, group Read+Write
4. Server-wide PASV port range + advertised external IP
5. Firewall rules `FTP-SZ-Control` and `FTP-SZ-Passive`
6. Restarts `FTPSVC` and the site

## SmartZone

**Administration → External Services → FTP → Create**

| Field | Value |
|---|---|
| Protocol | FTP |
| Host | `BindIp` / `ExternalIp` |
| Port | 21 |
| User | `szbackup` (or whatever you set) |
| Remote Directory | `/` (must start with `/`) |

Then enable Auto Export under Backup and Restore → Configuration. Click **Test** first.

## Failure modes

| Symptom | Likely cause |
|---|---|
| SZ Test fails / `425` | PASV advertised IP wrong, `50000-50050` blocked, or FTP ALG rewriting control channel |
| Auth rejected | Wrong password; user disabled; authorization not applied to the site |
| Upload works, file missing | User isolation on — look under `PhysicalPath\\LocalUser\\<user>` |
| SSL handshake fail | `SslMode = Require` but SZ is speaking plain FTP |

Restrict source IPs to the SmartZone management address at the host or upstream firewall.
