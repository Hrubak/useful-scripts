# Shoreware / Mitel MySQL backup to SharePoint

`Invoke-ShorewareBackup.ps1` dumps the Shoreware MySQL instances, gzip-compresses each dump, and uploads to a SharePoint document library with Graph (app-only).

## Files

| File | Role |
|---|---|
| `Invoke-ShorewareBackup.ps1` | Job. Safe to redownload. |
| `Invoke-ShorewareBackup.settings.json` | **Your** tenant, site, DB list. Do not commit secrets. |
| `CredFile` (Clixml) | DPAPI-protected MySQL password + Graph client secret. Created on first run. Never goes in Git. |

## One-time setup

1. Entra app with `Sites.Selected` or `Sites.ReadWrite.All` + admin consent. Grant the app write on the target site.
2. Copy the `.ps1` and `.settings.json` to the Shoreware server (example `C:\Scripts\ShorewareBackup`).
3. Edit JSON: `TenantId`, `ClientId`, `SiteName` / `GraphSitePath`, `LibraryName`, `FolderPath`, `BackupRoot`.
4. First run as the **same account** the scheduled task will use:

```powershell
Set-Location C:\Scripts\ShorewareBackup
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Invoke-ShorewareBackup.ps1 -DumpConfig
.\Invoke-ShorewareBackup.ps1
```

You will be prompted for MySQL password and Graph client secret. Stored via Export-Clixml.

```powershell
.\Invoke-ShorewareBackup.ps1 -ResetCredentials
```

Use `C:/ShorewareBackups` in JSON (forward slashes).

Uploads land in `FolderPath/ServerName/yyyy-MM-dd/`.

Default ports: Shoreware 4308, shorewarecdr 4309, shorewaremonitoring 4310, ShorewareWebBridge 4308.

Schedule: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\ShorewareBackup\Invoke-ShorewareBackup.ps1`

Switches: `-DumpConfig`, `-SkipBackup`, `-SkipUpload`, `-SettingsFile`, `-ResetCredentials`.

Do not put the MySQL password or client secret in the JSON or in Git.
