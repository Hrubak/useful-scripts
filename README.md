# useful-scripts

Operational scripts for standalone Windows servers, IIS, Mitel/Shoreware, and related MSP work.

Each script lives in its own folder with a `README.md`.

## Layout

| Path | Purpose |
|---|---|
| [windows/iis-ftp](windows/iis-ftp/) | IIS FTP drop site for SmartZone / SonicWall config exports |
| [windows/shoreware-backup](windows/shoreware-backup/) | Shoreware MySQL dump, gzip, Graph upload to SharePoint |
| [windows/Collect-NPS-Diagnostics.ps1](windows/Collect-NPS-Diagnostics.ps1) | NPS config, cert, and event collection (2012 R2+, secrets redacted) |
| [windows/Get-NpsRadiusDiagnostics.ps1](windows/Get-NpsRadiusDiagnostics.ps1) | NPS RADIUS health and recent Wi-Fi auth failures (markdown/JSON report) |

## Conventions

- Config in a sibling `*.settings.json`. Do not commit secrets.
- Scripts that change a server require an elevated session.
- Always push changes to this repo as new commits on `main`.

## License

Internal use. No warranty.
