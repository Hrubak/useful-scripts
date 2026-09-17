# useful-scripts

Operational scripts for standalone Windows servers, IIS, Mitel/Shoreware, and related MSP work.

Each script lives in its own folder with a `README.md`.

## Layout

| Path | Purpose |
|---|---|
| [windows/iis-ftp](windows/iis-ftp/) | IIS FTP drop site for SmartZone / SonicWall config exports |
| [windows/shoreware-backup](windows/shoreware-backup/) | Shoreware MySQL dump, gzip, Graph upload to SharePoint |

## Conventions

- Config in a sibling `*.settings.json`. Do not commit secrets.
- Scripts that change a server require an elevated session.
- Always push changes to this repo as new commits on `main`.

## License

Internal use. No warranty.
