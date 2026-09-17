# useful-scripts

Private collection of operational scripts used on standalone Windows servers, IIS, and related MSP work.

Each script lives in its own folder with a `README.md`.

## Layout

| Path | Purpose |
|---|---|
| [windows/iis-ftp](windows/iis-ftp/) | IIS FTP drop site for SmartZone / SonicWall config exports |

## Conventions

- Edit the `CONFIG` block (or pass parameters). Do not commit secrets.
- Scripts that change a server require an elevated session.
- Plain FTP / cleartext protocols stay on a management VLAN only.

## License

Internal use. No warranty.
