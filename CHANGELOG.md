# Changelog

## 2026-10-22

### Added
- `windows/Check-PhpNodeSecurity.ps1` — Checks PHP and Node.js versions against the Oct 21 2026 security releases (PHP2Shell: CVE-2026-109618 / CVE-2026-109619; Node.js October 2026 releases).
  - Scans PATH and common install locations (XAMPP, Laragon, Program Files, nvm-windows, etc.).
  - Not installed is reported as clean (advisory does not apply).
  - Optional interactive winget upgrade path when a vulnerable version is found.
  - Fixed thresholds: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; Node 22.23.4 / 24.22.1 / 26.12.1.

## 2026-10-21

### Added
- `windows/Collect-NPS-Diagnostics.ps1` — NPS diagnostic collector for Windows Server 2012 R2 and later.
  - Collects IAS service status, `netsh nps dump exportpsk=yes`, RADIUS clients, network and connection request policies, LocalMachine\My certificates, Security events 6272/6273/6274, and IAS text logs from the default and custom log paths.
  - Redacts shared secrets, passwords, and PSK-like values before writing output.
  - Writes a timestamped folder (and zip) to the Desktop.
  - Complements the existing `Get-NpsRadiusDiagnostics.ps1` with a file-based collection suitable for offline review.
