# Changelog

## 2026-10-21

### Added
- `windows/Collect-NPS-Diagnostics.ps1` — NPS diagnostic collector for Windows Server 2012 R2 and later.
  - Collects IAS service status, `netsh nps dump exportpsk=yes`, RADIUS clients, network and connection request policies, LocalMachine\My certificates, Security events 6272/6273/6274, and IAS text logs from the default and custom log paths.
  - Redacts shared secrets, passwords, and PSK-like values before writing output.
  - Writes a timestamped folder (and zip) to the Desktop.
  - Complements the existing `Get-NpsRadiusDiagnostics.ps1` with a file-based collection suitable for offline review.
