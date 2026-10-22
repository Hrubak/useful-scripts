# ConnectWise RMM (Asio): PHP / Node.js security check

Non-interactive, detection-only version of [`../Check-PhpNodeSecurity.ps1`](../Check-PhpNodeSecurity.ps1) for ConnectWise RMM. It runs as SYSTEM under Windows PowerShell 5.1 and needs no network, no winget and no prompts.

| File | Purpose |
|---|---|
| `Invoke-PhpNodeSecurityCheck.Asio.ps1` | Scans PATH, common install dirs, IIS FastCGI PHP, nvm/fnm/volta and per-user AppData for `php.exe` / `node.exe` |
| `Invoke-PhpNodeSecurityCheck.Asio.Tests.ps1` | Pester 5 tests with mocked discovery |
| `ASIO-SETUP.md` | Portal setup (monitor, task, custom field, groups, schedule) and pilot plan |

Thresholds: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (CVE-2026-109618, CVE-2026-109619); Node.js 26.12.1 / 24.22.1 / 22.23.4. EOL branches are always flagged.

Output and exit codes:
- `0`: `OK: no vulnerable PHP/Node found (checked N)`
- `1`: `VULNERABLE: <count> finding(s)` followed by one `Device=… Product=… Found=… Fixed=… Path=…` line per finding
- `2`: `ERROR: <message>`

`-Summary` prints a single line of at most 300 characters for a Text Box custom field.

Run the tests with `Invoke-Pester ./Invoke-PhpNodeSecurityCheck.Asio.Tests.ps1` (Pester 5).
