# ConnectWise RMM (Asio): PHP / Node.js vulnerability check (DRAFT)

Script: `Invoke-PhpNodeSecurityCheck.Asio.ps1`. It only detects: it makes no changes, needs no network and never prompts. It runs as SYSTEM under Windows PowerShell 5.1.

## Sources
Official ConnectWise RMM documentation (base https://docs.connectwise.com/):
- **[D1]** ConnectWise_RMM/Automation/Tasks/Creating_Tasks_Using_the_Script_Editor
- **[D2]** ConnectWise_RMM/Automation/Tasks/Create_and_Schedule_Script_Type_Tasks
- **[D3]** ConnectWise_RMM/Automation/Tasks/Run_Scripts_as_Current_Logged_In_User
- **[D4]** ConnectWise_RMM/Manage_Devices_with_ConnectWise_RMM/Custom_Fields
- **[D5]** ConnectWise_RMM/Alerts/Custom_Monitors/Script_Monitor
- **[D6]** ConnectWise_RMM/Alerts/Custom_Ticket_Template_for_Custom_Monitors
- **[D7]** .../Device_Groups/Device_Groups_Management
- **[D8]** .../Device_Groups/Device_Groups_Dynamic_Attributes

Community reference (conventions and examples only):
- **[P1]** ProVal monitor "CVE-2025-24084 - WSL Uninstall": https://content.provaltech.com/docs/b63666c3-5c0c-430b-b8c2-7e937c9109fe
- **[P2]** ProVal task "Detect SMB1": https://content.provaltech.com/docs/f5a58819-dcc7-4905-a3b5-52ff73751e21

Items still marked **(verify in pilot)** are ones the official docs don't cover.

## 1. Output contract

| Exit | Output (default mode) | Meaning |
|---|---|---|
| 0 | `OK: no vulnerable PHP/Node found (checked N)` | Clean. Not installed also counts as clean. |
| 1 | `VULNERABLE: <count> finding(s)` then `Device=<COMPUTERNAME> Product=<PHP\|Node.js> Found=<ver> Fixed=<ver> Path=<path>` per finding | Vulnerable |
| 2 | `ERROR: <message>` | Script failure |

`-Summary` mode prints one line of at most 300 characters, for a custom field: `OK (checked N)` / `VULNERABLE 2: PHP 8.3.30; Node.js 22.23.3` / `ERROR: <message>`. Exit codes are the same. A Script Editor step can't pass switches, so in the task copy change `$SummaryDefault = $false` to `$true` near the top of the script.

**Matching on output text is the primary signal.** The docs don't say whether a non-zero exit code makes a step or monitor count as "Failure", so exit-code handling is **(verify in pilot)**. Tokens to match: `VULNERABLE` (alert), `OK` (resolve; use `OK: no vulnerable` in the monitor), `ERROR:` (script health).

Thresholds: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (CVE-2026-109618, CVE-2026-109619). Node.js 26.12.1 / 24.22.1 / 22.23.4 (Oct 21 2026 release). EOL branches (PHP ≤ 8.1, Node ≤ 20) are always flagged. Unreadable versions are reported as `Found=unknown Fixed=review-manually`.

## 2. Device groups [D7][D8]
**Endpoints > Groups > Add**:
- **Pilot:** **Static Group** (pick devices). Name `PHP/Node Check - Pilot`, containing one internal server.
- **Servers:** **Dynamic Group** `Windows Servers - PHP/Node Check`: `OS Type` = `Windows` AND `Endpoint Type` = `server` (lowercase) [D8]. `OS Installation Type` = `Server` is an alternative attribute [D8].
- **Workstations (later):** Dynamic Group with `Endpoint Type` = `desktop` [D8].

## 3. Primary: Script monitor (daily, ticket, auto-resolve) [D5]
1. **Endpoints > Alerts > Monitors > Create Monitor**.
2. **Name:** `SEC - PHP/Node.js Oct-2026 Vulnerability`. **Description:** `Flags PHP < 8.5.12/8.4.27/8.3.36/8.2.35 and Node.js < 26.12.1/24.22.1/22.23.4 or EOL branches.` **Type:** `Script`. **Family:** a relevant family. **Severity:** a critical-level severity. (ProVal uses `Critical Impact Alerts` [P1]; check the available options in your tenant **(verify in pilot)**.)
3. **Conditions:** **Run script on** `Schedule`, **Repeat every** `1`, **Unit** `Days`. **Script Language** `PowerShell`. **Script**: paste the full default-mode script (leave `$SummaryDefault = $false`) [D5].
4. **Script Output** `Contains` `VULNERABLE`. Use AND/OR only if you add more criteria [D5].
5. Tick **Escalate ticket on script failure** so `ERROR:` runs and failed executions also raise tickets [D5]. Whether exit codes 1/2 alone count as "failure" is **(verify in pilot)**.
6. **Resources:** the Static pilot group first, then the Dynamic servers group [D5][D7].
7. **Ticket Resolution > Automatically resolve > Run same script as above**, Script Output `Contains` `OK: no vulnerable` [D5].
8. **Monitor Output: Generate Ticket** (recommended; auto-resolve works). Alternatives: Generate Ticket with Delay (5–60 min) or Do Not Generate Ticket [D5].
9. **Ticket content.** The default ticket body has a fixed format the docs don't describe **(verify in pilot)**. The variables available are ObservedDate, MonitorDesc, MonitorName, MonitorSummary, ScriptLanguage, **ScriptOutput** and Status [D6]. ScriptOutput carries the whole report, so each finding line already includes device, product, found and fixed versions. Output is kept short: one header line plus one line per finding.
10. Monitors alert only when the value **changes** and meets the criteria [D6]. A device that stays vulnerable won't re-alert daily; the ticket simply stays open until resolved.

**Optional custom ticket template [D6]:** build a Script Editor task with a **Create Ticket** step using `@MonitorName@`-style variables (e.g. summary `PHP/Node.js vulnerable: @MonitorName@`, body including the ScriptOutput variable). Attach it as the monitor's automation and set **Monitor Output: Do Not Generate Ticket**. The tradeoff is that **these tickets are not auto-closed**, so techs must close them by hand. Recommendation: keep the default **Generate Ticket**.

## 4. Secondary: Task and custom field (on demand, reporting)
1. **Custom field [D4]: Settings > Custom Fields > Add Field +**.
   - Name `PhpNodeVulnStatus` (32 characters or fewer; letters, numbers, underscores only). Level **Endpoint**. Type **Text Box**, which holds at most **300 characters**.
   - The full multi-line report won't fit, so the task stores the `-Summary` line instead. For a pure status field, use a **Dropdown** (`OK`/`VULNERABLE`/`ERROR`) or **Flag** type and set literal values from the If/Then branches.
2. **Task [D1]: Automation > Tasks > Add > Script Editor**. Name `SEC - PHP/Node.js Oct-2026 Check`; Category is optional (defaults to custom). Build it with **Add Row** / **Add Logic**:
   - **Row 1, PowerShell Script:** paste the script with `$SummaryDefault = $true`. **Run as: System** (set it explicitly; the other option is Current Logged In User [D3]). Timeout: set **300 s** explicitly. Per the docs, a step's timeout is its value + 5 min, an undefined step gets 20 min, and the task's global timeout is the sum of its steps + 15 min [D1].
   - **Row 2, Script Log:** `Output:%output%` [D1][P2]. `%output%` and `%status%` are system variables [D1].
   - **Row 3, If/Then (Output Contains `VULNERABLE`)** → **Set Custom Field** `PhpNodeVulnStatus` = `%output%`. Else-if **Output Contains `ERROR:`** → `%output%`. Else → `OK` [D1]. The docs don't say a custom-field value can be `%output%` **(verify in pilot)**. Fallback: set literal values (`VULNERABLE` / `ERROR` / `OK`), or switch the field to a Dropdown.
   - Simpler option (no custom field): **Automation > Tasks > Add > Powershell Script** (single-script task). Expected execution time defaults to **300 s**; run as System [D2][D3].
3. **Schedule [D2]:** Automation > Tasks > select the task > **Schedule**.
   - Recurrence **Daily** (e.g. 02:00), target the pilot group and later the servers group.
   - Tick **Execute at next agent check-in**. Offline devices then run when they reconnect within the expiration window; otherwise the run fails. Catch-up behaviour beyond that is undocumented.
   - Check statuses under **Automation > Scheduled Tasks**.
4. **On demand:** run the task against a device or group after patching, and read the Script Log output [D1].
5. Don't also build a monitor on the custom field while §3 is active, or you'll get duplicate tickets.

## 5. Alert rule
Ticket when the output contains `VULNERABLE`, or on script failure / `ERROR:` (escalate on script failure). Auto-resolve on `OK: no vulnerable`. Exit codes 0/1/2 are kept for future use; their effect on RMM status is **(verify in pilot)**.

## 6. Pilot plan
1. **One internal server** (Static pilot group).
   - Run the task on demand. Confirm the Script Log output, a runtime well under 300 s, and that the custom field receives the summary line (this answers the `%output%` question).
   - Attach the monitor. Confirm exactly one ticket, and record what the default ticket body shows.
   - Also record whether exit code 1 or 2 shows as Failure.
   - Negative test: place an old portable `node.exe` (e.g. 22.23.3) in `C:\Program Files\nodejs\`. Confirm the ticket opens, remove the file, and confirm it auto-resolves on the next run.
2. **All internal servers** for 2–3 daily cycles. Watch for `Found=unknown` and duplicate tickets.
3. **Client servers: only after Jonathan's explicit go-ahead**, per client/site, servers first.
4. Workstations (`Endpoint Type` = `desktop`) as an optional later phase.

## 7. Remediation notes (manual)
- PHP: install the matching branch build from windows.php.net, then restart IIS/Apache/PHP-FPM. Upgrade branches 8.1 and older.
- Node.js: install 22.23.4 / 24.22.1 / 26.12.1 or newer. Update every listed nvm version.
- `-AllowWingetUpgrade` exists but stays off, because winget is often unavailable as SYSTEM.
