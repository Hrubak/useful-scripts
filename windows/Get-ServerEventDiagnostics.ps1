<#
.SYNOPSIS
    Collect reboot and Windows Update events from domain servers and emit a Grok handoff.

.DESCRIPTION
    Windows PowerShell 5.1 only. WinForms when the session is interactive and -NoUI is
    not set. Otherwise a console menu.

    Default target list is domain controllers (Get-ADDomainController, or nltest /dclist
    if the ActiveDirectory module is missing). Member servers are an explicit second
    choice: enabled OperatingSystem like *Server*, minus DCs. A manual list or a
    one-host-per-line file overrides both.

    Current token first. On the first access denied, one credential prompt, then reuse.
    WinRM Invoke-Command first (filter runs on the target). RPC Get-WinEvent fallback.
    Local targets run in-process.

    Collectors: System 1074, 6006, 6008, 6005, 41 and
    Microsoft-Windows-WindowsUpdateClient/Operational 19, 20, 43, 44.
    Missing log is reported as missing. Markdown is capped at 25 events per module per
    host. JSON keeps the full set. Pair section lists update 19/20/43 followed within
    30 minutes by reboot 1074/6008/41. No verdicts.

    Writes report-<yyyyMMdd-HHmmss>.md and .json to the desktop of the account that
    ran the script, and copies the markdown to the clipboard.

.PARAMETER NoUI
    Skip WinForms and use the console menu.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-ServerEventDiagnostics.ps1

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-ServerEventDiagnostics.ps1 -NoUI
#>
[CmdletBinding()]
param(
    [switch]$NoUI
)

Set-StrictMode -Version 2.0
# WinForms click handlers run outside script scope. Entry points are global:
# so the Run button can resolve them. State is $global: for the same reason.
$ErrorActionPreference = 'Stop'

$global:MarkdownCap = 25
$global:PairWindowMinutes = 30
$global:DefaultDays = 7
$global:AltCred = $null
$global:CredPrompted = $false
$global:CredCancelled = $false

$global:RebootIds = @(1074, 6006, 6008, 6005, 41)
$global:UpdateIds = @(19, 20, 43, 44)
$global:PairUpdateIds = @(19, 20, 43)
$global:PairRebootIds = @(1074, 6008, 41)
$global:UpdateLog = 'Microsoft-Windows-WindowsUpdateClient/Operational'

$global:IdLabel = @{
    1074 = 'Shutdown initiated'
    6006 = 'Event Log service stopped'
    6008 = 'Unexpected shutdown'
    6005 = 'Event Log service started'
    41   = 'Kernel-Power unexpected reboot'
    19   = 'Update install success'
    20   = 'Update install failure'
    43   = 'Update install started'
    44   = 'Update download started'
}

function Test-UiAvailable {
    if ($NoUI) { return $false }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        return $false
    }
    $sta = [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
    return ([Environment]::UserInteractive -and $sta)
}

function global:Get-IdLabel {
    param([int]$Id)
    if ($global:IdLabel.ContainsKey($Id)) { return $global:IdLabel[$Id] }
    return "Event $Id"
}

function global:Test-AccessDeniedMessage {
    param([string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return $Message -match 'Access is denied|0x80070005|Access denied|UnauthorizedAccess|authentication|credentials|Logon failure|user name or password is incorrect'
}

function global:Get-DesktopPath {
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) {
        $desktop = Join-Path $env:USERPROFILE 'Desktop'
    }
    if (-not (Test-Path -LiteralPath $desktop)) {
        New-Item -ItemType Directory -Path $desktop -Force | Out-Null
    }
    return $desktop
}

function global:Get-DomainName {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain -and $cs.Domain) { return [string]$cs.Domain }
    } catch { }
    return $null
}

function global:Get-DcListFromNltest {
    param([string]$Domain)
    $lines = & nltest.exe /dclist:$Domain 2>&1 | ForEach-Object { "$_" }
    $hosts = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ($line -match '^\s+([A-Za-z0-9][A-Za-z0-9.-]+)\s+') {
            $name = $Matches[1]
            if ($name -notmatch '^(Get|The|Site)$') {
                $hosts.Add($name)
            }
        }
    }
    return @($hosts | Select-Object -Unique)
}

function global:Get-DomainControllerTargets {
    $notes = New-Object System.Collections.Generic.List[string]
    $ad = Get-Module -ListAvailable -Name ActiveDirectory
    if ($ad) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $dcs = @(Get-ADDomainController -Filter * | ForEach-Object {
            if ($_.HostName) { $_.HostName } else { $_.Name }
        })
        $notes.Add("DC source: Get-ADDomainController ($($dcs.Count))")
        return [pscustomobject]@{ Hosts = @($dcs | Where-Object { $_ } | Select-Object -Unique); Notes = @($notes) }
    }
    $notes.Add('ActiveDirectory module missing. DC list fell back to nltest /dclist.')
    $domain = Get-DomainName
    if (-not $domain) {
        $notes.Add('This computer is not domain-joined. DC list is empty. Use manual entry or a target file.')
        return [pscustomobject]@{ Hosts = @(); Notes = @($notes) }
    }
    $dcs = @(Get-DcListFromNltest -Domain $domain)
    $notes.Add("DC source: nltest /dclist:$domain ($($dcs.Count))")
    return [pscustomobject]@{ Hosts = $dcs; Notes = @($notes) }
}

function global:Get-MemberServerTargets {
    $notes = New-Object System.Collections.Generic.List[string]
    $ad = Get-Module -ListAvailable -Name ActiveDirectory
    if (-not $ad) {
        $notes.Add('Member-server query requires the ActiveDirectory module. It is not installed. List is empty.')
        return [pscustomobject]@{ Hosts = @(); Notes = @($notes) }
    }
    Import-Module ActiveDirectory -ErrorAction Stop
    $dcNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($dc in @(Get-ADDomainController -Filter *)) {
        foreach ($n in @($dc.HostName, $dc.Name)) {
            if ($n) {
                [void]$dcNames.Add([string]$n)
                [void]$dcNames.Add(([string]$n).Split('.')[0])
            }
        }
    }
    $servers = @(Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like '*Server*' } -Properties OperatingSystem, DNSHostName)
    $hosts = New-Object System.Collections.Generic.List[string]
    foreach ($s in $servers) {
        $fqdn = $s.DNSHostName
        if (-not $fqdn) { $fqdn = $s.Name }
        $short = ([string]$fqdn).Split('.')[0]
        if ($dcNames.Contains([string]$fqdn) -or $dcNames.Contains($short)) { continue }
        $hosts.Add([string]$fqdn)
    }
    $notes.Add("Member servers: enabled OperatingSystem like *Server*, DCs excluded ($($hosts.Count))")
    return [pscustomobject]@{ Hosts = @($hosts | Select-Object -Unique); Notes = @($notes) }
}

function global:Read-TargetFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Target file not found: $Path"
    }
    $hosts = New-Object System.Collections.Generic.List[string]
    foreach ($line in [IO.File]::ReadAllLines($Path)) {
        $t = $line.Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $hosts.Add($t)
    }
    return @($hosts | Select-Object -Unique)
}

function global:Parse-ManualHosts {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $parts = $Text -split '[,\s;]+' | Where-Object { $_ }
    return @($parts | Select-Object -Unique)
}

function global:Resolve-Targets {
    param(
        [ValidateSet('DomainControllers', 'MemberServers', 'Manual', 'File')]
        [string]$Mode,
        [string]$ManualText,
        [string]$FilePath
    )
    switch ($Mode) {
        'DomainControllers' { return Get-DomainControllerTargets }
        'MemberServers'     { return Get-MemberServerTargets }
        'Manual' {
            $hosts = @(Parse-ManualHosts -Text $ManualText)
            return [pscustomobject]@{
                Hosts = $hosts
                Notes = @("Manual override ($($hosts.Count))")
            }
        }
        'File' {
            $hosts = @(Read-TargetFile -Path $FilePath)
            return [pscustomobject]@{
                Hosts = $hosts
                Notes = @("File override: $FilePath ($($hosts.Count))")
            }
        }
    }
}

function global:Test-LocalHostName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $n = $Name.Trim().TrimEnd('.')
    if ($n -eq '.' -or $n -eq 'localhost' -or $n -eq '127.0.0.1') { return $true }
    if ($n -eq $env:COMPUTERNAME) { return $true }
    if ($n -eq "$env:COMPUTERNAME.$env:USERDNSDOMAIN") { return $true }
    try {
        $me = [Net.Dns]::GetHostEntry($env:COMPUTERNAME)
        foreach ($a in @($me.HostName) + @($me.Aliases)) {
            if ($a -and ($n -eq $a)) { return $true }
        }
    } catch { }
    return $false
}

function global:New-CollectorScript {
    # Self-contained. Do not close over caller functions. PS 5.1 Invoke-Command safe.
    return {
        param($StartTime, $RebootIds, $UpdateIds, $UpdateLog)
        function Convert-OneEvent {
            param($Event)
            $msg = ''
            if ($Event.Message) { $msg = [string]$Event.Message }
            $utc = $Event.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            [pscustomobject]@{
                TimeCreated  = $utc
                Id           = [int]$Event.Id
                ProviderName = [string]$Event.ProviderName
                Level        = [string]$Event.LevelDisplayName
                RecordId     = $Event.RecordId
                Message      = $msg
            }
        }
        function Read-Log {
            param($LogName, $Ids)
            $bucket = [ordered]@{
                LogName    = $LogName
                LogPresent = $true
                Error      = $null
                Events     = @()
            }
            try {
                $found = @(Get-WinEvent -FilterHashtable @{
                    LogName   = $LogName
                    Id        = $Ids
                    StartTime = $StartTime
                } -ErrorAction Stop)
                $bucket.Events = @($found | ForEach-Object { Convert-OneEvent $_ })
            } catch {
                $m = $_.Exception.Message
                if ($m -match 'No events were found') {
                    $bucket.Events = @()
                } elseif ($m -match 'channel could not be found|does not exist|not found') {
                    $bucket.LogPresent = $false
                    $bucket.Error = $m
                } else {
                    $bucket.Error = $m
                }
            }
            return $bucket
        }
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            Reboot       = (Read-Log -LogName 'System' -Ids $RebootIds)
            Update       = (Read-Log -LogName $UpdateLog -Ids $UpdateIds)
        }
    }
}

function global:Connect-Ipc {
    param([string]$ComputerName, [pscredential]$Credential)
    if (-not ('NetUseNative' -as [type])) {
        $src = @'
using System;
using System.Runtime.InteropServices;
public class NetUseNative {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NETRESOURCE {
        public int dwScope;
        public int dwType;
        public int dwDisplayType;
        public int dwUsage;
        public string lpLocalName;
        public string lpRemoteName;
        public string lpComment;
        public string lpProvider;
    }
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    public static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);
    [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
    public static extern int WNetCancelConnection2(string name, int flags, bool force);
}
'@
        Add-Type -TypeDefinition $src -ErrorAction Stop
    }
    $remote = "\\$ComputerName\IPC$"
    $nr = New-Object NetUseNative+NETRESOURCE
    $nr.dwType = 0
    $nr.lpRemoteName = $remote
    $user = $Credential.UserName
    $pass = $Credential.GetNetworkCredential().Password
    $code = [NetUseNative]::WNetAddConnection2([ref]$nr, $pass, $user, 4)
    if ($code -ne 0 -and $code -ne 1219) {
        throw "IPC$ connect to $ComputerName failed with Win32 $code"
    }
    return $remote
}

function global:Disconnect-Ipc {
    param([string]$Remote)
    if (-not $Remote) { return }
    try { [void][NetUseNative]::WNetCancelConnection2($Remote, 0, $true) } catch { }
}

function global:Invoke-CredentialPrompt {
    if ($global:CredPrompted) { return }
    $global:CredPrompted = $true
    Write-Host 'Access denied. Prompting once. This credential is reused for the remaining hosts.'
    $cred = Get-Credential -Message 'Access denied on a target. Credential is reused for the rest of this run.'
    if (-not $cred) {
        $global:CredCancelled = $true
        return
    }
    $global:AltCred = $cred
}

function global:Read-HostEventsRpc {
    param(
        [string]$ComputerName,
        [datetime]$StartTime,
        [pscredential]$Credential
    )
    $ipc = $null
    try {
        if ($Credential) {
            $ipc = Connect-Ipc -ComputerName $ComputerName -Credential $Credential
        }
        function Read-RemoteLog {
            param($LogName, $Ids)
            $bucket = [ordered]@{
                LogName    = $LogName
                LogPresent = $true
                Error      = $null
                Events     = @()
            }
            try {
                $found = @(Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
                    LogName   = $LogName
                    Id        = $Ids
                    StartTime = $StartTime
                } -ErrorAction Stop)
                $bucket.Events = @(foreach ($e in $found) {
                    $msg = ''
                    if ($e.Message) { $msg = [string]$e.Message }
                    [pscustomobject]@{
                        TimeCreated  = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                        Id           = [int]$e.Id
                        ProviderName = [string]$e.ProviderName
                        Level        = [string]$e.LevelDisplayName
                        RecordId     = $e.RecordId
                        Message      = $msg
                    }
                })
            } catch {
                $m = $_.Exception.Message
                if ($m -match 'No events were found') {
                    $bucket.Events = @()
                } elseif ($m -match 'channel could not be found|does not exist|not found') {
                    $bucket.LogPresent = $false
                    $bucket.Error = $m
                } else {
                    $bucket.Error = $m
                }
            }
            return $bucket
        }
        return [pscustomobject]@{
            ComputerName = $ComputerName
            Reboot       = (Read-RemoteLog -LogName 'System' -Ids $global:RebootIds)
            Update       = (Read-RemoteLog -LogName $global:UpdateLog -Ids $global:UpdateIds)
        }
    } finally {
        Disconnect-Ipc -Remote $ipc
    }
}

function global:Get-HostDiagnostics {
    param(
        [string]$ComputerName,
        [datetime]$StartTime
    )
    $row = [ordered]@{
        ComputerName = $ComputerName
        Transport    = $null
        Error        = $null
        Reboot       = $null
        Update       = $null
        Pairs        = @()
    }
    $collector = New-CollectorScript
    if (Test-LocalHostName -Name $ComputerName) {
        try {
            $bundle = & $collector $StartTime $global:RebootIds $global:UpdateIds $global:UpdateLog
            $row.Transport = 'Local'
            $row.Reboot = $bundle.Reboot
            $row.Update = $bundle.Update
            return [pscustomobject]$row
        } catch {
            $row.Error = $_.Exception.Message
            $row.Transport = 'Local'
            return [pscustomobject]$row
        }
    }

    $winrmError = $null
    try {
        $params = @{
            ComputerName = $ComputerName
            ScriptBlock  = $collector
            ArgumentList = @($StartTime, $global:RebootIds, $global:UpdateIds, $global:UpdateLog)
            ErrorAction  = 'Stop'
        }
        if ($global:AltCred) { $params.Credential = $global:AltCred }
        $bundle = Invoke-Command @params
        $row.Transport = 'WinRM'
        $row.Reboot = $bundle.Reboot
        $row.Update = $bundle.Update
        if ($bundle.PSComputerName) { $row.ComputerName = $bundle.PSComputerName }
        return [pscustomobject]$row
    } catch {
        $winrmError = $_.Exception.Message
        if ((Test-AccessDeniedMessage -Message $winrmError) -and -not $global:CredPrompted) {
            Invoke-CredentialPrompt
            if ($global:AltCred) {
                try {
                    $bundle = Invoke-Command -ComputerName $ComputerName -Credential $global:AltCred -ScriptBlock $collector -ArgumentList @($StartTime, $global:RebootIds, $global:UpdateIds, $global:UpdateLog) -ErrorAction Stop
                    $row.Transport = 'WinRM'
                    $row.Reboot = $bundle.Reboot
                    $row.Update = $bundle.Update
                    if ($bundle.PSComputerName) { $row.ComputerName = $bundle.PSComputerName }
                    return [pscustomobject]$row
                } catch {
                    $winrmError = $_.Exception.Message
                }
            }
        }
    }

    try {
        $bundle = Read-HostEventsRpc -ComputerName $ComputerName -StartTime $StartTime -Credential $global:AltCred
        $row.Transport = 'RPC'
        $row.Reboot = $bundle.Reboot
        $row.Update = $bundle.Update
        if ($winrmError) {
            $row.Error = "WinRM failed ($winrmError). RPC answered."
        }
        return [pscustomobject]$row
    } catch {
        $rpcError = $_.Exception.Message
        if ((Test-AccessDeniedMessage -Message $rpcError) -and -not $global:CredPrompted) {
            Invoke-CredentialPrompt
            if ($global:AltCred) {
                try {
                    $bundle = Read-HostEventsRpc -ComputerName $ComputerName -StartTime $StartTime -Credential $global:AltCred
                    $row.Transport = 'RPC'
                    $row.Reboot = $bundle.Reboot
                    $row.Update = $bundle.Update
                    $row.Error = "WinRM failed ($winrmError). RPC answered after credential prompt."
                    return [pscustomobject]$row
                } catch {
                    $rpcError = $_.Exception.Message
                }
            }
        }
        $row.Transport = 'Failed'
        $row.Error = "WinRM: $winrmError | RPC: $rpcError"
        return [pscustomobject]$row
    }
}

function global:Get-UpdateRebootPairs {
    param($RebootEvents, $UpdateEvents)
    $pairs = New-Object System.Collections.Generic.List[object]
    $reboots = @($RebootEvents | Where-Object { $_.Id -in $global:PairRebootIds })
    $updates = @($UpdateEvents | Where-Object { $_.Id -in $global:PairUpdateIds })
    foreach ($u in $updates) {
        $uTime = [datetime]::Parse($u.TimeCreated).ToUniversalTime()
        foreach ($r in $reboots) {
            $rTime = [datetime]::Parse($r.TimeCreated).ToUniversalTime()
            $delta = ($rTime - $uTime).TotalMinutes
            if ($delta -ge 0 -and $delta -le $global:PairWindowMinutes) {
                $pairs.Add([pscustomobject]@{
                    UpdateId       = [int]$u.Id
                    UpdateTimeUtc  = $u.TimeCreated
                    UpdateMessage  = $u.Message
                    RebootId       = [int]$r.Id
                    RebootTimeUtc  = $r.TimeCreated
                    DeltaMinutes   = [math]::Round($delta, 1)
                    RebootMessage  = $r.Message
                })
            }
        }
    }
    return @($pairs | Sort-Object UpdateTimeUtc, DeltaMinutes)
}

function global:Trim-Message {
    param([string]$Message, [int]$Max = 400)
    if (-not $Message) { return '' }
    $one = ($Message -replace '\s+', ' ').Trim()
    if ($one.Length -le $Max) { return $one }
    return $one.Substring(0, $Max) + '...'
}

function global:Format-EventLines {
    param($Events, [int]$Cap)
    $all = @($Events | Sort-Object TimeCreated -Descending)
    $shown = @($all | Select-Object -First $Cap)
    $lines = New-Object System.Collections.Generic.List[string]
    if ($all.Count -eq 0) {
        $lines.Add('_No matching events in the window._')
        return $lines
    }
    $lines.Add("Showing $($shown.Count) of $($all.Count). Newest first. JSON has the full set.")
    foreach ($e in $shown) {
        $label = Get-IdLabel -Id ([int]$e.Id)
        $lines.Add("- $($e.TimeCreated)  Id $($e.Id) ($label)  $($e.ProviderName)")
        $lines.Add("  $(Trim-Message -Message $e.Message)")
    }
    return $lines
}

function global:Build-Markdown {
    param($Report)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Server event diagnostics')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Paste this report to Grok for diagnosis. This markdown is capped at 25 events per module per host. The JSON sidecar has the full set. Pair rows are facts, not verdicts.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("- GeneratedUtc: $($Report.GeneratedUtc)")
    [void]$sb.AppendLine("- WindowStartUtc: $($Report.WindowStartUtc)")
    [void]$sb.AppendLine("- WindowDays: $($Report.WindowDays)")
    [void]$sb.AppendLine("- PairWindowMinutes: $($Report.PairWindowMinutes)")
    [void]$sb.AppendLine("- TargetMode: $($Report.TargetMode)")
    [void]$sb.AppendLine("- JsonPath: $($Report.JsonPath)")
    foreach ($n in @($Report.Notes)) { [void]$sb.AppendLine("- Note: $n") }
    [void]$sb.AppendLine('')
    foreach ($h in @($Report.Hosts)) {
        [void]$sb.AppendLine("## $($h.ComputerName)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("- Transport: $($h.Transport)")
        if ($h.Error) { [void]$sb.AppendLine("- TransportNote: $($h.Error)") }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('### Reboot / unexpected shutdown')
        [void]$sb.AppendLine('')
        if (-not $h.Reboot) {
            [void]$sb.AppendLine('_Not collected._')
        } else {
            [void]$sb.AppendLine("- Log: $($h.Reboot.LogName)")
            [void]$sb.AppendLine("- LogPresent: $($h.Reboot.LogPresent)")
            if ($h.Reboot.Error) { [void]$sb.AppendLine("- Error: $($h.Reboot.Error)") }
            foreach ($line in (Format-EventLines -Events $h.Reboot.Events -Cap $global:MarkdownCap)) {
                [void]$sb.AppendLine($line)
            }
        }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('### Windows Update')
        [void]$sb.AppendLine('')
        if (-not $h.Update) {
            [void]$sb.AppendLine('_Not collected._')
        } else {
            [void]$sb.AppendLine("- Log: $($h.Update.LogName)")
            [void]$sb.AppendLine("- LogPresent: $($h.Update.LogPresent)")
            if ($h.Update.Error) { [void]$sb.AppendLine("- Error: $($h.Update.Error)") }
            foreach ($line in (Format-EventLines -Events $h.Update.Events -Cap $global:MarkdownCap)) {
                [void]$sb.AppendLine($line)
            }
        }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('### Update followed by reboot within 30 minutes')
        [void]$sb.AppendLine('')
        $pairs = @($h.Pairs)
        if ($pairs.Count -eq 0) {
            [void]$sb.AppendLine('_No update 19/20/43 followed within 30 minutes by 1074/6008/41._')
        } else {
            foreach ($p in $pairs) {
                [void]$sb.AppendLine("- Update $($p.UpdateId) at $($p.UpdateTimeUtc) -> reboot $($p.RebootId) at $($p.RebootTimeUtc) ($($p.DeltaMinutes) min)")
                [void]$sb.AppendLine("  Update: $(Trim-Message -Message $p.UpdateMessage)")
                [void]$sb.AppendLine("  Reboot: $(Trim-Message -Message $p.RebootMessage)")
            }
        }
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('## Ask Grok')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Diagnose reboots and Windows Update on these hosts. Treat the pair list as timestamp facts, not a root cause. Call out unexpected shutdowns (6008, 41) that have no pair, and install failures (20) that have no following reboot.')
    return $sb.ToString()
}

function global:Export-DiagnosticsReport {
    param($Report)
    $desktop = Get-DesktopPath
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $mdPath = Join-Path $desktop "report-$stamp.md"
    $jsonPath = Join-Path $desktop "report-$stamp.json"
    $Report.JsonPath = $jsonPath
    $Report.MarkdownPath = $mdPath
    $md = Build-Markdown -Report $Report
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllText($mdPath, $md, $utf8)
    $json = $Report | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($jsonPath, $json, $utf8)
    $clip = 'copied'
    try {
        Set-Clipboard -Value $md
    } catch {
        $clip = "clipboard unavailable: $($_.Exception.Message)"
    }
    return [pscustomobject]@{
        MarkdownPath = $mdPath
        JsonPath     = $jsonPath
        Clipboard    = $clip
        Markdown     = $md
    }
}

function global:Invoke-DiagnosticsRun {
    param(
        [string]$Mode,
        [string]$ManualText,
        [string]$FilePath,
        [int]$Days
    )
    if ($Days -lt 1) { $Days = 1 }
    if ($Days -gt 90) { $Days = 90 }
    $resolved = Resolve-Targets -Mode $Mode -ManualText $ManualText -FilePath $FilePath
    $start = (Get-Date).AddDays(-1 * $Days)
    $hosts = @($resolved.Hosts)
    $rows = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($h in $hosts) {
        $i++
        Write-Host "[$i/$($hosts.Count)] $h"
        $row = Get-HostDiagnostics -ComputerName $h -StartTime $start
        if ($row.Reboot -and $row.Update) {
            $row.Pairs = @(Get-UpdateRebootPairs -RebootEvents $row.Reboot.Events -UpdateEvents $row.Update.Events)
        }
        $rows.Add($row)
    }
    $report = [pscustomobject]@{
        GeneratedUtc      = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        WindowStartUtc    = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        WindowDays        = $Days
        PairWindowMinutes = $global:PairWindowMinutes
        MarkdownCap       = $global:MarkdownCap
        TargetMode        = $Mode
        Notes             = @($resolved.Notes)
        JsonPath          = $null
        MarkdownPath      = $null
        Hosts             = @($rows)
    }
    return Export-DiagnosticsReport -Report $report
}

function Show-ConsoleMenu {
    $mode = 'DomainControllers'
    $manual = ''
    $file = ''
    $days = $global:DefaultDays
    while ($true) {
        Write-Host ''
        Write-Host 'Server event diagnostics'
        Write-Host "  1) Target source   [$mode]"
        Write-Host "  2) Manual hosts    [$manual]"
        Write-Host "  3) Target file     [$file]"
        Write-Host "  4) Days            [$days]"
        Write-Host '  5) Run'
        Write-Host '  6) Quit'
        $choice = Read-Host 'Select'
        switch ($choice) {
            '1' {
                Write-Host '  D = Domain controllers (default)'
                Write-Host '  M = Member servers (excludes DCs, requires ActiveDirectory)'
                Write-Host '  H = Manual hosts'
                Write-Host '  F = Target file'
                $s = (Read-Host 'Source').ToUpperInvariant()
                switch ($s) {
                    'D' { $mode = 'DomainControllers' }
                    'M' { $mode = 'MemberServers' }
                    'H' { $mode = 'Manual' }
                    'F' { $mode = 'File' }
                    default { Write-Host 'Unchanged.' }
                }
            }
            '2' { $manual = Read-Host 'Hosts (comma or space separated)' }
            '3' { $file = Read-Host 'Path to one-host-per-line file' }
            '4' {
                $d = Read-Host 'Days (1-90)'
                $n = 0
                if ([int]::TryParse($d, [ref]$n) -and $n -ge 1 -and $n -le 90) { $days = $n }
                else { Write-Host 'Invalid. Unchanged.' }
            }
            '5' {
                if ($mode -eq 'File' -and -not $file) { Write-Host 'Target file is empty.'; continue }
                if ($mode -eq 'Manual' -and -not $manual) { Write-Host 'Manual hosts are empty.'; continue }
                try {
                    $out = Invoke-DiagnosticsRun -Mode $mode -ManualText $manual -FilePath $file -Days $days
                    Write-Host "Markdown: $($out.MarkdownPath)"
                    Write-Host "JSON:     $($out.JsonPath)"
                    Write-Host "Clipboard: $($out.Clipboard)"
                } catch {
                    Write-Host "Run failed: $($_.Exception.Message)"
                }
            }
            '6' { return }
            default { Write-Host 'Unknown selection.' }
        }
    }
}

function Show-WinForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Server event diagnostics'
    $form.Size = New-Object System.Drawing.Size(560, 460)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false

    $lblMode = New-Object System.Windows.Forms.Label
    $lblMode.Text = 'Target source'
    $lblMode.Location = New-Object System.Drawing.Point(16, 16)
    $lblMode.AutoSize = $true
    $form.Controls.Add($lblMode)

    $rbDc = New-Object System.Windows.Forms.RadioButton
    $rbDc.Text = 'Domain controllers (default)'
    $rbDc.Location = New-Object System.Drawing.Point(16, 40)
    $rbDc.AutoSize = $true
    $rbDc.Checked = $true
    $form.Controls.Add($rbDc)

    $rbMem = New-Object System.Windows.Forms.RadioButton
    $rbMem.Text = 'Member servers (enabled, OS like *Server*, DCs excluded)'
    $rbMem.Location = New-Object System.Drawing.Point(16, 64)
    $rbMem.AutoSize = $true
    $form.Controls.Add($rbMem)

    $rbMan = New-Object System.Windows.Forms.RadioButton
    $rbMan.Text = 'Manual override'
    $rbMan.Location = New-Object System.Drawing.Point(16, 88)
    $rbMan.AutoSize = $true
    $form.Controls.Add($rbMan)

    $txtMan = New-Object System.Windows.Forms.TextBox
    $txtMan.Location = New-Object System.Drawing.Point(32, 112)
    $txtMan.Size = New-Object System.Drawing.Size(490, 23)
    $form.Controls.Add($txtMan)

    $rbFile = New-Object System.Windows.Forms.RadioButton
    $rbFile.Text = 'Target file override (one host per line)'
    $rbFile.Location = New-Object System.Drawing.Point(16, 144)
    $rbFile.AutoSize = $true
    $form.Controls.Add($rbFile)

    $txtFile = New-Object System.Windows.Forms.TextBox
    $txtFile.Location = New-Object System.Drawing.Point(32, 168)
    $txtFile.Size = New-Object System.Drawing.Size(390, 23)
    $form.Controls.Add($txtFile)

    $btnBrowse = New-Object System.Windows.Forms.Button
    $btnBrowse.Text = 'Browse'
    $btnBrowse.Location = New-Object System.Drawing.Point(430, 166)
    $btnBrowse.Size = New-Object System.Drawing.Size(90, 26)
    $btnBrowse.Add_Click({
        $dlg = New-Object System.Windows.Forms.OpenFileDialog
        $dlg.Filter = 'Text files (*.txt)|*.txt|All files (*.*)|*.*'
        if ($dlg.ShowDialog() -eq 'OK') { $txtFile.Text = $dlg.FileName }
    }.GetNewClosure())
    $form.Controls.Add($btnBrowse)

    $lblDays = New-Object System.Windows.Forms.Label
    $lblDays.Text = 'Window (days)'
    $lblDays.Location = New-Object System.Drawing.Point(16, 208)
    $lblDays.AutoSize = $true
    $form.Controls.Add($lblDays)

    $numDays = New-Object System.Windows.Forms.NumericUpDown
    $numDays.Location = New-Object System.Drawing.Point(130, 204)
    $numDays.Minimum = 1
    $numDays.Maximum = 90
    $numDays.Value = $global:DefaultDays
    $form.Controls.Add($numDays)

    $lblMod = New-Object System.Windows.Forms.Label
    $lblMod.Text = 'Modules: Reboot (System 1074/6006/6008/6005/41) and Windows Update (19/20/43/44). Pairing is on: update 19/20/43 followed within 30 minutes by 1074/6008/41.'
    $lblMod.Location = New-Object System.Drawing.Point(16, 244)
    $lblMod.Size = New-Object System.Drawing.Size(510, 48)
    $form.Controls.Add($lblMod)

    $status = New-Object System.Windows.Forms.Label
    $status.Text = 'Idle. Files land on this user desktop. Markdown is also copied to the clipboard.'
    $status.Location = New-Object System.Drawing.Point(16, 300)
    $status.Size = New-Object System.Drawing.Size(510, 64)
    $form.Controls.Add($status)

    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Text = 'Run'
    $btnRun.Location = New-Object System.Drawing.Point(330, 376)
    $btnRun.Size = New-Object System.Drawing.Size(90, 30)
    $btnRun.Add_Click({
        $mode = 'DomainControllers'
        if ($rbMem.Checked) { $mode = 'MemberServers' }
        elseif ($rbMan.Checked) { $mode = 'Manual' }
        elseif ($rbFile.Checked) { $mode = 'File' }
        if ($mode -eq 'Manual' -and -not $txtMan.Text.Trim()) {
            $status.Text = 'Manual override is empty.'
            return
        }
        if ($mode -eq 'File' -and -not $txtFile.Text.Trim()) {
            $status.Text = 'Target file is empty.'
            return
        }
        $btnRun.Enabled = $false
        $status.Text = 'Running. Hosts are sequential. A failure is recorded and the next host runs.'
        $form.Refresh()
        try {
            $out = Invoke-DiagnosticsRun -Mode $mode -ManualText $txtMan.Text -FilePath $txtFile.Text -Days ([int]$numDays.Value)
            $status.Text = "Markdown: $($out.MarkdownPath)`r`nJSON: $($out.JsonPath)`r`nClipboard: $($out.Clipboard)"
        } catch {
            $status.Text = "Run failed: $($_.Exception.Message)"
        } finally {
            $btnRun.Enabled = $true
        }
    }.GetNewClosure())
    $form.Controls.Add($btnRun)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = 'Close'
    $btnClose.Location = New-Object System.Drawing.Point(430, 376)
    $btnClose.Size = New-Object System.Drawing.Size(90, 30)
    $btnClose.Add_Click({ $form.Close() }.GetNewClosure())
    $form.Controls.Add($btnClose)

    [void]$form.ShowDialog()
    $form.Dispose()
}

if (Test-UiAvailable) {
    Show-WinForm
} else {
    if (-not $NoUI) {
        Write-Host 'WinForms unavailable (non-interactive session or MTA). Using the console menu.'
    }
    Show-ConsoleMenu
}
