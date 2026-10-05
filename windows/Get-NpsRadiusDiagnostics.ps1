<#
.SYNOPSIS
    Collect Windows NPS (RADIUS) health and recent Wi-Fi auth failures for a Grok handoff.

.DESCRIPTION
    Run this on the NPS server, in an elevated Windows PowerShell 5.1 session.
    WinForms when the session is interactive. -NoUI uses the console.

    Reads the IAS service, NPS audit subcategory, UDP 1812/1813/1645/1646 listeners,
    LocalMachine\My server-auth certificates, RADIUS client names and IPs, policy names,
    Security 6272/6273/6274, and System NPS/IAS events 13 and 18.

    Shared secrets are stripped. The script does not change audit policy, policies, or certs.

    Writes report-nps-<yyyyMMdd-HHmmss>.md and .json to the desktop of the account that
    ran it, and copies the markdown to the clipboard.

.PARAMETER NoUI
    Skip WinForms.

.PARAMETER Days
    Lookback window. Default 2. Max 14. Ignored when the form is used.

.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Get-NpsRadiusDiagnostics.ps1
#>
[CmdletBinding()]
param(
    [switch]$NoUI,
    [ValidateRange(1, 14)]
    [int]$Days = 2
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# WinForms click handlers run outside script scope. Entry points are global.

$global:NpsMarkdownCap = 25
$global:NpsDefaultDays = 2
$global:NpsReason = @{
    0  = 'Authenticated and authorized'
    1  = 'NPS internal error'
    2  = 'Insufficient access rights'
    3  = 'Malformed RADIUS Access-Request'
    4  = 'Cannot reach AD global catalog'
    5  = 'Cannot reach a domain controller for the user domain'
    6  = 'NPS unavailable (resource, DC name, or SAM/NTDS)'
    7  = 'Domain in User-Name does not exist'
    8  = 'User account in User-Name does not exist'
    9  = 'IAS extension DLL discarded the request'
    10 = 'IAS extension DLL failed'
    16 = 'Credential mismatch (bad password, or account/cert binding failed)'
    17 = 'Password change failed'
    18 = 'Client authentication method is not allowed'
    19 = 'CHAP requested but reversible encryption is not enabled'
    20 = 'LAN Manager authentication is not supported'
    21 = 'IAS extension DLL rejected the request'
    22 = 'EAP type negotiation failed'
    23 = 'EAP failure during authentication (check EAP logs under System32\LogFiles)'
    32 = 'Workgroup NPS received a domain username'
    33 = 'User must change password'
    34 = 'User account disabled'
    35 = 'User account expired'
    36 = 'Account locked out'
    37 = 'Outside allowed logon hours'
}

function global:Hide-NpsSecret {
    param([string]$Text)
    if (-not $Text) { return '' }
    $clean = $Text -replace '(?i)(shared\s*secret|secret|password)\s*[:=]\s*\S+', '$1=<redacted>'
    return $clean
}

function global:Get-NpsDesktop {
    $desktop = [Environment]::GetFolderPath('Desktop')
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = Join-Path $env:USERPROFILE 'Desktop' }
    if (-not (Test-Path -LiteralPath $desktop)) { New-Item -ItemType Directory -Path $desktop -Force | Out-Null }
    return $desktop
}

function global:Get-NpsReasonLabel {
    param([string]$Code)
    $n = 0
    if (-not [int]::TryParse($Code, [ref]$n)) { return 'Reason code not parsed' }
    if ($global:NpsReason.ContainsKey($n)) { return $global:NpsReason[$n] }
    return 'Not in the Microsoft 0-37 reason table'
}

function global:Convert-NpsEventData {
    param($Event)
    $bag = [ordered]@{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($node in @($xml.Event.EventData.Data)) {
            $name = $node.Name
            if (-not $name) { $name = 'Data' }
            $value = [string]$node.'#text'
            if ($name -match 'secret|password') { $value = '<redacted>' }
            $bag[$name] = $value
        }
    } catch {
        $bag['ParseError'] = $_.Exception.Message
    }
    return [pscustomobject]$bag
}

function global:Get-NpsField {
    param($Data, [string[]]$Names)
    foreach ($n in $Names) {
        $prop = $Data.PSObject.Properties[$n]
        if ($prop -and $prop.Value) { return [string]$prop.Value }
    }
    return ''
}

function global:Get-NpsServiceState {
    $svc = Get-Service -Name IAS -ErrorAction SilentlyContinue
    if (-not $svc) {
        return [pscustomobject]@{ Name = 'IAS'; Status = 'Missing'; StartType = 'Missing'; Note = 'Network Policy Server service (IAS) is not installed.' }
    }
    return [pscustomobject]@{ Name = $svc.Name; Status = [string]$svc.Status; StartType = [string]$svc.StartType; Note = '' }
}

function global:Get-NpsAuditState {
    $raw = @(& auditpol.exe /get /subcategory:"Network Policy Server" 2>&1 | ForEach-Object { "$_" })
    $text = ($raw -join "`n").Trim()
    $enabled = $text -match 'Success and Failure'
    return [pscustomobject]@{
        Raw     = $text
        Enabled = [bool]$enabled
        Note    = $(if ($enabled) { 'Success and Failure are on.' } else { '6272/6273 will be missing until Success and Failure are enabled. This script does not change audit policy.' })
    }
}

function global:Get-NpsListeners {
    $ports = 1812, 1813, 1645, 1646
    $rows = New-Object System.Collections.Generic.List[object]
    try {
        $eps = @(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $ports -contains $_.LocalPort })
        foreach ($ep in $eps) {
            $rows.Add([pscustomobject]@{ Port = [int]$ep.LocalPort; Address = [string]$ep.LocalAddress; OwningProcess = $ep.OwningProcess })
        }
    } catch {
        $rows.Add([pscustomobject]@{ Port = 0; Address = ''; OwningProcess = 0; Error = $_.Exception.Message })
    }
    return @($rows)
}

function global:Get-NpsServerCerts {
    $now = Get-Date
    $rows = New-Object System.Collections.Generic.List[object]
    $certs = @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue)
    foreach ($c in $certs) {
        $eku = @($c.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
        $serverAuth = $eku -contains '1.3.6.1.5.5.7.3.1'
        if (-not $serverAuth) { continue }
        $daysLeft = [math]::Round(($c.NotAfter - $now).TotalDays, 1)
        $rows.Add([pscustomobject]@{
            Subject    = $c.Subject
            Thumbprint = $c.Thumbprint
            NotAfter   = $c.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            DaysLeft   = $daysLeft
            HasPrivateKey = [bool]$c.HasPrivateKey
            Expired    = $c.NotAfter -lt $now
        })
    }
    return @($rows | Sort-Object DaysLeft)
}

function global:Get-NpsNetsh {
    param([string]$Args)
    $raw = @(& netsh.exe nps $Args 2>&1 | ForEach-Object { "$_" })
    $text = Hide-NpsSecret -Text ($raw -join "`n")
    return $text
}

function global:Get-NpsConfigSummary {
    $client = Get-NpsNetsh -Args 'show client'
    $np = Get-NpsNetsh -Args 'show np'
    $crp = Get-NpsNetsh -Args 'show crp'
    return [pscustomobject]@{
        Clients                 = $client
        NetworkPolicies         = $np
        ConnectionRequestPolicies = $crp
    }
}

function global:Get-NpsSecurityEvents {
    param([datetime]$Start)
    $bucket = [ordered]@{ LogPresent = $true; Error = $null; Events = @() }
    try {
        $found = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 6272, 6273, 6274
            StartTime = $Start
        } -ErrorAction Stop)
        $bucket.Events = @(foreach ($e in $found) {
            $data = Convert-NpsEventData -Event $e
            $code = Get-NpsField -Data $data -Names @('Reason-Code', 'ReasonCode')
            if (-not $code -and $e.Message -match 'Reason Code:\s*(\d+)') { $code = $Matches[1] }
            [pscustomobject]@{
                TimeCreated = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                Id          = [int]$e.Id
                ReasonCode  = $code
                Reason      = (Get-NpsReasonLabel -Code $code)
                UserName    = (Get-NpsField -Data $data -Names @('Account-Name', 'User-Name', 'SubjectUserName', 'TargetUserName'))
                NasIp       = (Get-NpsField -Data $data -Names @('Client-IP-Address', 'NAS-IP-Address', 'ClientIPAddress'))
                CallingId   = (Get-NpsField -Data $data -Names @('Calling-Station-ID', 'CallingStationID'))
                CalledId    = (Get-NpsField -Data $data -Names @('Called-Station-ID', 'CalledStationID'))
                Policy      = (Get-NpsField -Data $data -Names @('Network-Policy-Name', 'NP-Policy-Name', 'Proxy-Policy-Name'))
                AuthType    = (Get-NpsField -Data $data -Names @('Authentication-Type', 'AuthenticationType'))
                EapType     = (Get-NpsField -Data $data -Names @('EAP-Type', 'EAPType'))
                Message     = Hide-NpsSecret -Text ([string]$e.Message)
            }
        })
    } catch {
        $m = $_.Exception.Message
        if ($m -match 'No events were found') { $bucket.Events = @() }
        else { $bucket.Error = $m }
    }
    return [pscustomobject]$bucket
}

function global:Get-NpsSystemEvents {
    param([datetime]$Start)
    $bucket = [ordered]@{ Error = $null; Events = @() }
    try {
        $found = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 13, 18
            StartTime = $Start
        } -ErrorAction Stop | Where-Object { $_.ProviderName -match 'NPS|IAS|RemoteAccess' })
        $bucket.Events = @(foreach ($e in $found) {
            [pscustomobject]@{
                TimeCreated  = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                Id           = [int]$e.Id
                ProviderName = [string]$e.ProviderName
                Message      = Hide-NpsSecret -Text ([string]$e.Message)
            }
        })
    } catch {
        $m = $_.Exception.Message
        if ($m -notmatch 'No events were found') { $bucket.Error = $m }
    }
    return [pscustomobject]$bucket
}

function global:Get-NpsReasonRollup {
    param($Events)
    $denies = @($Events | Where-Object { $_.Id -eq 6273 -or $_.Id -eq 6274 })
    $groups = @($denies | Group-Object ReasonCode | Sort-Object Count -Descending)
    return @(foreach ($g in $groups) {
        [pscustomobject]@{
            ReasonCode = [string]$g.Name
            Reason     = (Get-NpsReasonLabel -Code ([string]$g.Name))
            Count      = $g.Count
        }
    })
}

function global:Build-NpsMarkdown {
    param($Report)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# NPS RADIUS diagnostics')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Paste this to Grok. Shared secrets are redacted. Pair rows are not used. Reason labels are the Microsoft 0-37 table.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("- GeneratedUtc: $($Report.GeneratedUtc)")
    [void]$sb.AppendLine("- Computer: $($Report.Computer)")
    [void]$sb.AppendLine("- WindowStartUtc: $($Report.WindowStartUtc)")
    [void]$sb.AppendLine("- WindowDays: $($Report.WindowDays)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Service')
    [void]$sb.AppendLine("- IAS status: $($Report.Service.Status) / $($Report.Service.StartType)")
    if ($Report.Service.Note) { [void]$sb.AppendLine("- $($Report.Service.Note)") }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Audit')
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine($Report.Audit.Raw)
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine($Report.Audit.Note)
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## UDP listeners')
    if (@($Report.Listeners).Count -eq 0) {
        [void]$sb.AppendLine('_No listener on 1812, 1813, 1645, or 1646._')
    } else {
        foreach ($l in @($Report.Listeners)) {
            [void]$sb.AppendLine("- $($l.Address):$($l.Port) pid $($l.OwningProcess)")
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Server-auth certificates (LocalMachine\My)')
    if (@($Report.Certificates).Count -eq 0) {
        [void]$sb.AppendLine('_No cert with Server Authentication EKU and a private key path was found in LocalMachine\My._')
    } else {
        foreach ($c in @($Report.Certificates)) {
            [void]$sb.AppendLine("- $($c.Subject)  $($c.Thumbprint)  notAfter $($c.NotAfter)  daysLeft $($c.DaysLeft)  privateKey $($c.HasPrivateKey)")
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Deny / discard reason rollup')
    if (@($Report.ReasonRollup).Count -eq 0) {
        [void]$sb.AppendLine('_No 6273 or 6274 in the window._')
    } else {
        foreach ($r in @($Report.ReasonRollup)) {
            [void]$sb.AppendLine("- $($r.Count) x reason $($r.ReasonCode): $($r.Reason)")
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## Newest deny / discard events')
    $denies = @($Report.Security.Events | Where-Object { $_.Id -ne 6272 } | Sort-Object TimeCreated -Descending)
    $shown = @($denies | Select-Object -First $global:NpsMarkdownCap)
    [void]$sb.AppendLine("Showing $($shown.Count) of $($denies.Count). JSON has the full set.")
    foreach ($e in $shown) {
        [void]$sb.AppendLine("- $($e.TimeCreated)  Id $($e.Id)  reason $($e.ReasonCode) ($($e.Reason))")
        [void]$sb.AppendLine("  user=$($e.UserName)  nas=$($e.NasIp)  policy=$($e.Policy)  auth=$($e.AuthType)  eap=$($e.EapType)  calling=$($e.CallingId)")
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## System 13 / 18 (unknown RADIUS client or shared-secret mismatch)')
    $sys = @($Report.SystemEvents.Events | Sort-Object TimeCreated -Descending | Select-Object -First 15)
    if ($sys.Count -eq 0) { [void]$sb.AppendLine('_None in the window._') }
    foreach ($e in $sys) {
        $msg = ($e.Message -replace '\s+', ' ')
        if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
        [void]$sb.AppendLine("- $($e.TimeCreated)  Id $($e.Id)  $($e.ProviderName)  $msg")
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('## RADIUS clients (secrets redacted)')
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine($Report.Config.Clients)
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine('## Connection request policies')
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine($Report.Config.ConnectionRequestPolicies)
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine('## Network policies')
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine($Report.Config.NetworkPolicies)
    [void]$sb.AppendLine('```')
    [void]$sb.AppendLine('## Ask Grok')
    [void]$sb.AppendLine('Diagnose Wi-Fi RADIUS failures from this report. Lead with the reason-code rollup. Do not invent a shared secret. If reason 16 is on EAP-TLS, check KB5014754 strong mapping. If 13 or 18 is present, the AP is missing or the secret does not match.')
    return $sb.ToString()
}

function global:Export-NpsReport {
    param($Report)
    $desktop = Get-NpsDesktop
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $mdPath = Join-Path $desktop "report-nps-$stamp.md"
    $jsonPath = Join-Path $desktop "report-nps-$stamp.json"
    $Report.MarkdownPath = $mdPath
    $Report.JsonPath = $jsonPath
    $md = Build-NpsMarkdown -Report $Report
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [IO.File]::WriteAllText($mdPath, $md, $utf8)
    [IO.File]::WriteAllText($jsonPath, ($Report | ConvertTo-Json -Depth 8), $utf8)
    $clip = 'copied'
    try { Set-Clipboard -Value $md } catch { $clip = "clipboard unavailable: $($_.Exception.Message)" }
    return [pscustomobject]@{ MarkdownPath = $mdPath; JsonPath = $jsonPath; Clipboard = $clip }
}

function global:Invoke-NpsDiagnostics {
    param([int]$Days)
    if ($Days -lt 1) { $Days = 1 }
    if ($Days -gt 14) { $Days = 14 }
    $start = (Get-Date).AddDays(-1 * $Days)
    $security = Get-NpsSecurityEvents -Start $start
    $report = [pscustomobject]@{
        GeneratedUtc   = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Computer       = $env:COMPUTERNAME
        WindowStartUtc = $start.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        WindowDays     = $Days
        Service        = (Get-NpsServiceState)
        Audit          = (Get-NpsAuditState)
        Listeners      = @(Get-NpsListeners)
        Certificates   = @(Get-NpsServerCerts)
        Config         = (Get-NpsConfigSummary)
        Security       = $security
        SystemEvents   = (Get-NpsSystemEvents -Start $start)
        ReasonRollup   = @(Get-NpsReasonRollup -Events $security.Events)
        MarkdownPath   = $null
        JsonPath       = $null
    }
    return Export-NpsReport -Report $report
}

function Test-NpsUi {
    if ($NoUI) { return $false }
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch { return $false }
    $sta = [Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
    return ([Environment]::UserInteractive -and $sta)
}

function Show-NpsForm {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'NPS RADIUS diagnostics'
    $form.Size = New-Object System.Drawing.Size(520, 280)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false

    $info = New-Object System.Windows.Forms.Label
    $info.Text = 'Run on the NPS server, elevated. Collects IAS, audit, listeners, server certs, policy names, and Security 6272/6273/6274. Secrets are redacted. Nothing is changed.'
    $info.Location = New-Object System.Drawing.Point(16, 16)
    $info.Size = New-Object System.Drawing.Size(470, 48)
    $form.Controls.Add($info)

    $lbl = New-Object System.Windows.Forms.Label
    $lbl.Text = 'Window (days)'
    $lbl.Location = New-Object System.Drawing.Point(16, 76)
    $lbl.AutoSize = $true
    $form.Controls.Add($lbl)

    $num = New-Object System.Windows.Forms.NumericUpDown
    $num.Location = New-Object System.Drawing.Point(130, 72)
    $num.Minimum = 1
    $num.Maximum = 14
    $num.Value = $global:NpsDefaultDays
    $form.Controls.Add($num)

    $status = New-Object System.Windows.Forms.Label
    $status.Text = 'Idle. Files land on this user desktop.'
    $status.Location = New-Object System.Drawing.Point(16, 112)
    $status.Size = New-Object System.Drawing.Size(470, 64)
    $form.Controls.Add($status)

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = 'Run'
    $btn.Location = New-Object System.Drawing.Point(290, 196)
    $btn.Size = New-Object System.Drawing.Size(90, 30)
    $btn.Add_Click({
        $btn.Enabled = $false
        $status.Text = 'Reading Security log and NPS config.'
        $form.Refresh()
        try {
            $out = Invoke-NpsDiagnostics -Days ([int]$num.Value)
            $status.Text = "Markdown: $($out.MarkdownPath)`r`nJSON: $($out.JsonPath)`r`nClipboard: $($out.Clipboard)"
        } catch {
            $status.Text = "Run failed: $($_.Exception.Message)"
        } finally {
            $btn.Enabled = $true
        }
    }.GetNewClosure())
    $form.Controls.Add($btn)

    $close = New-Object System.Windows.Forms.Button
    $close.Text = 'Close'
    $close.Location = New-Object System.Drawing.Point(390, 196)
    $close.Size = New-Object System.Drawing.Size(90, 30)
    $close.Add_Click({ $form.Close() }.GetNewClosure())
    $form.Controls.Add($close)
    [void]$form.ShowDialog()
    $form.Dispose()
}

if (Test-NpsUi) {
    Show-NpsForm
} else {
    Write-Host 'NPS RADIUS diagnostics. Local server only.'
    $d = Read-Host "Days [1-14, default $Days]"
    $n = 0
    if ([int]::TryParse($d, [ref]$n) -and $n -ge 1 -and $n -le 14) { $Days = $n }
    $out = Invoke-NpsDiagnostics -Days $Days
    Write-Host "Markdown: $($out.MarkdownPath)"
    Write-Host "JSON:     $($out.JsonPath)"
    Write-Host "Clipboard: $($out.Clipboard)"
}
