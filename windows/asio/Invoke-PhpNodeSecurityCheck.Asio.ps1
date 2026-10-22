#Requires -Version 5.1
<#
.SYNOPSIS
    Detection-only check for PHP and Node.js builds affected by the October 21, 2026 security releases.
    Intended for ConnectWise RMM (Asio) running as SYSTEM under Windows PowerShell 5.1.

.DESCRIPTION
    Thresholds (verified against php.net and nodejs.org, Oct 2026):
      PHP     CVE-2026-109618 / CVE-2026-109619: fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35.
              8.1 and older receive no upstream fix and are reported as vulnerable.
      Node.js October 21 2026 security releases: fixed in 26.12.1, 24.22.1, 22.23.4.
              Other major lines (20 and older, odd/unknown) are reported as vulnerable.
    Not installed = clean. No network access, no prompts, no changes to the system
    unless -AllowWingetUpgrade is passed explicitly.

    Output contract (stdout only):
      exit 0  OK: no vulnerable PHP/Node found (checked N)
      exit 1  VULNERABLE: <count> finding(s)
              Device=<name> Product=<PHP|Node.js> Found=<ver> Fixed=<ver> Path=<path>
      exit 2  ERROR: <message>

.PARAMETER TreatUnknownAsClean
    Ignore executables whose version cannot be determined (default: report them as findings with Found=unknown).

.PARAMETER AllowWingetUpgrade
    Optional. After reporting, attempt winget upgrades for vulnerable products. Off by default;
    winget is frequently unavailable in the SYSTEM context.

.PARAMETER Summary
    Emit one line only, at most 300 characters, for a ConnectWise RMM Text Box custom field:
      OK (checked N) | VULNERABLE <n>: PHP 8.3.30; Node.js 22.23.3 | ERROR: <message>
    Exit codes are unchanged. When pasting into a Script Editor step (no parameters),
    set $SummaryDefault = $true below instead.

.PARAMETER NoRun
    Load functions only (used by tests).
#>
[CmdletBinding()]
param(
    [switch]$TreatUnknownAsClean,
    [switch]$AllowWingetUpgrade,
    [switch]$Summary,
    [switch]$NoRun
)

# Set to $true in the custom-field task copy of this script.
$SummaryDefault = $false

$PhpFixed = @{
    '8.5' = [version]'8.5.12'
    '8.4' = [version]'8.4.27'
    '8.3' = [version]'8.3.36'
    '8.2' = [version]'8.2.35'
}
$NodeFixed = @{
    '26' = [version]'26.12.1'
    '24' = [version]'24.22.1'
    '22' = [version]'22.23.4'
}

function Get-CandidatePatterns {
    param([ValidateSet('PHP', 'Node.js')][string]$Product)

    $pf   = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) | Where-Object { $_ } | Select-Object -Unique
    $pd   = $env:ProgramData
    $sd   = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }
    $usersRoot = "$sd\Users"
    $list = New-Object System.Collections.Generic.List[string]

    if ($Product -eq 'PHP') {
        foreach ($p in $pf) {
            $list.Add("$p\PHP\php.exe"); $list.Add("$p\PHP\*\php.exe"); $list.Add("$p\PHP\*\*\php.exe")
            $list.Add("$p\iis express\PHP\*\php.exe")
        }
        if ($pd) { $list.Add("$pd\PHP\*\php.exe"); $list.Add("$pd\chocolatey\lib\php\tools\php.exe"); $list.Add("$pd\chocolatey\lib\php*\tools\php*\php.exe") }
        $list.Add("$sd\php*\php.exe"); $list.Add("$sd\php*\*\php.exe")
        $list.Add("$sd\xampp\php\php.exe"); $list.Add("$sd\xampp*\php\php.exe")
        $list.Add("$sd\wamp*\bin\php\*\php.exe")
        $list.Add("$sd\laragon\bin\php\*\php.exe")
        $list.Add("$sd\tools\php*\php.exe")
        $list.Add("$sd\inetpub\php*\php.exe")
        $list.Add("$usersRoot\*\AppData\Local\Programs\PHP\*\php.exe")
    }
    else {
        foreach ($p in $pf) { $list.Add("$p\nodejs\node.exe"); $list.Add("$p\nvm\*\node.exe") }
        if ($pd) { $list.Add("$pd\nvm\*\node.exe"); $list.Add("$pd\chocolatey\lib\nodejs*\tools\*\node.exe") }
        $list.Add("$sd\nvm\*\node.exe"); $list.Add("$sd\nvm4w\*\node.exe"); $list.Add("$sd\nodejs\node.exe")
        if ($env:NVM_HOME) { $list.Add("$env:NVM_HOME\*\node.exe") }
        if ($env:NVM_SYMLINK) { $list.Add("$env:NVM_SYMLINK\node.exe") }
        $list.Add("$usersRoot\*\AppData\Roaming\nvm\*\node.exe")
        $list.Add("$usersRoot\*\AppData\Local\nvm\*\node.exe")
        $list.Add("$usersRoot\*\AppData\Local\Programs\nodejs\node.exe")
        $list.Add("$usersRoot\*\AppData\Local\fnm\node-versions\*\installation\node.exe")
        $list.Add("$usersRoot\*\AppData\Roaming\fnm\node-versions\*\installation\node.exe")
        $list.Add("$usersRoot\*\.volta\tools\image\node\*\node.exe")
    }
    return $list
}

function Get-IisPhpPaths {
    # IIS FastCGI handlers registered in applicationHost.config (read-only parse, no WebAdministration module needed).
    $out = @()
    if (-not $env:windir) { return $out }
    try {
        $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
        if (Test-Path -LiteralPath $cfg) {
            $text = Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop
            foreach ($m in [regex]::Matches($text, 'fullPath\s*=\s*"([^"]*php-cgi\.exe)"', 'IgnoreCase')) {
                $exe = Join-Path (Split-Path -Parent $m.Groups[1].Value) 'php.exe'
                $out += $exe
            }
        }
    } catch { Write-Verbose "skipped: $($_.Exception.Message)" }
    return $out
}

function Get-PathExecutables {
    param([string]$ExeName)
    $out = @()
    $dirs = @()
    foreach ($scope in 'Process', 'Machine') {
        try { $v = [Environment]::GetEnvironmentVariable('Path', $scope); if (-not $v) { $v = [Environment]::GetEnvironmentVariable('PATH', $scope) }; if ($v) { $dirs += $v -split [regex]::Escape([string][System.IO.Path]::PathSeparator) } } catch { Write-Verbose "skipped: $($_.Exception.Message)" }
    }
    foreach ($d in ($dirs | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)) {
        try {
            $expanded = [Environment]::ExpandEnvironmentVariables($d.Trim().Trim('"'))
            $c = Join-Path $expanded $ExeName
            if (Test-Path -LiteralPath $c -PathType Leaf) { $out += $c }
        } catch { Write-Verbose "skipped: $($_.Exception.Message)" }
    }
    return $out
}

function Find-Executables {
    param([ValidateSet('PHP', 'Node.js')][string]$Product)
    $exe = if ($Product -eq 'PHP') { 'php.exe' } else { 'node.exe' }
    $paths = @()
    $paths += Get-PathExecutables -ExeName $exe
    if ($Product -eq 'PHP') { $paths += Get-IisPhpPaths }
    foreach ($pattern in (Get-CandidatePatterns -Product $Product)) {
        try {
            $paths += Get-Item -Path $pattern -ErrorAction SilentlyContinue |
                Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName }
        } catch { Write-Verbose "skipped: $($_.Exception.Message)" }
    }
    $seen = @{}
    $result = @()
    foreach ($p in $paths) {
        if (-not $p) { continue }
        try { $full = [System.IO.Path]::GetFullPath($p) } catch { $full = $p }
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { continue }
        $key = $full.TrimEnd('\').ToLowerInvariant()
        if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $result += $full }
    }
    return $result
}

function ConvertTo-SemVer {
    param([string]$Text)
    if ($Text -and $Text -match '(\d+)\.(\d+)\.(\d+)') {
        return [version]("{0}.{1}.{2}" -f $Matches[1], $Matches[2], $Matches[3])
    }
    return $null
}

function Get-ExeVersion {
    param([string]$Path)
    # 1) File metadata (no process launch).
    try {
        $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $v = ConvertTo-SemVer $fvi.ProductVersion
        if (-not $v) { $v = ConvertTo-SemVer $fvi.FileVersion }
        if ($v -and $v.Major -gt 0) { return $v }
    } catch { Write-Verbose "skipped: $($_.Exception.Message)" }
    # 2) Ask the binary, with a timeout so a hung exe cannot stall the agent.
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $Path
        $psi.Arguments = '-v'
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $stdout = $proc.StandardOutput.ReadToEndAsync()
        if (-not $proc.WaitForExit(15000)) { try { $proc.Kill() } catch { Write-Verbose "skipped: $($_.Exception.Message)" }; return $null }
        $first = ($stdout.Result -split "`r?`n" | Where-Object { $_ } | Select-Object -First 1)
        return ConvertTo-SemVer $first
    } catch { Write-Verbose "skipped: $($_.Exception.Message)" }
    return $null
}

function Get-FixedVersion {
    param([string]$Product, [version]$Version)
    if ($Product -eq 'PHP') {
        $key = "$($Version.Major).$($Version.Minor)"
        if ($PhpFixed.ContainsKey($key)) { return @{ Vulnerable = ($Version -lt $PhpFixed[$key]); Fixed = $PhpFixed[$key].ToString() } }
        $newest = ($PhpFixed.Values | Sort-Object -Descending | Select-Object -First 1)
        if ($Version -gt $newest -and $Version.Major -ge 8) { return @{ Vulnerable = $false; Fixed = 'n/a' } }
        return @{ Vulnerable = $true; Fixed = 'upgrade-to-8.2.35+(branch-unsupported)' }
    }
    $key = "$($Version.Major)"
    if ($NodeFixed.ContainsKey($key)) { return @{ Vulnerable = ($Version -lt $NodeFixed[$key]); Fixed = $NodeFixed[$key].ToString() } }
    if ($Version.Major -gt 26) { return @{ Vulnerable = $false; Fixed = 'n/a' } }
    return @{ Vulnerable = $true; Fixed = 'upgrade-to-22.23.4+(branch-unsupported)' }
}

function Invoke-SecurityScan {
    param([switch]$TreatUnknownAsClean)
    $device = $env:COMPUTERNAME
    if (-not $device) { $device = [Environment]::MachineName }
    $findings = @()
    $checked = 0
    foreach ($product in 'PHP', 'Node.js') {
        foreach ($path in @(Find-Executables -Product $product)) {
            $checked++
            $ver = Get-ExeVersion -Path $path
            if (-not $ver) {
                if (-not $TreatUnknownAsClean) {
                    $findings += "Device=$device Product=$product Found=unknown Fixed=review-manually Path=$path"
                }
                continue
            }
            $r = Get-FixedVersion -Product $product -Version $ver
            if ($r.Vulnerable) {
                $findings += "Device=$device Product=$product Found=$ver Fixed=$($r.Fixed) Path=$path"
            }
        }
    }
    return [pscustomobject]@{ Checked = $checked; Findings = $findings }
}

function Invoke-OptionalWinget {
    param([string[]]$Findings)
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) { Write-Output 'INFO: winget not available in this context; no upgrade attempted.'; return }
    if ($Findings -match 'Product=Node\.js') {
        & $winget.Source upgrade --id OpenJS.NodeJS.LTS --silent --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 | Out-Null
        Write-Output "INFO: winget Node.js upgrade exit code $LASTEXITCODE"
    }
    if ($Findings -match 'Product=PHP') {
        Write-Output 'INFO: PHP is not upgraded automatically; update the matching branch manually and restart IIS/Apache/PHP-FPM.'
    }
}

function Get-SummaryLine {
    param([int]$Checked, [string[]]$Findings, [int]$MaxLength = 300)
    if (-not $Findings -or $Findings.Count -eq 0) { return "OK (checked $Checked)" }
    $parts = foreach ($f in $Findings) {
        if ($f -match 'Product=(\S+) Found=(\S+)') { "$($Matches[1]) $($Matches[2])" }
    }
    $line = "VULNERABLE $($Findings.Count): " + (($parts | Select-Object -Unique) -join '; ')
    if ($line.Length -gt $MaxLength) { $line = $line.Substring(0, $MaxLength - 3) + '...' }
    return $line
}

function Invoke-Main {
    param([switch]$TreatUnknownAsClean, [switch]$AllowWingetUpgrade, [switch]$Summary)
    try {
        $scan = Invoke-SecurityScan -TreatUnknownAsClean:$TreatUnknownAsClean
        if ($Summary) {
            Write-Output (Get-SummaryLine -Checked $scan.Checked -Findings $scan.Findings)
            if ($scan.Findings.Count -eq 0) { return 0 } else { return 1 }
        }
        if ($scan.Findings.Count -eq 0) {
            Write-Output "OK: no vulnerable PHP/Node found (checked $($scan.Checked))"
            return 0
        }
        Write-Output "VULNERABLE: $($scan.Findings.Count) finding(s)"
        foreach ($f in $scan.Findings) { Write-Output $f }
        if ($AllowWingetUpgrade) { Invoke-OptionalWinget -Findings $scan.Findings }
        return 1
    }
    catch {
        $msg = ($_.Exception.Message -replace '\s+', ' ').Trim()
        $line = "ERROR: $msg"
        if ($Summary -and $line.Length -gt 300) { $line = $line.Substring(0, 297) + '...' }
        Write-Output $line
        return 2
    }
}

if (-not $NoRun) {
    # Invoke-Main emits the report lines followed by the exit code as the last pipeline item.
    $results = @(Invoke-Main -TreatUnknownAsClean:$TreatUnknownAsClean -AllowWingetUpgrade:$AllowWingetUpgrade -Summary:($Summary -or $SummaryDefault))
    $code = 2
    if ($results.Count -gt 0 -and $results[-1] -is [int]) { $code = $results[-1] } else { $results += 'ERROR: no result produced' }
    if ($results.Count -gt 1) { $results[0..($results.Count - 2)] | ForEach-Object { Write-Output $_ } }
    elseif ($code -eq 2) { Write-Output 'ERROR: no result produced' }
    exit $code
}
