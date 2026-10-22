BeforeAll {
    . (Join-Path $PSScriptRoot 'Invoke-PhpNodeSecurityCheck.Asio.ps1') -NoRun
    $env:COMPUTERNAME = 'TESTSRV01'
    function Set-Installs([hashtable]$Php, [hashtable]$Node) {
        $script:PhpMap = $Php; $script:NodeMap = $Node
        Mock Find-Executables { param($Product) if ($Product -eq 'PHP') { @($script:PhpMap.Keys | Sort-Object) } else { @($script:NodeMap.Keys | Sort-Object) } }
        Mock Get-ExeVersion { param($Path) $all = $script:PhpMap + $script:NodeMap; $v = $all[$Path]; if ($v) { [version]$v } else { $null } }
    }
}

Describe 'Invoke-PhpNodeSecurityCheck.Asio' {
    It 'none installed -> exit 0, OK line with checked 0' {
        Set-Installs @{} @{}
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 0
        $out[0] | Should -Be 'OK: no vulnerable PHP/Node found (checked 0)'
        $out.Count | Should -Be 2
    }
    It 'patched installs -> exit 0' {
        Set-Installs @{ 'C:\php\php.exe' = '8.3.36'; 'C:\php85\php.exe' = '8.5.12' } @{ 'C:\Program Files\nodejs\node.exe' = '24.22.1' }
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 0
        $out[0] | Should -Be 'OK: no vulnerable PHP/Node found (checked 3)'
    }
    It 'vulnerable PHP -> exit 1 with finding line' {
        Set-Installs @{ 'C:\xampp\php\php.exe' = '8.4.26' } @{}
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 1
        $out[0] | Should -Be 'VULNERABLE: 1 finding(s)'
        $out[1] | Should -Be 'Device=TESTSRV01 Product=PHP Found=8.4.26 Fixed=8.4.27 Path=C:\xampp\php\php.exe'
    }
    It 'vulnerable Node -> exit 1' {
        Set-Installs @{} @{ 'C:\Program Files\nodejs\node.exe' = '22.23.3' }
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 1
        $out[1] | Should -Be 'Device=TESTSRV01 Product=Node.js Found=22.23.3 Fixed=22.23.4 Path=C:\Program Files\nodejs\node.exe'
    }
    It 'EOL branches flagged (PHP 8.1, Node 20)' {
        Set-Installs @{ 'C:\php81\php.exe' = '8.1.33' } @{ 'C:\nvm\v20.19.0\node.exe' = '20.19.0' }
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 1
        $out[0] | Should -Be 'VULNERABLE: 2 finding(s)'
        ($out -join "`n") | Should -Match 'Fixed=upgrade-to-8\.2\.35\+'
        ($out -join "`n") | Should -Match 'Fixed=upgrade-to-22\.23\.4\+'
    }
    It 'multiple installs, mixed -> only vulnerable ones reported' {
        Set-Installs @{ 'C:\php\php.exe' = '8.2.34'; 'C:\php83\php.exe' = '8.3.36' } @{ 'C:\Program Files\nodejs\node.exe' = '26.12.0'; 'C:\Users\a\AppData\Roaming\nvm\v24.22.1\node.exe' = '24.22.1' }
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 1
        $out[0] | Should -Be 'VULNERABLE: 2 finding(s)'
        $out | Should -Contain 'Device=TESTSRV01 Product=PHP Found=8.2.34 Fixed=8.2.35 Path=C:\php\php.exe'
        $out | Should -Contain 'Device=TESTSRV01 Product=Node.js Found=26.12.0 Fixed=26.12.1 Path=C:\Program Files\nodejs\node.exe'
    }
    It 'unparsable version -> reported as unknown by default' {
        Set-Installs @{ 'C:\php\php.exe' = $null } @{}
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 1
        $out[1] | Should -Be 'Device=TESTSRV01 Product=PHP Found=unknown Fixed=review-manually Path=C:\php\php.exe'
    }
    It 'unparsable version with -TreatUnknownAsClean -> exit 0' {
        Set-Installs @{ 'C:\php\php.exe' = $null } @{}
        $out = @(Invoke-Main -TreatUnknownAsClean)
        $out[-1] | Should -Be 0
        $out[0] | Should -Be 'OK: no vulnerable PHP/Node found (checked 1)'
    }
    It 'discovery failure -> exit 2 ERROR line' {
        Mock Find-Executables { throw 'disk unreadable' }
        $out = @(Invoke-Main)
        $out[-1] | Should -Be 2
        $out[0] | Should -Be 'ERROR: disk unreadable'
    }
    It 'ConvertTo-SemVer parses real banners and rejects junk' {
        ConvertTo-SemVer 'PHP 8.3.36 (cli) (built: Oct 21 2026)' | Should -Be ([version]'8.3.36')
        ConvertTo-SemVer 'v24.22.1' | Should -Be ([version]'24.22.1')
        ConvertTo-SemVer 'garbage' | Should -BeNullOrEmpty
    }
    It 'future branches are not flagged' {
        (Get-FixedVersion -Product 'PHP' -Version ([version]'8.6.0')).Vulnerable | Should -BeFalse
        (Get-FixedVersion -Product 'Node.js' -Version ([version]'27.0.0')).Vulnerable | Should -BeFalse
    }
    It 'summary mode: clean' {
        Set-Installs @{ 'C:\php\php.exe' = '8.3.36' } @{}
        $out = @(Invoke-Main -Summary)
        $out[-1] | Should -Be 0
        $out[0] | Should -Be 'OK (checked 1)'
        $out.Count | Should -Be 2
    }
    It 'summary mode: vulnerable single line' {
        Set-Installs @{ 'C:\php\php.exe' = '8.3.30' } @{ 'C:\Program Files\nodejs\node.exe' = '22.23.3' }
        $out = @(Invoke-Main -Summary)
        $out[-1] | Should -Be 1
        $out.Count | Should -Be 2
        $out[0] | Should -Be 'VULNERABLE 2: PHP 8.3.30; Node.js 22.23.3'
    }
    It 'summary line capped at 300 chars' {
        $many = 1..60 | ForEach-Object { "Device=X Product=Node.js Found=20.0.$_ Fixed=f Path=p$_" }
        $line = Get-SummaryLine -Checked 60 -Findings $many
        $line.Length | Should -BeLessOrEqual 300
        $line | Should -Match '^VULNERABLE 60: '
    }
    It 'summary mode: error' {
        Mock Find-Executables { throw 'boom' }
        $out = @(Invoke-Main -Summary)
        $out[-1] | Should -Be 2
        $out[0] | Should -Be 'ERROR: boom'
    }
    It 'script source has no prompts or Write-Host and passes content checks' {
        $src = Get-Content (Join-Path $PSScriptRoot 'Invoke-PhpNodeSecurityCheck.Asio.ps1') -Raw
        $src | Should -Not -Match 'Read-Host|Write-Host'
        $src | Should -Not -Match ('\b' + 'A' + 'I\b')
    }
}
