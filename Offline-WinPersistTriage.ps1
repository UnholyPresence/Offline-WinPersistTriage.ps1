<#
.SYNOPSIS
  Read-only triage for common Windows persistence mechanisms on an offline Windows volume.

.DESCRIPTION
  This script inspects an offline/mounted Windows installation for common persistence locations
  and practical indicators of compromise. It does not write to the target volume.

  Registry hives are copied from the target volume to the analyst workstation's temp directory.
  The temp copies are loaded under HKLM, queried, and unloaded. This avoids loading or modifying
  the evidence hives in place.

.REQUIREMENTS
  - Run from an elevated PowerShell session on an analyst Windows host.
  - Mount the target Windows disk/volume read-only whenever possible.
  - PowerShell 5.1+ recommended.

.EXAMPLE
  .\Offline-WinPersistTriage.ps1 -TargetPath E:\ -Format Table

.EXAMPLE
  .\Offline-WinPersistTriage.ps1 -TargetPath E:\Windows -Format Json -OutFile C:\Cases\host01_triage.json -ParseEvents

.EXAMPLE
  .\Offline-WinPersistTriage.ps1 -TargetPath E:\ -Format Csv -OutFile C:\Cases\host01_triage.csv -DeepFileScan
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [ValidateSet('Table', 'Json', 'Csv')]
    [string]$Format = 'Table',

    [string]$OutFile,

    [switch]$ParseEvents,

    [int]$EventDaysBack = 90,

    [switch]$DeepFileScan,

    [int]$MaxFileResults = 5000,

    [switch]$KeepTemp
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Findings = New-Object System.Collections.Generic.List[object]
$script:LoadedHiveNames = New-Object System.Collections.Generic.List[string]
$script:TempRoot = $null
$script:WindowsRoot = $null
$script:VolumeRoot = $null
$script:TargetLabel = $TargetPath

function Normalize-PathString {
    param([Parameter(Mandatory = $true)][string]$Path)

    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.TrimEnd('\') -ieq $root.TrimEnd('\')) {
        return $root
    }
    return $full.TrimEnd('\')
}

function Test-IsUnderPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    $p = Normalize-PathString -Path $Path
    $parentPath = Normalize-PathString -Path $Parent
    if (-not $parentPath.EndsWith('\')) { $parentPath += '\' }
    return $p.StartsWith($parentPath, [System.StringComparison]::OrdinalIgnoreCase)
}

function Convert-ValueToString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) {
        $take = [Math]::Min($Value.Length, 256)
        $out = (($Value | Select-Object -First $take | ForEach-Object { $_.ToString('X2') }) -join '')
        if ($Value.Length -gt 256) { $out += '...' }
        return $out
    }
    if ($Value -is [Array]) {
        return (($Value | ForEach-Object { [string]$_ }) -join '; ')
    }
    return [string]$Value
}

function Add-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Artifact,
        [Parameter(Mandatory = $true)][string]$Location,
        [AllowNull()][object]$Value,
        [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
        [string]$Severity = 'Info',
        [string]$Notes = '',
        [string]$Source = 'Offline disk'
    )

    $script:Findings.Add([pscustomobject]@{
        TimeUtc  = ((Get-Date).ToUniversalTime().ToString('s') + 'Z')
        Target   = $script:TargetLabel
        Severity = $Severity
        Category = $Category
        Artifact = $Artifact
        Location = $Location
        Value    = (Convert-ValueToString -Value $Value)
        Notes    = $Notes
        Source   = $Source
    }) | Out-Null
}

function Resolve-OfflineWindowsRoot {
    param([Parameter(Mandatory = $true)][string]$InputPath)

    $resolved = Normalize-PathString -Path ((Resolve-Path -LiteralPath $InputPath).ProviderPath)

    if (Test-Path -LiteralPath (Join-Path $resolved 'System32\config\SYSTEM') -PathType Leaf) {
        $script:WindowsRoot = $resolved
        $script:VolumeRoot = Normalize-PathString -Path (Split-Path -Path $resolved -Parent)
        return
    }

    $possibleWindows = Join-Path $resolved 'Windows'
    if (Test-Path -LiteralPath (Join-Path $possibleWindows 'System32\config\SYSTEM') -PathType Leaf) {
        $script:WindowsRoot = Normalize-PathString -Path $possibleWindows
        $script:VolumeRoot = $resolved
        return
    }

    throw "Could not find an offline Windows installation under '$InputPath'. Provide either the volume root, such as E:\, or the Windows directory, such as E:\Windows."
}

function Assert-Administrator {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run PowerShell as Administrator. This is required to load copied registry hives under HKLM on the analyst workstation.'
    }
}

function New-TempRoot {
    $script:TempRoot = Join-Path $env:TEMP ('OfflineWinTriage_' + [guid]::NewGuid().ToString('N'))
    New-Item -Path $script:TempRoot -ItemType Directory -Force | Out-Null
}

function Get-SafeName {
    param([Parameter(Mandatory = $true)][string]$Name)
    return (($Name -replace '[^A-Za-z0-9_\-]', '_').Trim('_'))
}

function Mount-HiveCopy {
    param(
        [Parameter(Mandatory = $true)][string]$HiveSource,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if (-not (Test-Path -LiteralPath $HiveSource -PathType Leaf)) {
        return $null
    }

    $safe = Get-SafeName -Name $Name
    $hiveLeaf = Split-Path -Path $HiveSource -Leaf
    $hiveDir = Split-Path -Path $HiveSource -Parent
    $hiveTempDir = Join-Path $script:TempRoot ($safe + '_' + [guid]::NewGuid().ToString('N'))
    $copyPath = Join-Path $hiveTempDir $hiveLeaf

    try {
        New-Item -Path $hiveTempDir -ItemType Directory -Force | Out-Null

        # Copy the hive using its original filename so Windows can associate matching transaction logs.
        Copy-Item -LiteralPath $HiveSource -Destination $copyPath -Force

        # Copy common registry transaction/log files beside the temp hive copy.
        foreach ($suffix in @('.LOG', '.LOG1', '.LOG2')) {
            $logSource = "$HiveSource$suffix"
            $logDest = "$copyPath$suffix"

            if (Test-Path -LiteralPath $logSource -PathType Leaf) {
                Copy-Item -LiteralPath $logSource -Destination $logDest -Force -ErrorAction SilentlyContinue
            }
        }

        # Copy transaction manager files if present.
        foreach ($tmSource in @(Get-ChildItem -LiteralPath $hiveDir -Filter "$hiveLeaf*.TM*" -File -ErrorAction SilentlyContinue)) {
            Copy-Item -LiteralPath $tmSource.FullName -Destination (Join-Path $hiveTempDir $tmSource.Name) -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Add-Finding -Category 'Registry' -Artifact 'Hive copy failed' -Location $HiveSource -Value $_.Exception.Message -Severity 'High' -Notes 'Unable to copy hive and transaction files to analyst temp directory.'
        return $null
    }

    $mountName = 'OFFTRIAGE_' + $safe + '_' + ([guid]::NewGuid().ToString('N').Substring(0, 8))

    $regStdOut = Join-Path $hiveTempDir 'regload.stdout.txt'
    $regStdErr = Join-Path $hiveTempDir 'regload.stderr.txt'

    & reg.exe load "HKLM\$mountName" "$copyPath" 1> $regStdOut 2> $regStdErr
    $regExitCode = $LASTEXITCODE

    $output = @()
    if (Test-Path -LiteralPath $regStdOut -PathType Leaf) {
        $output += Get-Content -LiteralPath $regStdOut -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $regStdErr -PathType Leaf) {
        $output += Get-Content -LiteralPath $regStdErr -ErrorAction SilentlyContinue
    }

    if ($regExitCode -ne 0) {
        Add-Finding -Category 'Registry' -Artifact 'Hive load failed' -Location $HiveSource -Value ($output -join ' ') -Severity 'High' -Notes 'The copied hive could not be loaded. If LOG1/LOG2 were absent or the source image is inconsistent, use a cleaner image/export or dedicated registry forensic tooling.'
        return $null
    }

    $script:LoadedHiveNames.Add($mountName) | Out-Null
    return [pscustomobject]@{
        Name = $mountName
        Root = "Registry::HKEY_LOCAL_MACHINE\$mountName"
        Copy = $copyPath
        Source = $HiveSource
    }
}

function Dismount-AllHives {
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    Start-Sleep -Milliseconds 250

    foreach ($name in @($script:LoadedHiveNames)) {
        try {
            & reg.exe unload "HKLM\$name" *> $null
        }
        catch {
            Add-Finding -Category 'Registry' -Artifact 'Hive unload warning' -Location "HKLM\$name" -Value $_.Exception.Message -Severity 'Medium' -Notes 'Manual unload may be required from regedit/reg.exe.'
        }
    }
}

function Join-RegistryPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )
    return ($Root.TrimEnd('\') + '\' + $RelativePath.TrimStart('\'))
}

function Get-OfflineRegItemProperty {
    param(
        [Parameter(Mandatory = $true)][string]$HiveRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $path = Join-RegistryPath -Root $HiveRoot -RelativePath $RelativePath
    if (Test-Path -LiteralPath $path) {
        return Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    }
    return $null
}

function Get-OfflineRegValues {
    param(
        [Parameter(Mandatory = $true)][string]$HiveRoot,
        [Parameter(Mandatory = $true)][string]$RelativePath
    )

    $path = Join-RegistryPath -Root $HiveRoot -RelativePath $RelativePath
    if (-not (Test-Path -LiteralPath $path)) { return @() }

    $props = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
    $skip = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
    $values = @()
    foreach ($prop in $props.PSObject.Properties) {
        if ($skip -contains $prop.Name) { continue }
        $values += [pscustomobject]@{
            Name  = $prop.Name
            Value = $prop.Value
            Path  = $path
        }
    }
    return $values
}

function Get-RegistryDefaultValue {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return $key.GetValue('')
    }
    catch {
        return $null
    }
}

function Test-SuspiciousCommandText {
    param([AllowNull()][string]$Text)

    $reasons = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

    $checks = @(
        @{ Regex = '(?i)\\appdata\\|\\users\\public\\|\\programdata\\|\\temp\\|\\windows\\temp\\|\\perflogs\\|\$recycle\.bin'; Reason = 'user-writable or temp path' },
        @{ Regex = '(?i)\b(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|installutil|bitsadmin|certutil|msbuild|wmic|forfiles|schtasks|cmd\.exe|cmd)\b'; Reason = 'script interpreter or LOLBin invocation' },
        @{ Regex = '(?i)-enc(odedcommand)?\b|executionpolicy\s+bypass|windowstyle\s+hidden|downloadstring|frombase64string|invoke-expression|\biex\b|invoke-webrequest|\biwr\b|\bcurl\s+https?://|\bwget\s+https?://'; Reason = 'PowerShell/download/obfuscation pattern' },
        @{ Regex = '(?i)https?://|ftp://'; Reason = 'network URL in persistence command' },
        @{ Regex = '(?i)\.(ps1|vbs|vbe|js|jse|wsf|hta|scr)(\s|$|`"|\")'; Reason = 'scriptable or screen-saver payload extension' },
        @{ Regex = '(?i)(psexesvc|paexec|mimikatz|rubeus|adfind|bloodhound|sharphound|winpeas|lazagne|ncat|nc\.exe|chisel|plink|socat)'; Reason = 'known offensive/admin tool name' },
        @{ Regex = '(?i)^[a-z]:\\[^`"]*\s+[^`"]*\.exe(\s|$)'; Reason = 'unquoted executable path with spaces' }
    )

    foreach ($check in $checks) {
        if ($Text -match $check.Regex) {
            if (-not $reasons.Contains($check.Reason)) { $reasons.Add($check.Reason) | Out-Null }
        }
    }

    return @($reasons)
}

function Get-SeverityForReasons {
    param([string[]]$Reasons)

    if ($null -eq $Reasons -or $Reasons.Count -eq 0) { return 'Info' }
    $joined = ($Reasons -join '; ')
    if ($joined -match '(?i)obfuscation|download|offensive|URL|LOLBin') { return 'High' }
    return 'Medium'
}

function Get-ExecutableCandidate {
    param([AllowNull()][string]$CommandLine)

    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $s = $CommandLine.Trim()
    if ($s -match '^\s*"([^"]+)"') { return $Matches[1] }
    if ($s -match '^\s*([^\s]+)') { return $Matches[1] }
    return $null
}

function Convert-ToOfflinePath {
    param([AllowNull()][string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $null }
    $path = $Candidate.Trim().Trim('"')
    $path = $path -replace '^\\\?\?\\', ''

    if ($path -match '(?i)^%SystemRoot%\\(.+)$') { return (Join-Path $script:WindowsRoot $Matches[1]) }
    if ($path -match '(?i)^%windir%\\(.+)$') { return (Join-Path $script:WindowsRoot $Matches[1]) }
    if ($path -match '(?i)^\\SystemRoot\\(.+)$') { return (Join-Path $script:WindowsRoot $Matches[1]) }
    if ($path -match '(?i)^System32\\(.+)$') { return (Join-Path (Join-Path $script:WindowsRoot 'System32') $Matches[1]) }
    if ($path -match '(?i)^[A-Z]:\\(.+)$') { return (Join-Path $script:VolumeRoot $Matches[1]) }
    if ($path -match '(?i)^\\Windows\\(.+)$') { return (Join-Path $script:VolumeRoot ($path.TrimStart('\'))) }
    return $null
}

function Get-FileEvidenceString {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return "Missing offline path: $Path" }

    try {
        $item = Get-Item -LiteralPath $Path -Force
        $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
        $sigText = ''
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $sigText = " Signature=$($sig.Status)"
            if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
                $sigText += " Signer=$($sig.SignerCertificate.Subject)"
            }
        }
        catch {
            $sigText = ' Signature=NotChecked'
        }
        return "Size=$($item.Length) LastWriteUtc=$($item.LastWriteTimeUtc.ToString('s'))Z SHA256=$hash$sigText"
    }
    catch {
        return "Evidence collection failed: $($_.Exception.Message)"
    }
}

function Add-CommandFinding {
    param(
        [string]$Category,
        [string]$Artifact,
        [string]$Location,
        [string]$Command,
        [string]$DefaultSeverity = 'Low',
        [string]$ExtraNotes = ''
    )

    $reasons = @(Test-SuspiciousCommandText -Text $Command)
    $severity = $DefaultSeverity
    if ($reasons.Count -gt 0) { $severity = Get-SeverityForReasons -Reasons $reasons }

    $notes = $ExtraNotes
    if ($reasons.Count -gt 0) {
        if ($notes) { $notes += ' ' }
        $notes += 'Suspicious indicators: ' + ($reasons -join '; ')
    }

    $candidate = Get-ExecutableCandidate -CommandLine $Command
    $offline = Convert-ToOfflinePath -Candidate $candidate
    if ($offline) {
        $evidence = Get-FileEvidenceString -Path $offline
        if ($notes) { $notes += ' ' }
        $notes += "ResolvedExecutable=$offline $evidence"
        if ($evidence -match '^Missing offline path') { $severity = 'Medium' }
    }

    Add-Finding -Category $Category -Artifact $Artifact -Location $Location -Value $Command -Severity $severity -Notes $notes
}

function Inspect-SoftwareHive {
    param([Parameter(Mandatory = $true)][string]$HiveRoot)

    $autorunKeys = @(
        @{ Rel = 'Microsoft\Windows\CurrentVersion\Run'; Artifact = 'HKLM Run' },
        @{ Rel = 'Microsoft\Windows\CurrentVersion\RunOnce'; Artifact = 'HKLM RunOnce' },
        @{ Rel = 'Microsoft\Windows\CurrentVersion\RunOnceEx'; Artifact = 'HKLM RunOnceEx' },
        @{ Rel = 'Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Artifact = 'HKLM Policies Explorer Run' },
        @{ Rel = 'Wow6432Node\Microsoft\Windows\CurrentVersion\Run'; Artifact = 'HKLM Wow6432Node Run' },
        @{ Rel = 'Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Artifact = 'HKLM Wow6432Node RunOnce' }
    )

    foreach ($key in $autorunKeys) {
        foreach ($value in @(Get-OfflineRegValues -HiveRoot $HiveRoot -RelativePath $key.Rel)) {
            Add-CommandFinding -Category 'Registry autorun' -Artifact ("$($key.Artifact): $($value.Name)") -Location $value.Path -Command (Convert-ValueToString $value.Value) -DefaultSeverity 'Low'
        }
    }

    $winlogonRel = 'Microsoft\Windows NT\CurrentVersion\Winlogon'
    $winlogon = Get-OfflineRegItemProperty -HiveRoot $HiveRoot -RelativePath $winlogonRel
    if ($winlogon) {
        foreach ($name in @('Shell', 'Userinit', 'Taskman', 'AppSetup', 'VMApplet')) {
            $prop = $winlogon.PSObject.Properties[$name]
            if (-not $prop) { continue }
            $val = Convert-ValueToString $prop.Value
            $report = $false
            $severity = 'Medium'
            $note = 'Winlogon persistence-sensitive value.'

            if ($name -eq 'Shell' -and (($val.Trim()).ToLowerInvariant() -ne 'explorer.exe')) {
                $report = $true
                $severity = 'High'
                $note = 'Non-default Winlogon Shell value.'
            }
            elseif ($name -eq 'Userinit') {
                $compact = ($val -replace '\s', '').ToLowerInvariant()
                if ($compact -notmatch '^(c:\\windows\\system32\\)?userinit\.exe,?$') {
                    $report = $true
                    $severity = 'High'
                    $note = 'Non-default Winlogon Userinit value.'
                }
            }
            elseif ($name -in @('Taskman', 'AppSetup')) {
                if (-not [string]::IsNullOrWhiteSpace($val)) {
                    $report = $true
                    $severity = 'High'
                    $note = "Unexpected Winlogon $name value."
                }
            }

            if ($report) {
                Add-CommandFinding -Category 'Registry autorun' -Artifact "Winlogon $name" -Location (Join-RegistryPath $HiveRoot $winlogonRel) -Command $val -DefaultSeverity $severity -ExtraNotes $note
            }
        }
    }

    $appInitRel = 'Microsoft\Windows NT\CurrentVersion\Windows'
    $appInit = Get-OfflineRegItemProperty -HiveRoot $HiveRoot -RelativePath $appInitRel
    if ($appInit) {
        $dllsProp = $appInit.PSObject.Properties['AppInit_DLLs']
        $loadProp = $appInit.PSObject.Properties['LoadAppInit_DLLs']
        $dlls = ''
        $load = ''
        if ($dllsProp) { $dlls = Convert-ValueToString $dllsProp.Value }
        if ($loadProp) { $load = Convert-ValueToString $loadProp.Value }
        if (-not [string]::IsNullOrWhiteSpace($dlls) -or $load -eq '1') {
            Add-CommandFinding -Category 'Registry autorun' -Artifact 'AppInit_DLLs' -Location (Join-RegistryPath $HiveRoot $appInitRel) -Command ("AppInit_DLLs=$dlls LoadAppInit_DLLs=$load") -DefaultSeverity 'High' -ExtraNotes 'AppInit_DLLs can load DLLs into user-mode processes.'
        }
    }

    foreach ($baseRel in @('Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options')) {
        $basePath = Join-RegistryPath $HiveRoot $baseRel
        if (-not (Test-Path -LiteralPath $basePath)) { continue }
        foreach ($child in @(Get-ChildItem -LiteralPath $basePath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            foreach ($interesting in @('Debugger', 'VerifierDlls')) {
                $prop = $props.PSObject.Properties[$interesting]
                if ($prop -and -not [string]::IsNullOrWhiteSpace((Convert-ValueToString $prop.Value))) {
                    Add-CommandFinding -Category 'Registry autorun' -Artifact "IFEO $interesting for $($child.PSChildName)" -Location $child.PSPath -Command (Convert-ValueToString $prop.Value) -DefaultSeverity 'High' -ExtraNotes 'Image File Execution Options can redirect or instrument process execution.'
                }
            }

            $silentPath = Join-RegistryPath $child.PSPath 'SilentProcessExit'
            if (Test-Path -LiteralPath $silentPath) {
                $silentProps = Get-ItemProperty -LiteralPath $silentPath -ErrorAction SilentlyContinue
                if ($silentProps) {
                    foreach ($pname in @('MonitorProcess', 'ReportingMode')) {
                        $p = $silentProps.PSObject.Properties[$pname]
                        if ($p) {
                            Add-CommandFinding -Category 'Registry autorun' -Artifact "IFEO SilentProcessExit $pname for $($child.PSChildName)" -Location $silentPath -Command (Convert-ValueToString $p.Value) -DefaultSeverity 'High' -ExtraNotes 'SilentProcessExit can launch a monitor process when the target process exits.'
                        }
                    }
                }
            }
        }
    }

    foreach ($activeRel in @('Microsoft\Active Setup\Installed Components', 'Wow6432Node\Microsoft\Active Setup\Installed Components')) {
        $basePath = Join-RegistryPath $HiveRoot $activeRel
        if (-not (Test-Path -LiteralPath $basePath)) { continue }
        foreach ($child in @(Get-ChildItem -LiteralPath $basePath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $stub = $props.PSObject.Properties['StubPath']
            if ($stub) {
                $cmd = Convert-ValueToString $stub.Value
                $reasons = @(Test-SuspiciousCommandText -Text $cmd)
                if ($reasons.Count -gt 0) {
                    Add-CommandFinding -Category 'Registry autorun' -Artifact "Active Setup StubPath $($child.PSChildName)" -Location $child.PSPath -Command $cmd -DefaultSeverity 'Medium' -ExtraNotes 'Active Setup runs per-user initialization commands.'
                }
            }
        }
    }
}

function Get-CurrentControlSetName {
    param([Parameter(Mandatory = $true)][string]$HiveRoot)

    $select = Get-OfflineRegItemProperty -HiveRoot $HiveRoot -RelativePath 'Select'
    if ($select -and $select.PSObject.Properties['Current']) {
        return ('ControlSet{0:D3}' -f [int]$select.Current)
    }
    return 'ControlSet001'
}

function Inspect-SystemHive {
    param([Parameter(Mandatory = $true)][string]$HiveRoot)

    $ccs = Get-CurrentControlSetName -HiveRoot $HiveRoot

    $servicesPath = Join-RegistryPath $HiveRoot "$ccs\Services"
    if (Test-Path -LiteralPath $servicesPath) {
        foreach ($svc in @(Get-ChildItem -LiteralPath $servicesPath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $svc.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            $start = $null
            $type = $null
            if ($props.PSObject.Properties['Start']) { $start = [int]$props.Start }
            if ($props.PSObject.Properties['Type']) { $type = [int]$props.Type }
            $autoOrBoot = ($start -eq 0 -or $start -eq 1 -or $start -eq 2)

            $imageProp = $props.PSObject.Properties['ImagePath']
            if ($imageProp) {
                $image = Convert-ValueToString $imageProp.Value
                $reasons = @(Test-SuspiciousCommandText -Text $image)

                $candidate = Get-ExecutableCandidate -CommandLine $image
                $offline = Convert-ToOfflinePath -Candidate $candidate
                $extraReasons = New-Object System.Collections.Generic.List[string]

                if ($offline) {
                    if (-not (Test-Path -LiteralPath $offline -PathType Leaf)) {
                        $extraReasons.Add('referenced executable/driver missing from offline path') | Out-Null
                    }
                    elseif (($type -band 1) -or ($type -band 2)) {
                        if ($offline -notmatch '(?i)\\Windows\\System32\\drivers\\') {
                            $extraReasons.Add('driver service image outside System32\drivers') | Out-Null
                        }
                    }
                }

                $allReasons = @($reasons + @($extraReasons))
                if ($allReasons.Count -gt 0 -or ($autoOrBoot -and $image -match '(?i)\\users\\|\\programdata\\|\\temp\\')) {
                    $sev = Get-SeverityForReasons -Reasons $allReasons
                    if ($sev -eq 'Info') { $sev = 'Medium' }
                    Add-CommandFinding -Category 'Service persistence' -Artifact "Service ImagePath: $($svc.PSChildName)" -Location $svc.PSPath -Command $image -DefaultSeverity $sev -ExtraNotes ("Start=$start Type=$type " + (($allReasons | Select-Object -Unique) -join '; '))
                }
            }

            $paramsPath = Join-RegistryPath $svc.PSPath 'Parameters'
            if (Test-Path -LiteralPath $paramsPath) {
                $paramProps = Get-ItemProperty -LiteralPath $paramsPath -ErrorAction SilentlyContinue
                if ($paramProps -and $paramProps.PSObject.Properties['ServiceDll']) {
                    $dll = Convert-ValueToString $paramProps.ServiceDll
                    $reasons = @(Test-SuspiciousCommandText -Text $dll)
                    $offlineDll = Convert-ToOfflinePath -Candidate $dll
                    if ($offlineDll -and -not (Test-Path -LiteralPath $offlineDll -PathType Leaf)) {
                        $reasons += 'referenced ServiceDll missing from offline path'
                    }
                    if ($reasons.Count -gt 0 -or ($autoOrBoot -and $dll -match '(?i)\\users\\|\\programdata\\|\\temp\\')) {
                        Add-CommandFinding -Category 'Service persistence' -Artifact "ServiceDll: $($svc.PSChildName)" -Location $paramsPath -Command $dll -DefaultSeverity (Get-SeverityForReasons -Reasons $reasons) -ExtraNotes ("Start=$start " + (($reasons | Select-Object -Unique) -join '; '))
                    }
                }
            }
        }
    }

    $sessionRel = "$ccs\Control\Session Manager"
    $session = Get-OfflineRegItemProperty -HiveRoot $HiveRoot -RelativePath $sessionRel
    if ($session -and $session.PSObject.Properties['BootExecute']) {
        $boot = Convert-ValueToString $session.BootExecute
        if (($boot -replace '\s+', ' ').Trim().ToLowerInvariant() -ne 'autocheck autochk *') {
            Add-CommandFinding -Category 'Registry autorun' -Artifact 'BootExecute' -Location (Join-RegistryPath $HiveRoot $sessionRel) -Command $boot -DefaultSeverity 'High' -ExtraNotes 'Non-default Session Manager BootExecute value.'
        }
    }

    $lsaRel = "$ccs\Control\Lsa"
    $lsa = Get-OfflineRegItemProperty -HiveRoot $HiveRoot -RelativePath $lsaRel
    if ($lsa) {
        $known = @{
            'Authentication Packages' = @('msv1_0')
            'Notification Packages'   = @('scecli')
            'Security Packages'       = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u')
        }
        foreach ($name in $known.Keys) {
            $prop = $lsa.PSObject.Properties[$name]
            if (-not $prop) { continue }
            $vals = @($prop.Value | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })
            foreach ($v in $vals) {
                if ($known[$name] -notcontains $v.ToLowerInvariant()) {
                    Add-CommandFinding -Category 'Credential/security package persistence' -Artifact "LSA $name" -Location (Join-RegistryPath $HiveRoot $lsaRel) -Command $v -DefaultSeverity 'High' -ExtraNotes 'Unexpected LSA package value. Validate against the host baseline.'
                }
            }
        }
    }

    $printRel = "$ccs\Control\Print\Monitors"
    $printPath = Join-RegistryPath $HiveRoot $printRel
    if (Test-Path -LiteralPath $printPath) {
        $standardDrivers = @('localspl.dll', 'tcpmon.dll', 'usbmon.dll', 'wsdmon.dll', 'fxsmon.dll', 'apmon.dll', 'msonpppr.dll')
        foreach ($mon in @(Get-ChildItem -LiteralPath $printPath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $mon.PSPath -ErrorAction SilentlyContinue
            if ($props -and $props.PSObject.Properties['Driver']) {
                $driver = Convert-ValueToString $props.Driver
                if ($standardDrivers -notcontains $driver.ToLowerInvariant() -or (Test-SuspiciousCommandText -Text $driver).Count -gt 0) {
                    Add-CommandFinding -Category 'Registry autorun' -Artifact "Print Monitor: $($mon.PSChildName)" -Location $mon.PSPath -Command $driver -DefaultSeverity 'Medium' -ExtraNotes 'Print monitors can load DLLs under the spooler service context.'
                }
            }
        }
    }

    foreach ($portProxyRel in @("$ccs\Services\PortProxy\v4tov4\tcp", "$ccs\Services\PortProxy\v6tov6\tcp", "$ccs\Services\PortProxy\v4tov6\tcp", "$ccs\Services\PortProxy\v6tov4\tcp")) {
        $ppPath = Join-RegistryPath $HiveRoot $portProxyRel
        if (-not (Test-Path -LiteralPath $ppPath)) { continue }
        foreach ($val in @(Get-OfflineRegValues -HiveRoot $HiveRoot -RelativePath $portProxyRel)) {
            Add-Finding -Category 'Network persistence' -Artifact "PortProxy: $($val.Name)" -Location $val.Path -Value $val.Value -Severity 'Medium' -Notes 'netsh interface portproxy persistence/traffic relay setting.'
        }
    }

    $runControlKeys = @(
        "$ccs\Control\SafeBoot\AlternateShell",
        "$ccs\Control\Terminal Server\Wds\rdpwd\StartupPrograms"
    )
    foreach ($rel in $runControlKeys) {
        foreach ($val in @(Get-OfflineRegValues -HiveRoot $HiveRoot -RelativePath $rel)) {
            Add-CommandFinding -Category 'Registry autorun' -Artifact "System control autorun: $($val.Name)" -Location $val.Path -Command (Convert-ValueToString $val.Value) -DefaultSeverity 'Medium'
        }
    }
}

function Inspect-UserHive {
    param(
        [Parameter(Mandatory = $true)][string]$HiveRoot,
        [Parameter(Mandatory = $true)][string]$UserName
    )

    $autorunKeys = @(
        @{ Rel = 'Software\Microsoft\Windows\CurrentVersion\Run'; Artifact = 'HKCU Run' },
        @{ Rel = 'Software\Microsoft\Windows\CurrentVersion\RunOnce'; Artifact = 'HKCU RunOnce' },
        @{ Rel = 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Artifact = 'HKCU Policies Explorer Run' },
        @{ Rel = 'Software\Microsoft\Windows NT\CurrentVersion\Windows'; Artifact = 'HKCU Windows Load/Run' },
        @{ Rel = 'Software\Microsoft\Command Processor'; Artifact = 'HKCU Command Processor AutoRun' }
    )

    foreach ($key in $autorunKeys) {
        foreach ($value in @(Get-OfflineRegValues -HiveRoot $HiveRoot -RelativePath $key.Rel)) {
            if ($key.Artifact -eq 'HKCU Windows Load/Run' -and $value.Name -notin @('Load', 'Run')) { continue }
            if ($key.Artifact -eq 'HKCU Command Processor AutoRun' -and $value.Name -ne 'AutoRun') { continue }
            Add-CommandFinding -Category 'User registry autorun' -Artifact "$($key.Artifact): $UserName\$($value.Name)" -Location $value.Path -Command (Convert-ValueToString $value.Value) -DefaultSeverity 'Low'
        }
    }
}

function Inspect-UsrClassHive {
    param(
        [Parameter(Mandatory = $true)][string]$HiveRoot,
        [Parameter(Mandatory = $true)][string]$UserName
    )

    $clsidPath = Join-RegistryPath $HiveRoot 'CLSID'
    if (-not (Test-Path -LiteralPath $clsidPath)) { return }
    $count = 0
    foreach ($clsid in @(Get-ChildItem -LiteralPath $clsidPath -ErrorAction SilentlyContinue)) {
        foreach (${serverKey} in @('InprocServer32', 'LocalServer32')) {
            $serverPath = Join-RegistryPath $clsid.PSPath ${serverKey}
            if (-not (Test-Path -LiteralPath $serverPath)) { continue }
            $default = Get-RegistryDefaultValue -Path $serverPath
            if ([string]::IsNullOrWhiteSpace($default)) { continue }
            $reasons = @(Test-SuspiciousCommandText -Text $default)
            if ($reasons.Count -gt 0) {
                Add-CommandFinding -Category 'COM persistence' -Artifact "User COM ${serverKey}: $UserName\$($clsid.PSChildName)" -Location $serverPath -Command $default -DefaultSeverity 'Medium' -ExtraNotes 'User-writable COM registration can be used for hijacking or persistence.'
                $count++
                if ($count -ge 250) {
                    Add-Finding -Category 'COM persistence' -Artifact 'User COM scan truncated' -Location $clsidPath -Value $count -Severity 'Info' -Notes 'Stopped reporting after 250 suspicious COM entries for this hive.'
                    return
                }
            }
        }
    }
}

function Inspect-UserHives {
    $usersRoot = Join-Path $script:VolumeRoot 'Users'
    if (-not (Test-Path -LiteralPath $usersRoot -PathType Container)) { return }

    foreach ($profile in @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($profile.Name -in @('All Users', 'Default User')) { continue }

        $ntuser = Join-Path $profile.FullName 'NTUSER.DAT'
        if (Test-Path -LiteralPath $ntuser -PathType Leaf) {
            $hive = Mount-HiveCopy -HiveSource $ntuser -Name ("NTUSER_$($profile.Name)")
            if ($hive) {
                try { Inspect-UserHive -HiveRoot $hive.Root -UserName $profile.Name }
                catch { Add-Finding -Category 'User registry autorun' -Artifact 'User hive inspection failed' -Location $ntuser -Value $_.Exception.Message -Severity 'Medium' }
            }
        }

        $usrclass = Join-Path $profile.FullName 'AppData\Local\Microsoft\Windows\UsrClass.dat'
        if (Test-Path -LiteralPath $usrclass -PathType Leaf) {
            $hive = Mount-HiveCopy -HiveSource $usrclass -Name ("USRCLASS_$($profile.Name)")
            if ($hive) {
                try { Inspect-UsrClassHive -HiveRoot $hive.Root -UserName $profile.Name }
                catch { Add-Finding -Category 'COM persistence' -Artifact 'UsrClass inspection failed' -Location $usrclass -Value $_.Exception.Message -Severity 'Medium' }
            }
        }
    }
}

function Get-LnkTargetText {
    param([Parameter(Mandatory = $true)][string]$Path)

    try {
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut($Path)
        return (($lnk.TargetPath + ' ' + $lnk.Arguments).Trim())
    }
    catch {
        return ''
    }
}

function Inspect-StartupFolders {
    $folders = New-Object System.Collections.Generic.List[string]
    $folders.Add((Join-Path $script:VolumeRoot 'ProgramData\Microsoft\Windows\Start Menu\Programs\Startup')) | Out-Null

    $usersRoot = Join-Path $script:VolumeRoot 'Users'
    if (Test-Path -LiteralPath $usersRoot -PathType Container) {
        foreach ($profile in @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue)) {
            $folders.Add((Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')) | Out-Null
        }
    }

    foreach ($folder in @($folders)) {
        if (-not (Test-Path -LiteralPath $folder -PathType Container)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $folder -File -Force -ErrorAction SilentlyContinue)) {
            $value = $file.FullName
            $notes = Get-FileEvidenceString -Path $file.FullName
            if ($file.Extension -ieq '.lnk') {
                $target = Get-LnkTargetText -Path $file.FullName
                if ($target) { $value = "$($file.FullName) -> $target" }
            }
            Add-Finding -Category 'Startup folder' -Artifact 'Startup folder item' -Location $folder -Value $value -Severity 'Medium' -Notes $notes
        }
    }
}

function Inspect-ScheduledTasks {
    $tasksRoot = Join-Path $script:WindowsRoot 'System32\Tasks'
    if (-not (Test-Path -LiteralPath $tasksRoot -PathType Container)) { return }

    foreach ($taskFile in @(Get-ChildItem -LiteralPath $tasksRoot -File -Recurse -Force -ErrorAction SilentlyContinue)) {
        try {
            $raw = Get-Content -LiteralPath $taskFile.FullName -Raw -ErrorAction Stop
            [xml]$xml = $raw
            $execNodes = Select-Xml -Xml $xml -XPath "//*[local-name()='Exec']" -ErrorAction SilentlyContinue
            $hiddenNode = Select-Xml -Xml $xml -XPath "//*[local-name()='Hidden']" -ErrorAction SilentlyContinue | Select-Object -First 1
            $uriNode = Select-Xml -Xml $xml -XPath "//*[local-name()='URI']" -ErrorAction SilentlyContinue | Select-Object -First 1
            $authorNode = Select-Xml -Xml $xml -XPath "//*[local-name()='Author']" -ErrorAction SilentlyContinue | Select-Object -First 1

            $hidden = $false
            if ($hiddenNode -and $hiddenNode.Node.InnerText -match '(?i)^true$') { $hidden = $true }
            $uri = ''
            if ($uriNode) { $uri = $uriNode.Node.InnerText }
            $author = ''
            if ($authorNode) { $author = $authorNode.Node.InnerText }

            foreach ($exec in @($execNodes)) {
                # Walk child nodes directly to avoid namespace/XPath issues across PowerShell versions.
                $cmd = ''
                $args = ''
                foreach ($child in @($exec.Node.ChildNodes)) {
                    if ($child.LocalName -eq 'Command') { $cmd = $child.InnerText }
                    if ($child.LocalName -eq 'Arguments') { $args = $child.InnerText }
                }
                $combined = ($cmd + ' ' + $args).Trim()
                if ([string]::IsNullOrWhiteSpace($combined)) { continue }

                $reasons = @(Test-SuspiciousCommandText -Text $combined)
                if ($hidden) { $reasons += 'hidden scheduled task' }
                if ($reasons.Count -gt 0) {
                    $sev = Get-SeverityForReasons -Reasons $reasons
                    if ($hidden -and $sev -eq 'Info') { $sev = 'Medium' }
                    Add-CommandFinding -Category 'Scheduled task' -Artifact "Task action: $uri" -Location $taskFile.FullName -Command $combined -DefaultSeverity $sev -ExtraNotes ("Author=$author Hidden=$hidden Indicators=" + (($reasons | Select-Object -Unique) -join '; '))
                }
            }
        }
        catch {
            Add-Finding -Category 'Scheduled task' -Artifact 'Task parse failed' -Location $taskFile.FullName -Value $_.Exception.Message -Severity 'Low' -Notes 'Task file could not be parsed as XML.'
        }
    }
}

function Inspect-PowerShellArtifacts {
    $profilePaths = New-Object System.Collections.Generic.List[string]
    $profilePaths.Add((Join-Path $script:WindowsRoot 'System32\WindowsPowerShell\v1.0\profile.ps1')) | Out-Null
    $profilePaths.Add((Join-Path $script:WindowsRoot 'SysWOW64\WindowsPowerShell\v1.0\profile.ps1')) | Out-Null

    $usersRoot = Join-Path $script:VolumeRoot 'Users'
    if (Test-Path -LiteralPath $usersRoot -PathType Container) {
        foreach ($profile in @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue)) {
            $profilePaths.Add((Join-Path $profile.FullName 'Documents\WindowsPowerShell\profile.ps1')) | Out-Null
            $profilePaths.Add((Join-Path $profile.FullName 'Documents\PowerShell\profile.ps1')) | Out-Null
        }
    }

    foreach ($path in @($profilePaths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $content = ''
            try { $content = Get-Content -LiteralPath $path -Raw -ErrorAction Stop }
            catch { $content = '' }
            $reasons = @(Test-SuspiciousCommandText -Text $content)
            $sev = 'Medium'
            if ($reasons.Count -gt 0) { $sev = Get-SeverityForReasons -Reasons $reasons }
            Add-Finding -Category 'PowerShell persistence' -Artifact 'PowerShell profile' -Location $path -Value $path -Severity $sev -Notes ((Get-FileEvidenceString -Path $path) + ' Indicators=' + (($reasons | Select-Object -Unique) -join '; '))
        }
    }

    if (Test-Path -LiteralPath $usersRoot -PathType Container) {
        foreach ($profile in @(Get-ChildItem -LiteralPath $usersRoot -Directory -Force -ErrorAction SilentlyContinue)) {
            $history = Join-Path $profile.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (-not (Test-Path -LiteralPath $history -PathType Leaf)) { continue }
            try {
                $hits = Get-Content -LiteralPath $history -ErrorAction Stop | Where-Object { (Test-SuspiciousCommandText -Text $_).Count -gt 0 } | Select-Object -Last 25
                foreach ($hit in @($hits)) {
                    Add-Finding -Category 'PowerShell IOC' -Artifact "PSReadLine suspicious history: $($profile.Name)" -Location $history -Value $hit -Severity 'Medium' -Notes 'Command history hit; validate timeline and user context.'
                }
            }
            catch {
                Add-Finding -Category 'PowerShell IOC' -Artifact 'PSReadLine parse failed' -Location $history -Value $_.Exception.Message -Severity 'Low'
            }
        }
    }
}

function Inspect-WmiRepositoryStrings {
    $objects = Join-Path $script:WindowsRoot 'System32\wbem\Repository\OBJECTS.DATA'
    if (-not (Test-Path -LiteralPath $objects -PathType Leaf)) { return }

    try {
        $item = Get-Item -LiteralPath $objects -Force
        if ($item.Length -gt 268435456) {
            Add-Finding -Category 'WMI persistence' -Artifact 'WMI repository string scan skipped' -Location $objects -Value $item.Length -Severity 'Info' -Notes 'OBJECTS.DATA is larger than 256 MB. Use a dedicated WMI repository parser.'
            return
        }

        $bytes = [System.IO.File]::ReadAllBytes($objects)
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        $unicode = [System.Text.Encoding]::Unicode.GetString($bytes)
        $combined = $ascii + "`n" + $unicode

        $patterns = @('__EventFilter', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__FilterToConsumerBinding', 'powershell', 'mshta', 'wscript', 'rundll32', 'regsvr32')
        $hits = @()
        foreach ($p in $patterns) {
            if ($combined -match [regex]::Escape($p)) { $hits += $p }
        }
        if ($hits.Count -gt 0) {
            Add-Finding -Category 'WMI persistence' -Artifact 'WMI repository string hits' -Location $objects -Value (($hits | Select-Object -Unique) -join '; ') -Severity 'Medium' -Notes 'String hit only. Confirm with a dedicated WMI offline parser or live forensic image copy.'
        }
    }
    catch {
        Add-Finding -Category 'WMI persistence' -Artifact 'WMI repository scan failed' -Location $objects -Value $_.Exception.Message -Severity 'Low'
    }
}

function Inspect-PrefetchIocs {
    $prefetch = Join-Path $script:WindowsRoot 'Prefetch'
    if (-not (Test-Path -LiteralPath $prefetch -PathType Container)) { return }

    $interesting = '(?i)(PSEXESVC|PAEXEC|MIMIKATZ|RUBEUS|ADFind|SHARPHOUND|BLOODHOUND|WINPEAS|LAZAGNE|NCAT|NETCAT|CHISEL|PLINK|SOCAT|MSHTA|REGSVR32|RUNDLL32|CERTUTIL|BITSADMIN|POWERSHELL|PWSH|WScript|CScript)'
    foreach ($pf in @(Get-ChildItem -LiteralPath $prefetch -Filter '*.pf' -File -Force -ErrorAction SilentlyContinue)) {
        if ($pf.Name -match $interesting) {
            Add-Finding -Category 'Execution IOC' -Artifact 'Prefetch filename hit' -Location $pf.FullName -Value $pf.Name -Severity 'Medium' -Notes ("LastWriteUtc=$($pf.LastWriteTimeUtc.ToString('s'))Z Size=$($pf.Length)")
        }
    }
}

function Inspect-HostsFile {
    $hosts = Join-Path $script:WindowsRoot 'System32\drivers\etc\hosts'
    if (-not (Test-Path -LiteralPath $hosts -PathType Leaf)) { return }

    try {
        $lines = Get-Content -LiteralPath $hosts -ErrorAction Stop | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' -and $_ -notmatch '^(::1|127\.0\.0\.1)\s+localhost\b' }
        foreach ($line in @($lines)) {
            Add-Finding -Category 'Network IOC' -Artifact 'Hosts file non-default entry' -Location $hosts -Value $line -Severity 'Low' -Notes 'Review for sinkholing, blocking, or credential-harvesting redirection.'
        }
    }
    catch {
        Add-Finding -Category 'Network IOC' -Artifact 'Hosts file read failed' -Location $hosts -Value $_.Exception.Message -Severity 'Low'
    }
}

function Inspect-AmcacheHive {
    $amcache = Join-Path $script:WindowsRoot 'AppCompat\Programs\Amcache.hve'
    if (-not (Test-Path -LiteralPath $amcache -PathType Leaf)) { return }

    $hive = Mount-HiveCopy -HiveSource $amcache -Name 'AMCACHE'
    if (-not $hive) { return }

    try {
        $invPath = Join-RegistryPath $hive.Root 'Root\InventoryApplicationFile'
        if (-not (Test-Path -LiteralPath $invPath)) { return }
        $reported = 0
        foreach ($entry in @(Get-ChildItem -LiteralPath $invPath -ErrorAction SilentlyContinue)) {
            $props = Get-ItemProperty -LiteralPath $entry.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $path = ''
            $name = ''
            if ($props.PSObject.Properties['LowerCaseLongPath']) { $path = Convert-ValueToString $props.LowerCaseLongPath }
            if ($props.PSObject.Properties['Name']) { $name = Convert-ValueToString $props.Name }
            $combined = ($path + ' ' + $name).Trim()
            if ([string]::IsNullOrWhiteSpace($combined)) { continue }

            $reasons = @(Test-SuspiciousCommandText -Text $combined)
            if ($reasons.Count -gt 0) {
                Add-Finding -Category 'Execution IOC' -Artifact 'Amcache suspicious application file' -Location $entry.PSPath -Value $combined -Severity (Get-SeverityForReasons -Reasons $reasons) -Notes ('Indicators=' + (($reasons | Select-Object -Unique) -join '; '))
                $reported++
                if ($reported -ge 500) {
                    Add-Finding -Category 'Execution IOC' -Artifact 'Amcache scan truncated' -Location $invPath -Value $reported -Severity 'Info' -Notes 'Stopped reporting after 500 suspicious Amcache entries.'
                    return
                }
            }
        }
    }
    catch {
        Add-Finding -Category 'Execution IOC' -Artifact 'Amcache inspection failed' -Location $amcache -Value $_.Exception.Message -Severity 'Low'
    }
}

function Inspect-EventLogs {
    if (-not $ParseEvents) { return }

    $start = (Get-Date).AddDays(-1 * [Math]::Abs($EventDaysBack))
    $eventSpecs = @(
        @{ Path = (Join-Path $script:WindowsRoot 'System32\winevt\Logs\System.evtx'); Ids = @(7045, 7040, 7030); Category = 'Event IOC'; Artifact = 'System service change/install event' },
        @{ Path = (Join-Path $script:WindowsRoot 'System32\winevt\Logs\Security.evtx'); Ids = @(1102, 4688, 4697, 4698, 4702, 4720, 4728, 4732, 4738); Category = 'Event IOC'; Artifact = 'Security persistence-relevant event' },
        @{ Path = (Join-Path $script:WindowsRoot 'System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx'); Ids = @(4103, 4104, 4105, 4106); Category = 'PowerShell IOC'; Artifact = 'PowerShell operational event' },
        @{ Path = (Join-Path $script:WindowsRoot 'System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx'); Ids = @(5857, 5858, 5859, 5860, 5861); Category = 'WMI IOC'; Artifact = 'WMI activity event' }
    )

    foreach ($spec in $eventSpecs) {
        if (-not (Test-Path -LiteralPath $spec.Path -PathType Leaf)) { continue }
        try {
            $events = Get-WinEvent -FilterHashtable @{ Path = $spec.Path; Id = $spec.Ids; StartTime = $start } -ErrorAction Stop | Select-Object -First 300
            foreach ($evt in @($events)) {
                $msg = ''
                try { $msg = $evt.Message } catch { $msg = '' }
                $trimmed = ($msg -replace "\r?\n", ' ')
                if ($trimmed.Length -gt 1000) { $trimmed = $trimmed.Substring(0, 1000) + '...' }
                $sev = 'Medium'
                if ($evt.Id -in @(1102, 4697, 4698, 4702, 7045, 5861)) { $sev = 'High' }
                Add-Finding -Category $spec.Category -Artifact "$($spec.Artifact) ID=$($evt.Id)" -Location $spec.Path -Value $trimmed -Severity $sev -Notes "Provider=$($evt.ProviderName) TimeCreatedUtc=$($evt.TimeCreated.ToUniversalTime().ToString('s'))Z RecordId=$($evt.RecordId)"
            }
        }
        catch {
            Add-Finding -Category $spec.Category -Artifact 'Event log parse failed or no matching events' -Location $spec.Path -Value $_.Exception.Message -Severity 'Info' -Notes "EventDaysBack=$EventDaysBack"
        }
    }
}

function Inspect-DeepFileScan {
    if (-not $DeepFileScan) { return }

    $roots = @(
        (Join-Path $script:VolumeRoot 'Users'),
        (Join-Path $script:VolumeRoot 'ProgramData'),
        (Join-Path $script:WindowsRoot 'Temp'),
        (Join-Path $script:WindowsRoot 'Tasks'),
        (Join-Path $script:WindowsRoot 'System32\config\systemprofile\AppData')
    ) | Select-Object -Unique

    $exts = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.hta', '.scr', '.lnk')
    $reported = 0

    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $root -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            if ($exts -notcontains $file.Extension.ToLowerInvariant()) { continue }
            $reasons = @(Test-SuspiciousCommandText -Text $file.FullName)
            $interestingName = ($file.Name -match '(?i)(psexesvc|paexec|mimikatz|rubeus|adfind|bloodhound|sharphound|winpeas|lazagne|ncat|nc\.exe|chisel|plink|socat|payload|beacon|reverse|shell)')
            $interestingLocation = ($file.FullName -match '(?i)\\temp\\|\\users\\public\\|\\appdata\\local\\temp\\|\\programdata\\')
            if ($reasons.Count -gt 0 -or $interestingName -or $interestingLocation) {
                Add-Finding -Category 'File IOC' -Artifact 'Suspicious file in writable/common staging path' -Location $file.FullName -Value $file.Name -Severity (Get-SeverityForReasons -Reasons $reasons) -Notes (Get-FileEvidenceString -Path $file.FullName)
                $reported++
                if ($reported -ge $MaxFileResults) {
                    Add-Finding -Category 'File IOC' -Artifact 'Deep file scan truncated' -Location ($roots -join '; ') -Value $reported -Severity 'Info' -Notes "MaxFileResults=$MaxFileResults"
                    return
                }
            }
        }
    }
}

function Inspect-CoreRegistryHives {
    $config = Join-Path $script:WindowsRoot 'System32\config'
    $softwareHive = Join-Path $config 'SOFTWARE'
    $systemHive = Join-Path $config 'SYSTEM'

    $software = Mount-HiveCopy -HiveSource $softwareHive -Name 'SOFTWARE'
    if ($software) {
        try { Inspect-SoftwareHive -HiveRoot $software.Root }
        catch { Add-Finding -Category 'Registry autorun' -Artifact 'SOFTWARE hive inspection failed' -Location $softwareHive -Value $_.Exception.Message -Severity 'High' }
    }

    $system = Mount-HiveCopy -HiveSource $systemHive -Name 'SYSTEM'
    if ($system) {
        try { Inspect-SystemHive -HiveRoot $system.Root }
        catch { Add-Finding -Category 'Service persistence' -Artifact 'SYSTEM hive inspection failed' -Location $systemHive -Value $_.Exception.Message -Severity 'High' }
    }
}

function Invoke-OffDiskTriage {
    Assert-Administrator
    Resolve-OfflineWindowsRoot -InputPath $TargetPath
    $script:TargetLabel = $script:WindowsRoot

    if ($OutFile) {
        $outFull = [System.IO.Path]::GetFullPath($OutFile)
        if (Test-IsUnderPath -Path $outFull -Parent $script:VolumeRoot) {
            throw "Refusing to write output under the target volume root '$($script:VolumeRoot)'. Choose an analyst-workstation path for -OutFile."
        }
    }

    New-TempRoot

    Add-Finding -Category 'Run metadata' -Artifact 'Target resolved' -Location $script:WindowsRoot -Value "VolumeRoot=$($script:VolumeRoot) TempRoot=$($script:TempRoot)" -Severity 'Info' -Notes 'Registry hives will be copied to analyst temp before loading.'

    Inspect-CoreRegistryHives
    Inspect-UserHives
    Inspect-StartupFolders
    Inspect-ScheduledTasks
    Inspect-PowerShellArtifacts
    Inspect-WmiRepositoryStrings
    Inspect-PrefetchIocs
    Inspect-HostsFile
    Inspect-AmcacheHive
    Inspect-EventLogs
    Inspect-DeepFileScan
}

try {
    Invoke-OffDiskTriage
}
finally {
    Dismount-AllHives
    if ($script:TempRoot -and (Test-Path -LiteralPath $script:TempRoot) -and -not $KeepTemp) {
        try { Remove-Item -LiteralPath $script:TempRoot -Recurse -Force -ErrorAction SilentlyContinue }
        catch { Write-Warning "Could not remove temp directory: $($script:TempRoot)" }
    }
}

$results = $script:Findings | Sort-Object @{ Expression = {
    switch ($_.Severity) {
        'Critical' { 0 }
        'High'     { 1 }
        'Medium'   { 2 }
        'Low'      { 3 }
        default    { 4 }
    }
}}, Category, Artifact, Location

if ($OutFile) {
    $parent = Split-Path -Path ([System.IO.Path]::GetFullPath($OutFile)) -Parent
    if ($parent -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }

    switch ($Format) {
        'Json'  { $results | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $OutFile -Encoding UTF8 }
        'Csv'   { $results | Export-Csv -LiteralPath $OutFile -NoTypeInformation -Encoding UTF8 }
        'Table' { $results | Format-Table -AutoSize | Out-String -Width 4096 | Out-File -LiteralPath $OutFile -Encoding UTF8 }
    }
    Write-Host "Wrote $($results.Count) findings to $OutFile"
}
else {
    if ($Format -eq 'Json') {
        $results | ConvertTo-Json -Depth 6
    }
    elseif ($Format -eq 'Csv') {
        $results | ConvertTo-Csv -NoTypeInformation
    }
    else {
        if ($results.Count -eq 0) {
            Write-Host 'No findings produced.'
        }
        else {
            $results | Format-Table Severity, Category, Artifact, Location, Value -AutoSize -Wrap
        }
    }
}
