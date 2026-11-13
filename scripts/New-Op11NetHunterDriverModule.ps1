[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ModuleTree,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$KernelRelease,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$SystemMap,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Symvers,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputZip,
    [Parameter(Mandatory)][ValidatePattern('^[0-9]+$')][string]$BuildRunId,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$BuildCommit,
    [string]$AuditPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$automationName = 'New-Op11NetHunterDriverModule'
$automationVersion = '1.0.0'
$executionId = [guid]::NewGuid().ToString()
$startedUtc = [datetime]::UtcNow
$finalStatus = 'FAILED'
$exitCode = 1
$errorText = $null
$outputHash = $null
$depmodOutput = @()
$selectedRelativePaths = @()
$moduleHashes = @()
$stagePath = $null
$stageCreated = $false
$outputCreated = $false
$seedPattern = '^(ath|cfg80211\.ko$|mac80211\.ko$|mt7|rt2|rt28|rtw_|slcan\.ko$|usbmon\.ko$)'

function ConvertTo-WslPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "Only local Windows drive paths are supported for WSL conversion: $full"
    }
    $drive = $Matches[1].ToLowerInvariant()
    $tail = $Matches[2] -replace '\\', '/'
    return "/mnt/$drive/$tail"
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Content
    )
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    $normalized = $Content -replace "`r`n", "`n"
    if ($normalized.Length -gt 0 -and -not $normalized.EndsWith("`n")) {
        $normalized += "`n"
    }
    [System.IO.File]::WriteAllText($Path, $normalized, $utf8NoBom)
}

try {
    Add-Type -AssemblyName System.IO.Compression

    $ModuleTree = [System.IO.Path]::GetFullPath($ModuleTree)
    $SystemMap = [System.IO.Path]::GetFullPath($SystemMap)
    $Symvers = [System.IO.Path]::GetFullPath($Symvers)
    $OutputZip = [System.IO.Path]::GetFullPath($OutputZip)
    if (-not $AuditPath) {
        $AuditPath = "$OutputZip.audit.json"
    }
    $AuditPath = [System.IO.Path]::GetFullPath($AuditPath)

    if ((Split-Path -Leaf $ModuleTree) -ne $KernelRelease) {
        throw "Module tree directory does not match KernelRelease: $ModuleTree"
    }
    foreach ($requiredFile in @(
        (Join-Path $ModuleTree 'modules.dep'),
        $SystemMap,
        $Symvers
    )) {
        if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
            throw "Required input is missing: $requiredFile"
        }
    }
    if (Test-Path -LiteralPath $OutputZip) {
        throw "Refusing to overwrite existing output: $OutputZip"
    }
    if (Test-Path -LiteralPath $AuditPath) {
        throw "Refusing to overwrite existing audit record: $AuditPath"
    }

    $outputParent = Split-Path -Parent $OutputZip
    $auditParent = Split-Path -Parent $AuditPath
    foreach ($parent in @($outputParent, $auditParent) | Select-Object -Unique) {
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
            throw "Required parent directory does not exist: $parent"
        }
    }

    $dependencyMap = @{}
    $nameToRelativePath = @{}
    foreach ($line in Get-Content -LiteralPath (Join-Path $ModuleTree 'modules.dep')) {
        $parts = $line -split ':\s*', 2
        $relativePath = $parts[0]
        $moduleName = [System.IO.Path]::GetFileName($relativePath)
        if ($nameToRelativePath.ContainsKey($moduleName)) {
            throw "Duplicate module filename in input tree: $moduleName"
        }
        $nameToRelativePath[$moduleName] = $relativePath
        $dependencyMap[$relativePath] = if ($parts.Count -gt 1 -and $parts[1]) {
            @($parts[1] -split '\s+' | Where-Object { $_ })
        }
        else { @() }
    }

    $seedNames = @($nameToRelativePath.Keys | Where-Object {
        $_ -match $seedPattern -and $_ -ne 'br0k3n_memk.ko'
    } | Sort-Object)
    $requiredSeeds = @(
        'ath9k_htc.ko', 'ath10k_usb.ko', 'cfg80211.ko', 'mac80211.ko',
        'mt7601u.ko', 'mt76x2u.ko', 'rt2800usb.ko', 'rtw_8812au.ko',
        'rtw_8814au.ko', 'rtw_8821cu.ko', 'rtw_8822bu.ko', 'slcan.ko',
        'usbmon.ko'
    )
    $missingSeeds = @($requiredSeeds | Where-Object { $_ -notin $seedNames })
    if ($missingSeeds.Count -gt 0) {
        throw "Required NetHunter modules are missing: $($missingSeeds -join ', ')"
    }

    $queue = [System.Collections.Generic.Queue[string]]::new()
    foreach ($seed in $seedNames) {
        $queue.Enqueue($nameToRelativePath[$seed])
    }
    $selected = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    while ($queue.Count -gt 0) {
        $relativePath = $queue.Dequeue()
        if ($selected.Add($relativePath)) {
            if (-not $dependencyMap.ContainsKey($relativePath)) {
                throw "Dependency is absent from modules.dep: $relativePath"
            }
            foreach ($dependency in $dependencyMap[$relativePath]) {
                $queue.Enqueue($dependency)
            }
        }
    }
    $selectedRelativePaths = @($selected | Sort-Object)
    if ($selectedRelativePaths | Where-Object { $_ -match 'br0k3n_memk' }) {
        throw 'The physical-memory access module must never enter the hardened driver package.'
    }

    $stagePath = Join-Path $outputParent ".nethunter-driver-stage-$executionId"
    if (Test-Path -LiteralPath $stagePath) {
        throw "Unexpected staging-path collision: $stagePath"
    }
    New-Item -ItemType Directory -Path $stagePath | Out-Null
    $stageCreated = $true

    $stageModuleRoot = Join-Path $stagePath "system\lib\modules\$KernelRelease"
    New-Item -ItemType Directory -Path $stageModuleRoot -Force | Out-Null
    foreach ($relativePath in $selectedRelativePaths) {
        $source = Join-Path $ModuleTree ($relativePath -replace '/', '\')
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "Selected module file is missing: $source"
        }
        $destination = Join-Path $stageModuleRoot ($relativePath -replace '/', '\')
        $destinationParent = Split-Path -Parent $destination
        if (-not (Test-Path -LiteralPath $destinationParent)) {
            New-Item -ItemType Directory -Path $destinationParent -Force | Out-Null
        }
        Copy-Item -LiteralPath $source -Destination $destination
    }

    Write-Utf8NoBom -Path (Join-Path $stageModuleRoot 'modules.order') `
        -Content (($selectedRelativePaths -join "`n") + "`n")
    Write-Utf8NoBom -Path (Join-Path $stageModuleRoot 'modules.builtin') -Content ''
    Write-Utf8NoBom -Path (Join-Path $stageModuleRoot 'modules.builtin.modinfo') -Content ''

    $moduleVersionCode = ([int64]$BuildRunId % 2000000000)
    $moduleProp = @"
id=lockard_op11_nethunter_drivers
name=Lockard OnePlus 11 NetHunter Drivers
version=5.15.197-run-$BuildRunId
versionCode=$moduleVersionCode
author=Lockard Security
description=Audited, dependency-closed external Wi-Fi/CAN/USB monitor modules for $KernelRelease. No module is auto-loaded.
"@
    Write-Utf8NoBom -Path (Join-Path $stagePath 'module.prop') -Content $moduleProp

    $customize = @"
SKIPUNZIP=0
required_release='$KernelRelease'
actual_release=`$(uname -r)
[ "`$actual_release" = "`$required_release" ] || abort "! Kernel mismatch: expected `$required_release, found `$actual_release"
ui_print "- Verified kernel release: `$actual_release"
ui_print "- Installing dependency-closed NetHunter driver set"
ui_print "- Drivers are not auto-loaded"
set_perm_recursive "`$MODPATH/system/lib/modules" 0 0 0755 0644
set_perm "`$MODPATH/system/bin/nh-modprobe" 0 0 0755
"@
    Write-Utf8NoBom -Path (Join-Path $stagePath 'customize.sh') -Content $customize

    $binPath = Join-Path $stagePath 'system\bin'
    New-Item -ItemType Directory -Path $binPath -Force | Out-Null
    $modprobeWrapper = @"
#!/system/bin/sh
release=`$(uname -r)
busybox=/data/adb/ksu/bin/busybox
[ -x "`$busybox" ] || { echo "KernelSU BusyBox not found" >&2; exit 127; }
exec "`$busybox" modprobe -d /system -S "`$release" "`$@"
"@
    Write-Utf8NoBom -Path (Join-Path $binPath 'nh-modprobe') -Content $modprobeWrapper

    $wslStageSystem = ConvertTo-WslPath (Join-Path $stagePath 'system')
    $wslSymvers = ConvertTo-WslPath $Symvers
    $wslSystemMap = ConvertTo-WslPath $SystemMap
    $depmodCommand = "depmod -a -e -E '$wslSymvers' -F '$wslSystemMap' -b '$wslStageSystem' '$KernelRelease' 2>&1"
    $depmodOutput = @(& wsl.exe bash -lc $depmodCommand)
    $depmodExitCode = $LASTEXITCODE
    if ($depmodExitCode -ne 0) {
        throw "depmod verification failed with exit code $depmodExitCode`: $($depmodOutput -join ' | ')"
    }
    $depmodErrors = @($depmodOutput | Where-Object { $_ -match 'unknown symbol|needs unknown symbol| disagrees about version|ERROR|FATAL' })
    if ($depmodErrors.Count -gt 0) {
        throw "depmod reported ABI errors: $($depmodErrors -join ' | ')"
    }

    $moduleHashes = @($selectedRelativePaths | ForEach-Object {
        $path = Join-Path $stageModuleRoot ($_ -replace '/', '\')
        [pscustomobject]@{
            RelativePath = $_
            Length = (Get-Item -LiteralPath $path).Length
            Sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        }
    })

    $outputFile = [System.IO.File]::Open($OutputZip, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    $outputCreated = $true
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $outputFile, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $stagePrefixLength = $stagePath.TrimEnd('\').Length + 1
            foreach ($file in Get-ChildItem -LiteralPath $stagePath -File -Recurse | Sort-Object FullName) {
                $entryName = $file.FullName.Substring($stagePrefixLength) -replace '\\', '/'
                $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
                $mode = if ($entryName -in @('customize.sh', 'system/bin/nh-modprobe')) { 33261 } else { 33188 }
                $entry.ExternalAttributes = $mode -shl 16
                $inputStream = $file.OpenRead()
                $outputStream = $entry.Open()
                try { $inputStream.CopyTo($outputStream, 1024 * 1024) }
                finally { $outputStream.Dispose(); $inputStream.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $outputFile.Dispose() }

    $outputHash = (Get-FileHash -LiteralPath $OutputZip -Algorithm SHA256).Hash
    $zipFile = [System.IO.File]::OpenRead($OutputZip)
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $zipFile, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            foreach ($requiredEntry in @('module.prop', 'customize.sh', 'system/bin/nh-modprobe')) {
                if (-not $archive.GetEntry($requiredEntry)) {
                    throw "Required driver-module entry is missing: $requiredEntry"
                }
            }
            if ($archive.Entries | Where-Object { $_.FullName -match 'br0k3n_memk' }) {
                throw 'Forbidden physical-memory module found during output verification.'
            }
            $packagedModules = @($archive.Entries | Where-Object { $_.FullName -like '*.ko' })
            if ($packagedModules.Count -ne $selectedRelativePaths.Count) {
                throw "Packaged module count mismatch: $($packagedModules.Count)"
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $zipFile.Dispose() }

    $finalStatus = 'SUCCESS'
    $exitCode = 0
}
catch {
    $errorText = $_.Exception.Message
    if ($outputCreated -and (Test-Path -LiteralPath $OutputZip)) {
        Remove-Item -LiteralPath $OutputZip -Force
    }
}
finally {
    if ($stageCreated -and $stagePath) {
        $resolvedParent = [System.IO.Path]::GetFullPath((Split-Path -Parent $stagePath)).TrimEnd('\')
        $resolvedStage = [System.IO.Path]::GetFullPath($stagePath)
        if ($resolvedStage.StartsWith("$resolvedParent\.nethunter-driver-stage-", [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolvedStage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    $completedUtc = [datetime]::UtcNow
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $audit = [ordered]@{
        AutomationName = $automationName
        AutomationVersion = $automationVersion
        ExecutionId = $executionId
        Hostname = $env:COMPUTERNAME
        ExecutionContext = $identity.Name
        IsAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        StartedUtc = $startedUtc.ToString('o')
        CompletedUtc = $completedUtc.ToString('o')
        DurationSeconds = [math]::Round(($completedUtc - $startedUtc).TotalSeconds, 3)
        KernelRelease = $KernelRelease
        BuildRunId = $BuildRunId
        BuildCommit = $BuildCommit.ToLowerInvariant()
        ModuleTree = $ModuleTree
        SeedPattern = $seedPattern
        SelectedModuleCount = $selectedRelativePaths.Count
        SelectedModules = $moduleHashes
        DepmodOutput = @($depmodOutput)
        OutputZip = $OutputZip
        OutputSha256 = $outputHash
        Verification = if ($finalStatus -eq 'SUCCESS') {
            'Dependency closure packaged; depmod ABI check passed; no driver auto-load; MemKernel excluded.'
        } else { 'Verification did not complete.' }
        FinalStatus = $finalStatus
        ExitCode = $exitCode
        Error = $errorText
    }

    if ($AuditPath -and -not (Test-Path -LiteralPath $AuditPath)) {
        $audit | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $AuditPath -Encoding UTF8
    }
    [pscustomobject]$audit | Format-List
}

exit $exitCode
