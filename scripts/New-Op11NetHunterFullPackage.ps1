[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SourceZip,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputZip,

    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ExpectedSourceSha256 = 'A9DF9027177D548BF563826CD2984149632BC6EAF48351DA7912C81FF7EADA85',

    [string]$AuditPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$automationName = 'New-Op11NetHunterFullPackage'
$automationVersion = '1.0.0'
$executionId = [guid]::NewGuid().ToString()
$startedUtc = [datetime]::UtcNow
$finalStatus = 'FAILED'
$exitCode = 1
$errorText = $null
$sourceHash = $null
$outputHash = $null
$rootfsSourceHash = $null
$rootfsOutputHash = $null
$sourceEntryCount = 0
$outputEntryCount = 0
$skippedEntries = [System.Collections.Generic.List[string]]::new()
$outputCreatedByThisRun = $false

function Get-StreamSha256 {
    param([Parameter(Mandatory)][System.IO.Stream]$Stream)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $buffer = New-Object byte[] (1024 * 1024)
        while (($read = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
        return ([BitConverter]::ToString($sha.Hash) -replace '-', '')
    }
    finally {
        $sha.Dispose()
    }
}

function Copy-ZipEntry {
    param(
        [Parameter(Mandatory)][System.IO.Compression.ZipArchiveEntry]$SourceEntry,
        [Parameter(Mandatory)][System.IO.Compression.ZipArchive]$DestinationArchive
    )

    $isDirectory = $SourceEntry.FullName.EndsWith('/')
    if ($isDirectory) {
        $destinationEntry = $DestinationArchive.CreateEntry($SourceEntry.FullName)
        $destinationEntry.LastWriteTime = $SourceEntry.LastWriteTime
        $destinationEntry.ExternalAttributes = $SourceEntry.ExternalAttributes
        return
    }

    $compression = if ($SourceEntry.Length -gt 0 -and
        ($SourceEntry.CompressedLength / [double]$SourceEntry.Length) -gt 0.95) {
        [System.IO.Compression.CompressionLevel]::NoCompression
    }
    else {
        [System.IO.Compression.CompressionLevel]::Optimal
    }

    $destinationEntry = $DestinationArchive.CreateEntry($SourceEntry.FullName, $compression)
    $destinationEntry.LastWriteTime = $SourceEntry.LastWriteTime
    $destinationEntry.ExternalAttributes = $SourceEntry.ExternalAttributes

    $sourceStream = $SourceEntry.Open()
    $destinationStream = $destinationEntry.Open()
    try {
        $sourceStream.CopyTo($destinationStream, 1024 * 1024)
    }
    finally {
        $destinationStream.Dispose()
        $sourceStream.Dispose()
    }
}

try {
    Add-Type -AssemblyName System.IO.Compression

    $SourceZip = [System.IO.Path]::GetFullPath($SourceZip)
    $OutputZip = [System.IO.Path]::GetFullPath($OutputZip)
    if (-not $AuditPath) {
        $AuditPath = "$OutputZip.audit.json"
    }
    $AuditPath = [System.IO.Path]::GetFullPath($AuditPath)

    if (-not (Test-Path -LiteralPath $SourceZip -PathType Leaf)) {
        throw "Source package does not exist: $SourceZip"
    }
    if ($SourceZip -eq $OutputZip) {
        throw 'SourceZip and OutputZip must be different files.'
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

    $sourceItem = Get-Item -LiteralPath $SourceZip
    $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($OutputZip))
    $requiredFreeBytes = $sourceItem.Length + 1GB
    if ($drive.AvailableFreeSpace -lt $requiredFreeBytes) {
        throw "Insufficient free space on $($drive.Name): need at least $requiredFreeBytes bytes."
    }

    $sourceHash = (Get-FileHash -LiteralPath $SourceZip -Algorithm SHA256).Hash
    if ($sourceHash -ne $ExpectedSourceSha256.ToUpperInvariant()) {
        throw "Source package SHA-256 mismatch: $sourceHash"
    }

    $sourceFile = [System.IO.File]::Open($SourceZip, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $outputFile = [System.IO.File]::Open($OutputZip, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
    $outputCreatedByThisRun = $true
    try {
        $sourceArchive = [System.IO.Compression.ZipArchive]::new(
            $sourceFile, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        $outputArchive = [System.IO.Compression.ZipArchive]::new(
            $outputFile, [System.IO.Compression.ZipArchiveMode]::Create, $true)
        try {
            $sourceEntryCount = $sourceArchive.Entries.Count
            foreach ($entry in $sourceArchive.Entries) {
                $skip = $entry.FullName -match '^kernel-nethunter(?:-.*)?\.zip$' -or
                    $entry.FullName -match '^boot-patcher/Image(?:\..*)?$' -or
                    $entry.FullName -match '^boot-patcher/modules/.*\.ko$'
                if ($skip) {
                    $skippedEntries.Add($entry.FullName)
                    continue
                }
                Copy-ZipEntry -SourceEntry $entry -DestinationArchive $outputArchive
            }
        }
        finally {
            $outputArchive.Dispose()
            $sourceArchive.Dispose()
        }
    }
    finally {
        $outputFile.Dispose()
        $sourceFile.Dispose()
    }

    $outputHash = (Get-FileHash -LiteralPath $OutputZip -Algorithm SHA256).Hash

    $sourceFile = [System.IO.File]::OpenRead($SourceZip)
    $outputFile = [System.IO.File]::OpenRead($OutputZip)
    try {
        $sourceArchive = [System.IO.Compression.ZipArchive]::new(
            $sourceFile, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        $outputArchive = [System.IO.Compression.ZipArchive]::new(
            $outputFile, [System.IO.Compression.ZipArchiveMode]::Read, $false)
        try {
            $outputEntryCount = $outputArchive.Entries.Count
            $requiredEntries = @(
                'kalifs-full-arm64.tar.xz',
                'customize.sh',
                'module.prop',
                'data/app/NetHunter.apk'
            )
            foreach ($required in $requiredEntries) {
                if (-not $outputArchive.GetEntry($required)) {
                    throw "Required entry is missing from sanitized package: $required"
                }
            }
            foreach ($removed in $skippedEntries) {
                if ($outputArchive.GetEntry($removed)) {
                    throw "Forbidden stale kernel entry remains in output: $removed"
                }
            }

            $sourceRootfs = $sourceArchive.GetEntry('kalifs-full-arm64.tar.xz')
            $outputRootfs = $outputArchive.GetEntry('kalifs-full-arm64.tar.xz')
            $sourceRootfsStream = $sourceRootfs.Open()
            $outputRootfsStream = $outputRootfs.Open()
            try {
                $rootfsSourceHash = Get-StreamSha256 -Stream $sourceRootfsStream
                $rootfsOutputHash = Get-StreamSha256 -Stream $outputRootfsStream
            }
            finally {
                $outputRootfsStream.Dispose()
                $sourceRootfsStream.Dispose()
            }
            if ($rootfsSourceHash -ne $rootfsOutputHash) {
                throw 'Independent Kali rootfs hash verification failed.'
            }
        }
        finally {
            $outputArchive.Dispose()
            $sourceArchive.Dispose()
        }
    }
    finally {
        $outputFile.Dispose()
        $sourceFile.Dispose()
    }

    $finalStatus = 'SUCCESS'
    $exitCode = 0
}
catch {
    $errorText = $_.Exception.Message
    if ($outputCreatedByThisRun -and (Test-Path -LiteralPath $OutputZip)) {
        Remove-Item -LiteralPath $OutputZip -Force
    }
}
finally {
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
        SourceZip = $SourceZip
        SourceSha256 = $sourceHash
        ExpectedSourceSha256 = $ExpectedSourceSha256.ToUpperInvariant()
        OutputZip = $OutputZip
        OutputSha256 = $outputHash
        SourceEntryCount = $sourceEntryCount
        OutputEntryCount = $outputEntryCount
        RemovedEntryCount = $skippedEntries.Count
        RemovedEntries = @($skippedEntries)
        KaliRootfsSourceSha256 = $rootfsSourceHash
        KaliRootfsOutputSha256 = $rootfsOutputHash
        Verification = if ($finalStatus -eq 'SUCCESS') {
            'Required entries present; stale kernel payload absent; Kali rootfs content hash matched.'
        } else { 'Verification did not complete.' }
        FinalStatus = $finalStatus
        ExitCode = $exitCode
        Error = $errorText
    }

    if ($AuditPath -and -not (Test-Path -LiteralPath $AuditPath)) {
        $audit | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $AuditPath -Encoding UTF8
    }
    [pscustomobject]$audit | Format-List
}

exit $exitCode
