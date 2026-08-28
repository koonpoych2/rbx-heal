[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$Platform,
    [Parameter(Mandatory = $true)]
    [string]$BinaryPath,
    [string]$Destination = (Join-Path $PSScriptRoot "..\dist")
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$stage = Join-Path $env:RUNNER_TEMP "rbx-heal-release-$Platform"
$dist = [System.IO.Path]::GetFullPath($Destination)
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage, $dist | Out-Null

Copy-Item -LiteralPath (Resolve-Path $BinaryPath) -Destination (Join-Path $stage "rbx-heal.exe")
Copy-Item -LiteralPath (Join-Path $repo "rbx-heal.toml.example") -Destination (Join-Path $stage "rbx-heal.toml.example")
Copy-Item -LiteralPath (Join-Path $repo "README.md") -Destination (Join-Path $stage "README.md")
Copy-Item -LiteralPath (Join-Path $repo "CHANGELOG.md") -Destination (Join-Path $stage "CHANGELOG.md")
Copy-Item -LiteralPath (Join-Path $repo "LICENSE") -Destination (Join-Path $stage "LICENSE")
Copy-Item -LiteralPath (Join-Path $repo "ci/tools.lock.json") -Destination (Join-Path $stage "tools.lock.json")

$epoch = 946684800
if ($env:SOURCE_DATE_EPOCH) {
    $epoch = [long]$env:SOURCE_DATE_EPOCH
}
$epochDate = [DateTimeOffset]::FromUnixTimeSeconds($epoch)
$files = @(Get-ChildItem -LiteralPath $stage -File | Sort-Object Name | ForEach-Object {
    [ordered]@{
        name = $_.Name
        sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        bytes = $_.Length
    }
})
$manifest = [ordered]@{
    schema_version = 1
    product = "rbx-heal"
    version = $Version
    platform = $Platform
    artifact_type = "unsigned_zip"
    source_commit = if ($env:GITHUB_SHA) { $env:GITHUB_SHA } else { "local" }
    rust_toolchain = "1.85.0"
    action_lock = "ci/actions.lock.json"
    corpus_suite = "public-v1"
    corpus_manifest = "pilot/public-v1.toml"
    files = $files
}
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage "provenance.json") -Encoding utf8NoBOM

Add-Type -AssemblyName System.IO.Compression
function New-DeterministicZip([string]$Path) {
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create)
    $archive = [System.IO.Compression.ZipArchive]::new($stream, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath $stage -File | Sort-Object Name)) {
            $entry = $archive.CreateEntry($file.Name, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $epochDate
            $input = [System.IO.File]::OpenRead($file.FullName)
            $output = $entry.Open()
            try { $input.CopyTo($output) } finally { $output.Dispose(); $input.Dispose() }
        }
    } finally {
        $archive.Dispose()
        $stream.Dispose()
    }
}

$baseName = "rbx-heal-v$Version-windows-x86_64"
$first = Join-Path $env:RUNNER_TEMP "$baseName.first.zip"
$second = Join-Path $env:RUNNER_TEMP "$baseName.second.zip"
New-DeterministicZip $first
New-DeterministicZip $second
$firstHash = (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash.ToLowerInvariant()
$secondHash = (Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash.ToLowerInvariant()
if ($firstHash -ne $secondHash) { throw "deterministic archive hash mismatch" }
$archive = Join-Path $dist "$baseName.zip"
Copy-Item -LiteralPath $first -Destination $archive -Force
"$firstHash  $(Split-Path -Leaf $archive)" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
Copy-Item -LiteralPath (Join-Path $stage "provenance.json") -Destination (Join-Path $dist "$baseName-provenance.json") -Force
Write-Output $archive
