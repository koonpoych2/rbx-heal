param(
    [string]$Destination = (Join-Path $PSScriptRoot ".tools\windows-x86_64")
)

$ErrorActionPreference = "Stop"
$manifestPath = Join-Path $PSScriptRoot "tools.lock.json"
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$platform = "windows-x86_64"
$tools = @{
    rojo = "rojo.exe"
    luau = "luau-analyze.exe"
    stylua = "stylua.exe"
}

$destinationPath = [System.IO.Path]::GetFullPath($Destination)
New-Item -ItemType Directory -Force -Path $destinationPath | Out-Null
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("rbx-heal-tools-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

try {
    foreach ($toolName in $tools.Keys) {
        $spec = $manifest.tools.$toolName.assets.$platform
        if ($null -eq $spec) {
            throw "No locked asset for $toolName/$platform"
        }
        $archive = Join-Path $tempRoot "$toolName.zip"
        Write-Host "Downloading locked $toolName $($manifest.tools.$toolName.version)"
        Invoke-WebRequest -Uri $spec.url -OutFile $archive -UseBasicParsing
        $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $spec.sha256.ToLowerInvariant()) {
            throw "SHA-256 mismatch for ${toolName}: expected $($spec.sha256), got $actual"
        }
        $extract = Join-Path $tempRoot $toolName
        Expand-Archive -LiteralPath $archive -DestinationPath $extract -Force
        $binary = Get-ChildItem -LiteralPath $extract -Recurse -File |
            Where-Object { $_.Name -ieq $tools[$toolName] } |
            Select-Object -First 1
        if ($null -eq $binary) {
            throw "Locked $toolName archive did not contain $($tools[$toolName])"
        }
        Copy-Item -LiteralPath $binary.FullName -Destination (Join-Path $destinationPath $tools[$toolName]) -Force
        if ($toolName -eq "luau") {
            $compiler = Get-ChildItem -LiteralPath $extract -Recurse -File |
                Where-Object { $_.Name -ieq "luau-compile.exe" } |
                Select-Object -First 1
            if ($null -eq $compiler) {
                throw "Locked luau archive did not contain luau-compile.exe"
            }
            Copy-Item -LiteralPath $compiler.FullName -Destination (Join-Path $destinationPath "luau-compile.exe") -Force
        }
    }
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Locked verifier tools installed in $destinationPath"
