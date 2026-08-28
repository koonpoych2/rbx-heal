$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param(
        [string]$Label,
        [scriptblock]$Command
    )
    & $Command
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode"
    }
}

Write-Host "Formatting"
Invoke-Checked "cargo fmt" { cargo fmt --all -- --check }
Invoke-Checked "verifier helper fmt" { cargo fmt --manifest-path ci/verifier-helper/Cargo.toml -- --check }

Write-Host "Clippy"
Invoke-Checked "cargo clippy" { cargo clippy --workspace --all-targets --locked -- -D warnings }

Write-Host "Tests"
Invoke-Checked "cargo test" { cargo test --workspace --locked }

Write-Host "Property tests"
Invoke-Checked "property tests" { cargo test --workspace --locked --test property }

Write-Host "Release build"
Invoke-Checked "cargo release build" { cargo build --workspace --release --locked }
Invoke-Checked "verifier helper release build" { cargo build --manifest-path ci/verifier-helper/Cargo.toml --release --locked }

Write-Host "CLI contract smoke checks"
$binary = Join-Path $PSScriptRoot "..\target\release\rbx-heal.exe"
if (-not (Test-Path -LiteralPath $binary)) {
    $binary = Join-Path $PSScriptRoot "..\target\release\rbx-heal"
}
Invoke-Checked "SARIF smoke check" { & $binary check --format sarif | Out-Null }
Invoke-Checked "JSON smoke check" { & $binary check --format json | Out-Null }

Write-Host "Runtime dependency policy"
& (Join-Path $PSScriptRoot "..\ci\check-runtime-dependencies.ps1")

Write-Host "Release performance gate"
Invoke-Checked "release performance test" { cargo test --workspace --release --locked --test performance -- --ignored }

$pilotRoot = $env:RBX_HEAL_SLIME_FARM_ROOT
if ($pilotRoot) {
    Write-Host "Slime Farm pilot"
    $env:RBX_HEAL_SLIME_FARM_ROOT = [System.IO.Path]::GetFullPath($pilotRoot)
    & $binary pilot --format json
    if ($LASTEXITCODE -ne 0) {
        throw "Slime Farm pilot did not pass (exit code $LASTEXITCODE)"
    }
} else {
    Write-Host "Slime Farm pilot skipped: set RBX_HEAL_SLIME_FARM_ROOT for the official gate"
}

Write-Host "All Rust quality gates passed"
