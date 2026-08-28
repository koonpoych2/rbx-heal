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

Write-Host "Stable qualification verifier tests"
function Resolve-PythonExecutable {
    foreach ($name in @("python", "python3")) {
        $candidate = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate -and -not [string]::IsNullOrWhiteSpace($candidate.Source) -and (Test-Path -LiteralPath $candidate.Source -PathType Leaf)) {
            return $candidate.Source
        }
    }
    return $null
}

$python = Resolve-PythonExecutable
if ($python) {
    Invoke-Checked "stability verifier tests" { & $python ci/test_verify_stability_streak.py }
    Invoke-Checked "SARIF comparison tests" { & $python ci/test_compare_sarif.py }
    Invoke-Checked "SARIF privacy validation tests" { & $python ci/test_validate_sarif.py }
} else {
    throw "Python is required for stable qualification and SARIF contract tests"
}

Write-Host "Release build"
Invoke-Checked "cargo release build" { cargo build --workspace --release --locked }
Invoke-Checked "verifier helper release build" { cargo build --manifest-path ci/verifier-helper/Cargo.toml --release --locked }

Write-Host "CLI contract smoke checks"
$repoRoot = Split-Path -Parent $PSScriptRoot
$binary = Join-Path $repoRoot "target/release/rbx-heal.exe"
if (-not (Test-Path -LiteralPath $binary)) {
    $binary = Join-Path $repoRoot "target/release/rbx-heal"
}
$smokeProject = Join-Path $repoRoot "examples/ci-smoke"
Invoke-Checked "SARIF smoke check" { & $binary --project $smokeProject check --format sarif | Out-Null }
Invoke-Checked "JSON smoke check" { & $binary --project $smokeProject check --format json | Out-Null }

Write-Host "Runtime dependency policy"
& (Join-Path $repoRoot "ci/check-runtime-dependencies.ps1")

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
