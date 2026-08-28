$ErrorActionPreference = "Stop"

# Keep the execution path local and deterministic.  This policy is intentionally
# name based: these packages are HTTP/LLM clients and must never enter the
# normal dependency graph of the shipped binary.
$forbidden = @(
    "reqwest",
    "ureq",
    "hyper",
    "isahc",
    "surf",
    "awc",
    "attohttpc",
    "llm",
    "async-openai",
    "openai-api",
    "genai"
)

$tree = & cargo tree --workspace --locked --edges normal --format "{p}" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "cargo tree failed with exit code $LASTEXITCODE"
}

$hits = @()
foreach ($line in $tree) {
    foreach ($package in $forbidden) {
        if ($line -match "(^|[^A-Za-z0-9_-])$([regex]::Escape($package)) v") {
            $hits += $line.Trim()
            break
        }
    }
}

if ($hits.Count -gt 0) {
    throw "forbidden network/LLM runtime dependency detected:`n$($hits -join "`n")"
}

Write-Host "Runtime dependency policy passed: no HTTP or LLM client crates in the normal graph."
