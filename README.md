# Roblox Heal Engine 0.10.0-rc.2 — Stable Qualification Candidate

`rbx-heal` is a local, deterministic Luau diagnostics and safe-fix CLI for Roblox projects. It parses Luau without an LLM, reports server-authority/data/performance risks, and only writes guarded mechanical edits after verification.

The 0.10.0-rc.2 candidate validates the adoption workflow on
public pinned corpus projects, cross-platform CI, deterministic artifacts, and
SARIF upload. It keeps portable baselines, named remote handler coverage, and a conservative DataStore error-boundary rule on top of
the 0.8.0 project-boundary, crash-recovery, verifier-identity, privacy-safe
history, and distribution hardening. Every source path is
canonicalized beneath `--project`; writes use a durable journal and atomic
replacement; and history export validates and allowlists every record. Runtime
dependencies contain no network or LLM client.

## Build

```powershell
cargo build --release
```

The binary is `target/release/rbx-heal.exe` on Windows.

## Quick start

```powershell
rbx-heal init
rbx-heal check --format human
rbx-heal check --format json > heal-report.json
rbx-heal check --format sarif > heal.sarif
rbx-heal baseline create --write --reason "accepted legacy debt"
rbx-heal baseline prune --write
rbx-heal fix
rbx-heal fix --write
rbx-heal doctor
rbx-heal history export heal-history.jsonl
rbx-heal history summarize --format human
rbx-heal pilot --suite public-v1 --format json
```

`fix` is preview-only unless `--write` is supplied. A write transaction reparses candidates, applies configured verification commands, and restores the original bytes if verification fails.

`check --format json` emits schema version `1`; findings use relative paths and byte/line ranges. `history` stores only local project/rule fingerprints, engine/rule-pack versions, timings, actions, and verification status. Source, diffs, absolute paths, and command output are excluded unless an explicit `--save-artifacts` directory is supplied to `fix`.

## Baseline and CI adoption

baseline create is preview-only by default. The write mode requires a review
reason and records every unsuppressed finding currently present in the full
project scan. Later checks keep matched debt visible but fail only on findings
whose portable baseline_id is new. Use check --no-baseline for a full audit;
there is no automatic baseline update command.

The JSON contract remains schema version 1 with additive baseline fields.
check --format sarif emits deterministic SARIF 2.1.0 with relative URIs,
portable fingerprints, suppressions, and safe-fix metadata for GitHub code
scanning. SARIF is intentionally check-only; use JSON for agent workflows and
baseline commands.

## Codex workflow

```text
Before changing Luau: rbx-heal check --format json
After changing Luau:  rbx-heal fix
Safe fixes only:      rbx-heal fix --write
Finish with:          rbx-heal check --format json and the project verifier
```

The default rule pack is intentionally conservative. Community knowledge mining, custom executable rules, Studio UI integration, and automatic rule promotion are future layers; the local run history only records metadata to make those layers possible later.

The 0.9 rule pack also reports proven DataStore calls that lack a configured
local pcall/xpcall (or project-defined protector) boundary. Ambiguous receivers
and dynamic helpers are declined rather than guessed.
The rule follows Roblox's
[client-server boundary guidance](https://create.roblox.com/docs/scripting/security/client-server-boundary)
and [DataStore error guidance](https://create.roblox.com/docs/cloud-services/data-stores/error-codes-and-limits).

## Verification and pilot

Verification commands are executable plus argument arrays; they never pass
through a shell. `rojo_build` always writes its build output to a temporary
directory, `stylua_check` is forced into check-only mode, and `{changed}` expands
to one argument per changed file. Required tools are preflighted before a write.

Run the reproducible pilot without touching the adjacent game repository:

```powershell
rbx-heal pilot --format human
$env:RBX_HEAL_SLIME_FARM_ROOT = "C:\path\to\Slime farm"
rbx-heal pilot --format json
```

The pilot hashes Luau sources before and after the run, exercises safe fixes only
on a temporary copy, and reports an incomplete official gate when real Rojo is
not installed (an Aftman shim is not accepted as Rojo).

The warm-cache synthetic gate (470 × 213-line Luau modules, about 100k LOC) completed in under one second wall time on the development machine.

The 0.10.0-rc.2 release workflow produces unsigned Windows x64 and Ubuntu x64
archives with checksums, provenance manifests, and attestations. Copy-ready generic JSON and
SARIF GitHub Actions examples are in docs/github-ci.md.

Scheduled CI qualifies this exact candidate for seven consecutive UTC days.
Each successful run writes only a metadata-only `StableQualificationRunV1`
artifact. Stable promotion is manual and requires the offline
`ci/verify-stability-streak.py` proof plus a version-only commit after RC2.
The uploaded `rbx-heal-smoke` SARIF is intentionally empty; suppression
coverage is tested locally and is never dismissed as a Code Scanning alert.
CI validates that uploaded SARIF has no findings, runner paths, or embedded
source content before it reaches Code Scanning.

The public-v1 pilot is manifest-driven and read-only. CI checks out pinned
public repositories and passes their canonical roots through environment
variables; the CLI never clones repositories or uses network access. The
private Slime Farm checkout remains a legacy local pilot and is not a release
gate.

CI pins Rust 1.85.0 and uses the checked-in `ci/tools.lock.json` manifest for
official Rojo 7.7.0, Luau 0.735, and StyLua 2.5.2 assets with SHA-256 checks.

## Suppressions

Use a statement-scoped inline suppression with a reason:

```luau
-- rbx-heal: ignore RBX-PERF-001 -- the list is bounded by the scene contract
local refs = workspace:GetDescendants()
```

File/path suppressions belong in `rbx-heal.toml` and also require a reason.
