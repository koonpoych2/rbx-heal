# Changelog

## 0.10.0-rc.3

- Replaced the private `roblox-infected` public-v1 corpus entry with the
  public, MIT-licensed `jblaz6335/hacker-tycoon` repository pinned at an
  immutable commit.
- Regenerated reviewed portable finding expectations and advanced the stable
  qualification candidate so scheduled CI cannot depend on a private repo.

## 0.10.0-rc.2

- Made the uploaded SARIF smoke project clean; suppression coverage now lives
  in a local-only fixture so Code Scanning receives zero results.
- Added fail-closed SARIF privacy validation and strict duplicate/interspersed
  scheduled-run checks for stable qualification evidence.
- Added a pinned stable-candidate manifest, metadata-only scheduled
  qualification records, and an offline seven-day first-attempt streak verifier.
- Reworked release proof to derive version and prerelease state from any `v*`
  tag, support non-publishing preflight runs, and fail closed for stable
  promotion unless the RC2 qualification and version-only diff checks pass.

## 0.10.0-rc.1

- Added the manifest-driven public-v1 pilot for pinned open-source Roblox
  projects.
- Added cross-platform pilot reports with reviewed baseline identities,
  precision gates, source-hash protection, and verifier status.
- Reworked CI and release packaging around pinned actions, deterministic
  archives, provenance, SARIF, and artifact attestations.
- Kept runtime execution local and deterministic with no network or LLM
  dependency.

## 0.9.0

- Added portable baselines, SARIF output, named remote coverage, and the
  conservative DataStore protection rule.
