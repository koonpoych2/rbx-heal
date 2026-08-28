# Contributing to rbx-heal

Thanks for helping improve the Roblox Heal Engine. The project is intentionally
proof-first: a change must preserve deterministic output, relative-path
privacy, and the guarded write transaction.

## Before opening a pull request

Run the local quality gates from a clean checkout:

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked
    pwsh ./scripts/quality-gates.ps1

Rule changes require positive, negative, suppression, and malformed fixtures.
Explain any new baseline or pilot expectation in the review description; do not
use blanket suppressions to make a gate pass.

The public corpus is checked out by CI at pinned commits. Do not commit corpus
source, generated artifacts, credentials, or verifier output. The CLI itself
must remain offline: network access belongs only in CI checkout and release
steps.

During RC qualification, scheduled CI checks out the tag in
`ci/stable-candidate.json`. Do not change rules, semantic behavior, workflows,
or corpus expectations during the seven-day streak; such a change requires a
new RC and a fresh streak. Stable promotion is manual after the offline
`ci/verify-stability-streak.py` proof succeeds.

## Pull requests

Keep commits focused and include the user-visible contract impact. JSON schema
version 1, config version 1, and exit codes 0/1/2/3 are backward-compatible
contracts. Add fields rather than renaming or removing existing ones.
