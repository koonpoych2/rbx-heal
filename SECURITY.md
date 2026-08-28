# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. If
that channel is unavailable, open a minimal issue requesting a private
contact; do not include exploit details, source snapshots, credentials, or
verifier output in a public issue.

The engine is local by design. A report should include the affected release,
platform, command, and a small synthetic reproduction where possible.

## Security boundaries

- Paths are confined to the canonical project root.
- Safe writes require guarded edits, reparsing, verification, and rollback.
- History and pilot reports contain metadata only; source and absolute paths
  are not exported.
- Verification arguments are passed directly to executables and never through
  a shell.

We will acknowledge reports as soon as practical and coordinate a fix and
release timeline with the reporter.
