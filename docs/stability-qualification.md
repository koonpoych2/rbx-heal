# Stable qualification

`ci/stable-candidate.json` is the single checked-in source of truth for the
candidate tag and the seven-run requirement. Scheduled CI reads that manifest,
checks out the protected candidate tag, and writes a metadata-only
`StableQualificationRunV1` artifact after every gate passes. Push and pull
request workflows continue to scan their submitted revision.

The streak is intentionally strict: all records must be successful scheduled
runs on the same candidate, use attempt one, and occupy seven consecutive UTC
dates. A failure, cancellation, rerun, missing artifact, date gap, or candidate
change invalidates the proof. No source, path, diff, message, or verifier
output is included.

To verify downloaded run metadata and artifacts offline:

```text
python ci/verify-stability-streak.py \
  --runs scheduled-runs.json \
  --evidence-dir stability-evidence \
  --candidate-tag v0.10.0-rc.3 \
  --candidate-commit <40-hex-commit> \
  --required-runs 7 \
  --output rbx-heal-v0.10.0-stability.json
```

Stable publication remains a human-approved operation. The release workflow
performs a non-publishing preflight first and requires the candidate named by
`ci/stable-candidate.json` as the direct parent of the one version-only stable
commit. Prerelease releases do not require a streak.
