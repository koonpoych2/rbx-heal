#!/usr/bin/env bash
set -euo pipefail

version="${1:?version required}"
platform="${2:?platform required}"
binary="${3:?binary required}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
stage="${RUNNER_TEMP:-/tmp}/rbx-heal-release-${platform}"
dist="${4:-$repo/dist}"
rm -rf "$stage" "$dist"
mkdir -p "$stage" "$dist"

cp "$binary" "$stage/rbx-heal"
cp "$repo/rbx-heal.toml.example" "$repo/README.md" "$repo/CHANGELOG.md" "$repo/LICENSE" "$repo/ci/tools.lock.json" "$stage/"

export STAGE_DIR="$stage"
export RELEASE_VERSION="$version"
export RELEASE_PLATFORM="$platform"
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

root = Path(os.environ["STAGE_DIR"])
rows = []
for path in sorted(root.iterdir(), key=lambda item: item.name):
    if path.is_file():
        rows.append({
            "name": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size,
        })
manifest = {
    "schema_version": 1,
    "product": "rbx-heal",
    "version": os.environ["RELEASE_VERSION"],
    "platform": os.environ["RELEASE_PLATFORM"],
    "artifact_type": "unsigned_tar_gz",
    "source_commit": os.environ.get("GITHUB_SHA", "local"),
    "rust_toolchain": "1.85.0",
    "action_lock": "ci/actions.lock.json",
    "corpus_suite": "public-v1",
    "corpus_manifest": "pilot/public-v1.toml",
    "files": rows,
}
(root / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY

epoch="${SOURCE_DATE_EPOCH:-946684800}"
base="rbx-heal-v${version}-ubuntu-x86_64"
tar_one="${RUNNER_TEMP:-/tmp}/${base}.first.tar"
tar_two="${RUNNER_TEMP:-/tmp}/${base}.second.tar"
archive="$dist/${base}.tar.gz"
tar -C "$stage" --sort=name --mtime="@${epoch}" --owner=0 --group=0 --numeric-owner -cf "$tar_one" .
tar -C "$stage" --sort=name --mtime="@${epoch}" --owner=0 --group=0 --numeric-owner -cf "$tar_two" .
gzip -n -c "$tar_one" > "$archive"
gzip -n -c "$tar_two" > "${RUNNER_TEMP:-/tmp}/${base}.second.tar.gz"
hash_one="$(sha256sum "$archive" | awk '{print tolower($1)}')"
hash_two="$(sha256sum "${RUNNER_TEMP:-/tmp}/${base}.second.tar.gz" | awk '{print tolower($1)}')"
if [[ "$hash_one" != "$hash_two" ]]; then
  echo "deterministic archive hash mismatch" >&2
  exit 1
fi
printf '%s  %s\n' "$hash_one" "$(basename "$archive")" > "$archive.sha256"
cp "$stage/provenance.json" "$dist/${base}-provenance.json"
printf '%s\n' "$archive"
