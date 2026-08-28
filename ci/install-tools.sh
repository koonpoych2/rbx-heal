#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
manifest="$script_dir/tools.lock.json"
destination="${1:-$script_dir/.tools/ubuntu-x86_64}"
mkdir -p "$destination"
temp_root="$(mktemp -d)"
trap 'rm -rf "$temp_root"' EXIT

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required to read ci/tools.lock.json" >&2
  exit 2
fi

read_lock() {
  python3 - "$manifest" "$1" <<'PY'
import json
import sys

manifest, tool = sys.argv[1:]
with open(manifest, encoding="utf-8") as handle:
    data = json.load(handle)
spec = data["tools"][tool]["assets"]["ubuntu-x86_64"]
print(spec["url"])
print(spec["sha256"])
PY
}

for tool in rojo luau stylua; do
  mapfile -t lock < <(read_lock "$tool")
  url="${lock[0]}"
  expected="${lock[1]}"
  archive="$temp_root/$tool.zip"
  echo "Downloading locked $tool"
  curl --fail --location --proto '=https' --tlsv1.2 --silent --show-error "$url" --output "$archive"
  actual="$(sha256sum "$archive" | awk '{print tolower($1)}')"
  if [[ "$actual" != "${expected,,}" ]]; then
    echo "SHA-256 mismatch for $tool: expected $expected, got $actual" >&2
    exit 1
  fi
  extract="$temp_root/$tool"
  mkdir -p "$extract"
  unzip -q "$archive" -d "$extract"
  case "$tool" in
    rojo) binary_name="rojo" ;;
    luau) binary_name="luau-analyze" ;;
    stylua) binary_name="stylua" ;;
  esac
  binary="$(find "$extract" -type f -name "$binary_name" -print -quit)"
  if [[ -z "$binary" ]]; then
    echo "Locked $tool archive did not contain $binary_name" >&2
    exit 1
  fi
  install -m 0755 "$binary" "$destination/$binary_name"
  if [[ "$tool" == "luau" ]]; then
    compile_binary="$(find "$extract" -type f -name "luau-compile" -print -quit)"
    if [[ -z "$compile_binary" ]]; then
      echo "Locked luau archive did not contain luau-compile" >&2
      exit 1
    fi
    install -m 0755 "$compile_binary" "$destination/luau-compile"
  fi
done

echo "Locked verifier tools installed in $destination"
