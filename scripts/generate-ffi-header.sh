#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! command -v cbindgen >/dev/null 2>&1; then
  echo "cbindgen is required; install version 0.29.4" >&2
  exit 1
fi

cbindgen_version="$(cbindgen --version)"
if [[ "$cbindgen_version" != "cbindgen 0.29.4" ]]; then
  echo "expected cbindgen 0.29.4, got: $cbindgen_version" >&2
  exit 1
fi

cbindgen -q \
  --config bindings/ffi/cbindgen.toml \
  --lockfile Cargo.lock \
  --output bindings/ffi/include/curvy.h \
  bindings/ffi

