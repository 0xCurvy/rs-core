#!/usr/bin/env bash
# Build the THREADED (rayon) wasm packages the SDK's hybrid prover/scanner worker
# consumes, and either copy them into an SDK, or print copy instructions.
#
#   _corewasm  <- curvy-wasm    (crypto core + rayon scanner)
#   _arkwasm   <- curvy-prover   (arkworks Groth16 prover)
#
# Both are `wasm-bindgen --target web` outputs of the wasm-threads build, packaged
# with the two shim files that wasm-bindgen-rayon's package-DIRECTORY import needs
# (`package.json` + `index.js`). Staged under ./dist-hybrid/.
#
# Usage:
#   scripts/build-hybrid-wasm.sh [SDK_PATH]
#     SDK_PATH  root of the @0xcurvy/sdk package. If given (or via $SDK_PATH), the
#               built dirs are copied to <SDK_PATH>/src/proving/hybridProver/.
#               If omitted and stdin is a TTY, you're prompted for it; otherwise
#               the script prints the copy command and stops.
#
# Requires: rustup nightly with rust-src, the wasm32-unknown-unknown target, and
# wasm-bindgen-cli 0.2.114.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DEST_SUB="src/proving/hybridProver"

# Shared link flags: imported SHARED memory + the TLS/heap symbol exports the
# wasm-bindgen threads transform requires.
FLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals'
FLAGS+=' -C link-arg=--shared-memory -C link-arg=--import-memory'
FLAGS+=' -C link-arg=--max-memory=2147483648'
FLAGS+=' -C link-arg=--export=__heap_base -C link-arg=--export=__data_end'
FLAGS+=' -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size'
FLAGS+=' -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'

STAGE="$ROOT/dist-hybrid"
rm -rf "$STAGE"
mkdir -p "$STAGE"

# Write the two shim files. wasm-bindgen-rayon's worker helper does
# `import("../../..")` (the package directory), so a `package.json` (`main`) and
# an `index.js` at the dir root are required for that directory import to resolve.
# $1 = staged dir, $2 = wasm-bindgen module basename (no extension).
write_shims() {
  printf '{ "type": "module", "main": "./%s.js", "module": "./%s.js", "sideEffects": true }\n' "$2" "$2" >"$1/package.json"
  printf 'export * from "./%s.js";\nexport { default } from "./%s.js";\n' "$2" "$2" >"$1/index.js"
}

echo "==> building _corewasm (curvy-wasm, threaded)"
RUSTFLAGS="$FLAGS" cargo +nightly build --release --target wasm32-unknown-unknown \
  -p curvy-wasm --features curvy-wasm/wasm-threads -Z build-std=panic_abort,std
wasm-bindgen --target web --out-dir "$STAGE/_corewasm" \
  "$ROOT/target/wasm32-unknown-unknown/release/curvy_wasm.wasm"
write_shims "$STAGE/_corewasm" curvy_wasm

echo "==> building _arkwasm (curvy-prover, threaded)"
# curvy-prover is a detached workspace with its own target dir.
(
  cd crates/prover
  RUSTFLAGS="$FLAGS" cargo +nightly build --release --target wasm32-unknown-unknown \
    -Z build-std=panic_abort,std --no-default-features --features std,wasm-threads
  wasm-bindgen --target web --out-dir "$STAGE/_arkwasm" \
    target/wasm32-unknown-unknown/release/curvy_prover.wasm
)
write_shims "$STAGE/_arkwasm" curvy_prover

echo "staged:"
echo "  $STAGE/_corewasm  (import ./_corewasm/curvy_wasm.js)"
echo "  $STAGE/_arkwasm   (import ./_arkwasm/curvy_prover.js)"

# Resolve an SDK path: positional arg, then $SDK_PATH, then interactive prompt.
SDK="${1:-${SDK_PATH:-}}"
if [ -z "$SDK" ] && [ -t 0 ]; then
  read -rp "SDK path to copy into (blank to skip): " SDK || true
fi

if [ -n "${SDK:-}" ]; then
  dest="$SDK/$DEST_SUB"
  if [ ! -d "$dest" ]; then
    echo "error: $dest does not exist — pass the @0xcurvy/sdk package root" >&2
    exit 1
  fi
  rm -rf "$dest/_corewasm" "$dest/_arkwasm"
  cp -r "$STAGE/_corewasm" "$STAGE/_arkwasm" "$dest/"
  echo "copied _corewasm + _arkwasm -> $dest"
  echo "the SDK worker must import ./_corewasm/curvy_wasm.js and ./_arkwasm/curvy_prover.js"
else
  cat <<EOF

Not copied. To install into the SDK, run:
  cp -r "$STAGE/_corewasm" "$STAGE/_arkwasm" <sdk>/$DEST_SUB/
The SDK worker imports:
  ./_corewasm/curvy_wasm.js
  ./_arkwasm/curvy_prover.js
EOF
fi
