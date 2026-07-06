#!/usr/bin/env bash
# Build the Curvy crypto core to wasm and generate the JS bindings.
#
# Usage: scripts/build-wasm.sh [nodejs|web|bundler]   (default: nodejs)
#   nodejs  -> sync CommonJS (vitest / node services)
#   web     -> async ESM (browser, explicit init())
#   bundler -> ESM for vite/webpack/tsup
#
# Requires: rustup target add wasm32-unknown-unknown; cargo install wasm-bindgen-cli --version 0.2.114
set -euo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:-nodejs}"
case "$TARGET" in
  nodejs) OUT="crates/wasm/pkg-node" ;;
  web)    OUT="crates/wasm/pkg-web" ;;
  bundler) OUT="crates/wasm/pkg-bundler" ;;
  *) echo "unknown target: $TARGET (use nodejs|web|bundler)" >&2; exit 1 ;;
esac

cargo build --target wasm32-unknown-unknown -p curvy-wasm --release
wasm-bindgen --target "$TARGET" --out-dir "$OUT" \
  target/wasm32-unknown-unknown/release/curvy_wasm.wasm

# Mark the CommonJS (nodejs) output explicitly (the workspace root is type:module).
if [ "$TARGET" = "nodejs" ]; then
  printf '{\n  "name": "@curvy/core-wasm-node",\n  "type": "commonjs",\n  "main": "curvy_wasm.js",\n  "types": "curvy_wasm.d.ts"\n}\n' > "$OUT/package.json"
fi

echo "built $OUT (target: $TARGET)"
