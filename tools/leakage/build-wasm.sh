#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
RUSTFLAGS='-C target-feature=+simd128,+bulk-memory' \
CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
cargo build --locked --release --target wasm32-unknown-unknown -p curvy-leakage --features wasm
wasm-bindgen --target web --out-dir tools/leakage/pkg \
  "${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release/curvy_leakage.wasm"
