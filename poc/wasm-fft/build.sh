#!/usr/bin/env bash
# Build natively and for WASM with the production portable flags
# (+simd128,+bulk-memory, fat LTO, 1 CGU, opt-level 3, wasm-opt -O4).
set -euo pipefail
cd "$(dirname "$0")"
SCRATCH="${WASM_FFT_SCRATCH:-../../../wasm-fft}"
mkdir -p "$SCRATCH"; SCRATCH="$(cd "$SCRATCH" && pwd)"
export CARGO_TARGET_DIR="$SCRATCH/target" TMPDIR="$SCRATCH/tmp"
mkdir -p "$TMPDIR" "$SCRATCH/pkg"
cargo build --offline --release
cp "$CARGO_TARGET_DIR/release/poc" "$SCRATCH/pkg/poc-native"
RUSTFLAGS='-C target-feature=+simd128,+bulk-memory' \
  cargo build --offline --release --target wasm32-unknown-unknown --lib
wasm-opt -O4 --enable-bulk-memory --enable-mutable-globals --enable-reference-types \
  --enable-simd --enable-nontrapping-float-to-int --enable-sign-ext \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/wasm_fft_poc.wasm" -o "$SCRATCH/pkg/wasm_fft_poc.wasm"
ls -l "$SCRATCH/pkg"
