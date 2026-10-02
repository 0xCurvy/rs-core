#!/usr/bin/env bash
# Build the PoC natively and for WASM with the production portable flags
# (scripts/build-wasm.sh: +simd128,+bulk-memory, fat LTO, one codegen unit,
# opt-level 3, then wasm-opt -O4). All output goes to the scratch directory.
set -euo pipefail
cd "$(dirname "$0")"
SCRATCH="${WASM_FIELD_SCRATCH:-../../target/claude-scratch/wasm-field}"
mkdir -p "$SCRATCH"
SCRATCH="$(cd "$SCRATCH" && pwd)"
export CARGO_TARGET_DIR="$SCRATCH/target"
export TMPDIR="$SCRATCH/tmp"
mkdir -p "$TMPDIR" "$SCRATCH/pkg"

cargo build --offline --locked --release
cp "$CARGO_TARGET_DIR/release/poc" "$SCRATCH/pkg/poc-native"

RUSTFLAGS='-C target-feature=+simd128,+bulk-memory' \
  cargo build --offline --locked --release --target wasm32-unknown-unknown --lib
raw="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/wasm_field_poc.wasm"
cp "$raw" "$SCRATCH/pkg/wasm_field_poc.raw.wasm"
wasm-opt -O4 --enable-bulk-memory --enable-mutable-globals --enable-reference-types \
  --enable-simd --enable-nontrapping-float-to-int --enable-sign-ext \
  "$raw" -o "$SCRATCH/pkg/wasm_field_poc.wasm"
ls -l "$SCRATCH/pkg"

# Supplemental variant: LLVM auto-vectorization off (the SLP vectorizer packs
# the scalar 9x29 products into i64x2.mul, which V8 emulates on arm64).
export CARGO_TARGET_DIR="$SCRATCH/target-noslp"
RUSTFLAGS='-C target-feature=+simd128,+bulk-memory -C no-vectorize-slp -C no-vectorize-loops' \
  cargo build --offline --locked --release --target wasm32-unknown-unknown --lib
wasm-opt -O4 --enable-bulk-memory --enable-mutable-globals --enable-reference-types \
  --enable-simd --enable-nontrapping-float-to-int --enable-sign-ext \
  "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/wasm_field_poc.wasm" -o "$SCRATCH/pkg/noslp.wasm"
