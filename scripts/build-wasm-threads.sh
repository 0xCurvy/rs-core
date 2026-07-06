#!/usr/bin/env bash
# THREADED (rayon) wasm build of curvy-wasm, for cross-origin-isolated pages —
# enables parallel scan via the `wasm-threads` feature (exports initThreadPool).
#
# Requires: rustup nightly with rust-src (`rustup toolchain install nightly
# --component rust-src`), the wasm32-unknown-unknown target on nightly, and
# wasm-bindgen-cli 0.2.114. The link flags produce an IMPORTED SHARED memory and
# export the TLS/heap symbols wasm-bindgen's threads transform needs.
set -euo pipefail
cd "$(dirname "$0")/.."

FLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals'
FLAGS+=' -C link-arg=--shared-memory -C link-arg=--import-memory'
FLAGS+=' -C link-arg=--max-memory=2147483648'
FLAGS+=' -C link-arg=--export=__heap_base -C link-arg=--export=__data_end'
FLAGS+=' -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size'
FLAGS+=' -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'

RUSTFLAGS="$FLAGS" cargo +nightly build --release --target wasm32-unknown-unknown \
  -p curvy-wasm --features curvy-wasm/wasm-threads -Z build-std=panic_abort,std

wasm-bindgen --target web --out-dir crates/wasm/pkg-web-threads \
  target/wasm32-unknown-unknown/release/curvy_wasm.wasm


echo "built crates/wasm/pkg-web-threads (web target, rayon threads)"
