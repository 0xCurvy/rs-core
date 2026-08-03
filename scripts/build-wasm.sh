#!/usr/bin/env bash
# Build the complete Curvy Rust core for WebAssembly and generate JS bindings.
#
# Usage: scripts/build-wasm.sh [nodejs|web|bundler] [--threads]
#
# `--threads` is available only for the `web` target and requires nightly with
# rust-src plus a cross-origin-isolated browser at runtime.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -gt 2 ]; then
  echo "usage: scripts/build-wasm.sh [nodejs|web|bundler] [--threads]" >&2
  exit 1
fi

binding_target="${1:-nodejs}"
thread_mode="${2:-}"

case "$binding_target" in
  nodejs) portable_output_suffix="node" ;;
  web|bundler) portable_output_suffix="$binding_target" ;;
  *)
    echo "unknown target: $binding_target (use nodejs|web|bundler)" >&2
    exit 1
    ;;
esac

case "$thread_mode" in
  "")
    output_suffix="$portable_output_suffix"
    cargo build --locked --release --target wasm32-unknown-unknown \
      -p curvy-wasm -p curvy-prover --lib --no-default-features \
      --features curvy-prover/std,curvy-prover/wasm
    ;;
  --threads)
    if [ "$binding_target" != "web" ]; then
      echo "--threads requires the web target" >&2
      exit 1
    fi
    output_suffix="web-threads"
    thread_toolchain="${CURVY_WASM_THREADS_TOOLCHAIN:-nightly-2026-07-03}"
    rust_flags='-C target-feature=+atomics,+bulk-memory,+mutable-globals'
    rust_flags+=' -C link-arg=--shared-memory -C link-arg=--import-memory'
    rust_flags+=' -C link-arg=--max-memory=2147483648'
    rust_flags+=' -C link-arg=--export=__heap_base -C link-arg=--export=__data_end'
    rust_flags+=' -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size'
    rust_flags+=' -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'
    RUSTFLAGS="$rust_flags" cargo +"$thread_toolchain" build --locked --release \
      --target wasm32-unknown-unknown -Z build-std=panic_abort,std \
      -p curvy-wasm -p curvy-prover --lib --no-default-features \
      --features curvy-wasm/wasm-threads,curvy-prover/std,curvy-prover/wasm-threads
    ;;
  *)
    echo "unknown mode: $thread_mode (use --threads or omit it)" >&2
    exit 1
    ;;
esac

wasm_target_dir="${CARGO_TARGET_DIR:-target}/wasm32-unknown-unknown/release"
core_output="crates/wasm/pkg-${output_suffix}"
prover_output="crates/prover/pkg-${output_suffix}"

wasm-bindgen --target "$binding_target" --out-dir "$core_output" \
  "$wasm_target_dir/curvy_wasm.wasm"
wasm-bindgen --target "$binding_target" --out-dir "$prover_output" \
  "$wasm_target_dir/curvy_prover.wasm"

if [ "$binding_target" = "nodejs" ]; then
  printf '{\n  "name": "@curvy/core-wasm-node",\n  "type": "commonjs",\n  "main": "curvy_wasm.js",\n  "types": "curvy_wasm.d.ts"\n}\n' > "$core_output/package.json"
  printf '{\n  "name": "@curvy/prover-wasm-node",\n  "type": "commonjs",\n  "main": "curvy_prover.js",\n  "types": "curvy_prover.d.ts"\n}\n' > "$prover_output/package.json"
fi

echo "built complete WASM core: $core_output and $prover_output"
