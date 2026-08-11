#!/usr/bin/env bash
# Build the complete Curvy Rust core for WebAssembly and generate JS bindings.
#
# Usage: scripts/build-wasm.sh [nodejs|web|bundler] [--threads] [--signet-v2] [--sparrow] [--bench]
#
# `--threads` is available only for the `web` target and requires nightly with
# rust-src plus a cross-origin-isolated browser at runtime. The non-threaded
# build is portable across memory models, not legacy CPUs: both modes require
# WebAssembly SIMD and bulk-memory support.
# `--sparrow` opts the prover module into SPARROW and its SAGE witness engine.
# Published/default WASM packages intentionally omit both.
# `--signet-v2` enables only the compact witness body decoder; SPARROW implies it.
# `--bench` adds development-only arithmetic kernels and implies SPARROW.
#
# Build controls:
#   CURVY_WASM_LTO               release LTO mode (default: fat)
#   CURVY_WASM_CODEGEN_UNITS     release codegen units (default: 1)
#   CURVY_WASM_THREADS_TOOLCHAIN pinned nightly for --threads
#   CURVY_WASM_OPT               set to 0 to skip wasm-opt (default: 1)
set -euo pipefail

cd "$(dirname "$0")/.."

if [ "$#" -gt 5 ]; then
  echo "usage: scripts/build-wasm.sh [nodejs|web|bundler] [--threads] [--signet-v2] [--sparrow] [--bench]" >&2
  exit 1
fi

binding_target="${1:-nodejs}"
if [ "$#" -gt 0 ]; then
  shift
fi
thread_mode=""
signet_v2_mode=""
sparrow_mode=""
bench_mode=""
for mode in "$@"; do
  case "$mode" in
    --threads)
      if [ -n "$thread_mode" ]; then
        echo "--threads may be supplied only once" >&2
        exit 1
      fi
      thread_mode="--threads"
      ;;
    --sparrow)
      if [ -n "$sparrow_mode" ]; then
        echo "--sparrow may be supplied only once" >&2
        exit 1
      fi
      sparrow_mode="--sparrow"
      ;;
    --signet-v2)
      if [ -n "$signet_v2_mode" ]; then
        echo "--signet-v2 may be supplied only once" >&2
        exit 1
      fi
      signet_v2_mode="--signet-v2"
      ;;
    --bench)
      if [ -n "$bench_mode" ]; then
        echo "--bench may be supplied only once" >&2
        exit 1
      fi
      bench_mode="--bench"
      ;;
    *)
      echo "unknown mode: $mode (use --threads, --signet-v2, --sparrow, --bench, or omit it)" >&2
      exit 1
      ;;
  esac
done
wasm_release_lto="${CURVY_WASM_LTO:-fat}"
wasm_release_codegen_units="${CURVY_WASM_CODEGEN_UNITS:-1}"
portable_rust_flags='-C target-feature=+simd128,+bulk-memory'

case "$binding_target" in
  nodejs) portable_output_suffix="node" ;;
  web|bundler) portable_output_suffix="$binding_target" ;;
  *)
    echo "unknown target: $binding_target (use nodejs|web|bundler)" >&2
    exit 1
    ;;
esac

prover_features="curvy-prover/std,curvy-prover/wasm"
if [ "$bench_mode" = "--bench" ]; then
  prover_features+=",curvy-prover/bench"
elif [ "$sparrow_mode" = "--sparrow" ]; then
  prover_features+=",curvy-prover/sparrow"
elif [ "$signet_v2_mode" = "--signet-v2" ]; then
  prover_features+=",curvy-prover/signet-v2"
fi

case "$thread_mode" in
  "")
    output_suffix="$portable_output_suffix"
    CARGO_PROFILE_RELEASE_LTO="$wasm_release_lto" \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$wasm_release_codegen_units" \
    RUSTFLAGS="$portable_rust_flags" \
    cargo build --locked --release --target wasm32-unknown-unknown \
      -p curvy-wasm -p curvy-prover --lib --no-default-features \
      --features "$prover_features"
    ;;
  --threads)
    if [ "$binding_target" != "web" ]; then
      echo "--threads requires the web target" >&2
      exit 1
    fi
    output_suffix="web-threads"
    thread_toolchain="${CURVY_WASM_THREADS_TOOLCHAIN:-nightly-2026-07-03}"
    rust_flags='-C target-feature=+atomics,+bulk-memory,+mutable-globals,+simd128'
    rust_flags+=' -C link-arg=--shared-memory -C link-arg=--import-memory'
    rust_flags+=' -C link-arg=--max-memory=2147483648'
    rust_flags+=' -C link-arg=--export=__heap_base -C link-arg=--export=__data_end'
    rust_flags+=' -C link-arg=--export=__wasm_init_tls -C link-arg=--export=__tls_size'
    rust_flags+=' -C link-arg=--export=__tls_align -C link-arg=--export=__tls_base'
    prover_features="curvy-wasm/wasm-threads,curvy-prover/std,curvy-prover/wasm-threads"
    if [ "$bench_mode" = "--bench" ]; then
      prover_features+=",curvy-prover/bench"
    elif [ "$sparrow_mode" = "--sparrow" ]; then
      prover_features+=",curvy-prover/sparrow"
    elif [ "$signet_v2_mode" = "--signet-v2" ]; then
      prover_features+=",curvy-prover/signet-v2"
    fi
    CARGO_PROFILE_RELEASE_LTO="$wasm_release_lto" \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS="$wasm_release_codegen_units" \
    RUSTFLAGS="$rust_flags" cargo +"$thread_toolchain" build --locked --release \
      --target wasm32-unknown-unknown -Z build-std=panic_abort,std \
      -p curvy-wasm -p curvy-prover --lib --no-default-features \
      --features "$prover_features"
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

if [ "${CURVY_WASM_OPT:-1}" != "0" ] && command -v wasm-opt >/dev/null 2>&1; then
  optimization_dir="$(mktemp -d "${TMPDIR:-/tmp}/curvy-wasm-opt.XXXXXX")"
  cleanup_optimization_dir() {
    rm -f \
      "$optimization_dir/curvy_wasm_bg.wasm" \
      "$optimization_dir/curvy_prover_bg.wasm"
    rmdir "$optimization_dir" 2>/dev/null || true
  }
  trap cleanup_optimization_dir EXIT
  optimize_wasm() {
    wasm_file="$1"
    optimized_file="$optimization_dir/$(basename "$wasm_file")"
    optimization_flags=(
      -O4
      --enable-bulk-memory
      --enable-mutable-globals
      --enable-reference-types
      --enable-simd
    )
    if [ "$thread_mode" = "--threads" ]; then
      optimization_flags+=(--enable-threads)
    fi
    wasm-opt "${optimization_flags[@]}" "$wasm_file" -o "$optimized_file"
    mv "$optimized_file" "$wasm_file"
  }
  optimize_wasm "$core_output/curvy_wasm_bg.wasm"
  optimize_wasm "$prover_output/curvy_prover_bg.wasm"
  cleanup_optimization_dir
  trap - EXIT
else
  echo "wasm-opt unavailable or disabled; generated module was not post-optimized" >&2
fi

if [ "$binding_target" = "nodejs" ]; then
  printf '{\n  "name": "@curvy/core-wasm-node",\n  "type": "commonjs",\n  "main": "curvy_wasm.js",\n  "types": "curvy_wasm.d.ts"\n}\n' > "$core_output/package.json"
  printf '{\n  "name": "@curvy/prover-wasm-node",\n  "type": "commonjs",\n  "main": "curvy_prover.js",\n  "types": "curvy_prover.d.ts"\n}\n' > "$prover_output/package.json"
fi

if [ "$sparrow_mode" = "--sparrow" ]; then
  sparrow_status="enabled"
else
  sparrow_status="disabled"
fi
if [ "$sparrow_mode" = "--sparrow" ] || [ "$signet_v2_mode" = "--signet-v2" ]; then
  signet_v2_status="enabled"
else
  signet_v2_status="disabled"
fi
echo "built complete WASM core: $core_output and $prover_output (LTO=$wasm_release_lto, codegen-units=$wasm_release_codegen_units, simd128, SIGNET-v2=$signet_v2_status, SPARROW=$sparrow_status)"
