#!/usr/bin/env bash
# Builds rs-core. Without arguments it asks what to build.
#
#   scripts/build.sh <target> [options]
#
# Targets and what they write:
#   native              native libraries with Rayon, and target/release/curvy-native-prover
#   wasm-nodejs         portable modules for Node.js   crates/{wasm,prover}/pkg-node
#   wasm-web            portable modules for browsers  crates/{wasm,prover}/pkg-web
#   wasm-bundler        portable modules for bundlers  crates/{wasm,prover}/pkg-bundler
#   wasm-web-threads    threaded modules for browsers  crates/{wasm,prover}/pkg-web-threads
#   all-portable        native, wasm-nodejs, wasm-web and wasm-bundler
#   npm [--pack]        @0xcurvy/rs-core-wasm from wasm-web and wasm-web-threads:
#                       dist/npm, and with --pack the .tgz in the repository root
#   node-release        @0xcurvy/rs-core-node packages (Apple Silicon Mac with
#                       Docker): bindings/node/release
#   ffi-header          bindings/ffi/include/curvy.h (cbindgen 0.29.4)
#   kernels             the generated SIMD kernels in crates/prover/src
#   graph <circuit> <out.bin>
#                       a witness graph (crates/signet/scripts/build-graph.sh; set
#                       CIRCUITS_DIR and PROVING_KEY_R1CS)
#
# The wasm-* targets take the options of scripts/lib/build-wasm.sh, for example
# `scripts/build.sh wasm-web-threads --simd`.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

wasm() {
  scripts/lib/build-wasm.sh "$@"
}

native() {
  cargo build --locked --release \
    -p curvy-core -p curvy-witness -p curvy-prover \
    --features curvy-core/parallel,curvy-prover/parallel
  echo "built the native libraries and ${CARGO_TARGET_DIR:-target}/release/curvy-native-prover"
}

ffi_header() {
  local version
  version="$(cbindgen --version 2>/dev/null || true)"
  if [[ "$version" != "cbindgen 0.29.4" ]]; then
    echo "needs cbindgen 0.29.4 (found: ${version:-none}): cargo install --locked cbindgen --version 0.29.4" >&2
    return 1
  fi
  cbindgen -q --config bindings/ffi/cbindgen.toml --lockfile Cargo.lock \
    --output bindings/ffi/include/curvy.h bindings/ffi
  echo "wrote bindings/ffi/include/curvy.h"
}

build() {
  local target="$1"
  shift
  case "$target" in
    native) native ;;
    wasm-nodejs) wasm nodejs "$@" ;;
    wasm-web) wasm web "$@" ;;
    wasm-bundler) wasm bundler "$@" ;;
    wasm-web-threads) wasm web --threads "$@" ;;
    all-portable)
      native
      wasm nodejs
      wasm web
      wasm bundler
      ;;
    npm)
      wasm web
      wasm web --threads
      node scripts/lib/build-npm.mjs "$@"
      ;;
    node-release) node scripts/lib/node-release.mjs "$@" ;;
    ffi-header) ffi_header ;;
    kernels) python3 crates/prover/scripts/gen_simd_u29.py "$@" ;;
    graph) crates/signet/scripts/build-graph.sh "$@" ;;
    help | --help | -h) usage ;;
    *)
      echo "unknown target: $target" >&2
      usage >&2
      return 2
      ;;
  esac
}

if [[ $# -gt 0 ]]; then
  build "$@"
  exit
fi

cat <<'EOF'
What do you want to build?
  1) native libraries and curvy-native-prover
  2) portable WASM modules for Node.js
  3) portable WASM modules for browsers
  4) portable WASM modules for bundlers
  5) threaded WASM modules for browsers
  6) native plus all portable WASM targets
  7) the npm package (@0xcurvy/rs-core-wasm)
EOF
read -r -p "Select [1-7]: " selection
case "$selection" in
  1) build native ;;
  2) build wasm-nodejs ;;
  3) build wasm-web ;;
  4) build wasm-bundler ;;
  5) build wasm-web-threads ;;
  6) build all-portable ;;
  7) build npm ;;
  *)
    echo "invalid selection: $selection" >&2
    exit 2
    ;;
esac
