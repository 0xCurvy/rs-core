#!/usr/bin/env bash
# Runs rs-core's checks. Without arguments it lists them.
#
#   scripts/check.sh <check> [options]
#
# Checks, with the build each one needs:
#   kernels        the generated SIMD kernels match their generator
#   js             unit tests of the SPARROW JS adapter and the npm packager
#   ffi            curvy.h is current (cbindgen 0.29.4), the C ABI covers the WASM
#                  API, and both agree on the golden vectors  [wasm-nodejs]
#   wasm [--signet-v2]
#                  the Node.js modules match the golden vectors, prove a Groth16
#                  proof, and accept SIGNET v2 graphs exactly when built with
#                  --signet-v2 or --sparrow (say so with --signet-v2)  [wasm-nodejs]
#   simd-codegen   the SIMD kernels compiled to extmul, not emulated i64x2.mul
#                  [any build with --simd]
#   simd [options] SIMD differential self-tests, stress rounds and kernel
#                  benchmark; options go to scripts/lib/simd-selftest.mjs
#                  [wasm-nodejs --sparrow --simd --simd-selftest, or the web
#                  equivalent with --engine]
#   npm            pack @0xcurvy/rs-core-wasm, install it and prove with it
#                  [wasm-web and wasm-web-threads]
#   browser [threaded|portable]
#                  proofs in Chromium and Firefox  [wasm-web and wasm-web-threads;
#                  npm ci --prefix tools/browser; npx playwright install]
#   graph          the witness-graph pipeline end to end (circom 2.2.3, node)
#   artifacts      the release bundle validator  [npm ci --prefix tools/artifacts]
#   all            kernels, js, ffi, wasm, npm, graph and artifacts, skipping the
#                  ones whose build or tools are missing and saying which
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'
}

# A missing prerequisite: exit status 2, so `all` can tell a skip from a failure.
needs() {
  echo "needs $*" >&2
  return 2
}

have_file() {
  [[ -e "$1" ]] || needs "$2"
}

have_tool() {
  command -v "$1" >/dev/null 2>&1 || needs "$2"
}

check() {
  local name="$1"
  shift
  case "$name" in
    kernels)
      have_tool python3 "python3" || return
      python3 crates/prover/scripts/gen_simd_u29.py --check
      ;;
    js)
      node --test crates/prover/js/*.test.mjs scripts/lib/*.test.mjs
      ;;
    ffi)
      have_file crates/wasm/pkg-node/curvy_wasm.js "scripts/build.sh wasm-nodejs" || return
      [[ "$(cbindgen --version 2>/dev/null || true)" == "cbindgen 0.29.4" ]] ||
        needs "cbindgen 0.29.4: cargo install --locked cbindgen --version 0.29.4" || return
      cbindgen -q --verify --config bindings/ffi/cbindgen.toml --lockfile Cargo.lock \
        --output bindings/ffi/include/curvy.h bindings/ffi
      echo "bindings/ffi/include/curvy.h is current"
      node scripts/lib/ffi-surface.mjs
      node scripts/lib/ffi-vectors.mjs
      ;;
    wasm)
      have_file crates/prover/pkg-node/curvy_prover.js "scripts/build.sh wasm-nodejs" || return
      local signet_v2=(--expect-v2-disabled)
      case "${1:-}" in
        --signet-v2) signet_v2=() ;;
        "") ;;
        *) echo "unknown option for wasm: $1" >&2; return 2 ;;
      esac
      node crates/wasm/smoke-test.cjs
      node tools/browser/node-proof-check.mjs
      node scripts/lib/signet-v2.cjs "${signet_v2[@]+"${signet_v2[@]}"}"
      ;;
    simd-codegen)
      [[ -n "${WASM_TOOLS:-}" ]] || have_tool wasm-tools "wasm-tools on PATH, or WASM_TOOLS" || return
      node scripts/lib/simd-codegen.mjs "$@"
      ;;
    simd)
      node scripts/lib/simd-selftest.mjs "$@"
      ;;
    npm)
      for dir in crates/wasm/pkg-web crates/prover/pkg-web crates/wasm/pkg-web-threads crates/prover/pkg-web-threads; do
        have_file "$dir" "scripts/build.sh wasm-web and wasm-web-threads" || return
      done
      local version install_dir status=0
      node scripts/lib/build-npm.mjs --pack
      version="$(node -p 'require("./dist/npm/package.json").version')"
      install_dir="$(mktemp -d "${TMPDIR:-/tmp}/curvy-npm-smoke.XXXXXX")"
      (
        cd "$install_dir"
        npm init -y >/dev/null
        npm install --ignore-scripts --no-audit --no-fund "$OLDPWD/0xcurvy-rs-core-wasm-$version.tgz" >/dev/null
      ) && node scripts/lib/smoke-npm.mjs "$install_dir" || status=$?
      rm -rf "$install_dir"
      return "$status"
      ;;
    browser)
      have_file tools/browser/node_modules/playwright "npm ci --prefix tools/browser and npx --prefix tools/browser playwright install" || return
      node tools/browser/check.mjs "$@"
      ;;
    graph)
      have_tool circom "circom 2.2.3" || return
      grep -qE '^rev=[0-9a-f]{40}$' crates/signet/scripts/ir-builder.pin || [[ -n "${SIGNET_IR_BUILDER:-}" ]] ||
        needs "rev in crates/signet/scripts/ir-builder.pin, or SIGNET_IR_BUILDER" || return
      crates/signet/scripts/smoke-graph.sh
      ;;
    artifacts)
      have_tool python3 "python3" || return
      have_file tools/artifacts/node_modules "npm ci --prefix tools/artifacts" || return
      # Both suites drive the validator example.
      cargo build --locked -p curvy-prover --example artifact_manifest_check --features sage
      python3 tools/artifacts/test_release.py
      python3 tools/artifacts/test_pipeline.py
      ;;
    all)
      local each passed=() skipped=() failed=() status
      for each in kernels js ffi wasm npm graph artifacts; do
        echo "==> $each"
        # A separate process, so `set -e` applies inside the check.
        status=0
        "$0" "$each" || status=$?
        case "$status" in
          0) passed+=("$each") ;;
          2) skipped+=("$each") ;;
          *) failed+=("$each") ;;
        esac
      done
      echo "passed:  ${passed[*]:-none}"
      echo "skipped: ${skipped[*]:-none} (prerequisites missing; see above)"
      echo "failed:  ${failed[*]:-none}"
      [[ ${#failed[@]} -eq 0 ]]
      ;;
    help | --help | -h) usage ;;
    *)
      echo "unknown check: $name" >&2
      usage >&2
      return 2
      ;;
  esac
}

if [[ $# -eq 0 ]]; then
  usage
  exit
fi
check "$@"
