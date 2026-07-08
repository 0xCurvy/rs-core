#!/usr/bin/env bash
# M1 spike reproduce driver.
#
#   ./run.sh                 pure-Rust prove + verify + on-chain (fast inner loop)
#   ./run.sh test            same, as `cargo test` (integration test)
#   ./run.sh regen-fixtures  rebuild the offline golden fixtures (needs v3-e2e + snarkjs)
#
# anvil is spawned in-process by alloy's node-bindings; no external anvil needed.
# The 13 MB proving key and 3 MB witness .wasm are NOT vendored — they are read
# from the canonical v3-e2e assets (override the repo root with CURVY_V3E2E).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

V3E2E="${CURVY_V3E2E:-/Users/vanja/Projects/v3-e2e}"
SNARKJS="$V3E2E/packages/zk-circuits/node_modules/.bin/snarkjs"
ZKDIR="$V3E2E/packages/zk-keys/v2/withdrawal"
CIRCUITS="$V3E2E/packages/zk-circuits"
BUILD_CIRCUIT="$HERE/vendor/circom-witnesscalc/target/release/build-circuit"
CIRCUIT_SRC="./circuits/v2/instances/verifySingleWithdrawalNoHashing_2_30.circom"

case "${1:-run}" in
  run|"")
    exec cargo run --release --bin prove-verify
    ;;
  test)
    exec cargo test --release --test e2e -- --nocapture
    ;;
  regen-fixtures)
    echo "[1/5] input.json + expected-public.json (from rs-core parity vectors)"
    cargo run -q --release --bin gen-input

    echo "[2/5] pure-Rust witness graph from circuit sources (build-circuit)"
    if [ ! -x "$BUILD_CIRCUIT" ]; then
      ( cd "$HERE/vendor/circom-witnesscalc" && cargo build --release --bin build-circuit )
    fi
    ( cd "$CIRCUITS" && "$BUILD_CIRCUIT" "$CIRCUIT_SRC" "$HERE/fixtures/withdrawal_2_30.graph.bin" )

    echo "[3/5] golden .wtns via snarkjs from the committed circuit .wasm"
    "$SNARKJS" wtns calculate \
      "$ZKDIR/verifySingleWithdrawalNoHashing_2_30.wasm" \
      fixtures/input.json fixtures/golden.wtns

    echo "[4/5] snarkjs proof + public cross-reference"
    "$SNARKJS" groth16 prove \
      "$ZKDIR/verifySingleWithdrawalNoHashing_2_30_0001.zkey" \
      fixtures/golden.wtns fixtures/snarkjs-proof.json fixtures/snarkjs-public.json

    echo "[5/5] verifier bytecode + abi from the contracts artifact"
    ART="$V3E2E/packages/contracts/evm/artifacts/src/v2/aggregator-alpha/verifiers/CurvyWithdrawalVerifier.sol/CurvyWithdrawalVerifier.json"
    python3 - "$ART" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
open("fixtures/CurvyWithdrawalVerifier.bytecode.txt", "w").write(d["bytecode"].strip())
json.dump(d["abi"], open("fixtures/CurvyWithdrawalVerifier.abi.json", "w"), indent=1)
PY
    echo "fixtures regenerated. sha256:"
    shasum -a 256 fixtures/*
    ;;
  *)
    echo "usage: run.sh [run|test|regen-fixtures]" >&2
    exit 1
    ;;
esac
