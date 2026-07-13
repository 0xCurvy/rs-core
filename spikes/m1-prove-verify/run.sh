#!/usr/bin/env bash
# M1 spike reproduce driver — all three deployed Curvy circuit configs
# (withdrawal(2,30), aggregation(2,3,30,6), pending-notes-commitment(5,30)).
#
#   ./run.sh                 pure-Rust prove + verify + on-chain, all circuits
#   ./run.sh test            same, as `cargo test` (integration test)
#   ./run.sh regen-fixtures  rebuild the offline golden fixtures (needs v3-e2e + snarkjs)
#
# anvil is spawned in-process by alloy's node-bindings; no external anvil needed.
# The multi-MB proving keys and witness .wasm are NOT vendored — they are read from the
# canonical v3-e2e assets (override the repo root with CURVY_V3E2E). The 13 MB pending
# graph + 7 MB pending golden .wtns are gitignored (sha256-pinned in src/lib.rs);
# `regen-fixtures` recreates them.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

V3E2E="/home/dev/Projects/curvy-monorepo/"
SNARKJS="$V3E2E/packages/zk-circuits/node_modules/.bin/snarkjs"
ZKROOT="$V3E2E/packages/zk-keys/v2"
CIRCUITS="$V3E2E/packages/zk-circuits"
ART="$V3E2E/packages/contracts/evm/artifacts/src/v2/aggregator-alpha/verifiers"
BUILD_CIRCUIT="$HERE/vendor/circom-witnesscalc/target/release/build-circuit"

# key | instance-circom (rel to $CIRCUITS) | zkey subdir | artifact-basename | fixture subdir | graph filename | verifier contract
CIRCUITS_TABLE=(
  "withdrawal|verifySingleWithdrawalNoHashing_2_30|withdrawal|verifySingleWithdrawalNoHashing_2_30|.|withdrawal_2_30.graph.bin|CurvyWithdrawalVerifier"
  "aggregation|verifySingleAggregationNoHashing_2_3_30|aggregation|verifySingleAggregationNoHashing_2_3_30|aggregation|aggregation_2_3_30.graph.bin|CurvyAggregationVerifier"
  "pending|verifyPendingNotesCommitment_5_30|pending-notes-commitment|verifyPendingNotesCommitment_5_30|pending|pending_5_30.graph.bin|CurvyPendingNotesCommitmentVerifier"
)

case "${1:-run}" in
  run|"")
    exec cargo run --release --bin prove-verify
    ;;
  test)
    exec cargo test --release --test e2e -- --nocapture
    ;;
  regen-fixtures)
    echo "[1/5] input.json + expected-public.json for all circuits (from rs-core parity vectors)"
    cargo run -q --release --bin gen-input

    if [ ! -x "$BUILD_CIRCUIT" ]; then
      ( cd "$HERE/vendor/circom-witnesscalc" && cargo build --release --bin build-circuit )
    fi

    for row in "${CIRCUITS_TABLE[@]}"; do
      IFS='|' read -r key inst zksub artbase fxsub graph verifier <<< "$row"
      fxdir="$HERE/fixtures/$fxsub"; mkdir -p "$fxdir"
      wasm="$ZKROOT/$zksub/${artbase}.wasm"
      zkey="$ZKROOT/$zksub/${artbase}_0001.zkey"
      echo ""
      echo "── $key ──"
      echo "  [2/5] evaluation graph (build-circuit from circuit sources)"
      ( cd "$CIRCUITS" && "$BUILD_CIRCUIT" "./circuits/v2/instances/${inst}.circom" "$fxdir/$graph" )
      echo "  [3/5] golden .wtns via snarkjs from the committed circuit .wasm"
      "$SNARKJS" wtns calculate "$wasm" "$fxdir/input.json" "$fxdir/golden.wtns"
      echo "  [4/5] snarkjs proof + public cross-reference"
      "$SNARKJS" groth16 prove "$zkey" "$fxdir/golden.wtns" "$fxdir/snarkjs-proof.json" "$fxdir/snarkjs-public.json"
      echo "  [5/5] verifier bytecode + abi from the contracts artifact"
      python3 - "$ART/${verifier}.sol/${verifier}.json" "$fxdir/${verifier}.bytecode.txt" "$fxdir/${verifier}.abi.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
open(sys.argv[2], "w").write(d["bytecode"].strip())
json.dump(d["abi"], open(sys.argv[3], "w"), indent=1)
PY
    done

    echo ""
    echo "fixtures regenerated. sha256 (graphs + goldens):"
    shasum -a 256 \
      fixtures/withdrawal_2_30.graph.bin fixtures/golden.wtns \
      fixtures/aggregation/aggregation_2_3_30.graph.bin fixtures/aggregation/golden.wtns \
      fixtures/pending/pending_5_30.graph.bin fixtures/pending/golden.wtns
    ;;
  *)
    echo "usage: run.sh [run|test|regen-fixtures]" >&2
    exit 1
    ;;
esac
