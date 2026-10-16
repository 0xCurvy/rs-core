#!/usr/bin/env bash
#
# End-to-end smoke test for the graph pipeline, on a circuit small enough to run
# in seconds.
#
#   scripts/smoke-graph.sh
#
# Runs build-graph.sh the way a release does, with the R1CS circom compiled as
# PROVING_KEY_R1CS, then `signet export`, which round-trips the artifact through the
# shipped evaluator, and checks the artifact's witness against circom's own on both
# sides of every input-dependent select. It also checks that build-graph.sh refuses
# another circuit's R1CS and leaves no graph behind. The circuit holds the construct
# circomlib's IsZero uses, an input-dependent `<--` ternary with a division, both
# inline and in a subcomponent.
#
# Needs circom 2.2.3, node and cargo, and git when the builder is not installed yet.
# It does not need a circuits tree or circomlib, so it exercises the toolchain wiring
# rather than any particular circuit.

set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/../../.." && pwd)"
source "$SCRIPTS_DIR/ir-builder.sh"

signet_require node cargo
signet_require_circom
signet_ir_builder
signet_work_dir

CIRCUITS="$SIGNET_WORK/circuits/smoke"
mkdir -p "$CIRCUITS"
cat > "$CIRCUITS/smoke.circom" <<'CIRCOM'
pragma circom 2.0.0;

template IsZero() {
    signal input in;
    signal output out;
    signal inverse;

    inverse <-- in != 0 ? 1 / in : 0;
    out <== -in * inverse + 1;
    in * out === 0;
}

template Smoke() {
    signal input a;
    signal input b;
    signal output product;
    signal output aIsZero;
    signal output bIsZero;
    signal inverse;

    product <== a * b;
    inverse <-- a != 0 ? 1 / a : 0;
    aIsZero <== 1 - a * inverse;
    a * aIsZero === 0;

    component zero = IsZero();
    zero.in <== b;
    bIsZero <== zero.out;
}

component main = Smoke();
CIRCOM
cat > "$CIRCUITS/other.circom" <<'CIRCOM'
pragma circom 2.0.0;

template Other() {
    signal input a;
    signal output b;
    b <== a * a;
}

component main = Other();
CIRCOM

echo "==> compiling the proving-key R1CS and the reference witness generator with circom"
circom "$CIRCUITS/smoke.circom" --r1cs --wasm --O2 -o "$SIGNET_WORK" >/dev/null
circom "$CIRCUITS/other.circom" --r1cs --O2 -o "$SIGNET_WORK" >/dev/null

echo "==> build-graph.sh refuses another circuit's R1CS"
if CIRCUITS_DIR="$SIGNET_WORK" PROVING_KEY_R1CS="$SIGNET_WORK/other.r1cs" \
  "$SCRIPTS_DIR/build-graph.sh" smoke/smoke.circom "$SIGNET_WORK/refused.bin" \
  > "$SIGNET_WORK/refused.log" 2>&1; then
  echo "build-graph.sh accepted the R1CS of a different circuit" >&2
  exit 1
fi
grep -q "does not describe the compiled circuit" "$SIGNET_WORK/refused.log" \
  || { cat "$SIGNET_WORK/refused.log" >&2; echo "build-graph.sh failed for another reason" >&2; exit 1; }
test ! -e "$SIGNET_WORK/refused.bin" || { echo "a refused build left a graph" >&2; exit 1; }

echo "==> building the graph with build-graph.sh"
CIRCUITS_DIR="$SIGNET_WORK" PROVING_KEY_R1CS="$SIGNET_WORK/smoke.r1cs" \
  "$SCRIPTS_DIR/build-graph.sh" smoke/smoke.circom "$SIGNET_WORK/graph.bin" \
  | tee "$SIGNET_WORK/build.log"
R1CS_SHA256="$(sed -n 's/^r1cs_sha256=//p' "$SIGNET_WORK/build.log")"
[[ "$R1CS_SHA256" == "$(signet_sha256 "$SIGNET_WORK/smoke.r1cs")" ]] \
  || { echo "build-graph.sh reported r1cs_sha256=$R1CS_SHA256 for another file" >&2; exit 1; }
test -s "$SIGNET_WORK/graph.bin" || { echo "build-graph.sh produced no graph.bin" >&2; exit 1; }

echo "==> exporting an artifact, which round-trips it through WitnessGraph"
cargo build --quiet --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" -p curvy-signet
SIGNET="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release/signet"
"$SIGNET" export "$SIGNET_WORK/graph.bin" "$SIGNET_WORK/artifact.bin" "$R1CS_SHA256" \
  | tee "$SIGNET_WORK/export.log"
grep -q '^round_trip=ok$' "$SIGNET_WORK/export.log" \
  || { echo "export did not report round_trip=ok" >&2; exit 1; }
ARTIFACT_SHA256="$(sed -n 's/^artifact_sha256=//p' "$SIGNET_WORK/export.log")"

for input in '{"a": "0", "b": "5"}' '{"a": "7", "b": "0"}' '{"a": "7", "b": "5"}'; do
  echo "==> parity against circom's witness for $input"
  echo "$input" > "$SIGNET_WORK/input.json"
  node "$SIGNET_WORK/smoke_js/generate_witness.js" "$SIGNET_WORK/smoke_js/smoke.wasm" \
    "$SIGNET_WORK/input.json" "$SIGNET_WORK/reference.wtns"
  "$SIGNET" validate "$SIGNET_WORK/artifact.bin" "$ARTIFACT_SHA256" "$SIGNET_WORK/input.json" \
    "$SIGNET_WORK/reference.wtns" | tee "$SIGNET_WORK/validate.log"
  grep -q '^parity=exact$' "$SIGNET_WORK/validate.log" \
    || { echo "validate did not report parity=exact" >&2; exit 1; }
done

echo "==> smoke test passed"
