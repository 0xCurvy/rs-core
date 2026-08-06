#!/usr/bin/env bash
#
# End-to-end smoke test for the graph pipeline, on a circuit small enough to run
# in seconds.
#
#   scripts/smoke-generator.sh
#
# Runs the same path as build-graph.sh -- circom -> generator -> graph.bin ->
# signet export -> round-trip through the shipped evaluator -- but against a
# three-signal multiplier instead of a production circuit. A real circuit writes
# hundreds of MB of C++ objects and takes minutes; this takes seconds, so it is
# cheap enough to run before every pipeline change.
#
# What it is actually guarding: the generator is a separate workspace that
# nothing in `cargo build --workspace` ever compiles, so a break in it stays
# invisible until someone builds a production artifact. It does not need a
# circuits tree or circomlib, so it exercises the toolchain wiring rather than
# any particular circuit.

set -euo pipefail

CRATE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
GENERATOR_MANIFEST="$CRATE_DIR/generator/Cargo.toml"

for tool in circom cargo shasum; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signet-smoke.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

cat > "$WORK_DIR/multiplier.circom" <<'CIRCOM'
pragma circom 2.0.0;

template Multiplier() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main = Multiplier();
CIRCOM

echo "==> building the generator (compiles the circuit through its build script)"
# The generator writes graph.bin into its working directory, so run it in the
# scratch dir rather than in the crate.
(
  cd "$WORK_DIR"
  WITNESS_CPP="$WORK_DIR/multiplier.circom" \
    cargo build --quiet --release --manifest-path "$GENERATOR_MANIFEST"
  WITNESS_CPP="$WORK_DIR/multiplier.circom" \
    cargo run --quiet --release --manifest-path "$GENERATOR_MANIFEST" >/dev/null
)

test -s "$WORK_DIR/graph.bin" || { echo "generator produced no graph.bin" >&2; exit 1; }
echo "==> graph.bin: $(wc -c < "$WORK_DIR/graph.bin" | tr -d ' ') bytes"

circom "$WORK_DIR/multiplier.circom" --r1cs --O2 -o "$WORK_DIR" >/dev/null
R1CS_SHA256="$(shasum -a 256 "$WORK_DIR/multiplier.r1cs" | cut -d' ' -f1)"

echo "==> exporting an artifact and round-tripping it through WitnessGraph"
# `export` loads the bytes back through the shipped evaluator before writing, so
# `round_trip=ok` is the assertion that matters here.
cargo run --quiet --release --manifest-path "$REPO_ROOT/Cargo.toml" -p curvy-signet -- \
  export "$WORK_DIR/graph.bin" "$WORK_DIR/artifact.bin" "$R1CS_SHA256" \
  | tee "$WORK_DIR/export.log"

grep -q '^round_trip=ok$' "$WORK_DIR/export.log" \
  || { echo "export did not report round_trip=ok" >&2; exit 1; }

echo "==> smoke test passed"
