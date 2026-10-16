#!/usr/bin/env bash
#
# Circuit half of the graph pipeline: .circom -> graph.bin (postcard).
#
#   CIRCUITS_DIR=/path/to/packages/zk-circuits \
#   PROVING_KEY_R1CS=/path/to/circuit.r1cs \
#     scripts/build-graph.sh v2/instances/verifyPendingNotesCommitment_5_30.circom /tmp/pending.bin
#
# The circuit path is relative to $CIRCUITS_DIR/circuits. Everything downstream of
# the graph.bin this writes is pure Rust and lives in the `signet` binary, so the
# script deliberately stops there.
#
# The graph comes from curvy-signet-ir-builder (see ir-builder.sh), which compiles
# the circuit with circom 2.2.3 and writes the graph only if that compilation
# describes the circuit in PROVING_KEY_R1CS, the R1CS the proving key was made
# from: the same header, the same witness layout and the same constraints. Hints
# (`<--`) add no constraints, so that check does not cover the values they compute;
# `signet validate` against circom's witness for a real input does.
#
# Without PROVING_KEY_R1CS the script checks nothing itself: it reports the digest
# of the builder's own R1CS, the compilation the graph came from, and the caller
# must compare that with the proving key's R1CS digest, as the monorepo's
# export-native-witness-graphs.sh does.
#
# Prints key=value lines: builder=, builder_version= and builder_sha256= (what
# built the graph), postcard_graph=, r1cs= and r1cs_sha256=, the digest `signet
# export` takes as its provenance argument.

set -euo pipefail

source "$(cd "$(dirname "$0")" && pwd)/ir-builder.sh"

[[ $# -eq 2 ]] || { echo "usage: build-graph.sh <circuit-relative-path> <output.bin>" >&2; exit 2; }
CIRCUIT_RELATIVE_PATH="$1"
OUTPUT_PATH="$2"
CIRCUITS_DIR="${CIRCUITS_DIR:?set CIRCUITS_DIR to the zk-circuits package}"
CIRCUIT="$CIRCUITS_DIR/circuits/$CIRCUIT_RELATIVE_PATH"
CIRCUIT_NAME="$(basename "$CIRCUIT_RELATIVE_PATH" .circom)"
test -f "$CIRCUIT" || { echo "no circuit at $CIRCUIT" >&2; exit 1; }

# Resolved first, so a missing pin or a failed install stops the script before
# anything is compiled.
signet_ir_builder
signet_work_dir

if [[ -n "${PROVING_KEY_R1CS:-}" ]]; then
  test -f "$PROVING_KEY_R1CS" || { echo "no R1CS at $PROVING_KEY_R1CS" >&2; exit 1; }
  # One private copy is both checked and hashed, so the digest printed is that of
  # the bytes the graph was checked against.
  R1CS="$SIGNET_WORK/proving-key.r1cs"
  cp "$PROVING_KEY_R1CS" "$R1CS"
  R1CS_SOURCE="$PROVING_KEY_R1CS"
  R1CS_OPTION=(--expect-r1cs "$R1CS")
else
  R1CS="$SIGNET_WORK/$CIRCUIT_NAME.r1cs"
  R1CS_SOURCE="this compilation (no PROVING_KEY_R1CS: compare r1cs_sha256 with the proving key's)"
  R1CS_OPTION=(--r1cs "$R1CS")
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"
# circom's compilation summary goes to stdout; keep stdout for the key=value
# lines below.
"$SIGNET_BUILDER" "$CIRCUIT" -o "$OUTPUT_PATH" "${R1CS_OPTION[@]}" >&2

R1CS_SHA256="$(signet_sha256 "$R1CS")"
signet_ir_builder_provenance
echo "postcard_graph=$OUTPUT_PATH"
echo "r1cs=$R1CS_SOURCE"
echo "r1cs_sha256=$R1CS_SHA256"
