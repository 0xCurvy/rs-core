#!/usr/bin/env bash
#
# Circuit half of the graph pipeline: .circom -> graph.bin (postcard).
#
# Needs `circom`, a C++ toolchain, and a circuits tree. Everything downstream of
# the graph.bin it writes is pure Rust and lives in the `signet` binary, so this
# script deliberately stops there.
#
#   CIRCUITS_DIR=/path/to/packages/zk-circuits \
#     scripts/build-graph.sh v2/instances/verifyPendingNotesCommitment_5_30.circom /tmp/pending.bin
#
# It prints the optimised R1CS digest, which is what `signet export` takes as its
# provenance argument.

set -euo pipefail

CRATE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
# The generator is an ordinary cargo dependency of ../generator, pinned in that
# crate's Cargo.lock. Nothing here clones a repository or executes code from a URL;
# cargo fetches and verifies it like any other dependency.
#
# It carries what used to be applied here as a zero-context patch: bitwise OR/XOR,
# canonical-integer evaluation for non-field operations, and the build_graph entry
# point. See its README for the consequence that matters: Operation variant order
# differs from upstream, so graph.bin files are not interchangeable.
GENERATOR_MANIFEST="$CRATE_DIR/generator/Cargo.toml"

CIRCUIT_RELATIVE_PATH="${1:?usage: build-graph.sh <circuit-relative-path> <output.bin>}"
OUTPUT_PATH="${2:?usage: build-graph.sh <circuit-relative-path> <output.bin>}"
CIRCUITS_DIR="${CIRCUITS_DIR:?set CIRCUITS_DIR to the zk-circuits package}"

for tool in circom cargo patch cmp; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 1; }
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/signet-graph.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$WORK_DIR/zk-circuits/node_modules"
cp -R "$CIRCUITS_DIR/circuits" "$WORK_DIR/zk-circuits/circuits"
cp -RL "$CIRCUITS_DIR/node_modules/circomlib" "$WORK_DIR/zk-circuits/node_modules/circomlib"
patch --quiet -d "$WORK_DIR/zk-circuits" -p1 < "$CRATE_DIR/patches/circomlib-iszero-bbf.patch"

ORIGINAL_CIRCUIT="$CIRCUITS_DIR/circuits/$CIRCUIT_RELATIVE_PATH"
PATCHED_CIRCUIT="$WORK_DIR/zk-circuits/circuits/$CIRCUIT_RELATIVE_PATH"
CIRCUIT_NAME="$(basename "$CIRCUIT_RELATIVE_PATH" .circom)"

# The gate that makes the patch safe to use: moving circomlib's IsZero ternary
# into a black box must leave the constraint system byte-identical. If this cmp
# ever fails, the graph would be proving a different circuit than the deployed
# verifier checks.
mkdir -p "$WORK_DIR/original-r1cs" "$WORK_DIR/patched-r1cs"
circom "$ORIGINAL_CIRCUIT" --r1cs --O2 -o "$WORK_DIR/original-r1cs"
circom "$PATCHED_CIRCUIT" --r1cs --O2 -o "$WORK_DIR/patched-r1cs"
cmp "$WORK_DIR/original-r1cs/$CIRCUIT_NAME.r1cs" "$WORK_DIR/patched-r1cs/$CIRCUIT_NAME.r1cs"

# The generator writes graph.bin into its working directory, so run it in the
# scratch dir rather than in the crate.
(
  cd "$WORK_DIR"
  WITNESS_CPP="$PATCHED_CIRCUIT" \
    cargo run --quiet --release --manifest-path "$GENERATOR_MANIFEST"
)

mkdir -p "$(dirname "$OUTPUT_PATH")"
cp "$WORK_DIR/graph.bin" "$OUTPUT_PATH"

# Report what actually produced this graph. The checksum is the durable half: a
# crates.io version cannot be republished with different bytes.
awk '/name = "curvy-signet-builder"/{f=1} f&&/^version/{v=$3} f&&/^checksum/{print "generator=curvy-signet-builder " v; print "generator_checksum=" $3; exit}' \
  "$CRATE_DIR/generator/Cargo.lock" | tr -d '"' 
echo "postcard_graph=$OUTPUT_PATH"
echo -n "r1cs_sha256="
shasum -a 256 "$WORK_DIR/original-r1cs/$CIRCUIT_NAME.r1cs" | cut -d' ' -f1

# Build one graph at a time. Each run writes hundreds of MB of C++ objects, and
# two concurrent generations have exhausted a disk here - surfacing as a
# misleading `ar: internal ranlib command failed`.
