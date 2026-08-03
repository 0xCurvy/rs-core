#!/usr/bin/env bash
# Build the complete Curvy Rust core for the native host.
set -euo pipefail

cd "$(dirname "$0")/.."

native_target_dir="${CARGO_TARGET_DIR:-target}"

cargo build --locked --release \
  -p curvy-core -p curvy-witness -p curvy-prover \
  --features curvy-core/parallel

echo "built native core libraries and ${native_target_dir}/release/curvy-native-prover"
