#!/usr/bin/env bash
# Container helper: read-only repository at /source, builds/results at /work.
set -euo pipefail
cd /source
case "${1:?build or measure}" in
build)
  uname -a > /work/platform.txt
  rustc --version >> /work/platform.txt
  cargo test --release --locked -p curvy-prover --features scratch,parallel,sparrow --all-targets > /work/tests.log 2>&1
  for profile in stock-serial compact-serial compact-parallel; do
    case "$profile" in
      stock-serial) features=(--no-default-features);;
      compact-serial) features=(--no-default-features --features compact-matrix);;
      compact-parallel) features=(--features compact-matrix);;
    esac
    cargo build --release --locked -p curvy-benchmarks "${features[@]}" --bin resident_repeated >> /work/build.log 2>&1
    cp "$CARGO_TARGET_DIR/release/resident_repeated" "/work/$profile"
  done
  ;;
measure)
  for config in /work/config-*.json; do
    stem="${config##*/}"
    profile="${stem#config-}"
    profile="${profile%-*}"
    "/work/$profile" "$config" > "/work/result-${stem#config-}"
  done
  ;;
*) exit 2;;
esac
