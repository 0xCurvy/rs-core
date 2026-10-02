#!/usr/bin/env bash
# Run every experiment and write JSON results to $SCRATCH/results.
# Build first with ./build.sh. Optional inputs (skipped when absent):
#   ANCHOR_DIR  CURVY_WASM_OUT_DIR of `scripts/build-wasm.sh {nodejs,web} --bench`
#   INSTR_PKG   instrumented `scripts/build-wasm.sh web` prover package (see README)
#   CASES       benchmark case file with zkeyPath/graphPath/input/expectedPublics
#   NOSLP_WASM  the PoC built with -C no-vectorize-slp -C no-vectorize-loops
# STEPS selects groups (default: tests fields msm g2 anchor project phases).
set -euo pipefail
cd "$(dirname "$0")"
SCRATCH="${WASM_FIELD_SCRATCH:-../../target/claude-scratch/wasm-field}"
SCRATCH="$(cd "$SCRATCH" && pwd)"
export WASM_FIELD_SCRATCH="$SCRATCH" TMPDIR="$SCRATCH/tmp"
PKG="$SCRATCH/pkg"
WASM="$PKG/wasm_field_poc.wasm"
OUT="$SCRATCH/results"
mkdir -p "$OUT" "$TMPDIR"
STEPS="${STEPS:-tests fields msm g2 anchor project phases}"

log() { echo "[$(date +%T)] load $(sysctl -n vm.loadavg | tr -d '{}') :: $*" | tee -a "$OUT/run.log"; }
has() { [[ " $STEPS " == *" $1 "* ]]; }
native() { "$PKG/poc-native" "$@"; }
node_() { node js/node.mjs "$WASM" "$@"; }
chrome() { node js/chromium.mjs "$WASM" "$@"; }

log "start; wasm sha256 $(shasum -a 256 "$WASM" | cut -c1-16), $(wc -c < "$WASM") bytes"

if has tests; then
  for seed in 1 2 3; do log "tests native seed $seed"; native test $seed 200000 1000000 100 > "$OUT/test-native-$seed.json"; done
  log "tests node"; node_ test 4 200000 1000000 100 > "$OUT/test-node.json"
  log "tests chromium"; chrome test 5 200000 1000000 100 > "$OUT/test-chromium.json"
fi

if has fields; then
  for round in 1 2; do
    log "fields native $round"; native fields 1 7 > "$OUT/fields-native-$round.json"
    log "fields node $round"; node_ fields 1 7 > "$OUT/fields-node-$round.json"
    log "fields chromium $round"; chrome fields 1 7 > "$OUT/fields-chromium-$round.json"
  done
  if [ -n "${NOSLP_WASM:-}" ]; then
    log "fields node no-SLP"; node js/node.mjs "$NOSLP_WASM" fields 1 7 > "$OUT/fields-node-noslp.json"
  fi
fi

if has msm; then
  for log2 in 14 16 18; do
    log "msm g1 2^$log2 native"; native msm $log2 12,13,14 ark,u29x9,u32x8 random 3 > "$OUT/msm-g1-$log2-native.json"
    fields=ark,u29x9,simd; [ $log2 = 14 ] && fields=ark,u32x8,u29x9,simd
    log "msm g1 2^$log2 node"; node_ msm $log2 12,13,14 $fields random 3 > "$OUT/msm-g1-$log2-node.json"
    log "msm g1 2^$log2 chromium"; chrome msm $log2 12,13,14 $fields random 3 > "$OUT/msm-g1-$log2-chromium.json"
  done
fi

if has g2; then
  for spec in "14 12,13,14" "16 12,13,14" "18 13,14"; do
    set -- $spec
    log "msm g2 2^$1 native"; native msm $1 $2 ark,u29x9 random 3 g2 > "$OUT/msm-g2-$1-native.json"
    log "msm g2 2^$1 node"; node_ msm $1 $2 ark,u29x9,simd random 3 g2 > "$OUT/msm-g2-$1-node.json"
    log "msm g2 2^$1 chromium"; chrome msm $1 $2 ark,u29x9,simd random 3 g2 > "$OUT/msm-g2-$1-chromium.json"
  done
fi

if has anchor && [ -n "${ANCHOR_DIR:-}" ]; then
  log "anchor production node"; node js/anchor.mjs node "$ANCHOR_DIR" 14,16,18 12,13,14 3 > "$OUT/anchor-prod-node.json"
  log "anchor production chromium"; node js/anchor.mjs chromium "$ANCHOR_DIR" 14,16,18 12,13,14 3 > "$OUT/anchor-prod-chromium.json"
  for log2 in 14 16 18; do
    log "anchor poc generator 2^$log2 node"; node_ msm $log2 12,13,14 ark,simd generator 3 > "$OUT/anchor-poc-$log2-node.json"
    log "anchor poc generator 2^$log2 chromium"; chrome msm $log2 12,13,14 ark,simd generator 3 > "$OUT/anchor-poc-$log2-chromium.json"
  done
fi

if has project; then
  # The production proofs' MSM calls (sizes, serial_window_bits widths and the
  # measured witness-scalar mix), G1 and G2, arkworks vs SIMD kernel.
  for spec in "h-2 262144 14 random g1" "h-10 524288 15 random g1" \
              "w-2 149451 13 witness:0.484:0.322 g1" "w-2 149451 13 witness:0.484:0.322 g2" \
              "w-5 224504 13 witness:0.417:0.261 g1" "w-5 224504 13 witness:0.417:0.261 g2" \
              "w-10 388475 14 witness:0.402:0.225 g1" "w-10 388475 14 witness:0.402:0.225 g2"; do
    set -- $spec
    for engine in node chromium; do
      log "project $1 $5 $engine"
      if [ $engine = node ]; then node_ msm $2 $3 ark,simd $4 3 $5; else chrome msm $2 $3 ark,simd $4 3 $5; fi \
        > "$OUT/project-$1-$5-$engine.json"
    done
  done
fi

if has phases && [ -n "${INSTR_PKG:-}" ] && [ -n "${CASES:-}" ]; then
  log "proof phases node"; node js/proof-phases.mjs node "$INSTR_PKG" "$CASES" 2,5,10 3 > "$OUT/phases-node.json"
  log "proof phases chromium"; node js/proof-phases.mjs chromium "$INSTR_PKG" "$CASES" 2,5,10 3 > "$OUT/phases-chromium.json"
fi
log "done"
