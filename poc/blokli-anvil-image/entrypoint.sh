#!/usr/bin/env bash
# entrypoint.sh — single-container "bloklid-anvil WITH Curvy".
#
# Reproduces blokli's own docker/blokli-anvil-entrypoint.sh flow, extended for Curvy:
#   1. start anvil (chain 31337) in AUTOMINE for a fast deploy phase
#   2. run the FORKED blokli-contract-deployer --with-curvy  (HOPR + Curvy suites,
#      deployed + wired + init'd on one provider; emits [contracts] + Curvy JSON/TOML)
#   3. assemble bloklid config = baked base + [contracts]  (Curvy stays in its OWN file)
#   4. switch anvil to interval mining so bloklid's indexer keeps getting heads and
#      self-drains to ready (no external mining loop needed)
#   5. exec bloklid on :8080   (anvil :8545 also exposed — the Curvy SDK needs direct RPC)
#
# Tunables (env): ANVIL_BLOCK_TIME (post-deploy interval, s; default 1), ANVIL_ACCOUNTS,
# ANVIL_BALANCE, CURVY (1=deploy Curvy, default 1), CURVY_SHARED_DIR (default /shared).
set -euo pipefail

ANVIL_HOST="${ANVIL_HOST:-0.0.0.0}"
ANVIL_PORT="${ANVIL_PORT:-8545}"
ANVIL_ACCOUNTS="${ANVIL_ACCOUNTS:-10}"
ANVIL_BALANCE="${ANVIL_BALANCE:-10000}"
ANVIL_BLOCK_TIME="${ANVIL_BLOCK_TIME:-1}"     # post-deploy interval-mining block time (seconds)
ANVIL_RPC_URL="http://127.0.0.1:${ANVIL_PORT}"

DATA_DIR="${BLOKLI_DATA_DIRECTORY:-/data}"
SHARED_DIR="${CURVY_SHARED_DIR:-/shared}"     # Curvy addresses land here (mount to fetch them)
BASE_CONFIG="${BLOKLI_BASE_CONFIG:-/etc/bloklid.base.toml}"
CONFIG_PATH="${BLOKLI_CONFIG_PATH:-${DATA_DIR}/config.toml}"
CURVY="${CURVY:-1}"                            # Curvy is the point of THIS image → default ON

mkdir -p "$DATA_DIR" "$SHARED_DIR"

ANVIL_PID=""
cleanup() {
  if [ -n "$ANVIL_PID" ]; then kill "$ANVIL_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

# ── 1. anvil in AUTOMINE (no --block-time) for a fast deploy ─────────────────────────
# Rationale (verified in poc/blokli-env): the alloy-based deployers mine per-tx under
# automine (HOPR's `.watch()` + Curvy's `get_receipt()` each need their tx mined). The
# same deployers STALL under interval mining, so we deploy under automine, then flip to
# interval mining below so bloklid's indexer keeps getting heads.
echo "[entrypoint] starting anvil (automine, chain 31337) on ${ANVIL_HOST}:${ANVIL_PORT}"
anvil --host "$ANVIL_HOST" --port "$ANVIL_PORT" \
      --accounts "$ANVIL_ACCOUNTS" --balance "$ANVIL_BALANCE" &
ANVIL_PID=$!

anvil_ready=false
for _ in $(seq 1 120); do
  if cast block-number --rpc-url "$ANVIL_RPC_URL" >/dev/null 2>&1; then anvil_ready=true; break; fi
  sleep 0.5
done
if [ "$anvil_ready" != true ]; then echo "[entrypoint] FATAL: anvil did not become ready" >&2; exit 1; fi
echo "[entrypoint] anvil ready"

# ── 2. deploy HOPR (+ Curvy) via the forked blokli-contract-deployer ─────────────────
CONTRACTS="${DATA_DIR}/contracts.toml"
DEPLOY_ARGS=(--rpc-url "$ANVIL_RPC_URL" --output "$CONTRACTS")
if [ "$CURVY" = "1" ]; then
  DEPLOY_ARGS+=(--with-curvy
    --curvy-json-out "${SHARED_DIR}/curvy_deployed_addresses.json"
    --curvy-toml-out "${SHARED_DIR}/curvy_contracts.toml")
fi
echo "[entrypoint] deploying contracts (CURVY=${CURVY}) via forked blokli-contract-deployer..."
blokli-contract-deployer "${DEPLOY_ARGS[@]}"
[ -f "$CONTRACTS" ] || { echo "[entrypoint] FATAL: $CONTRACTS not produced" >&2; exit 1; }
if [ "$CURVY" = "1" ]; then
  [ -f "${SHARED_DIR}/curvy_deployed_addresses.json" ] \
    || { echo "[entrypoint] FATAL: curvy_deployed_addresses.json not produced" >&2; exit 1; }
  echo "[entrypoint] Curvy addresses written to ${SHARED_DIR}/curvy_deployed_addresses.json"
fi

# ── 3. assemble bloklid config = base + [contracts] (Curvy stays in its own file) ─────
{ cat "$BASE_CONFIG"; echo; cat "$CONTRACTS"; } > "$CONFIG_PATH"
echo "[entrypoint] wrote $CONFIG_PATH (base + [contracts])"

# ── 4. switch anvil to interval mining so bloklid's indexer stays fed ────────────────
# bloklid advances its historical sync on new-head events; a frozen (automine, idle)
# chain would stall it below head. Interval mining produces a block every
# ANVIL_BLOCK_TIME s, so bloklid catches up and stays ready without any external drain.
# IMPORTANT: anvil's *setIntervalMining takes SECONDS (NOT milliseconds like Hardhat's
# evm_setIntervalMining) — passing ms sets e.g. a 1000s interval and FREEZES the chain,
# which stalls bloklid's indexer at indexed=0. Pass ANVIL_BLOCK_TIME (seconds) verbatim.
echo "[entrypoint] switching anvil to ${ANVIL_BLOCK_TIME}s interval mining"
if ! cast rpc anvil_setIntervalMining "$ANVIL_BLOCK_TIME" --rpc-url "$ANVIL_RPC_URL" >/dev/null 2>&1; then
  cast rpc evm_setIntervalMining "$ANVIL_BLOCK_TIME" --rpc-url "$ANVIL_RPC_URL" >/dev/null 2>&1 || true
fi
# Verify the chain is actually advancing; if not, fall back to an explicit miner loop.
# (Guards against a wrong unit/method silently leaving the chain frozen.)
_b0="$(cast block-number --rpc-url "$ANVIL_RPC_URL" 2>/dev/null || echo 0)"
sleep "$((ANVIL_BLOCK_TIME + 2))"
_b1="$(cast block-number --rpc-url "$ANVIL_RPC_URL" 2>/dev/null || echo 0)"
if [ "${_b1:-0}" -le "${_b0:-0}" ]; then
  echo "[entrypoint] WARN: chain not advancing after interval-mining switch; starting a background miner"
  ( while true; do cast rpc evm_mine --rpc-url "$ANVIL_RPC_URL" >/dev/null 2>&1 || true; sleep "$ANVIL_BLOCK_TIME"; done ) &
fi

# ── 5. exec bloklid (becomes PID 1; anvil keeps running as its child) ────────────────
echo "[entrypoint] starting bloklid on :8080 (anvil RPC on :8545)"
exec bloklid -c "$CONFIG_PATH"
