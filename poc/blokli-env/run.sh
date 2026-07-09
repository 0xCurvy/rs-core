#!/usr/bin/env bash
# run.sh — one command to stand up the M2 substrate and prove it end-to-end.
#
#   ./run.sh up      compose up -> HOPR deploy -> bloklid -> Curvy deploy+init
#                    (curvy-deployer) -> blokli-smoke   (idempotent)
#   ./run.sh down    tear everything down + remove volumes
#   ./run.sh smoke   re-run the Rust smoke test only
#   ./run.sh deploy  re-run the Curvy deploy+init only (curvy-deployer)
#   ./run.sh logs    follow bloklid logs
#
# Prereqs on host: docker, cast/forge (foundry), cargo, jq, curl.
#   NO node / pnpm / hardhat / v3-e2e toolchain is needed at deploy time anymore —
#   the entire Curvy v2 suite is deployed + initialised by the Rust `curvy-deployer`
#   (sdk/curvy-deployer), which vendors its own creation bytecode + ABIs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
COMPOSE="docker compose"
BLOKLI_URL="${BLOKLI_URL:-http://127.0.0.1:8080}"
SDK_DIR="$HERE/../../sdk"
ADDRESSES="$HERE/curvy_deployed_addresses.json"

# Deploy + initialise the full Curvy v2 suite from ONE Rust binary (replaces the old
# deploy-curvy.sh Hardhat/Ignition leg + the separate curvy-init). Runs under anvil
# AUTOMINE — alloy `.get_receipt()` mines each tx immediately, so the old interval-
# mining toggle + Ignition 5-confirmation dance are gone.
deploy_curvy() {
  echo "==> deploying + initialising Curvy v2 suite (curvy-deployer)"
  ( cd "$SDK_DIR" && cargo run --release --quiet -p curvy-deployer -- \
      --rpc-url "http://127.0.0.1:8545" \
      --json-out "$ADDRESSES" \
      --toml-out "$HERE/generated/curvy_contracts.toml" )
  [ -f "$ADDRESSES" ] || { echo "FATAL: $ADDRESSES not produced by curvy-deployer" >&2; exit 1; }

  # The deployer mines ~24 txs in an automine BURST (no --block-time), which outruns
  # bloklid's indexer: it advances only a few blocks per new-head event and then
  # STALLS once the chain freezes (automine produces no blocks between txs). Feed it
  # one block at a time until it catches up (lag <= max_indexer_lag) and /readyz is
  # ready — empty blocks are harmless, and thereafter each SDK/smoke tx keeps it fed.
  drain_indexer
}

# Mine blocks one-per-second until bloklid's indexer drains its backlog and reports ready.
drain_indexer() {
  echo "==> draining bloklid indexer (mining blocks until it catches up to head)..."
  for _ in $(seq 1 90); do
    if curl -sf "$BLOKLI_URL/readyz" 2>/dev/null | grep -q '"status":"ready"'; then
      echo "    bloklid ready (indexer caught up)"; return 0
    fi
    cast rpc anvil_mine 0x1 --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1 || true
    sleep 1
  done
  echo "FATAL: bloklid indexer did not catch up after draining; recent logs:" >&2
  $COMPOSE logs --tail 20 bloklid >&2 || true
  exit 1
}

wait_anvil() {
  echo "==> waiting for anvil to be healthy..."
  for _ in $(seq 1 60); do
    s="$(docker inspect --format '{{.State.Health.Status}}' curvy-blokli-anvil 2>/dev/null || echo none)"
    [ "$s" = "healthy" ] && { echo "    anvil healthy"; return 0; }
    sleep 1
  done
  echo "FATAL: anvil did not become healthy" >&2; exit 1
}

wait_ready() {
  echo "==> waiting for bloklid /readyz (indexer sync)..."
  for _ in $(seq 1 120); do
    if curl -sf "$BLOKLI_URL/readyz" 2>/dev/null | grep -q '"status":"ready"'; then
      echo "    bloklid ready"; return 0
    fi
    sleep 2
  done
  echo "FATAL: bloklid did not become ready; recent logs:" >&2
  $COMPOSE logs --tail 40 bloklid >&2 || true
  exit 1
}

case "${1:-up}" in
  up)
    mkdir -p generated
    echo "==> docker compose up anvil"
    $COMPOSE up -d anvil
    wait_anvil

    echo "==> deploying HOPR contract suite (blokli-contract-deployer) + assembling bloklid config"
    $COMPOSE run --rm hopr-deploy
    [ -f generated/config.toml ] || { echo "FATAL: generated/config.toml not produced" >&2; exit 1; }

    echo "==> seeding one tx (bloklid verify_rpc_capabilities)"
    $COMPOSE run --rm seed-tx

    echo "==> docker compose up bloklid"
    $COMPOSE up -d bloklid
    wait_ready

    deploy_curvy

    echo "==> blokli-smoke (raw tx through sendTransactionSync + negatives)"
    ( cd rs && cargo run --release --quiet --bin blokli-smoke )

    echo
    echo "==> M2 stack is UP and all checks passed."
    echo "    bloklid GraphQL:   $BLOKLI_URL/graphql"
    echo "    anvil RPC:         http://127.0.0.1:8545"
    ;;

  down)
    echo "==> tearing down"
    $COMPOSE down -v --remove-orphans
    rm -f generated/config.toml generated/contracts.toml generated/curvy_contracts.toml
    echo "    done"
    ;;

  smoke)  ( cd rs && cargo run --release --quiet --bin blokli-smoke ) ;;
  deploy) deploy_curvy ;;
  logs)   $COMPOSE logs -f bloklid ;;
  *) echo "usage: $0 [up|down|smoke|deploy|logs]" >&2; exit 1 ;;
esac
