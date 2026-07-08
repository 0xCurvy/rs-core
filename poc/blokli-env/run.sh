#!/usr/bin/env bash
# run.sh — one command to stand up the M2 substrate and prove it end-to-end.
#
#   ./run.sh up      compose up -> HOPR deploy -> bloklid -> Curvy deploy ->
#                    curvy-init -> blokli-smoke   (idempotent)
#   ./run.sh down    tear everything down + remove volumes
#   ./run.sh smoke   re-run the Rust smoke test only
#   ./run.sh init    re-run curvy-init only
#   ./run.sh logs    follow bloklid logs
#
# Prereqs on host: docker, cast/forge (foundry), node, pnpm, cargo, jq, curl.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
COMPOSE="docker compose"
BLOKLI_URL="${BLOKLI_URL:-http://127.0.0.1:8080}"

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

    echo "==> deploying Curvy v2 contracts"
    ./deploy-curvy.sh

    echo "==> curvy-init (initPerTokenGasFees + initFeeNotePublicKey + read-back)"
    ( cd rs && cargo run --release --quiet --bin curvy-init )

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
    rm -f generated/config.toml generated/contracts.toml
    echo "    done"
    ;;

  smoke) ( cd rs && cargo run --release --quiet --bin blokli-smoke ) ;;
  init)  ( cd rs && cargo run --release --quiet --bin curvy-init ) ;;
  logs)  $COMPOSE logs -f bloklid ;;
  *) echo "usage: $0 [up|down|smoke|init|logs]" >&2; exit 1 ;;
esac
