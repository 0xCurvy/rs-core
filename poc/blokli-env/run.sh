#!/usr/bin/env bash
# run.sh — one command to stand up the M2 substrate and prove it end-to-end.
#
#   ./run.sh up      compose up anvil -> ONE forked blokli-contract-deployer
#                    (HOPR + Curvy, --with-curvy) -> bloklid -> blokli-smoke  (idempotent)
#   ./run.sh down    tear everything down + remove volumes
#   ./run.sh smoke   re-run the Rust smoke test only
#   ./run.sh deploy  re-run the Curvy-only deploy+init (host sdk/curvy-deployer)
#   ./run.sh logs    follow bloklid logs
#
# Prereqs on host: docker, cast/forge (foundry), cargo, jq, curl.
#   NO node / pnpm / hardhat / v3-e2e toolchain is needed at deploy time —
#   BOTH the HOPR suite and the whole Curvy v2 suite are deployed + initialised by a
#   single HOST-BUILT binary: a fork of hoprnet/blokli's `blokli-contract-deployer`
#   whose `--with-curvy` flag calls the Curvy `sdk/curvy-deployer` lib after the HOPR
#   deploy. See README.md "Fork provenance".
#
# Fallback: set CURVY_LEGACY_DEPLOY=1 to use the OLD two-step flow instead (the bloklid
# image's own `blokli-contract-deployer` for HOPR + the host `sdk/curvy-deployer` bin
# for Curvy) — kept working for comparison / if the fork is unavailable.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
COMPOSE="docker compose"
BLOKLI_URL="${BLOKLI_URL:-http://127.0.0.1:8080}"
SDK_DIR="$HERE/../../sdk"
ADDRESSES="$HERE/curvy_deployed_addresses.json"

# The forked blokli-contract-deployer (host build). Override BLOKLI_FORK to relocate.
BLOKLI_FORK="${BLOKLI_FORK:-/Users/vanja/Projects/blokli}"
FORK_DEPLOYER="$BLOKLI_FORK/target/release/blokli-contract-deployer"

# Build the forked deployer bin on the host if missing (blokli pins rustc 1.96 via its
# rust-toolchain.toml; rustup selects it automatically inside $BLOKLI_FORK).
build_fork_deployer() {
  if [ ! -x "$FORK_DEPLOYER" ]; then
    echo "==> building forked blokli-contract-deployer ($BLOKLI_FORK) — first run only"
    ( cd "$BLOKLI_FORK" && cargo build --release -p bloklid --bin blokli-contract-deployer )
  fi
  [ -x "$FORK_DEPLOYER" ] || { echo "FATAL: $FORK_DEPLOYER not built" >&2; exit 1; }
}

# NEW default: ONE deployer invocation provisions HOPR + Curvy on the fresh chain, then
# assembles bloklid's config.toml. Runs BEFORE bloklid so config.toml exists at boot.
# IMPORTANT: the Curvy [curvy_contracts] section goes to its OWN file — bloklid's Config
# is #[serde(deny_unknown_fields)] and would reject an extra section in its config.toml.
deploy_all_forked() {
  build_fork_deployer
  echo "==> deploying HOPR + Curvy suites (ONE forked blokli-contract-deployer --with-curvy)"
  "$FORK_DEPLOYER" \
    --rpc-url "http://127.0.0.1:8545" \
    --output "$HERE/generated/contracts.toml" \
    --with-curvy \
    --curvy-json-out "$ADDRESSES" \
    --curvy-toml-out "$HERE/generated/curvy_contracts.toml"
  [ -f "$HERE/generated/contracts.toml" ] || { echo "FATAL: generated/contracts.toml not produced" >&2; exit 1; }
  [ -f "$ADDRESSES" ] || { echo "FATAL: $ADDRESSES not produced (--curvy-json-out)" >&2; exit 1; }
  # Assemble bloklid config = base + HOPR [contracts]. Curvy [curvy_contracts] is NOT
  # appended here (deny_unknown_fields); it lives in generated/curvy_contracts.toml.
  { cat "$HERE/config/bloklid.base.toml"; echo; cat "$HERE/generated/contracts.toml"; } > "$HERE/generated/config.toml"
  echo "    wrote generated/config.toml (base + [contracts]); Curvy → $ADDRESSES + generated/curvy_contracts.toml"
}

# LEGACY Curvy-only deploy (host sdk/curvy-deployer bin) — used by `./run.sh deploy` and
# by the CURVY_LEGACY_DEPLOY=1 fallback path. Assumes HOPR + bloklid are already up.
deploy_curvy() {
  echo "==> deploying + initialising Curvy v2 suite only (sdk/curvy-deployer)"
  ( cd "$SDK_DIR" && cargo run --release --quiet -p curvy-deployer -- \
      --rpc-url "http://127.0.0.1:8545" \
      --json-out "$ADDRESSES" \
      --toml-out "$HERE/generated/curvy_contracts.toml" )
  [ -f "$ADDRESSES" ] || { echo "FATAL: $ADDRESSES not produced by curvy-deployer" >&2; exit 1; }
  drain_indexer
}

# LEGACY HOPR deploy via the bloklid image's own blokli-contract-deployer one-shot.
deploy_hopr_image() {
  echo "==> deploying HOPR contract suite (image blokli-contract-deployer) + assembling config"
  $COMPOSE run --rm hopr-deploy
  [ -f generated/config.toml ] || { echo "FATAL: generated/config.toml not produced" >&2; exit 1; }
}

# Mine blocks one-per-second until bloklid's indexer drains its backlog and reports ready.
# The deployer mines the whole HOPR+Curvy burst under automine, then the chain freezes;
# bloklid advances only a few blocks per new-head event and STALLS once frozen. Feed it
# one block at a time until it catches up (lag <= max_indexer_lag) and /readyz is ready.
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

    if [ -n "${CURVY_LEGACY_DEPLOY:-}" ]; then
      # OLD two-step flow: HOPR via image one-shot, bloklid up, then Curvy via host bin.
      echo "==> [legacy] two-step deploy (CURVY_LEGACY_DEPLOY set)"
      deploy_hopr_image
      echo "==> seeding one tx (bloklid verify_rpc_capabilities)"
      $COMPOSE run --rm seed-tx
      echo "==> docker compose up bloklid"
      $COMPOSE up -d bloklid
      wait_ready
      deploy_curvy
    else
      # NEW default: ONE forked deployer provisions HOPR + Curvy before bloklid starts.
      deploy_all_forked
      echo "==> seeding one tx (bloklid verify_rpc_capabilities)"
      $COMPOSE run --rm seed-tx
      echo "==> docker compose up bloklid"
      $COMPOSE up -d bloklid
      # The whole deploy burst happened pre-bloklid; nudge the indexer to fully sync.
      drain_indexer
    fi

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
  *) echo "usage: $0 [up|down|smoke|deploy|logs]  (env: CURVY_LEGACY_DEPLOY=1, BLOKLI_FORK=…)" >&2; exit 1 ;;
esac
