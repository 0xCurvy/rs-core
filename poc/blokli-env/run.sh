#!/usr/bin/env bash
# Local Blokli/Curvy acceptance runner.
#
#   ./run.sh image-up    build/start the native Blokli Curvy image and run strict E2E
#   ./run.sh image-down  stop it and remove generated state
#   ./run.sh down    tear everything down + remove volumes
#   ./run.sh smoke   re-run the Rust smoke test only
#   ./run.sh check-proving-keys  validate the external v3-e2e zkeys
#   ./run.sh logs    follow bloklid logs
#
# Prerequisites: Nix, Docker, jq, and curl. Deployment needs no Node toolchain.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
COMPOSE="docker compose"
BLOKLI_URL="${BLOKLI_URL:-http://127.0.0.1:8080}"
RS_CORE_ROOT="$(cd "$HERE/../.." && pwd)"
SDK_DIR="$RS_CORE_ROOT/sdk"
ADDRESSES="$HERE/curvy_deployed_addresses.json"

# The forked blokli-contract-deployer (host build). Override BLOKLI_FORK to relocate.
BLOKLI_FORK="${BLOKLI_FORK:-/Users/vanja/Projects/blokli}"
FORK_DEPLOYER="$BLOKLI_FORK/target/release/blokli-contract-deployer"

# Native image built by the Blokli fork.
IMAGE_NAME="${IMAGE_NAME:-bloklid-anvil-curvy:latest}"
IMAGE_CONTAINER="${IMAGE_CONTAINER:-curvy-bloklid-anvil}"
REBUILD_IMAGE="${REBUILD_IMAGE:-true}"

run_cargo_in() {
  local flake="$1"
  shift
  if command -v cargo >/dev/null 2>&1; then
    cargo "$@"
  elif command -v nix >/dev/null 2>&1; then
    echo "    cargo not on PATH; using Nix dev shell: $flake" >&2
    nix develop "$flake" -c cargo "$@"
  else
    echo "FATAL: cargo is unavailable and nix cannot provide it" >&2
    exit 1
  fi
}

run_cargo() { run_cargo_in "$RS_CORE_ROOT" "$@"; }
run_blokli_cargo() { run_cargo_in "$BLOKLI_FORK" "$@"; }

prepare_proving_keys() {
  local root="${CURVY_ZK_KEYS_DIR:-}"
  local candidate
  if [ -z "$root" ]; then
    for candidate in \
      "$RS_CORE_ROOT/zk-keys/v2" \
      "${V3_E2E:-}/packages/zk-keys/v2" \
      "$RS_CORE_ROOT/../v3-e2e/packages/zk-keys/v2" \
      "$RS_CORE_ROOT/../curvy-monorepo/packages/zk-keys/v2"; do
      if [ "$candidate" != "/packages/zk-keys/v2" ] && [ -d "$candidate" ]; then
        root="$candidate"
        break
      fi
    done
  fi

  local missing=0
  local spec env_name relative path
  for spec in \
    "CURVY_WITHDRAWAL_ZKEY|withdrawal/verifySingleWithdrawalNoHashing_2_30_0001.zkey" \
    "CURVY_AGGREGATION_ZKEY|aggregation/verifySingleAggregationNoHashing_2_3_30_0001.zkey" \
    "CURVY_PENDING_ZKEY|pending-notes-commitment/verifyPendingNotesCommitment_5_30_0001.zkey"; do
    IFS='|' read -r env_name relative <<< "$spec"
    path="${!env_name:-${root:+$root/$relative}}"
    if [ -z "$path" ] || [ ! -f "$path" ]; then
      echo "FATAL: missing Curvy proving key: ${path:-$relative}" >&2
      missing=1
    elif head -c 80 "$path" | grep -q '^version https://git-lfs.github.com/spec/v1$'; then
      echo "FATAL: Curvy proving key is still a Git LFS pointer: $path" >&2
      missing=1
    else
      printf -v "$env_name" '%s' "$path"
      export "$env_name"
    fi
  done
  if [ "$missing" -ne 0 ]; then
    echo "Fetch the in-repo keys with 'git lfs pull' (rs-core zk-keys/v2)," >&2
    echo "or set CURVY_ZK_KEYS_DIR to a packages/zk-keys/v2 checkout." >&2
    exit 1
  fi
  if [ -n "$root" ]; then
    export CURVY_ZK_KEYS_DIR="$root"
    echo "    Curvy proving keys: $CURVY_ZK_KEYS_DIR"
  fi
}

build_fork_deployer() {
  echo "==> building Curvy-enabled blokli-contract-deployer ($BLOKLI_FORK)"
  ( cd "$BLOKLI_FORK" && run_blokli_cargo build --locked --release -p bloklid \
      --bin blokli-contract-deployer --features curvy-test-deployment )
  [ -x "$FORK_DEPLOYER" ] || { echo "FATAL: $FORK_DEPLOYER not built" >&2; exit 1; }
}

deploy_all_forked() {
  build_fork_deployer
  echo "==> deploying HOPR + Curvy suites (ONE forked blokli-contract-deployer --with-curvy)"
  "$FORK_DEPLOYER" \
    --rpc-url "http://127.0.0.1:8545" \
    --output "$HERE/generated/contracts.toml" \
    --with-curvy \
    --curvy-json-out "$ADDRESSES"
  [ -f "$HERE/generated/contracts.toml" ] || { echo "FATAL: generated/contracts.toml not produced" >&2; exit 1; }
  [ -f "$ADDRESSES" ] || { echo "FATAL: $ADDRESSES not produced (--curvy-json-out)" >&2; exit 1; }
  { cat "$HERE/config/bloklid.base.toml"; echo; cat "$HERE/generated/contracts.toml"; } > "$HERE/generated/config.toml"
  echo "    wrote generated/config.toml; Curvy addresses → $ADDRESSES"
}

# LEGACY Curvy-only deploy (host sdk/curvy-deployer bin) — used by `./run.sh deploy` and
# by the CURVY_LEGACY_DEPLOY=1 fallback path. Assumes HOPR + bloklid are already up.
deploy_curvy() {
  echo "==> deploying + initialising Curvy v2 suite only (sdk/curvy-deployer)"
  ( cd "$SDK_DIR" && run_cargo run --release --quiet -p curvy-deployer -- \
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

wait_ready_image() {
  echo "==> waiting for bloklid /readyz (single container)..."
  for _ in $(seq 1 150); do
    if curl -sf "$BLOKLI_URL/readyz" 2>/dev/null | grep -q '"status":"ready"'; then
      echo "    bloklid ready"; return 0
    fi
    sleep 2
  done
  echo "FATAL: bloklid did not become ready; recent container logs:" >&2
  docker logs --tail 60 "$IMAGE_CONTAINER" >&2 || true
  exit 1
}

image_up() {
  mkdir -p generated
  if [ "$REBUILD_IMAGE" = "true" ] || ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    echo "==> building native Blokli Curvy image"
    ( cd "$BLOKLI_FORK" && nix build -L .#docker-bloklid-anvil-curvy-x86_64-linux --out-link result-curvy )
    docker load < "$BLOKLI_FORK/result-curvy"
  fi
  echo "==> starting single container $IMAGE_CONTAINER (anvil+HOPR+Curvy+bloklid)"
  rm -f "$ADDRESSES" generated/curvy_deployed_addresses.json
  docker rm -f "$IMAGE_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$IMAGE_CONTAINER" \
    -p 8545:8545 -p 8080:8080 \
    -e ANVIL_HOST=0.0.0.0 \
    -v "$HERE/generated:/data" \
    "$IMAGE_NAME" >/dev/null
  wait_ready_image
  # Copy through Docker so host/container UID differences cannot block the SDK.
  if docker cp "$IMAGE_CONTAINER:/data/curvy_deployed_addresses.json" "$ADDRESSES"; then
    echo "    copied Curvy addresses -> $ADDRESSES"
  else
    echo "FATAL: /data/curvy_deployed_addresses.json missing after readiness" >&2
    docker logs --tail 60 "$IMAGE_CONTAINER" >&2 || true
    exit 1
  fi
  echo "==> blokli-smoke (raw tx through sendTransactionSync + negatives)"
  ( cd rs && run_cargo run --release --quiet --bin blokli-smoke )
  echo "==> strict Curvy shield → commit → aggregate → scan → withdraw E2E"
  prepare_proving_keys
  ( cd "$SDK_DIR" && run_cargo run --release --locked --quiet -p curvy-e2e )
  echo
  echo "==> single-container stack is UP and all checks passed."
  echo "    bloklid GraphQL:   $BLOKLI_URL/graphql"
  echo "    anvil RPC:         http://127.0.0.1:8545"
}

image_down() {
  echo "==> tearing down single container $IMAGE_CONTAINER"
  docker rm -f -v "$IMAGE_CONTAINER" >/dev/null 2>&1 || true   # -v drops the anon /data volume
  rm -f "$ADDRESSES" generated/curvy_deployed_addresses.json generated/curvy_contracts.toml
  echo "    done (compose path untouched)"
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
    ( cd rs && run_cargo run --release --quiet --bin blokli-smoke )

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

  smoke)  ( cd rs && run_cargo run --release --quiet --bin blokli-smoke ) ;;
  deploy) deploy_curvy ;;
  logs)   $COMPOSE logs -f bloklid ;;

  image-up)   image_up ;;
  image-down) image_down ;;
  image-logs) docker logs -f "$IMAGE_CONTAINER" ;;
  check-proving-keys) prepare_proving_keys ;;

  *) echo "usage: $0 [up|down|smoke|deploy|logs|image-up|image-down|image-logs|check-proving-keys]  (env: CURVY_LEGACY_DEPLOY=1, BLOKLI_FORK=…, CURVY_ZK_KEYS_DIR=…)" >&2; exit 1 ;;
esac
