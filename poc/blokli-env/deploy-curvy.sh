#!/usr/bin/env bash
# deploy-curvy.sh — deploy Curvy's v2 contracts onto the compose anvil.
#
# Steps (replicates packages/contracts/evm/scripts/devenv.ts, minus its own anvil):
#   1. bootstrap CreateX via the pre-signed (Nick's-method) raw tx embedded in
#      devenv.ts — required because the full Devenv Ignition graph deploys
#      PortalFactory through CreateX.
#   2. run the Hardhat Ignition `Devenv.ts` graph against the compose anvil
#      (vault + aggregator + 3 verifiers + PortalFactory + Multicall3 + ERC20Mock
#      + local ENS + fixture funding).
#   3. copy the resulting deployed_addresses.json into this directory.
#
# The two MANDATORY post-deploy calls (initPerTokenGasFees / initFeeNotePublicKey)
# are NOT done here — they are ported to Rust/alloy in rs/src/bin/curvy-init.rs and
# run by run.sh right after this script.
#
# RELAXATION of v3-e2e read-only: running this writes UNTRACKED artifacts under
# v3-e2e/.../ignition/deployments/blokli_anvil_poc/. No tracked file is modified.
set -euo pipefail

RPC="${RPC_URL:-http://127.0.0.1:8545}"
EVM="${CURVY_EVM_DIR:-/Users/vanja/Projects/v3-e2e/packages/contracts/evm}"
DEVENV_TS="$EVM/scripts/devenv.ts"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_ID="blokli_anvil_poc"

# anvil dev account 0 (deployer/owner — matches environment-parameters.json "local".owner)
ACC0_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
# CreateX keyless deployer EOA + canonical CreateX address (immutable, Nick's method).
CREATEX_DEPLOYER="0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5"
CREATEX_ADDR="0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed"

echo "==> [curvy-deploy] RPC=$RPC  evm=$EVM"
cast block-number --rpc-url "$RPC" >/dev/null || { echo "anvil not reachable at $RPC"; exit 1; }

# Hardhat Ignition waits for block confirmations, so it needs blocks to keep being
# produced — switch anvil from automine to 1s interval mining for the deploy, and
# restore automine on exit (curvy-init's alloy .get_receipt() is happiest on automine,
# the same as the M1 spike). Restore even on failure.
restore_automine() { cast rpc evm_setAutomine true --rpc-url "$RPC" >/dev/null 2>&1 || true; }
trap restore_automine EXIT
echo "==> [curvy-deploy] enabling 1s interval mining for the Ignition deploy"
cast rpc evm_setIntervalMining 1 --rpc-url "$RPC" >/dev/null

# ── 1. CreateX bootstrap ────────────────────────────────────────────────────────
CODE="$(cast code "$CREATEX_ADDR" --rpc-url "$RPC")"
if [ "$CODE" = "0x" ] || [ -z "$CODE" ]; then
  echo "==> [curvy-deploy] CreateX absent — bootstrapping"
  RAW_TX="$(node -e 'const fs=require("fs");const s=fs.readFileSync(process.argv[1],"utf8");const m=s.match(/0xf9[0-9a-fA-F]{2000,}/);process.stdout.write(m?m[0]:"")' "$DEVENV_TS")"
  [ -n "$RAW_TX" ] || { echo "FATAL: could not extract CreateX raw tx from $DEVENV_TS"; exit 1; }
  echo "    funding CreateX deployer $CREATEX_DEPLOYER with 1 ETH"
  cast send --rpc-url "$RPC" --private-key "$ACC0_KEY" "$CREATEX_DEPLOYER" --value 1ether >/dev/null
  echo "    publishing pre-signed CreateX deploy tx (${#RAW_TX} hex chars)"
  cast publish --rpc-url "$RPC" "$RAW_TX" >/dev/null
  CODE="$(cast code "$CREATEX_ADDR" --rpc-url "$RPC")"
  [ "$CODE" != "0x" ] && [ -n "$CODE" ] || { echo "FATAL: CreateX not deployed at $CREATEX_ADDR"; exit 1; }
  echo "    CreateX live at $CREATEX_ADDR"
else
  echo "==> [curvy-deploy] CreateX already present at $CREATEX_ADDR — skipping bootstrap"
fi

# ── 2. Ignition deploy of the full Devenv graph ─────────────────────────────────
# Clean any prior journal for this deployment-id so a fresh chain gets a fresh
# deploy (untracked artifact — safe to remove).
rm -rf "$EVM/ignition/deployments/$DEPLOYMENT_ID"

echo "==> [curvy-deploy] running Ignition Devenv.ts (deployment-id=$DEPLOYMENT_ID)"
# CURVY_ENVIRONMENT/CURVY_NETWORK short-circuit the module's parameter resolver so
# it reads ignition/{network,environment}-parameters.json under keys anvil/local
# (the deployment-id itself is not a valid environment_network pair).
# HARDHAT_DEVENV=true makes hardhat.config include the devenv/ sources (ENS mocks).
( cd "$EVM" && \
  printf 'y\ny\n' | CURVY_ENVIRONMENT=local CURVY_NETWORK=anvil HARDHAT_DEVENV=true \
    pnpm hardhat ignition deploy \
      --deployment-id "$DEPLOYMENT_ID" \
      --network anvil \
      ./ignition/modules/deployments/dev/Devenv.ts )

# ── 3. Copy deployed addresses out ──────────────────────────────────────────────
SRC="$EVM/ignition/deployments/$DEPLOYMENT_ID/deployed_addresses.json"
DST="$HERE/curvy_deployed_addresses.json"
[ -f "$SRC" ] || { echo "FATAL: $SRC not produced by deploy"; exit 1; }
cp "$SRC" "$DST"
echo "==> [curvy-deploy] deployed addresses copied to $DST"
jq . "$DST"
