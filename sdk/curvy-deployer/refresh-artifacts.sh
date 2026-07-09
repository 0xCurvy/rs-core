#!/usr/bin/env bash
# refresh-artifacts.sh — re-vendor the Curvy v2 creation bytecode + ABIs used by
# curvy-deployer, straight from the READ-ONLY v3-e2e Hardhat artifacts, and
# regenerate the sha256 provenance manifest.
#
#   ./refresh-artifacts.sh          # re-copy + re-hash (writes SHA256SUMS)
#   ./refresh-artifacts.sh --check  # verify vendored files against SHA256SUMS
#
# Each vendored `*.json` is a TRIMMED artifact: exactly
#   { contractName, sourceName, abi, bytecode, linkReferences }
# extracted with `jq` from the compiled artifact (solc 0.8.28 / cancun). The
# deployer never reads v3-e2e at build or run time — only these files.
#
# Provenance: v3-e2e @ branch v3-backend, packages/contracts/evm/artifacts/**.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$HERE/artifacts"
EVM="${CURVY_EVM_DIR:-/Users/vanja/Projects/v3-e2e/packages/contracts/evm}"
ART="$EVM/artifacts"
DEVENV_TS="$EVM/scripts/devenv.ts"

# dest-basename : source artifact JSON (relative to $ART)
PAIRS=(
  "PoseidonT4.json:src/v2/utils/PoseidonT4.sol/PoseidonT4.json"
  "CurvyAggregatorAlphaV2.json:src/v2/aggregator-alpha/CurvyAggregatorAlphaV2.sol/CurvyAggregatorAlphaV2.json"
  "CurvyVaultV2.json:src/v2/vault/CurvyVaultV2.sol/CurvyVaultV2.json"
  "CurvyAggregationVerifier.json:src/v2/aggregator-alpha/verifiers/CurvyAggregationVerifier.sol/CurvyAggregationVerifier.json"
  "CurvyPendingNotesCommitmentVerifier.json:src/v2/aggregator-alpha/verifiers/CurvyPendingNotesCommitmentVerifier.sol/CurvyPendingNotesCommitmentVerifier.json"
  "CurvyWithdrawalVerifier.json:src/v2/aggregator-alpha/verifiers/CurvyWithdrawalVerifier.sol/CurvyWithdrawalVerifier.json"
  "PortalFactory.json:src/v2/portal/PortalFactory.sol/PortalFactory.json"
  "ERC1967Proxy.json:@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol/ERC1967Proxy.json"
  "Multicall3.json:devenv/Multicall3.sol/Multicall3.json"
  "ERC20Mock.json:devenv/ERC20Mock.sol/ERC20Mock.json"
  "ICreateX.json:src/v2/utils/ICreateX.sol/ICreateX.json"
)

if [ "${1:-}" = "--check" ]; then
  cd "$OUT" && shasum -a 256 -c SHA256SUMS
  exit $?
fi

command -v jq >/dev/null || { echo "FATAL: jq required" >&2; exit 1; }
[ -d "$ART" ] || { echo "FATAL: artifacts dir not found: $ART" >&2; exit 1; }

echo "==> vendoring trimmed artifacts from $ART"
for pair in "${PAIRS[@]}"; do
  dest="${pair%%:*}"; src="${pair#*:}"
  [ -f "$ART/$src" ] || { echo "FATAL: missing source artifact $ART/$src" >&2; exit 1; }
  jq '{contractName, sourceName, abi, bytecode, linkReferences}' "$ART/$src" > "$OUT/$dest"
  echo "    $dest  <=  $src"
done

# CreateX keyless-deployment pre-signed raw tx (Nick's method), embedded verbatim in
# devenv.ts. Extract the single long 0xf9… legacy-tx blob.
echo "==> extracting CreateX bootstrap raw tx from $DEVENV_TS"
node -e 'const fs=require("fs");const s=fs.readFileSync(process.argv[1],"utf8");const m=s.match(/0xf9[0-9a-fA-F]{2000,}/);if(!m){console.error("could not find CreateX raw tx");process.exit(1)};process.stdout.write(m[0])' \
  "$DEVENV_TS" > "$OUT/createx_bootstrap_tx.hex"
echo "    createx_bootstrap_tx.hex ($(wc -c < "$OUT/createx_bootstrap_tx.hex") bytes)"

echo "==> regenerating SHA256SUMS"
cd "$OUT" && shasum -a 256 *.json *.hex > SHA256SUMS
echo "==> done. $(wc -l < "$OUT/SHA256SUMS") files hashed."
