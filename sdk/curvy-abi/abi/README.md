# Vendored contract ABIs — provenance

These four `*.abi.json` files are the `.abi` arrays extracted verbatim from the
compiled Hardhat artifacts in the **read-only** `v3-e2e` checkout, so the SDK never
reads `v3-e2e` at build or run time. `curvy-abi`'s `sol!` macro consumes them at
**compile time** to generate the bindings.

| file | source artifact (v3-e2e) |
|---|---|
| `CurvyAggregatorAlphaV2.abi.json` | `packages/contracts/evm/artifacts/src/v2/aggregator-alpha/CurvyAggregatorAlphaV2.sol/CurvyAggregatorAlphaV2.json` → `.abi` |
| `CurvyVaultV2.abi.json`           | `packages/contracts/evm/artifacts/src/v2/vault/CurvyVaultV2.sol/CurvyVaultV2.json` → `.abi` |
| `PortalFactory.abi.json`          | `packages/contracts/evm/artifacts/src/v2/portal/PortalFactory.sol/PortalFactory.json` → `.abi` |
| `Portal.abi.json`                 | `packages/contracts/evm/artifacts/src/v2/portal/Portal.sol/Portal.json` → `.abi` |

Extraction command (recorded for reproducibility):

```bash
V3=…/v3-e2e/packages/contracts/evm/artifacts/src/v2
jq '.abi' $V3/aggregator-alpha/CurvyAggregatorAlphaV2.sol/CurvyAggregatorAlphaV2.json > CurvyAggregatorAlphaV2.abi.json
# … likewise for the other three
```

The contract sources they compile from are pinned at `v3-e2e@v3-backend`
(`packages/contracts/evm/src/v2/**`); the deployed bytecode on the M2 anvil is from
the same tree (Ignition `Devenv.ts`). Re-extract if the contracts change.
