# Vendored Curvy v2 artifacts — provenance

Creation bytecode + ABI for every contract `curvy-deployer` deploys, vendored from
the **read-only** `v3-e2e` checkout so the deployer never reads `v3-e2e` at build or
run time. Regenerate with [`../refresh-artifacts.sh`](../refresh-artifacts.sh);
verify with `./refresh-artifacts.sh --check` (checks `SHA256SUMS`).

- Source tree: `v3-e2e` @ branch `v3-backend`,
  `packages/contracts/evm/artifacts/**`.
- Compiler: **solc 0.8.28**, EVM version **cancun** (from the build-info).
- Each `*.json` is a TRIMMED artifact — `jq '{contractName, sourceName, abi,
  bytecode, linkReferences}'` of the Hardhat artifact. `bytecode` is the **creation**
  bytecode (constructor-runnable); `deployedBytecode`/`metadata`/`immutableReferences`
  are dropped (not needed to deploy).

| vendored file | source artifact (under `packages/contracts/evm/artifacts/`) | role |
|---|---|---|
| `PoseidonT4.json` | `src/v2/utils/PoseidonT4.sol/PoseidonT4.json` | library (linked into aggregator impl) |
| `CurvyAggregatorAlphaV2.json` | `src/v2/aggregator-alpha/CurvyAggregatorAlphaV2.sol/…json` | aggregator impl; **unlinked** `PoseidonT4` placeholder `__$da668b34bdb7a81662c478d887f0e664bc$__` at byte 6783 (`linkReferences` preserved) |
| `CurvyVaultV2.json` | `src/v2/vault/CurvyVaultV2.sol/…json` | vault impl |
| `CurvyAggregationVerifier.json` | `src/v2/aggregator-alpha/verifiers/CurvyAggregationVerifier.sol/…json` | Groth16 verifier (2,3,30) |
| `CurvyPendingNotesCommitmentVerifier.json` | `…/verifiers/CurvyPendingNotesCommitmentVerifier.sol/…json` | Groth16 verifier (5,30) |
| `CurvyWithdrawalVerifier.json` | `…/verifiers/CurvyWithdrawalVerifier.sol/…json` | Groth16 verifier (2,30) |
| `PortalFactory.json` | `src/v2/portal/PortalFactory.sol/…json` | deployed via CreateX `deployCreate2` (ctor arg: `owner`) |
| `ERC1967Proxy.json` | `@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol/…json` | UUPS proxy for vault + aggregator (ctor: `impl, initialize(owner)` calldata) |
| `Multicall3.json` | `devenv/Multicall3.sol/…json` | devenv utility |
| `ERC20Mock.json` | `devenv/ERC20Mock.sol/…json` | mock ERC20 (`mockMint`) |
| `ICreateX.json` | `src/v2/utils/ICreateX.sol/…json` | interface only (`bytecode` is `0x`); kept for reference — the deployer hand-declares the `deployCreate2` + `ContractCreation(address,bytes32)` subset it uses (the artifact overloads `ContractCreation`, which `sol!` cannot disambiguate) |

`createx_bootstrap_tx.hex` — the CreateX keyless-deployment **pre-signed raw
transaction** (Nick's method), extracted verbatim from
`packages/contracts/evm/scripts/devenv.ts`. Publishing it (after funding the keyless
deployer `0xeD456e05CaAb11d66C4c797dD6c1D6f9A7F352b5` with 1 ETH) deploys CreateX at
its canonical address `0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed`.
