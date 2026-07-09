# Design: `curvy-bindings` — the blokli-native drop-in

*Status: design, 2026-07-09. Owner directive: Curvy must fit blokli/hoprnet's
scaffold and principles — no vendoring, no custom shapes, no refactors asked of
their side. Supersedes the `curvy-deployer`-as-integration-surface approach
(that crate remains valid as the validated logic to migrate).*

## 1. The pattern blokli already consumes (verified from hopr-bindings 4.9.1 source)

```
hopr-bindings/                       ← crates.io 4.9.1 (hopli comes via git — both
  src/codegen/hopr_token.rs            hosting modes are blokli-native)
  src/codegen/hopr_channels.rs         one generated sol! file per contract,
  src/codegen/…_events.rs              committed, #[rustfmt::skip], forge-bind style
  src/config.rs                        ContractAddresses (named serde slots)
                                       ContractInstances<P>:
                                         new(&addresses, provider)
                                         deploy_for_testing(provider, deployer)
                                           ← deploys + wires + POST-DEPLOY CONFIG
                                             (grants MINTER, mints wxHOPR, sets
                                             ticket-price + win-prob oracles)
                                         get_contract_addresses()
  src/constants.rs                     dev/protocol constants
  src/bin/hopr-contract-addresses.rs   tiny CLI
```

blokli's deployer then does exactly one thing:
`ContractInstances::deploy_for_testing(provider, addr)` → emit `[contracts]` TOML.

## 2. The Curvy mirror

**`curvy-bindings`** — same layout, same idioms, nothing else:

```
curvy-bindings/
  src/codegen/curvy_vault_v2.rs            generated sol! from contract sources
  src/codegen/curvy_aggregator_alpha_v2.rs (forge bind --alloy, matching their
  src/codegen/portal_factory.rs             committed-codegen style; includes the
  src/codegen/portal.rs                     3 verifiers, PoseidonT4, ERC1967Proxy)
  src/config.rs                            CurvyContractAddresses (named slots:
                                             vault, aggregator, portal_factory,
                                             verifiers…, serde like theirs)
                                           CurvyContractInstances<P>:
                                             new(&addresses, provider)
                                             deploy_for_testing(provider, deployer)
                                               ← CreateX bootstrap, PoseidonT4 link,
                                                 impl+proxy deploys, verifier
                                                 registration, bilateral wiring,
                                                 initPerTokenGasFees +
                                                 setFeeNotePublicKey — the direct
                                                 analogue of their mint/oracle setup
                                             get_contract_addresses()
  src/constants.rs                         dev fee table + precomputed commitment-fee
                                           root + DEV_FEE_COLLECTOR key + CreateX
                                           salt/address (keeps arkworks OUT, like
                                           hopr-bindings carries no heavy crypto)
```

The blokli fork diff then collapses to the truly symmetrical drop-in:

```toml
curvy-bindings = { git = "…" }   # hopli-style now; crates.io like hopr-bindings later
```
```rust
if args.with_curvy {
    let curvy = CurvyContractInstances::deploy_for_testing(provider.clone(), addr).await?;
    write_curvy_outputs(curvy.get_contract_addresses(), …)?;   // [curvy_contracts] TOML
}
```

A blokli reviewer sees their own pattern, one flag, ~30 lines. The Nix problem
disappears structurally: a git/crates.io dep is Cargo.lock-pinned and their build
(cargo and Nix alike) already handles exactly that for `hopli`. No vendoring, ever.

## 3. Contracts scaffold

HOPR keeps contracts in their contracts scaffold and generates bindings from
source. Curvy equivalent, minimal-first:
- Contracts source of truth stays `@0xcurvy/monorepo packages/contracts/evm`
  (solc 0.8.28/cancun). Add a **foundry profile** (foundry.toml + remappings) so
  `forge build` + `forge bind --alloy` produce the codegen from the same sources —
  no Hardhat removal, the two coexist. Verify generated-bindings bytecode parity
  against the deployed artifacts (sha-compare creation code) as a codegen gate.
- Long-term option (owner's call, not required for the drop-in): extract a
  `curvy-contracts` repo mirroring `hoprnet/contracts`, with `curvy-bindings`
  generated/versioned alongside (their version tracks contract releases — 4.9.1).

## 4. Migration from what exists today (all logic already validated)

1. Foundry profile in curvy contracts → `forge bind --alloy` → committed
   `src/codegen/` (replaces curvy-abi's trimmed ABI JSONs).
2. `curvy-bindings::config`: port `curvy-deployer`'s deploy/wire/init/read-back
   logic (zero new logic — it passed full regression repeatedly) into
   `CurvyContractInstances`, their naming and error style.
3. `constants.rs`: dev fee table, precomputed root, fee-collector key, CreateX
   raw tx — everything the deployer currently takes via config.
4. Shrink the blokli fork diff to the symmetrical form above; delete the
   path-dep and the `CurvyDeployConfig` plumbing from the fork side.
5. Git-host `curvy-bindings` (push rs-core or the extracted repo) → fork builds
   anywhere; the Nix image variant becomes a normal `nix build` with zero special
   handling (same as hopli).
6. `curvy-sdk` migrates from `curvy-abi` to `curvy-bindings` (one bindings source
   for SDK and deployer alike); `curvy-deployer`/`curvy-abi` dissolve or become
   thin re-exports.
7. Regression gates unchanged: compose up, e2e 5/5, strategy settle, image build.

## 5. Decisions (owner, 2026-07-09)

1. **Contracts home**: inside the monorepo contracts package —
   `packages/contracts/evm/bindings/curvy-bindings/` (+ foundry profile files at
   the package root), mirroring hoprnet's contracts-with-bindings-alongside
   layout. Additive files only; nothing existing in the monorepo changes.
2. **Hosting**: postponed until the implementation is finished (path deps in the
   interim; git/crates.io hosting is the final step).
3. **Versioning**: yes — `curvy-bindings` versions in lockstep with contract
   releases, like hopr-bindings.
4. Still to confirm during implementation: exact codegen flag parity with
   hoprnet's generator (header style says `forge bind --alloy`).
