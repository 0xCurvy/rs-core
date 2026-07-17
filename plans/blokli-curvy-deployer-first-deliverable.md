---
title: Blokli Curvy Contract Deployer — First Deliverable
status: implemented-pending-linux-acceptance
date: 2026-07-13
target: one week
repositories:
  - curvy contracts / curvy-bindings
  - blokli fork
  - rs-core acceptance harness
---

# Blokli Curvy Contract Deployer — First Deliverable

## Goal

Ship a local-development Blokli Anvil image whose existing contract deployer can optionally:

1. deploy the normal HOPR contract suite;
2. deploy, wire, and initialize the Curvy v2 contract suite through `curvy-bindings`;
3. emit Curvy's existing Ignition-compatible address JSON; and
4. pass the Curvy shield → commit → aggregate → scan → withdraw E2E flow.

The deliverable must build from a clean HOPR-side checkout with no sibling Curvy or rs-core directory.

## Implementation status

Implemented on 2026-07-13:

- `curvy-bindings` release hardening, locked CI, package allowlist, artifact manifest,
  notices inventory, and publishing handoff;
- optional, feature-gated Curvy deployment in Blokli with immutable Git consumption;
- separate stock and Curvy Nix binary/image definitions;
- stock entrypoint regression behavior and explicit Curvy image activation;
- strict rs-core acceptance flow through withdrawal; and
- local feature-off/on checks, tests, clippy, package verification, and a live combined
  HOPR + Curvy deployment against Anvil.

Still user-owned:

- license and redistribution approval, crates.io ownership, tagging, and publication;
- switching Blokli from the temporary immutable Git revision to the published exact
  Cargo version; and
- Nix derivation builds, Docker image loading, stock-image regression, and strict image
  E2E execution in a Linux VM.

## Explicit non-goals

This delivery does **not** include:

- PIX protocol or settlement work;
- HOPR packet, SURB, acknowledgement, or strategy changes;
- Curvy runtime indexing in Blokli;
- new Blokli GraphQL operations;
- transaction-relay hardening or expansion;
- production-chain Curvy deployment;
- proof generation inside Blokli;
- publication of the broader rs-core SDK; or
- a broad rs-core workspace reorganization.

`CurvyContractInstances::deploy_for_testing` remains an Anvil/development facility. Production deployment, ownership handoff, upgrades, and network manifests are separate work.

## Decisions

### 1. Publish one crate, not the rs-core SDK tree

Blokli should consume exactly one Curvy dependency: `curvy-bindings`.

The canonical implementation already exists beside the Curvy EVM contracts at:

```text
packages/contracts/evm/bindings/curvy-bindings
```

The implementation originated in commit `90b8d4b5`. It contains the generated Alloy bindings, embedded deployment bytecode, address types, and `deploy_for_testing`. It does not depend on rs-core, arkworks, the prover, or the Rust SDK.

### 2. Do not consolidate all rs-core crates this week

The current problem is duplicated ownership of bindings and deployment logic, not simply crate count.

| Crate | Decision for this delivery |
|---|---|
| `curvy-bindings` | Make canonical, harden, and publish |
| `sdk/curvy-deployer` | Superseded; do not publish or add new functionality |
| `sdk/curvy-abi` | Keep temporarily because SDK/E2E still uses its signing, encoding, and event helpers |
| `curvy-types`, `curvy-chain-api` | Keep internal; they are lightweight domain/capability boundaries |
| `curvy-chain-rpc`, `curvy-chain-blokli` | Keep as separate internal adapters |
| `curvy-core`, `curvy-prover`, `curvy-witnesscalc` | Keep separate because of their heavy and target-specific dependency profiles |
| `curvy-sdk` | Keep as the internal facade |
| `curvy-e2e` | Keep as a non-published acceptance harness |
| HOPR strategy/runner crates | Freeze and exclude |

After the Blokli-driven E2E is green, remove the legacy standalone deployment path. A later SDK cleanup can turn `curvy-abi` into a smaller EVM helper around `curvy-bindings` and delete `sdk/curvy-deployer` completely.

### 3. Prefer crates.io; retain an immutable Git fallback

The consumer-facing release should be a small crates.io package. A Cargo dependency on the large, LFS-bearing Curvy monorepo would make HOPR/Nix fetching unnecessarily expensive.

Recommended stable dependency:

```toml
curvy-bindings = { version = "=1.0.0", optional = true }
```

During review, before committing the stable crates.io version, use either:

- a crates.io prerelease such as `=1.0.0-rc.1`; or
- a small public HTTPS Git repository pinned to a full commit.

```toml
curvy-bindings = {
  git = "https://github.com/0xCurvy/curvy-bindings",
  rev = "<full-40-character-commit>",
  version = "=1.0.0",
  optional = true,
}
```

Do not use an SSH URL, branch, mutable tag, local path, or direct rs-core dependency.

### 4. Preserve stock Blokli behavior

Curvy deployment must be feature-gated and supplied in a separately named Anvil image. The default Blokli binary, production image, and stock Anvil image must remain HOPR-only.

## Task list

### P0 — Resolve publication and redistribution metadata

This is a hard gate for a public crate and distributable image.

- [ ] Inventory every generated binding and embedded bytecode artifact.
- [ ] Record its source path, source commit, SPDX identifier, compiler configuration, ABI hash, creation-bytecode hash, and runtime-bytecode hash.
- [ ] Resolve the current mismatch: `curvy-bindings` declares MIT, while the included sources/artifacts span Apache-2.0, GPL-3.0, BUSL-1.1, AGPL-3.0-only, and MIT.
- [ ] Confirm Curvy's redistribution/relicensing authority for the generated files and embedded bytecode.
- [ ] Confirm the treatment of the embedded CreateX signed deployment transaction.
- [ ] Add the approved Cargo `license` expression or `license-file`.
- [ ] Add the required `LICENSE*` files and `THIRD_PARTY_NOTICES`.
- [ ] Ensure the resulting Blokli image's notices and distribution terms are documented.

Engineering and private review builds can proceed in parallel, but public publication cannot pass this gate implicitly.

### T1 — Prepare the canonical `curvy-bindings` release

Repository: Curvy contracts repository.

- [ ] Put the existing implementation on a clean release branch based on the accepted Curvy v2 contract source.
- [ ] Ensure all required files are committed and reachable from a public HTTPS remote.
- [ ] Keep the crate independently buildable with its own `[workspace]`.
- [ ] Keep `alloy = "=2.1.0"` for this release to match Blokli and `hopr-bindings`.
- [ ] Verify and declare the actual MSRV; Alloy 2.1 suggests Rust 1.91, while Blokli currently builds with Rust 1.96.
- [ ] Replace the package description with an accurate summary, for example: "Alloy bindings and local deployment helpers for Curvy v2 contracts."
- [ ] Add `repository`, `homepage`, `documentation`, `readme`, and maintainers.
- [ ] Add an explicit package allowlist:

```toml
include = [
  "src/**",
  "curvy_aggregator_alpha_v2_unlinked.hex",
  "README.md",
  "LICENSE*",
  "THIRD_PARTY_NOTICES",
  "artifact-manifest.json",
]
```

- [ ] Move Alloy's `node-bindings` feature to test-only configuration if the library does not need it at runtime.
- [ ] Keep generated files committed and never hand-edit them.
- [ ] Scope lint suppression to `src/codegen`; remove crate-wide `#![allow(clippy::all)]` so handwritten deployment code is checked.
- [ ] Add a machine-readable artifact manifest with contract release, source commit, Forge/solc versions, generation command, and hashes.
- [ ] Ensure regeneration/parity instructions work from the source repository. The packaged README should link to this maintainer workflow rather than assume `../generate.sh` exists in the crate tarball.
- [ ] Correct the stale PortalFactory comment in `constants.rs`: this binding build expects `0x410607…`, not the old Hardhat-path `0x3c0C…` address.

#### Deployment-code DX pass

- [ ] Keep the validated deployment order unchanged.
- [ ] Replace chain-dependent `assert!`/`expect` calls with errors that name the failed deployment step and transaction. Compile-time embedded-artifact invariants may remain assertions when generator CI proves them.
- [ ] Verify every returned address is nonzero and contains code.
- [ ] Verify proxy ownership and the Vault/Aggregator/PortalFactory wiring.
- [ ] Verify verifier registrations and their circuit dimensions.
- [ ] Verify token registration, per-token gas fees, commitment fee root, and fee-note public key.
- [ ] Mark dev funding, mock token deployment, and dev fee keys clearly as local-development behavior.
- [ ] Log concise deployment phases and a final address summary; never log a private key.

#### Comment rule

Public API documentation should state guarantees. Internal comments should explain only invariants, provenance, or non-obvious chain behavior.

Remove or shorten comments that:

- repeat the next statement;
- narrate project history or say "PoC", "validated 1:1", "owner decision", or "same proven scheme";
- explain an obvious provider clone or serialization call; or
- contain local checkout paths.

Retain concise explanations for:

- CreateX bootstrap;
- PoseidonT4 bytecode linking;
- CREATE2 metadata/address behavior;
- why proxy addresses are consumer-facing;
- why the circuit-bound settings are read back; and
- artifact generation and provenance.

### T2 — Add authoritative `curvy-bindings` CI

Repository: Curvy contracts repository.

- [ ] `generate.sh --check` with pinned Forge and solc.
- [ ] Bytecode parity check against the accepted contract artifacts.
- [ ] `cargo fmt --check`.
- [ ] `cargo clippy --all-targets -- -D warnings` for handwritten code.
- [ ] `cargo test --locked` with Anvil available.
- [ ] `cargo doc --no-deps`.
- [ ] `cargo package --locked --list` and review every packaged file.
- [ ] Build and test the unpacked `.crate` archive.
- [ ] `cargo publish --locked --dry-run`.

The Anvil test must cover:

- [ ] full suite deployment;
- [ ] code at every emitted address;
- [ ] expected owners and proxy-facing addresses;
- [ ] Vault/Aggregator/PortalFactory wiring;
- [ ] verifier registrations;
- [ ] token and fee configuration;
- [ ] the stable Ignition JSON key set and proxy aliases; and
- [ ] the expected deterministic PortalFactory address for this build.

Dependency tests are not run by a downstream consumer, so this CI remains Curvy-owned after Blokli stops vendoring the crate.

### T3 — Publish the dependency

Repository: Curvy bindings/contracts release repository.

- [ ] Verify the crates.io package name and establish at least two Curvy owners.
- [ ] Decide the release sequence:
  - exact Git revision or `1.0.0-rc.1` during HOPR review;
  - stable `1.0.0` only after acceptance and the P0 gate.
- [ ] Create a signed/annotated `curvy-bindings-v<version>` Git tag on the exact source/generator commit.
- [ ] Publish the verified Cargo package.
- [ ] Publish release notes containing the contract revision, artifact-manifest hash, supported Alloy/Rust versions, test evidence, and dev-only warning.
- [ ] Prove a fresh consumer can build using only the public registry or Git URL.

Publish only:

- generated Rust bindings;
- handwritten addresses/deployment/constants modules;
- the required unlinked aggregator bytecode;
- README, licenses/notices, and provenance manifest.

Do not publish:

- rs-core SDK/prover crates;
- proving keys, witness graphs, or circuit WASM;
- `target`, `.forge`, `node_modules`, Hardhat caches, or local artifacts; or
- developer-machine paths.

### T4 — Replace the vendored dependency in Blokli

Repository: Blokli fork.

- [ ] Delete `vendor/curvy-bindings` and remove the ~62k generated lines from the fork diff.
- [ ] Add the exact registry dependency to the workspace, or the immutable public Git fallback.
- [ ] Make it optional in `bloklid`:

```toml
[features]
curvy-test-deployment = ["dep:curvy-bindings"]

[dependencies]
curvy-bindings = { workspace = true, optional = true }
```

- [ ] Guard Curvy imports, output types, and deployment calls with `curvy-test-deployment`.
- [ ] Keep the CLI flags visible in a feature-off binary, but return a clear error if Curvy is requested without compiled support.
- [ ] Replace the long PoC Cargo comment with one short description and a documentation link.
- [ ] Regenerate and commit `Cargo.lock` with the registry checksum or full Git revision.
- [ ] Verify the lockfile contains no Curvy `path` source.
- [ ] Remove the temporary `.hex` additions from Blokli's Nix source filters; the external Cargo package carries its own `.hex` file.
- [ ] Confirm no Blokli source contains an absolute Curvy/rs-core path.

### T5 — Tighten the Blokli deployer interface

Repository: Blokli fork.

- [ ] Keep `--with-curvy` as the sole activation flag.
- [ ] Require `--with-curvy` when `--curvy-json-out` is supplied; output flags must not silently enable deployment.
- [ ] Remove `--curvy-toml-out` unless a concrete consumer is identified. The current acceptance flow uses the Ignition JSON, and Blokli rejects unknown top-level config sections.
- [ ] Reject colliding HOPR and Curvy output paths before sending transactions.
- [ ] Validate the local-development chain ID, with any override named explicitly as unsafe.
- [ ] Serialize all requested outputs in memory first.
- [ ] Write outputs only after both HOPR and Curvy deployment/read-back succeed.
- [ ] Use atomic, same-directory file replacement and end JSON with a newline.
- [ ] Include failed paths and deployment phases in error messages.
- [ ] Keep CLI help short and user-facing; move internal serde/config details to documentation.
- [ ] Never append `[curvy_contracts]` to Blokli's own config.

### T6 — Add a separate feature-enabled Nix/image target

Repository: Blokli fork.

- [ ] Restore the stock Anvil entrypoint so it does not always deploy Curvy.
- [ ] Add a feature-enabled binary derivation:

```text
binary-bloklid-<platform>-curvy
```

- [ ] Add a separately named image:

```text
docker-bloklid-anvil-curvy-<platform>
```

- [ ] Build the Curvy binary with:

```text
-p bloklid --bins --locked --features curvy-test-deployment
```

- [ ] Fix the common stock Nix Cargo arguments to include `--locked`; Blokli currently overrides Crane's default and drops it.
- [ ] Use one entrypoint for both variants:
  - stock image: HOPR only;
  - Curvy image: set `BLOKLI_DEPLOY_CURVY=true` and append the Curvy CLI arguments.
- [ ] Fail clearly if the environment requests Curvy from a feature-disabled binary.
- [ ] Preserve the current production and stock Anvil image outputs unchanged.
- [ ] Build x86_64 and aarch64 derivations; run the first-week image E2E on x86_64.
- [ ] Do not change `flake.lock`: Curvy is a Cargo dependency, not a Flake input.

For a crates.io dependency, Cargo.lock supplies the immutable checksum and Crane vendors it before the sandboxed compile. A strict Git fixed-output hash path can be added later if HOPR's pinned `nix-lib` exposes Crane's `outputHashes`/`cargoVendorDir`; it should not block the registry-based delivery.

### T7 — Make the combined tests release-blocking

#### Blokli CLI/integration tests

- [ ] Feature-off build and existing arguments remain unchanged.
- [ ] Curvy defaults off.
- [ ] Curvy output requires explicit activation.
- [ ] Output-path collisions fail before deployment.
- [ ] One deployer invocation deploys HOPR and Curvy through the same provider.
- [ ] Both HOPR TOML and Curvy JSON parse successfully.
- [ ] A failed Curvy phase leaves no valid-looking final output files.
- [ ] Every Curvy address has code and the configured values match expectations.

#### Image acceptance E2E

- [ ] Build from a clean Blokli checkout with no sibling repositories.
- [ ] Start `docker-bloklid-anvil-curvy-x86_64-linux`.
- [ ] Wait for Anvil and Blokli readiness.
- [ ] Assert the Curvy JSON exists and has the exact expected keys.
- [ ] Run the existing rs-core shield → commit → aggregate through Blokli → scan flow using those exact addresses.
- [ ] Make the E2E fail when the stack is absent. The current test's successful skip is not a release gate.
- [ ] Make commit/withdrawal failures fail the ledger rather than print warnings.
- [ ] Run the stock Anvil image separately and confirm it does not deploy Curvy.
- [ ] Tear both environments down cleanly.

The full flow remains Curvy-owned. Blokli CI should own the build, deployment, output, and read-back coverage rather than depending on all rs-core crates.

### T8 — Retire the legacy rs-core deployment path after acceptance

Repository: rs-core.

- [ ] Point the acceptance runbook at the native Blokli Curvy image.
- [ ] Remove `CURVY_LEGACY_DEPLOY` after the new E2E is green.
- [ ] Remove the standalone `sdk/curvy-deployer` invocation from `poc/blokli-env/run.sh`.
- [ ] Remove the staging Dockerfile/path-rewrite workaround.
- [ ] Remove hard-coded local artifact/dependency paths from the deployment workflow.
- [ ] Remove `sdk/curvy-deployer` from the active SDK workspace, then delete it once no consumer remains.
- [ ] Keep `curvy-abi` temporarily; migrate it to `curvy-bindings` in a separate SDK task.
- [ ] Replace the existing deployment documentation with one short runbook: build, start, locate addresses, run strict E2E, stop.

## Clean-clone acceptance commands

The exact Nix attribute names may be adjusted during implementation, but the final equivalents must pass from a clean Blokli checkout:

```bash
cargo metadata --locked
cargo build --locked -p bloklid \
  --features curvy-test-deployment \
  --bin blokli-contract-deployer

nix build -L .#binary-bloklid-x86_64-linux-curvy
nix build -L .#docker-bloklid-anvil-curvy-x86_64-linux
```

Also require:

- [ ] `cargo fetch --locked`, followed by `cargo build --locked --offline`.
- [ ] The Nix compilation phase succeeds in its normal network-isolated sandbox.
- [ ] `git diff --exit-code Cargo.lock` after all builds.
- [ ] No `path = "../vendor/..."`, absolute Curvy path, or sibling checkout dependency.
- [ ] Both feature-off and feature-on binaries build.
- [ ] Both stock and Curvy Anvil images build.

## PR sequence

1. **Curvy release PR** — licensing/provenance, package metadata, error/comment pass, CI, and stronger Anvil test.
2. **Blokli dependency PR** — remove vendor copy, add exact optional dependency and feature; stock behavior unchanged.
3. **Blokli deployer PR** — Curvy CLI branch, atomic output, and focused integration tests.
4. **Blokli image PR** — separate Curvy Anvil image and container smoke/E2E.
5. **rs-core cleanup PR** — strict acceptance mode and removal of the legacy deployment route.

PRs 2 and 3 may be combined for the one-week fork delivery. The 62k-line vendor copy should not remain in the review branch.

## Suggested one-week order

| Day | Work |
|---|---|
| 1 | P0 decision; clean Curvy release branch; package metadata, license/notices, comment/error pass |
| 2 | Provenance/generator CI; strengthened Anvil test; package and tag/publish candidate |
| 3 | Delete Blokli vendor copy; exact optional dependency; feature gate; separate image derivation |
| 4 | CLI/output tests, Nix builds, stock regression, and strict full Curvy E2E |
| 5 | Clean-clone handoff verification, documentation, rs-core legacy-path cleanup, and small fork PR preparation |

If P0 is not resolved by Day 2, continue engineering against an internal immutable revision, but do not label the crate or image publicly releasable.

## Definition of done

- [ ] Blokli contains no vendored Curvy generated code and no rs-core dependency.
- [ ] Only `curvy-bindings` is visible as a Curvy dependency.
- [ ] The dependency is public and immutable through crates.io or a full Git revision.
- [ ] Stock Blokli builds and images behave exactly as before.
- [ ] The explicitly named Curvy image deploys both suites in one invocation.
- [ ] Curvy address JSON is complete and written only after verified initialization.
- [ ] The existing strict Curvy E2E passes without fallback, warning-only steps, or successful skips.
- [ ] x86_64 and aarch64 compilation pass.
- [ ] Cargo and Nix builds work from a clean checkout with no sibling repositories.
- [ ] Contract source, generated bindings, embedded bytecode, license information, and release provenance are traceable.
- [ ] PIX, indexing, proving, and production deployment remain explicitly out of scope.
