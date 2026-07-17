---
title: HOPR PIX Integration Readiness Review
status: proposed
date: 2026-07-13
scope:
  - rs-core
  - blokli
  - curvy-monorepo
  - HOPR RFCs 78, 89, and 90
---

# HOPR PIX Integration Readiness Review

## Executive verdict

The direction is viable, and the existing work has already retired meaningful technical risk. However, the current branches are proof-of-concept branches, not yet suitable upstream changes:

- `rs-core` proves that Rust witness generation, proving, Curvy contract interaction, Blokli submission, and HOPR strategy composition are possible.
- `blokli` proves that a Curvy development deployment can be colocated with HOPR.
- `curvy-monorepo` contains useful workflow, policy, and future decentralization patterns.
- None of them yet implements the HOPR packet/session/acknowledgement integration that PIX actually depends on.

The recommendation is:

> Proceed, but pause feature implementation until the PIX wire format, crypto profile, settlement mapping, lifecycle, and repository ownership are agreed with HOPR.

In particular, the current Blokli branch should not be submitted upstream in its present shape, and `CurvyStrategy` should not be evolved directly into PIX. Both should be treated as test harnesses from which smaller, upstreamable changes are extracted.

No implementation files were modified during this review.

## Reviewed state

| Repository | Snapshot | Assessment |
|---|---|---|
| `rs-core` | `plan/hopr-blokli-poc` at `a613f09` | Strong ~34k-line PoC; detached workspaces, no CI, production state/key/artifact gaps |
| `blokli` | `curvy-deployer` at `2e20a00` | Useful co-deployment prototype; ~62k generated lines, no runtime Curvy indexing/API |
| `curvy-monorepo` | `agents-mcp` at `f191acc` | Useful pattern library and future protocol direction; not directly PIX-compatible |
| HOPR RFCs | PRs 78, 89, and 90 are open | Protocol is still being designed; implementation should not assume a final profile |

The pre-existing untracked `.DS_Store` in Blokli was left untouched.

## Recommended ownership architecture

Blokli and rs-core can form the settlement/data backbone of PIX, but HOPR must own the transport side:

```text
HOPR packet + session layer
  - PIX negotiation and wire messages
  - SURB recipient data
  - verified acknowledgement / ack_secret events
                     │
                     ▼
Durable PIX agreement engine
  - commitments and shares
  - threshold progress
  - expiry, retry and recovery
  - no concrete chain or pool assumptions
              ┌──────┴──────┐
              ▼             ▼
   Curvy settlement port   Agreement store
              │
              ▼
 rs-core SDK / prover / checked crypto types
              │
              ▼
      official blokli-client
              │
              ▼
 Blokli Curvy projection + typed transaction jobs
              │
              ▼
       Curvy contracts and verifiers
```

The boundaries should be:

- HOPR owns session negotiation, packet construction, SURBs, and verified acknowledgements.
- A durable PIX engine owns agreement state and cryptographic share processing.
- `rs-core` owns Curvy-compatible cryptography, proving, note state, and the privacy-pool adapter.
- Blokli owns finalized/reorg-aware public-chain projection and, if desired, authenticated typed transaction submission.
- Blokli should not hold polynomial secrets, SSA private material, viewing keys, or unrestricted proving responsibility.
- Curvy batching should remain a separate role unless a later ADR explicitly places it in Blokli.

## Principal findings

### 1. RFC convergence and HOPR transport are the first blockers

The RFC repository defines core HOPR protocol and interface specifications, but the PIX work remains an open stack of changes: [PR 78](https://github.com/hoprnet/rfc/pull/78) is the initial PIX draft; [PR 89](https://github.com/hoprnet/rfc/pull/89) adds a Curvy/BabyJubJub appendix on top of the `pix` branch; [PR 90](https://github.com/hoprnet/rfc/pull/90) is a broader rewrite, also on top of `pix`. PR 89 and PR 90 are therefore not independent, finalized alternatives.

There are immediate implementation mismatches:

- PR 90 introduces Session Start messages `0x04` and `0x05`. Current HOPR exposes only four variants and rejects unknown discriminants: [current Start protocol](https://github.com/hoprnet/hoprnet/blob/ac365f2b82143fcf69adf043f6c0a38203e61f00/protocols/start/src/lib.rs#L105-L117), [decoder](https://github.com/hoprnet/hoprnet/blob/ac365f2b82143fcf69adf043f6c0a38203e61f00/protocols/start/src/lib.rs#L238-L252).
- HOPR currently reserves exactly 32 bytes in `SurbReceiverInfo` for future Shamir data: [current SURB receiver data](https://github.com/hoprnet/hoprnet/blob/ac365f2b82143fcf69adf043f6c0a38203e61f00/crypto/packet/src/por.rs#L94-L135). PR 90's `EncryptedShare` is 40 bytes when the scalar encoding is 32 bytes.
- The Exit acknowledgement pipeline explicitly drains acknowledgements without processing them, even though the comment anticipates PIX: [acknowledgement drain](https://github.com/hoprnet/hoprnet/blob/ac365f2b82143fcf69adf043f6c0a38203e61f00/transport/hopr/src/protocol/pipeline/mod.rs#L521-L538). PIX requires a verified acknowledgement correlated with the session, agreement, SURB, sender key, and encrypted share.
- PR 90's main profile uses secp256k1 polynomial commitments; PR 89 proposes switching the protocol curve to BabyJubJub. That changes the scalar field, point validation, encoding, hash-to-field, and transcript—not merely the name of the privacy pool.
- PIX proves reply handoff to the first return-path relayer, not end-to-end application delivery. Product and telemetry language must preserve that distinction.

A versioned recipient-data extension is preferable to relying on implicit SURB order to recover `i/r/s`. It is a larger packet change, but it gives reliable restart, reordering, replay, and auditing semantics.

The RFC also needs an explicit negotiated profile such as:

```text
PIX protocol version
+ commitment/share crypto suite
+ settlement/privacy-pool profile
+ encoding version
```

Only one profile needs to ship initially, but the wire protocol must support safe negotiation, rejection, and future deprecation.

### 2. PIX's recovered SSA key cannot currently spend a Curvy note

This is the most important settlement compatibility finding.

`rs-core` derives a BabyJubJub account key from seed material, and witness signing also expects that seed: [account.rs](../sdk/curvy-sdk/src/account.rs#L39), [witness.rs](../crates/core/src/witness.rs#L116). PIX reconstructs an actual subgroup scalar. It cannot invert Curvy's seed derivation.

Curvy is also currently hybrid:

- Stealth/viewing behavior is secp256k1-oriented.
- Note ownership and circuit signatures use BabyJubJub/BN254 machinery.
- Curvy computes `ownerHash`, `noteId`, and `nullifier` using a BabyJubJub point plus `sharedSecret`: [note.ts](../../curvy-monorepo/packages/sdk/src/types/note.ts#L123).
- The current SDK fills `sharedSecret` from a stealth spending point's x-coordinate: [core/index.ts](../../curvy-monorepo/packages/sdk/src/core/index.ts#L220). That is not interchangeable with the reconstructed SSA scalar.

Before building the adapter, rs-core needs:

- Separate checked `BabyJubScalar`, `Bn254Fr`, and `BabyJubPoint` types.
- Point-on-curve and subgroup validation at every untrusted boundary.
- Scalar-native signing accepted by the real Curvy circuits.
- A specified `KnownOwner { owner, shared_secret }` note-construction path.
- Exact `DepositHandle`, `Allocate` output-note, and `Withdraw` semantics.
- Domain-separated owner hash, shared-secret, nullifier, and PoP transcripts.
- Cross-language vectors covering Rust, TypeScript, Circom, and Solidity.

The first compatibility gate should be a kill-shot test:

> Reconstruct an SSA scalar from PIX shares, allocate a note to its public point, and spend it through the real deployed Curvy verifier.

If this cannot be demonstrated, the current Curvy circuits or the proposed PIX profile must change.

### 3. Durable agreement and note state are missing

The current rs-core synchronization path rebuilds from block zero and lacks durable cursors, block hashes, log positions, finality, rollback, and nullifier state: [client sync](../sdk/curvy-sdk/src/client.rs#L241).

`CurvyStrategy` is a timer-based auto-withdraw harness. Its settled set is in memory, failures are swallowed, and after restart it can repeatedly select the first historically spent note: [strategy selection](../hopr/curvy-hopr-strategy/src/lib.rs#L175), [error loop](../hopr/curvy-hopr-strategy/src/lib.rs#L222). A strategy tick cannot replace the transport hook or the agreement state machine.

The PIX engine should persist transitions such as:

```text
negotiated
→ commitments complete
→ allocation submitted
→ allocation finalized
→ shares in flight
→ threshold reached
→ SSA reconstructed
→ withdrawal submitted
→ withdrawal finalized
```

It also needs explicit failed, expired, cancelled, and reorg-invalidated states. Every transition should use compare-and-set semantics and an append-only event record.

Persist at least:

- Session and agreement IDs.
- Exact negotiated profile and `m/t/price/chunk_size`.
- Commitment transcript hash.
- Allocation transaction and block/hash.
- SURB/share assignment and acknowledgement status.
- Distinct `x` values and verified rows.
- Retry attempts and idempotency keys.
- Expiry and final withdrawal receipt.

Curvy's portal repository already provides useful CAS/retry patterns: [portal repository](../../curvy-monorepo/packages/backend/src/lib/repositories/portal/database/repository.ts#L148). Its decentralization draft also provides useful `UNKNOWN → PENDING → INCLUDED`, historical-root, and persisted-cursor concepts: [Curvy decentralization RFC](../../curvy-monorepo/knowledge/rfc/curvy-decentralization-rfc.md#L13).

One correction is needed there: canonical replay order should be chain order `(block_number, transaction_index, log_index, event_ordinal)`, with block hash and chain/deployment identity. Block timestamp should be metadata, not the primary ordering key.

### 4. Blokli has the right indexing base, but the branch only deploys Curvy

Blokli already has valuable foundations: finalized-block processing, raw-log journaling, rollback, watermarks, and dynamic Safe discovery. Its indexer commits state before publishing notifications, which is a good base for an outbox: [indexer handlers](../../blokli/chain/indexer/src/handlers/mod.rs#L350).

But the WIP currently has no Curvy runtime integration:

- Runtime configuration is still HOPR-only: [config.rs](../../blokli/bloklid/src/config.rs#L258).
- Handler/filter dispatch is statically HOPR-specific: [handlers](../../blokli/chain/indexer/src/handlers/mod.rs#L72).
- There are no Curvy migrations, indexed entities, queries, or resumable subscriptions.
- The normal Anvil entrypoint always enables Curvy, despite the deployer CLI itself being opt-in: [entrypoint](../../blokli/docker/blokli-anvil-entrypoint.sh#L64).
- `curvy-bindings` contributes approximately 62k generated lines through an unpublished path dependency: [dependency](../../blokli/bloklid/Cargo.toml#L88). Its deployment test is outside the workspace and its documented generation-check script is absent.

The bindings and generator should live with the canonical Curvy contracts and artifacts. Blokli should consume an immutable revision or released crate. Curvy development deployment should be an optional feature or separate image, with production deployment and development seeding as separate APIs.

The deployment manifest should attest:

- Chain and deployment identity.
- Activation block.
- Contract, ABI, runtime-bytecode, and circuit hashes.
- Verifier and trusted-setup versions.
- Initializer arguments and transaction hashes.
- Ownership, role handoff, and revocation state.

### 5. Blokli's transaction relay is a hard security gate

The GraphQL mutation accepts pre-signed transactions, but current validation accepts any non-empty byte string while contract, selector, chain, signature, size, and gas checks remain TODOs: [transaction validator](../../blokli/chain/api/src/transaction_validator.rs#L22). Embedded Blokli also uses permissive CORS without application-level TLS or client authentication: [main.rs](../../blokli/bloklid/src/main.rs#L313).

PIX must not enable that surface externally in its present form.

Prefer typed operations such as `prepareAllocation`, `submitAllocation`, `submitWithdrawal`, and `operationStatus`. If raw relay remains, require:

- Authentication and authorization.
- EIP-2718 decoding and signature/chain-ID verification.
- Deployment-derived contract and selector allowlists.
- Value, calldata-size, gas, and fee bounds.
- Simulation and revert classification.
- Nonce coordination and replacement policy.
- Idempotency keys and durable operation records.
- Rate limits, quotas, and privacy-aware audit records.

The official [blokli-client](https://github.com/hoprnet/blokli-client) should replace rs-core's permissive hand-written GraphQL parsing.

### 6. Blokli needs a durable, protocol-neutral event surface

A full runtime plugin system would be premature. A compile-time module registry should provide:

- Module and schema version.
- Deployment identity and activation block.
- Addresses, topics, and dynamic discovery.
- Typed decode/reduce handlers.
- Namespaced migrations.
- Reorg/finality hooks and health/watermark reporting.

Curvy should then be implemented as the first additional module.

PIX consumers need a transactional outbox keyed by:

```text
(chain_id, deployment_id, block_number, block_hash,
 transaction_index, log_index, event_ordinal)
```

The current in-memory event bus can overflow and subscribers continue after missing data: [subscription handling](../../blokli/api/src/subscription.rs#L543). The API needs `afterCursor`, deterministic replay, and finalized/provisional status.

For the initial scope, use one Blokli writer instance per EVM chain/deployment, while still including chain and deployment identity in every API record. Solana and cross-chain aggregation can remain separate adapters until requirements are explicit.

### 7. rs-core needs to become reproducible before it becomes a dependency

The PoC has good separation and useful conformance tests, but release gates are incomplete:

- The root test and dependency-policy commands do not cover the detached SDK, prover, and HOPR workspaces.
- No CI covers the whole repository.
- Proving artifacts use machine-specific absolute paths and are reloaded/rehashed per proof: [witness calculator](../sdk/curvy-witnesscalc/src/lib.rs#L76).
- The live E2E test succeeds when the stack is unavailable, and a failed withdrawal may only produce a warning: [E2E test](../sdk/curvy-e2e/tests/e2e.rs#L5).
- Private keys are cloneable strings rather than zeroizing secret types.
- Transaction submission assumes one confirmation, fixed gas, and local-Anvil behavior.
- The core/prover boundary still contains panic paths for malformed inputs.

Proving artifacts need a signed/versioned manifest and process-wide initialized cache behind a bounded, cancellable worker pool. The manifest should bind circuit IDs, hashes, sizes, trusted-setup provenance, and expected on-chain verifier code hashes.

The HOPR adapter should remain separate from the MIT cryptographic core. HOPR's repositories are GPL-3.0 and increasingly split into `hoprd`, `hopr-api`, `hopr-strategy`, `edge-client`, Blokli, and related crates, so distribution and linking boundaries should be deliberate and legally reviewed. The current organization shape is visible in the [HOPR repositories](https://github.com/hoprnet).

## Prioritized implementation plan

### Phase 0 — Specifications and ADRs

No production code should precede this phase.

Deliver:

1. RFC 78/89/90 resolution matrix, identifying retained, replaced, and unresolved sections.
2. PIX wire and negotiation ADR, including the `0x04/0x05` messages, packet versioning, recipient-data format, resource bounds, and downgrade behavior.
3. Crypto-suite ADR covering fields, curves, point/scalar encodings, subgroup rules, hash-to-field, KDF/AEAD, and all domain separators.
4. Curvy settlement ADR defining `Deposit`, `DepositHandle`, `Allocate`, SSA note ownership, `sharedSecret`, PoP, and `Withdraw`.
5. Agreement lifecycle ADR covering persistence, timeout, cancellation, retries, idempotency, restart, and reorg behavior.
6. Component ownership, licensing, release, and artifact-provenance ADR.
7. Threat/privacy model covering griefing, replay, duplicate shares, malformed points, resource exhaustion, telemetry, and data retention.

Exit gate: HOPR and Curvy reviewers agree on one initial profile, and cross-language test vectors are approved.

### Phase 1 — Make both WIPs truthful and reproducible

For Blokli:

- Remove the vendored bindings as the canonical source.
- Consume an immutable Curvy release.
- Restore unchanged default Blokli/Anvil behavior.
- Separate production deployment from dev seeding.
- Add deployment/read-back and code-generation parity CI.
- Produce an attested deployment manifest.

For rs-core:

- Add one top-level check covering every Rust workspace, WASM, fixtures, and adapters.
- Fix false-positive E2E behavior.
- Remove absolute paths and mutable artifact sources.
- Cache proving artifacts.
- Commit a reproducible HOPR adapter lockfile.
- Migrate from duplicate ABI definitions to canonical bindings.
- Add secret wrappers, strict external newtypes, and panic-free public boundaries.

Exit gate: a fresh checkout can reproduce bindings, artifacts, deployments, and tests without developer-machine paths.

### Phase 2 — Prove Curvy/PIX settlement compatibility

- Add checked scalar/point/field types.
- Add scalar-native signing.
- Implement the known-owner/SSA recipient path.
- Define the narrow `PrivacyPool` interface.
- Publish Rust/TypeScript/Solidity/Circom vectors.
- Run the real SSA reconstruct → allocate → prove → withdraw test.

Exit gate: the deployed verifier accepts a spend by a reconstructed SSA scalar.

### Phase 3 — Build the Blokli data plane

Split this into separate upstreamable changes:

1. Protocol-neutral module registry and backfill/migration mechanics.
2. Read-only Curvy indexing for portals, configuration, notes, roots, nullifiers, and withdrawals.
3. Transactional outbox and cursor-based API.
4. Official-client support.
5. Authenticated typed transaction jobs; generic raw relay remains disabled by default.

Exit gate: restart, reorg, backfill, slow-consumer, and duplicate-delivery tests pass without losing or reordering events.

### Phase 4 — Implement HOPR transport integration upstream

Suggested HOPR PR order:

1. Merge the agreed RFC changes and negotiation profile.
2. Add versioned Start message codecs.
3. Add the agreed SURB recipient-data extension.
4. Expose a verified acknowledgement event containing the required correlation data.
5. Add a narrow HOPR transport port to the PIX engine.
6. Add hoprd/edge-client configuration and lifecycle integration.

The current hoprd configuration has a closed `StrategyKind` enum even though runtime `MultiStrategy` can compose external traits: [hoprd strategy configuration](https://github.com/hoprnet/hoprd/blob/bd1ef0d61e73d76048228b73ea67cf1cf57dd535/hoprd/src/strategy.rs#L53-L71). This needs an accepted configuration seam; simply compiling `CurvyStrategy` against the trait is not deployment integration.

Exit gate: two real HOPR endpoints complete PIX with loss, duplication, reordering, restart, and allocation-reorg injection.

### Phase 5 — Production hardening

- External cryptographic and application security reviews.
- Fuzz packet codecs, artifact parsers, witness construction, and event decoding.
- Bounded proof scheduling, cancellation, and memory/CPU quotas.
- PostgreSQL/HA deployment and leader election for Blokli ingestion.
- Operation authentication, authorization, and rate limiting.
- Code/circuit/artifact attestation and upgrade rollback procedures.
- Compatibility CI against hoprd's pinned revisions and extracted HOPR repositories.
- Privacy review of logs, metrics, traces, and retained note data.
- Performance and recovery SLOs.

## Recommended immediate decisions

The preferred starting positions are:

- Use PR 90 as the structural PIX baseline, then rebase PR 89's Curvy proposal onto it as an explicit crypto/settlement profile.
- Ship one agreed profile first; make the protocol profile-aware without trying to implement secp256k1 and BabyJubJub simultaneously.
- Use a versioned SURB recipient-data extension rather than implicit ordering.
- Keep Blokli as the public-chain projection and authenticated job service, not the holder of PIX secrets.
- Run one Blokli ingestion instance per chain/deployment initially.
- Keep Curvy bindings and proving artifacts with canonical Curvy releases.
- Treat `CurvyStrategy` and the current Blokli deployer as harnesses, then extract smaller upstream PRs.
- Do not expose Blokli's generic transaction relay until its validation and authentication gates are implemented.

## Next deliverable

The next deliverable should be the Phase 0 ADR package and RFC resolution matrix. It should be reviewed before implementation begins.
