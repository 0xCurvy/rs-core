# curvy-core

Production-compatible Curvy cryptography and circuit-input construction in
Rust. This crate contains Poseidon, BabyJubjub EdDSA, note encryption and
commitments, Merkle trees, witness builders, and stealth addressing. It does not
evaluate compiled Circom graphs or generate Groth16 proofs.

## Install

```toml
[dependencies]
curvy-core = "=0.1.0-rc.5"
```

Rust 1.94 or newer is required.

## Signing profiles

Seed-backed and direct-scalar BabyJubjub signing are both first-class supported
profiles. Choose the profile that matches the account's stored key material;
neither profile is deprecated.

| Profile | Key derivation | Primary API |
|---|---|---|
| Seed-backed | Hex seed bytes are processed with Curvy's established BLAKE-512/prune derivation | `SeedNoteSigner`, `sign_hex`, `pub_from_private_key_hex` |
| Direct-scalar | A canonical non-zero subgroup scalar directly derives `scalar * Base8` | `ScalarSigningKey`, `BabyJubSecretScalar`, `BabyJubPoint` |

Both signer types implement `NoteSigner` and can be passed to
`build_withdrawal_with_signer` or `build_aggregation_with_signer`:

```rust
use curvy_core::eddsa::ScalarSigningKey;
use curvy_core::witness::{NoteSigner, SeedNoteSigner};

let seed_signer = SeedNoteSigner::new(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
)?;
let scalar_signer = ScalarSigningKey::from_decimal("1")?;

let _seed_public_key = seed_signer.public_key();
let _scalar_public_key = scalar_signer.public_key();
# Ok::<(), Box<dyn std::error::Error>>(())
```

Do not reinterpret key material from one profile as the other: the derivations
produce different account keys.

## Parallel feature

The optional `parallel` feature uses Rayon for independent stealth scans and
bulk Merkle-tree construction:

```toml
[dependencies]
curvy-core = { version = "=0.1.0-rc.5", features = ["parallel"] }
```

Native applications can select the global Rayon pool size with
`RAYON_NUM_THREADS` or configure `rayon::ThreadPoolBuilder` before the first
parallel call.

Poseidon uses fixed-width stack scratch space and performs no per-round heap
allocation. This matters most for Merkle construction, where every parent is a
binary Poseidon hash; use the bulk tree methods to add Rayon parallelism on top
of that allocation-free kernel.

The default `poseidon-optimized` feature selects generated folded constants and
sparse partial-round matrices without changing any output or API. Merkle-heavy
workloads benefit most. Those tables are authenticated and decoded per arity on
first use, so a caller that only hashes pairs pays for the arity-2 block rather
than all sixteen; first-hash latency is tens of microseconds. Consumers that explicitly prefer the smaller compressed
browser artifact can select the direct reference schedule with
`default-features = false`; see the workspace
[benchmarks](https://github.com/0xCurvy/rs-core/blob/main/docs/benchmarks.md#7-poseidon)
for measured native/WASM tradeoffs.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for complete
native and WASM build targets.

## September 2026 boundary hardening

Secret BabyJubjub multiplication and signature-response arithmetic use pinned
RustCrypto `crypto-bigint` 0.7.5, fixed-width modular arithmetic, and a fixed
256-bit point schedule. Public verification retains the independent variable-time
implementation. This change preserves the established seed and direct-scalar
signature vectors; it is not an external side-channel certification. Stealth
pairing/scanning and prover arithmetic remain variable-time.

Stealth private keys now require exactly 64 unprefixed hex characters; truncated,
odd-length, prefixed, and invalid hex is rejected. Previously generated shorter
keys need explicit left-padding to 64 characters before import. Do not recover
keys from previously lossy inputs by silently padding the truncated result.
Generated meta keys use 64 hex characters and spending keys use `0x` plus 64.
Random nonzero field scalars use rejection sampling rather than reduction.

Signing keys/nonces use fixed-width RustCrypto arithmetic and complete
BabyJubjub projective formulas (EFD `add-2008-bbjlp`), computing both candidates
and selecting without scalar-dependent branches. This includes scalar response
arithmetic, not just point multiplication. Rejection sampling can repeat on a
negligible fraction of nonce candidates; parsing and public verification are
outside the fixed secret-arithmetic schedule. Source review and differential
tests do not establish a compiler- and hardware-independent timing guarantee.

Owned signing buffers, hash/cipher state, and witness evaluation buffers are
wiped where their types permit it. Caller copies, exposed legacy `BigUint`
values, compiler/register copies, and all third-party arithmetic temporaries
are not covered by a complete-erasure claim.

Note encryption is an additive field one-time pad, so recipients must recompute
and validate `noteId` for integrity. Reusing a shared secret and ephemeral key
reuses the pad and reveals amount differences. Use a fresh ephemeral key for
every payment. Stealth point coordinates require canonical unsigned
field decimals with no leading zeroes, and the point at infinity (`"0.0"`) is
rejected as a key and skipped as a scan announcement. `send_with_r` requires
`r` as a canonical decimal in `[1, p)` of the BN254 scalar field. Legacy
witness builders reject a stored public key that does not match the seed.

`imt::verify_proof` (deprecated) trusts the proof's sibling count; verify proofs
against a known tree with `imt::verify_proof_at_depth`, which also rejects
truncated internal-node and zero-sibling proofs.

`ephemeral_pub_key` accepts values from zero through `2^256 - 1`, including
values above the subgroup order. Larger values panic in Rust and return errors
through WASM `ephemeralPubKey` and C `curvy_ephemeral_pub_key`. Its fixed-schedule
timing model covers scalar multiplication; input parsing and encoding are
outside that model.

Secret scalar decimal imports convert directly into zeroizing 32-byte storage
over a padded 78-digit buffer. Canonical subgroup keys reject zero, leading
zeroes and values at or above the subgroup order. Raw ephemeral scalars accept
zero and leading zeroes within the 78-character input limit. Length, syntax and
range errors are observable; byte-based imports avoid decimal conversion.

Both Poseidon schedules use fixed-width BN254 arithmetic, copy field
representations without value-dependent canonicalization, and wipe owned state
buffers. Decimal field accumulation has a fixed schedule for a given digit
count; sign, length and validation status remain observable. Public signature
verification and formatting returned values may take variable time.

BLAKE-512 wipes owned state and compression buffers on drop. These protections
do not guarantee erasure of caller copies or compiler temporaries, or timing
behaviour independent of the compiler and runtime.
