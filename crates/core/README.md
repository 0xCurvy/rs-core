# curvy-core

Production-compatible Curvy cryptography and circuit-input construction in
Rust. This crate contains Poseidon, BabyJubjub EdDSA, note encryption and
commitments, Merkle trees, witness builders, and stealth addressing. It does not
evaluate compiled Circom graphs or generate Groth16 proofs.

## Install

```toml
[dependencies]
curvy-core = "=0.1.1"
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
curvy-core = { version = "=0.1.1", features = ["parallel"] }
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
`default-features = false`.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for complete
native and WASM build targets.

## Input formats

- Stealth spend and view private keys are exactly 64 unprefixed hex characters.
  Shorter keys produced by earlier versions must be left-padded to 64 characters
  before import. Generated meta keys use 64 hex characters and spending keys use
  `0x` plus 64.
- Stealth point coordinates are canonical unsigned field decimals with no leading
  zeroes. The point at infinity (`"0.0"`) is rejected as a key and skipped as a
  scan announcement.
- `send_with_r` takes `r` as a canonical decimal in `[1, p)` of the BN254 scalar
  field. Use a fresh ephemeral key for every payment.
- `ephemeral_pub_key` accepts values from zero through `2^256 - 1`. Larger values
  panic in Rust and return errors through WASM `ephemeralPubKey` and C
  `curvy_ephemeral_pub_key`.
- Canonical subgroup keys reject zero, leading zeroes and values at or above the
  subgroup order.
- Recipients recompute `noteId` for each received note and compare it with the
  announced one.
- Verify Merkle proofs against a known tree with `imt::verify_proof_at_depth`;
  `imt::verify_proof` is deprecated.
- Legacy witness builders reject a stored public key that does not match the seed.
