# curvy-core

Curvy cryptography and circuit-input construction in Rust: Poseidon,
BabyJubjub EdDSA, note encryption and commitments, Merkle trees, witness
builders, and stealth addressing. It does not evaluate compiled Circom graphs or
generate Groth16 proofs.

## Install

```toml
[dependencies]
curvy-core = "=0.1.2"
```

Rust 1.99 or newer is required.

## Signing profiles

Two BabyJubjub signing profiles are supported. Use the one that matches the
account's stored key material.

| Profile | Key derivation | Primary API |
|---|---|---|
| Seed-backed | BLAKE-512/prune derivation from the hex seed bytes | `SeedNoteSigner`, `sign_hex`, `pub_from_private_key_hex` |
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

## Features

The optional `parallel` feature uses Rayon for stealth scans and bulk
Merkle-tree construction:

```toml
[dependencies]
curvy-core = { version = "=0.1.2", features = ["parallel"] }
```

Native applications can set the global Rayon pool size with
`RAYON_NUM_THREADS` or configure `rayon::ThreadPoolBuilder` before the first
parallel call. Use the bulk tree methods to get parallel Merkle construction.

The default `poseidon-optimized` feature uses generated folded constants and
sparse partial-round matrices; outputs and API are identical. Its tables are authenticated and
decoded per arity on first use, which takes tens of microseconds. Set
`default-features = false` to use the reference schedule and a smaller
browser artifact.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for native
and WASM build targets.

## Inputs and verification

- Stealth spend and view private keys are exactly 64 unprefixed hex characters.
  Left-pad shorter keys to 64 characters before import. Generated meta keys use
  64 hex characters and spending keys use `0x` plus 64.
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
- Recompute `noteId` for each received note and compare it with the announced
  one.
- Verify Merkle proofs against a known tree depth with
  `imt::verify_proof_at_depth`; `imt::verify_proof` is deprecated.
- `build_withdrawal` and `build_aggregation` reject a public key that does not
  match the seed.
