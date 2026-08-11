# curvy-core

Production-compatible Curvy cryptography and circuit-input construction in
Rust. This crate contains Poseidon, BabyJubjub EdDSA, note encryption and
commitments, Merkle trees, witness builders, and stealth addressing. It does not
evaluate compiled Circom graphs or generate Groth16 proofs.

## Install

```toml
[dependencies]
curvy-core = "=0.1.0-rc.4"
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

let seed_signer = SeedNoteSigner::new("000102030405060708090a0b0c0d0e0f");
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
curvy-core = { version = "=0.1.0-rc.4", features = ["parallel"] }
```

Native applications can select the global Rayon pool size with
`RAYON_NUM_THREADS` or configure `rayon::ThreadPoolBuilder` before the first
parallel call.

See the [workspace guide](https://github.com/0xCurvy/rs-core#readme) for complete
native and WASM build targets.
