#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
//!
//! ## Implementation notes
//!
//! Every function here is pinned to a reference implementation by **golden
//! vectors** (see "Verification" below), so behaviour must stay byte-for-byte
//! identical - even where that means code that looks unusual.
//!
//! ## New here? Read this first
//!
//! The crate is split into two cryptographic *domains*. They are very different;
//! treat them separately.
//!
//! - **Domain B - the circuit/commitment layer.** BabyJubjub + Poseidon over the
//!   BN254 scalar field, a note cipher, note commitments, and the Merkle trees and
//!   witness builders the zk-circuits consume. Start here - it is self-contained
//!   and where most code lives.
//! - **Domain A - the stealth addressing core** ([`stealth`]). The hard part:
//!   *dual-curve* and *pairing-based* (secp256k1 spend keys + BN254 viewing keys),
//!   ported from the Go `curvy-core`.
//!
//! ## Module map
//!
//! | Module | What it is | Mirrors |
//! |---|---|---|
//! | [`field`] | BN254 scalar field `Fr` + decimal⇄`Fr` helpers (the boundary) | - |
//! | [`encoding`] | hex / little-endian / big-endian byte helpers | - |
//! | [`poseidon`](mod@poseidon) | Poseidon hash over `Fr` | `poseidon-lite` |
//! | [`babyjubjub`] | BabyJubjub curve (point add + scalar mul) | `@zk-kit/baby-jubjub` |
//! | [`blake512`] | original BLAKE-512 (not BLAKE2) | `@zk-kit/eddsa-poseidon` |
//! | [`eddsa`] | EdDSA-Poseidon signing + key derivation | `@zk-kit/eddsa-poseidon` |
//! | [`cipher`] | note-data AES-256-CTR additive field-OTP | `balanceCipher.ts` |
//! | [`note`] | note `id` / `ownerHash` / `nullifier` commitments | `note.ts` |
//! | [`hash_utils`] | `sha256BigInt` | `proving/utils.ts` |
//! | [`imt`] | indexed IMT + stateful bounded sharded tree | `@zk-kit/imt` / `shardedNotesTree.ts` |
//! | [`witness`] | aggregation / withdrawal / pending-commit witness builders | `witnessFromNotes.ts` |
//! | [`stealth`] | **Domain A** stealth addressing (pairing) | Go `curvy-core` |
//!
//! ## The boundary: how values cross in and out
//!
//! Scalar crypto boundaries speak **decimal strings** (and `"X.Y"` for points),
//! matching the existing TypeScript/Go wire shapes. Bulk tree boundaries use
//! canonical packed 32-byte field elements. Two conversions matter and are easy
//! to get wrong, so they live in exactly one place each:
//!
//! - **Trusted/internal field elements** → [`field::fr_from_dec`] /
//!   [`field::fr_to_dec`], which reduce modulo the field. Use them for amounts,
//!   hashes, and commitments -
//!   anything that *is* a field element.
//! - **Untrusted canonical field elements** → [`field::Bn254Fr`], which rejects
//!   values outside the field instead of reducing them.
//! - **Scalar-native BabyJubJub keys** → [`babyjubjub::BabyJubSecretScalar`] and
//!   [`eddsa::ScalarSigningKey`], which derive `A = scalar·Base8` directly without
//!   the seed-backed profile's hash/prune step.
//! - **Raw 256-bit integers** (the cipher key material, [`hash_utils::sha256_bigint`]
//!   inputs, the EdDSA message) → `num_bigint::BigUint`, packed **without** field
//!   reduction. See [`encoding`].
//! - **Endianness:** big-endian for the cipher / `sha256BigInt`; little-endian for
//!   EdDSA. They are named explicitly in [`encoding`] so the two never get mixed up.
//!
//! ## Error convention
//!
//! Internal boundary parsers **panic** on malformed input (e.g. a non-numeric
//! "decimal"), because callers pass already-validated values and a panic surfaces a
//! programming error loudly. Untrusted input is validated at the wasm boundary
//! before reaching here.
//!
//! ## Signing profiles
//!
//! Seed-backed keys and direct-scalar keys are co-equal supported profiles. Use
//! [`witness::SeedNoteSigner`] for established seed-derived accounts and
//! [`eddsa::ScalarSigningKey`] when the account stores a canonical BabyJubjub
//! subgroup scalar. Both implement [`witness::NoteSigner`] and produce the same
//! Curvy circuit-input shapes; neither profile is deprecated.
//!
//! ## Verification
//!
//! Committed compatibility vectors from the production TypeScript and Go
//! implementations are asserted in the crate's test suite. Primitive behavior
//! must remain byte-for-byte compatible with those vectors.
//!
//! ## Example
//!
//! ```
//! use curvy_core::field::{fr_from_dec, fr_to_dec};
//! use curvy_core::poseidon::poseidon;
//!
//! // The canonical circomlib test vector: Poseidon([1, 2]).
//! let h = poseidon(&[fr_from_dec("1"), fr_from_dec("2")]);
//! assert_eq!(
//!     fr_to_dec(&h),
//!     "7853200120776062878684798364095072458815029376092732009249414926327459813530",
//! );
//! ```

// ── Shared: the boundary (field arithmetic + byte encodings) ────────────────────
pub mod encoding;
pub mod field;

// ── Domain B: circuit/commitment layer (BabyJubjub + Poseidon over BN254 Fr) ────
pub mod babyjubjub;
pub mod blake512;
pub mod cipher;
pub mod eddsa;
pub mod hash_utils;
pub mod note;
pub mod poseidon;

// ── Trees & witness builders (consumed by the v2 zk-circuits) ───────────────────
pub mod imt;
pub mod witness;

// ── Domain A: stealth addressing core (secp256k1 + BN254 pairing) ───────────────
pub mod stealth;

// Convenience re-exports for the two most-used items.
pub use field::Fr;
pub use imt::{NOTES_SHARD_HEIGHT, NOTES_SHARD_SIZE, NOTES_TREE_DEPTH, NOTES_TREE_VERSION};
pub use poseidon::poseidon;
