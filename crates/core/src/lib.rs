//! # Curvy crypto core
//!
//! A self-contained implementation of the cryptography behind the Curvy privacy
//! protocol. It is split into two parts that are quite different and are best read
//! separately.
//!
//! - **The circuit / commitment layer.** BabyJubjub + Poseidon over the BN254
//!   scalar field, a note-data cipher, note commitments, and the incremental Merkle
//!   trees and circuit witness builders. This is where most of the code is and is
//!   the gentler starting point.
//! - **Stealth addressing** ([`stealth`]). Dual-curve and pairing-based (secp256k1
//!   spend keys + BN254 viewing keys); the more involved part.
//!
//! ## Module map
//!
//! | Module | What it is |
//! |---|---|
//! | [`field`] | BN254 scalar field `Fr` and decimal⇄`Fr` conversion (the boundary) |
//! | [`encoding`] | hex / little-endian / big-endian byte helpers |
//! | [`poseidon`](mod@poseidon) | Poseidon hash over `Fr` |
//! | [`babyjubjub`] | BabyJubjub curve (point addition + scalar multiplication) |
//! | [`blake512`] | BLAKE-512 (the original SHA-3 finalist, not BLAKE2) |
//! | [`eddsa`] | EdDSA-Poseidon signing + key derivation on BabyJubjub |
//! | [`cipher`] | note-data cipher (AES-256-CTR additive field one-time pad) |
//! | [`note`] | note `id` / `ownerHash` / `nullifier` commitments |
//! | [`hash_utils`] | `sha256BigInt` |
//! | [`imt`] | incremental Merkle tree (+ sharded variant) |
//! | [`witness`] | aggregation / withdrawal / pending-commit witness builders |
//! | [`stealth`] | dual-curve, pairing-based stealth addressing |
//!
//! The standard primitives follow the circomlib / iden3 conventions used across
//! the Circom ecosystem: Poseidon uses the circomlib round constants and MDS
//! matrices, and BabyJubjub, EdDSA-Poseidon, and the incremental Merkle tree match
//! the corresponding `@zk-kit` / iden3 reference implementations. The conformance
//! test suite pins each against those references (see "Verification").
//!
//! ## The boundary: how values cross in and out
//!
//! The public API speaks **decimal strings** (and `"X.Y"` for curve points). Two
//! conversions are easy to get wrong, so each lives in exactly one place:
//!
//! - **Field elements** → [`field::fr_from_dec`] / [`field::fr_to_dec`], which
//!   reduce modulo the field. Use them for amounts, hashes, and commitments -
//!   anything that *is* a field element.
//! - **Raw 256-bit integers** (cipher key material, [`hash_utils::sha256_bigint`]
//!   inputs, the EdDSA message) → `num_bigint::BigUint`, packed **without** field
//!   reduction. See [`encoding`].
//! - **Endianness:** big-endian for the cipher and `sha256BigInt`; little-endian
//!   for EdDSA. Both are named explicitly in [`encoding`] to keep them distinct.
//!
//! ## Error convention
//!
//! The [`stealth`] module validates untrusted input and returns
//! [`stealth::StealthError`]. The commitment-layer boundary parsers instead
//! **panic** on malformed input (e.g. a non-numeric "decimal"): callers pass
//! already-validated values, so malformed input there is a programming error and a
//! panic surfaces it loudly rather than silently producing a wrong field element.
//!
//! ## Verification
//!
//! Correctness is measured, not argued: each module is checked against committed
//! test vectors in `tests/` - Poseidon additionally against an independent audited
//! implementation ([`light-poseidon`](https://crates.io/crates/light-poseidon)),
//! and the standard primitives against their circomlib / `@zk-kit` references.
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

// ── Circuit / commitment layer (BabyJubjub + Poseidon over BN254 Fr) ────────────
pub mod babyjubjub;
pub mod blake512;
pub mod cipher;
pub mod eddsa;
pub mod hash_utils;
pub mod note;
pub mod poseidon;

// ── Trees & witness builders (consumed by the zk-circuits) ──────────────────────
pub mod imt;
pub mod witness;

// ── Stealth addressing (secp256k1 + BN254 pairing) ──────────────────────────────
pub mod stealth;

// Convenience re-exports for the two most-used items.
pub use field::Fr;
pub use poseidon::poseidon;
