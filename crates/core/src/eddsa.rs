//! EdDSA-Poseidon over BabyJubjub, matching the default (original BLAKE-512) entry
//! of the `@zk-kit/eddsa-poseidon` reference.
//!
//! Two subtleties where this scheme diverges from circomlibjs (it deliberately
//! follows the `@zk-kit/eddsa-poseidon` convention, which the verifier circuit
//! expects):
//! - the private key is hashed with **original BLAKE-512** (see [`crate::blake512`]);
//! - signing computes `S = r + hm·s mod l` with the **un-shifted** pruned scalar
//!   `s` (not `s >> 3`). Because key pruning zeroes the low 3 bits, `s = 8·(s>>3)`,
//!   so the signature still verifies — but the `S` *value* differs from circomlibjs
//!   by a factor of 8.

use num_bigint::BigUint;

use crate::babyjubjub::{mul_point_escalar, Point, BASE8, SUB_ORDER};
use crate::blake512::blake512;
use crate::encoding::{biguint_to_le_bytes, from_hex, le_bytes_to_biguint};
use crate::field::{fr_from_biguint, fr_to_biguint};
use crate::poseidon::poseidon;

/// EdDSA-Poseidon signature: the point `R8` and the scalar `S` (`S < l`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r8: Point,
    pub s: BigUint,
}

/// Clear the low 3 bits and force the top two bits of a 32-byte little-endian
/// scalar buffer (BabyJubjub key clamping).
fn prune_buffer(mut b: [u8; 32]) -> [u8; 32] {
    b[0] &= 0xf8;
    b[31] &= 0x7f;
    b[31] |= 0x40;
    b
}

/// First 32 bytes of `BLAKE-512(private_key)`, pruned.
fn pruned_scalar_buffer(private_key: &[u8]) -> [u8; 32] {
    let hash = blake512(private_key);
    let mut h32 = [0u8; 32];
    h32.copy_from_slice(&hash[0..32]);
    prune_buffer(h32)
}

/// The secret scalar `(LE(pruned) >> 3) mod l`.
pub fn derive_secret_scalar(private_key: &[u8]) -> BigUint {
    let pruned = pruned_scalar_buffer(private_key);
    (le_bytes_to_biguint(&pruned) >> 3u32) % &*SUB_ORDER
}

/// Public key `derive_secret_scalar(pk) · Base8`.
pub fn derive_public_key(private_key: &[u8]) -> Point {
    mul_point_escalar(*BASE8, &derive_secret_scalar(private_key))
}

/// Public key from a hex-encoded private key (`Buffer.from(hex, "hex")`
/// semantics: the hex is decoded to raw bytes first).
pub fn pub_from_private_key_hex(hex: &str) -> Point {
    derive_public_key(&from_hex(hex))
}

/// Ephemeral public key `R = scalar · Base8`.
pub fn ephemeral_pub_key(scalar: &BigUint) -> Point {
    mul_point_escalar(*BASE8, scalar)
}

/// EdDSA-Poseidon signing over BabyJubjub.
///
/// `message` is a **raw integer**, not a field element: it is not reduced before
/// its little-endian bytes are packed into the `r` derivation, so a message in
/// `[modulus, 2^256)` produces a different `R8`/`S` than its reduced value would.
/// The Poseidon input `hm`, by contrast, reduces `message` (Poseidon reduces all
/// inputs internally). Panics on a message `>= 2^256` (the 32-byte packing guard).
pub fn sign(message: &BigUint, private_key: &[u8]) -> Signature {
    let hash = blake512(private_key);

    let mut h32 = [0u8; 32];
    h32.copy_from_slice(&hash[0..32]);
    let s = le_bytes_to_biguint(&prune_buffer(h32)); // un-shifted pruned scalar
    let a = mul_point_escalar(*BASE8, &(&s >> 3u32));

    // r = LE(BLAKE-512(hash[32..64] || LE32(message))) mod l  — message un-reduced.
    let msg_buff = biguint_to_le_bytes(message, 32);
    let mut compose = Vec::with_capacity(64);
    compose.extend_from_slice(&hash[32..64]);
    compose.extend_from_slice(&msg_buff);
    let r = le_bytes_to_biguint(&blake512(&compose)) % &*SUB_ORDER;

    let r8 = mul_point_escalar(*BASE8, &r);
    let hm = poseidon(&[r8.0, r8.1, a.0, a.1, fr_from_biguint(message)]);

    // S = (r + hm·s) mod l  — s un-shifted (see module note).
    let s_sig = (r + fr_to_biguint(&hm) * s) % &*SUB_ORDER;

    Signature { r8, s: s_sig }
}

/// Signing entry point keyed by a hex-encoded private key.
pub fn sign_hex(message: &BigUint, hex: &str) -> Signature {
    sign(message, &from_hex(hex))
}
