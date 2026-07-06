//! Miscellaneous hash helpers.

use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::encoding::biguint_to_be_32;

/// `sha256BigInt`: 32-byte big-endian pack each input, concatenate, SHA-256, then
/// interpret the 32-byte digest as a big-endian integer - **no field reduction**
/// (this is the `inputHash` digest the pending-commit circuit verifies against).
///
/// Inputs are **raw 256-bit integers**, not field elements: each value is packed
/// directly, so values in `[modulus, 2^256)` are hashed literally rather than
/// reduced. Panics on a value `>= 2^256` (the 32-byte packing guard).
pub fn sha256_bigint(inputs: &[BigUint]) -> BigUint {
    let mut h = Sha256::new();
    for x in inputs {
        h.update(biguint_to_be_32(x));
    }
    BigUint::from_bytes_be(&h.finalize())
}
