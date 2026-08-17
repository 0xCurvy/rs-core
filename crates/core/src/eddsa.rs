//! EdDSA-Poseidon over BabyJubJub, compatible with `@zk-kit/eddsa-poseidon`.
//!
//! Compatibility notes:
//! - Private keys use original BLAKE-512.
//! - `signMessage` uses the unshifted pruned scalar in `S`. This matches zk-kit
//!   and the deployed verifier, but differs from circomlibjs.

use std::{fmt, sync::LazyLock};

use hmac::{Hmac, KeyInit, Mac};
use num_bigint::BigUint;
use sha2::Sha512;

use crate::babyjubjub::{
    BASE8, BabyJubError, BabyJubPoint, BabyJubScalar, BabyJubSecretScalar, Point, SUB_ORDER,
    add_point, mul_point_escalar, public_key_from_scalar,
};
use crate::blake512::blake512;
use crate::encoding::{HexDecodeError, biguint_to_le_bytes, from_hex_exact, le_bytes_to_biguint};
use crate::field::{Bn254Fr, fr_from_biguint, fr_to_biguint};
use crate::poseidon::poseidon;

const SCALAR_NONCE_LABEL: &[u8] = b"CURVY_BABYJUB_SCALAR_NONCE_V1";

static NONCE_REJECTION_LIMIT: LazyLock<BigUint> = LazyLock::new(|| {
    let two_512 = BigUint::from(1u8) << 512usize;
    &two_512 - (&two_512 % &*SUB_ORDER)
});

type HmacSha512 = Hmac<Sha512>;

/// EdDSA-Poseidon signature: the point `R8` and the scalar `S` (`S < l`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r8: Point,
    pub s: BigUint,
}

/// Direct-scalar signature with checked subgroup points and a canonical response
/// scalar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScalarSignature {
    pub r8: BabyJubPoint,
    pub s: BabyJubScalar,
}

impl ScalarSignature {
    /// Convert to the established witness signature shape without changing values.
    pub fn to_signature(&self) -> Signature {
        Signature {
            r8: self.r8.as_tuple(),
            s: self.s.as_biguint().clone(),
        }
    }
}

/// An owned scalar-native signing key. Its public point is derived directly from
/// the scalar; seed hashing, pruning, and clamping are never invoked.
pub struct ScalarSigningKey {
    secret: BabyJubSecretScalar,
    public: BabyJubPoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScalarSignatureError {
    InvalidKey(BabyJubError),
    /// Seed-backed key material that is not exactly 32 bytes of unprefixed hex.
    InvalidSeedKey(HexDecodeError),
    NonceCounterExhausted,
    InternalVerificationFailed,
}

impl fmt::Display for ScalarSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(e) => write!(f, "invalid scalar signing key: {e}"),
            Self::InvalidSeedKey(e) => write!(f, "invalid seed-backed signing key: {e}"),
            Self::NonceCounterExhausted => f.write_str("deterministic nonce counter exhausted"),
            Self::InternalVerificationFailed => {
                f.write_str("scalar signature failed internal verification")
            }
        }
    }
}

impl std::error::Error for ScalarSignatureError {}

impl From<BabyJubError> for ScalarSignatureError {
    fn from(value: BabyJubError) -> Self {
        Self::InvalidKey(value)
    }
}

impl From<HexDecodeError> for ScalarSignatureError {
    fn from(value: HexDecodeError) -> Self {
        Self::InvalidSeedKey(value)
    }
}

impl ScalarSigningKey {
    pub fn from_secret(secret: BabyJubSecretScalar) -> Self {
        let public = public_key_from_scalar(&secret);
        Self { secret, public }
    }

    pub fn from_decimal(value: &str) -> Result<Self, ScalarSignatureError> {
        Ok(Self::from_secret(BabyJubSecretScalar::try_from_dec(value)?))
    }

    pub fn from_le_bytes(bytes: [u8; 32]) -> Result<Self, ScalarSignatureError> {
        Ok(Self::from_secret(BabyJubSecretScalar::try_from_le_bytes(
            bytes,
        )?))
    }

    #[inline]
    pub fn verifying_key(&self) -> &BabyJubPoint {
        &self.public
    }

    pub fn sign_curvy_v1(&self, message: Bn254Fr) -> Result<ScalarSignature, ScalarSignatureError> {
        sign_scalar_compat(message, &self.secret, &self.public)
    }
}

/// `pruneBuffer`: clear the low 3 bits and force the top two bits of a 32-byte
/// little-endian scalar buffer (BabyJubjub key clamping).
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

/// `deriveSecretScalar`: `(LE(pruned) >> 3) mod l`.
pub fn derive_secret_scalar(private_key: &[u8]) -> BigUint {
    let pruned = pruned_scalar_buffer(private_key);
    (le_bytes_to_biguint(&pruned) >> 3u32) % &*SUB_ORDER
}

/// `derivePublicKey`: `deriveSecretScalar(pk) * Base8`.
pub fn derive_public_key(private_key: &[u8]) -> Point {
    mul_point_escalar(*BASE8, &derive_secret_scalar(private_key))
}

/// `pubFromPrivateKey`: public key from exactly 32 bytes of unprefixed hex.
pub fn pub_from_private_key_hex(hex: &str) -> Result<Point, HexDecodeError> {
    Ok(derive_public_key(&from_hex_exact::<32>(hex)?))
}

/// `ephemeralPubKey`: `R = scalar * Base8`.
pub fn ephemeral_pub_key(scalar: &BigUint) -> Point {
    mul_point_escalar(*BASE8, scalar)
}

/// Signs a raw 256-bit integer with zk-kit EdDSA-Poseidon semantics.
///
/// Non-reduced messages affect nonce derivation; Poseidon reduces the challenge
/// input. Panics when `message >= 2^256`.
pub fn sign(message: &BigUint, private_key: &[u8]) -> Signature {
    let hash = blake512(private_key);

    let mut h32 = [0u8; 32];
    h32.copy_from_slice(&hash[0..32]);
    let s = le_bytes_to_biguint(&prune_buffer(h32)); // zk-kit uses the unshifted scalar.
    let a = mul_point_escalar(*BASE8, &(&s >> 3u32));

    // Derive r from the unreduced message bytes.
    let msg_buff = biguint_to_le_bytes(message, 32);
    let mut compose = Vec::with_capacity(64);
    compose.extend_from_slice(&hash[32..64]);
    compose.extend_from_slice(&msg_buff);
    let r = le_bytes_to_biguint(&blake512(&compose)) % &*SUB_ORDER;

    let r8 = mul_point_escalar(*BASE8, &r);
    let hm = poseidon(&[r8.0, r8.1, a.0, a.1, fr_from_biguint(message)]);

    // Use the unshifted scalar to match zk-kit.
    let s_sig = (r + fr_to_biguint(&hm) * s) % &*SUB_ORDER;

    Signature { r8, s: s_sig }
}

/// Signs with exactly 32 bytes of unprefixed private-key hex.
pub fn sign_hex(message: &BigUint, hex: &str) -> Result<Signature, HexDecodeError> {
    Ok(sign(message, &from_hex_exact::<32>(hex)?))
}

fn deterministic_scalar_nonce(
    secret: &BabyJubSecretScalar,
    public: &BabyJubPoint,
    message: Bn254Fr,
) -> Result<BabyJubSecretScalar, ScalarSignatureError> {
    let key = secret.to_le_32();
    let ax = Bn254Fr::from_fr(public.x()).to_le_32();
    let ay = Bn254Fr::from_fr(public.y()).to_le_32();
    let msg = message.to_le_32();

    for counter in 0..=u32::MAX {
        let mut mac = HmacSha512::new_from_slice(&key).expect("HMAC accepts a 32-byte key");
        mac.update(SCALAR_NONCE_LABEL);
        mac.update(&ax);
        mac.update(&ay);
        mac.update(&msg);
        mac.update(&counter.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let candidate = BigUint::from_bytes_le(&digest);
        if candidate >= *NONCE_REJECTION_LIMIT {
            continue;
        }
        let reduced = candidate % &*SUB_ORDER;
        if reduced != BigUint::from(0u8) {
            return Ok(BabyJubSecretScalar::try_from_biguint(reduced)
                .expect("nonce is canonical and non-zero"));
        }
    }
    Err(ScalarSignatureError::NonceCounterExhausted)
}

/// Sign a canonical Curvy field message directly with a BabyJubJub subgroup
/// scalar. This is compatible with the deployed circomlib equation:
///
/// `S*Base8 = R8 + Poseidon(R8,A,M)*8*A`.
pub fn sign_scalar_compat(
    message: Bn254Fr,
    secret: &BabyJubSecretScalar,
    public: &BabyJubPoint,
) -> Result<ScalarSignature, ScalarSignatureError> {
    let expected_public = public_key_from_scalar(secret);
    if &expected_public != public {
        return Err(ScalarSignatureError::InternalVerificationFailed);
    }

    let nonce = deterministic_scalar_nonce(secret, public, message)?;
    let r = nonce.to_biguint();
    let r8 = public_key_from_scalar(&nonce);
    let h = poseidon(&[r8.x(), r8.y(), public.x(), public.y(), message.into_inner()]);
    let e = (BigUint::from(8u8) * fr_to_biguint(&h)) % &*SUB_ORDER;
    let response = (r + e * secret.to_biguint()) % &*SUB_ORDER;
    let signature = ScalarSignature {
        r8,
        s: BabyJubScalar::try_from_biguint(response)
            .expect("response was reduced modulo subgroup order"),
    };
    if !verify_scalar_compat(message, public, &signature) {
        return Err(ScalarSignatureError::InternalVerificationFailed);
    }
    Ok(signature)
}

/// Verify the checked scalar-native signature using the exact equation enforced
/// by Curvy's current `EdDSAPoseidonVerifier`.
pub fn verify_scalar_compat(
    message: Bn254Fr,
    public: &BabyJubPoint,
    signature: &ScalarSignature,
) -> bool {
    if public.is_identity() || signature.r8.is_identity() {
        return false;
    }
    let h = poseidon(&[
        signature.r8.x(),
        signature.r8.y(),
        public.x(),
        public.y(),
        message.into_inner(),
    ]);
    let e = (BigUint::from(8u8) * fr_to_biguint(&h)) % &*SUB_ORDER;
    let left = mul_point_escalar(*BASE8, signature.s.as_biguint());
    let right = add_point(
        signature.r8.as_tuple(),
        mul_point_escalar(public.as_tuple(), &e),
    );
    left == right
}

#[cfg(test)]
mod hex_boundary_tests {
    use super::*;

    #[test]
    fn prefixed_private_keys_fail_loudly() {
        let message = BigUint::from(1u8);
        let error = sign_hex(&message, "0xab").unwrap_err();
        assert!(error.to_string().contains("remove the leading 0x"));

        let error = pub_from_private_key_hex("0xab").unwrap_err();
        assert!(error.to_string().contains("remove the leading 0x"));
    }

    #[test]
    fn short_private_keys_are_rejected() {
        let error = sign_hex(&BigUint::from(1u8), "ab").unwrap_err();
        assert_eq!(
            error,
            HexDecodeError::WrongLength {
                expected: 32,
                actual: 1,
            }
        );
    }
}
