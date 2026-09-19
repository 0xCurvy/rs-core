//! EdDSA-Poseidon over BabyJubJub, compatible with `@zk-kit/eddsa-poseidon`.
//!
//! Compatibility notes:
//! - Private keys use original BLAKE-512.
//! - `signMessage` uses the unshifted pruned scalar in `S`. This matches zk-kit
//!   and the deployed verifier, but differs from circomlibjs.

use crate::secret_arithmetic;
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

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
    PublicKeyMismatch,
    NonceCounterExhausted,
    InternalVerificationFailed,
    /// A witness whose note count would need a Poseidon arity outside `1..=16`.
    UnsupportedNoteCount {
        notes: usize,
        min: usize,
        max: usize,
    },
}

impl fmt::Display for ScalarSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey(e) => write!(f, "invalid scalar signing key: {e}"),
            Self::InvalidSeedKey(e) => write!(f, "invalid seed-backed signing key: {e}"),
            Self::PublicKeyMismatch => f.write_str("public key does not match the signing seed"),
            Self::NonceCounterExhausted => f.write_str("deterministic nonce counter exhausted"),
            Self::InternalVerificationFailed => {
                f.write_str("scalar signature failed internal verification")
            }
            Self::UnsupportedNoteCount { notes, min, max } => write!(
                f,
                "unsupported note count {notes}: this witness supports {min}..={max} notes \
                 because Poseidon accepts at most 16 inputs"
            ),
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
    let hash = Zeroizing::new(leakage_phase!(SeedExpansion, blake512(private_key)));
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
    let mut scalar = Zeroizing::new(pruned_scalar_buffer(private_key));
    for i in 0..31 {
        scalar[i] = (scalar[i] >> 3) | (scalar[i + 1] << 5);
    }
    scalar[31] >>= 3;
    secret_arithmetic::base_mul(&scalar)
}

/// `pubFromPrivateKey`: public key from exactly 32 bytes of unprefixed hex.
pub fn pub_from_private_key_hex(hex: &str) -> Result<Point, HexDecodeError> {
    Ok(derive_public_key(
        &Zeroizing::new(from_hex_exact::<32>(hex)?)[..],
    ))
}

/// Computes `R = scalar * Base8` for `0 <= scalar < 2^256`.
///
/// Accepts zero and values above the subgroup order.
///
/// # Panics
/// Panics when `scalar >= 2^256`.
pub fn ephemeral_pub_key(scalar: &BigUint) -> Point {
    assert!(scalar.bits() <= 256, "ephemeral scalar exceeds 256 bits");
    let mut bytes = Zeroizing::new([0_u8; 32]);
    let mut digits = scalar.iter_u64_digits();
    for chunk in bytes.chunks_exact_mut(8) {
        chunk.copy_from_slice(&digits.next().unwrap_or(0).to_le_bytes());
    }
    ephemeral_pub_key_bytes(&bytes)
}

/// Computes `R = scalar * Base8` from a raw little-endian 256-bit scalar.
pub fn ephemeral_pub_key_bytes(scalar: &[u8; 32]) -> Point {
    secret_arithmetic::base_mul(scalar)
}

/// Signs a raw 256-bit integer with zk-kit EdDSA-Poseidon semantics.
///
/// Non-reduced messages affect nonce derivation; Poseidon reduces the challenge
/// input. Panics when `message >= 2^256`.
pub fn sign(message: &BigUint, private_key: &[u8]) -> Signature {
    let hash = Zeroizing::new(leakage_phase!(SeedExpansion, blake512(private_key)));
    let mut seed_scalar = Zeroizing::new([0u8; 32]);
    seed_scalar.copy_from_slice(&hash[..32]);
    *seed_scalar = prune_buffer(*seed_scalar);
    let mut public_scalar = Zeroizing::new(*seed_scalar);
    for i in 0..31 {
        public_scalar[i] = (public_scalar[i] >> 3) | (public_scalar[i + 1] << 5);
    }
    public_scalar[31] >>= 3;
    let a = secret_arithmetic::base_mul(&public_scalar);
    let msg_buff = Zeroizing::new(biguint_to_le_bytes(message, 32));
    let mut compose = Zeroizing::new([0u8; 64]);
    compose[..32].copy_from_slice(&hash[32..]);
    compose[32..].copy_from_slice(&msg_buff);
    let nonce_hash = Zeroizing::new(leakage_phase!(NonceDerivation, blake512(&compose[..])));
    let r = Zeroizing::new(secret_arithmetic::reduce_wide(&nonce_hash));
    let r8 = secret_arithmetic::base_mul(&r);
    let hm = leakage_phase!(
        Challenge,
        poseidon(&[r8.0, r8.1, a.0, a.1, fr_from_biguint(message)])
    );
    let response = leakage_phase!(
        Response,
        secret_arithmetic::response(&r, hm, &seed_scalar, 1)
    );
    Signature {
        r8,
        s: leakage_phase!(SignatureEncoding, BigUint::from_bytes_le(&response)),
    }
}

/// Signs with exactly 32 bytes of unprefixed private-key hex.
pub fn sign_hex(message: &BigUint, hex: &str) -> Result<Signature, HexDecodeError> {
    Ok(sign(
        message,
        &Zeroizing::new(from_hex_exact::<32>(hex)?)[..],
    ))
}

fn deterministic_scalar_nonce(
    secret: &BabyJubSecretScalar,
    public: &BabyJubPoint,
    message: Bn254Fr,
) -> Result<BabyJubSecretScalar, ScalarSignatureError> {
    let key = Zeroizing::new(secret.to_le_32());
    let ax = Bn254Fr::from_fr(public.x()).to_le_32();
    let ay = Bn254Fr::from_fr(public.y()).to_le_32();
    let msg = message.to_le_32();

    for counter in 0..=u32::MAX {
        let mut mac = HmacSha512::new_from_slice(&key[..]).expect("HMAC accepts a 32-byte key");
        mac.update(SCALAR_NONCE_LABEL);
        mac.update(&ax);
        mac.update(&ay);
        mac.update(&msg);
        mac.update(&counter.to_be_bytes());
        let mut digest = mac.finalize().into_bytes();
        let mut bytes = Zeroizing::new([0u8; 64]);
        bytes.copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
        if let Some(reduced) = secret_arithmetic::nonce_candidate(&bytes) {
            return Ok(BabyJubSecretScalar::try_from_le_bytes(reduced)
                .expect("nonce is canonical and nonzero"));
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

    let nonce = leakage_phase!(
        NonceDerivation,
        deterministic_scalar_nonce(secret, public, message)
    )?;
    let r = Zeroizing::new(nonce.to_le_32());
    let r8 = public_key_from_scalar(&nonce);
    let h = leakage_phase!(
        Challenge,
        poseidon(&[r8.x(), r8.y(), public.x(), public.y(), message.into_inner()])
    );
    let key = Zeroizing::new(secret.to_le_32());
    let response = leakage_phase!(Response, secret_arithmetic::response(&r, h, &key, 8));
    let signature = ScalarSignature {
        r8,
        s: leakage_phase!(
            SignatureEncoding,
            BabyJubScalar::try_from_le_bytes(response)
                .expect("response was reduced modulo subgroup order")
        ),
    };
    if !leakage_phase!(
        PublicVerification,
        verify_scalar_compat(message, public, &signature)
    ) {
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
