//! Fixed-width BN254 field arithmetic and representation conversion.

use ark_ff::BigInt;
use crypto_bigint::{
    Limb, U256, const_monty_params,
    ctutils::{CtEq, CtLt, CtSelect},
    modular::{ConstMontyForm, ConstMontyParams},
};
use zeroize::Zeroizing;

use crate::field::Fr;

const_monty_params!(
    BaseModulus,
    U256,
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
);
pub(crate) type Element = ConstMontyForm<BaseModulus, { U256::LIMBS }>;

/// BN254 residues sum to less than `2^256`. The non-const selection retains
/// ctutils' optimization barrier around the reduction decision.
pub(crate) fn add(left: Element, right: Element) -> Element {
    let sum = Zeroizing::new(left.as_montgomery().wrapping_add(right.as_montgomery()));
    let modulus = BaseModulus::PARAMS.modulus().as_ref();
    let reduced = Zeroizing::new(sum.wrapping_sub(modulus));
    Element::from_montgomery(sum.ct_select(&reduced, !sum.ct_lt(modulus)))
}

pub(crate) fn negate(value: Element) -> Element {
    let (difference, borrow) = U256::ZERO.borrowing_sub(value.as_montgomery(), Limb::ZERO);
    let difference = Zeroizing::new(difference);
    let corrected = Zeroizing::new(difference.wrapping_add(BaseModulus::PARAMS.modulus().as_ref()));
    Element::from_montgomery(difference.ct_select(&corrected, !borrow.ct_eq(&Limb::ZERO)))
}

/// Both representations use Montgomery radix `2^256`, including wasm32.
/// Copying the residue avoids value-dependent canonicalization in arkworks.
pub(crate) fn from_ark(value: Fr) -> Element {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(value.0.0) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    Element::from_montgomery(U256::from_le_slice(&bytes[..]))
}

pub(crate) fn into_ark(value: Element) -> Fr {
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(value.as_montgomery().to_le_bytes().into());
    let mut limbs = Zeroizing::new([0_u64; 4]);
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("64-bit field limb"));
    }
    // Element maintains a reduced Montgomery residue with the same modulus/radix.
    Fr::new_unchecked(BigInt::new(*limbs))
}

pub(crate) fn from_le_bytes(bytes: &[u8; 32]) -> Option<Fr> {
    let integer = Zeroizing::new(U256::from_le_slice(bytes));
    let canonical = bool::from(integer.ct_lt(BaseModulus::PARAMS.modulus().as_ref()));
    #[cfg(feature = "leakage")]
    let canonical = crate::leakage::public_flag(canonical);
    canonical.then(|| into_ark(Element::new(&integer)))
}

pub(crate) fn to_le_bytes(value: Fr) -> [u8; 32] {
    let value = Zeroizing::new(from_ark(value));
    value.retrieve().to_le_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, BigInteger, PrimeField};

    #[test]
    fn montgomery_bridge_matches_canonical_arkworks_conversion() {
        assert_eq!(
            BaseModulus::PARAMS
                .modulus()
                .as_ref()
                .to_le_bytes()
                .as_slice(),
            Fr::MODULUS.to_bytes_le(),
        );
        let mut cases = vec![Fr::ZERO, Fr::from(1), -Fr::from(1)];
        for bit in 0..256 {
            let mut bytes = [0_u8; 32];
            bytes[bit / 8] = 1 << (bit % 8);
            cases.push(Fr::from_le_bytes_mod_order(&bytes));
        }
        for value in cases {
            let encoded = to_le_bytes(value);
            assert_eq!(encoded.as_slice(), value.into_bigint().to_bytes_le());
            assert_eq!(from_le_bytes(&encoded), Some(value));
            assert_eq!(into_ark(from_ark(value)), value);
            assert_eq!(into_ark(from_ark(value).square()), value * value);
            assert_eq!(into_ark(negate(from_ark(value))), -value);
            for other in [Fr::ZERO, Fr::from(1), -Fr::from(1), value] {
                assert_eq!(
                    into_ark(add(from_ark(value), from_ark(other))),
                    value + other
                );
            }
        }
        assert!(from_le_bytes(&[0xff; 32]).is_none());
        assert!(from_le_bytes(&Fr::MODULUS.to_bytes_le().try_into().unwrap()).is_none());
    }
}
