//! Development-only operations for timing and secret-taint assessment.

use crate::{babyjubjub, blake512, eddsa, encoding, field, poseidon, secret_arithmetic};
use num_bigint::BigUint;
use std::hint::black_box;
use std::sync::OnceLock;

type Declassifier = fn(&mut [u8]);
static DECLASSIFIER: OnceLock<Declassifier> = OnceLock::new();

type Observer = fn(u32, bool);
static OBSERVER: OnceLock<Observer> = OnceLock::new();

#[repr(u32)]
pub enum Phase {
    PointArithmetic,
    PointEncoding,
    SeedExpansion,
    NonceDerivation,
    Challenge,
    Response,
    SignatureEncoding,
    PublicVerification,
}

pub fn set_observer(callback: Observer) {
    OBSERVER.set(callback).expect("observer already configured");
}

pub struct Measurement {
    phase: u32,
    observer: Option<Observer>,
}

pub fn phase(phase: Phase) -> Measurement {
    let phase = phase as u32;
    let observer = OBSERVER.get().copied();
    if let Some(observer) = observer {
        observer(phase, true);
    }
    Measurement { phase, observer }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        if let Some(observer) = self.observer {
            observer(self.phase, false);
        }
    }
}

pub fn set_declassifier(callback: Declassifier) {
    DECLASSIFIER
        .set(callback)
        .expect("declassifier already configured");
}

pub(crate) fn public_bytes(bytes: &mut [u8]) {
    if let Some(callback) = DECLASSIFIER.get() {
        callback(bytes);
    }
}

pub(crate) fn public_flag(flag: bool) -> bool {
    let mut byte = [u8::from(flag)];
    public_bytes(&mut byte);
    byte[0] != 0
}

pub const CASES: &[&str] = &[
    "control",
    "base_mul",
    "reduce_wide",
    "nonce_candidate",
    "response",
    "sign_seed",
    "sign_scalar",
    "blake512",
    "poseidon_secret",
    "decimal",
    "owner_hash_decimal",
    "poseidon_vartime",
];

pub fn check_poseidon_arities(input: &[u8; 32]) {
    let secret = field::fr_from_be_32_checked(input).unwrap();
    let inputs = zeroize::Zeroizing::new([secret; 16]);
    for arity in 1..=16 {
        black_box(poseidon::poseidon(&inputs[..arity]));
    }
}

/// Inputs and outputs contain synthetic test data only.
#[inline(never)]
pub fn run(case: usize, input: &[u8; 96]) -> [u8; 96] {
    let mut output = [0_u8; 96];
    let scalar: &[u8; 32] = input[..32].try_into().unwrap();
    let wide: &[u8; 64] = input[..64].try_into().unwrap();
    let point = match case {
        0 => Some(babyjubjub::mul_point_escalar(
            *babyjubjub::BASE8,
            &BigUint::from_bytes_le(scalar),
        )),
        1 => Some(secret_arithmetic::base_mul(scalar)),
        2 => {
            output[..32].copy_from_slice(&secret_arithmetic::reduce_wide(wide));
            None
        }
        3 => {
            if let Some(nonce) = secret_arithmetic::nonce_candidate(wide) {
                output[..32].copy_from_slice(&nonce);
                output[32] = 1;
            }
            None
        }
        4 => {
            output[..32].copy_from_slice(&secret_arithmetic::response(
                input[32..64].try_into().unwrap(),
                field::Fr::from(42_u8),
                scalar,
                8,
            ));
            None
        }
        5 => {
            let signature = eddsa::sign(&BigUint::from(42_u8), scalar);
            output[64..].copy_from_slice(&encoding::biguint_to_le_bytes(&signature.s, 32));
            Some(signature.r8)
        }
        6 => {
            let key = eddsa::ScalarSigningKey::from_le_bytes(*scalar).unwrap();
            let signature = key
                .sign_curvy_v1(field::Bn254Fr::from_fr(field::Fr::from(42_u8)))
                .unwrap();
            output[64..].copy_from_slice(&signature.s.to_le_32());
            Some(signature.r8.as_tuple())
        }
        7 => {
            output[..64].copy_from_slice(&blake512::blake512(wide));
            None
        }
        8 => {
            let secret = field::fr_from_be_32_checked(scalar).unwrap();
            let hash = poseidon::poseidon(&[field::Fr::from(1_u8), field::Fr::from(2_u8), secret]);
            output[..32].copy_from_slice(&field::fr_to_be_32(&hash));
            None
        }
        9 => {
            output[..32]
                .copy_from_slice(&*encoding::try_decimal_bytes_to_le_32(&input[..78]).unwrap());
            None
        }
        10 => {
            let secret = field::try_fr_from_decimal_bytes(&input[..78]).unwrap();
            let hash =
                crate::note::owner_hash((field::Fr::from(1_u8), field::Fr::from(2_u8)), secret);
            output[..32].copy_from_slice(&field::fr_to_be_32(&hash));
            None
        }
        11 => {
            let secret = field::fr_from_be_32_checked(scalar).unwrap();
            let hash =
                poseidon::poseidon_vartime(&[field::Fr::from(1_u8), field::Fr::from(2_u8), secret]);
            output[..32].copy_from_slice(&field::fr_to_be_32(&hash));
            None
        }
        _ => panic!("unknown leakage case"),
    };
    if let Some((x, y)) = point {
        output[..32].copy_from_slice(&field::fr_to_be_32(&x));
        output[32..64].copy_from_slice(&field::fr_to_be_32(&y));
    }
    black_box(output)
}
