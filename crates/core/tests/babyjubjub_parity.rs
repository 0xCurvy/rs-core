//! Cross-checks BabyJubJub primitives against the committed zk-kit vectors.
//!
//! Run `cargo run -p curvy-core --example babyjubjub_vectors` to regenerate
//! outputs from the Rust implementation.

use std::str::FromStr;

use curvy_core::babyjubjub::{BASE8, SUB_ORDER, add_point, is_on_curve, mul_point_escalar};
use curvy_core::eddsa::{derive_public_key, derive_secret_scalar, ephemeral_pub_key, sign_hex};
use curvy_core::encoding::from_hex_lossy;
use curvy_core::field::{FIELD_MODULUS_DEC, Fr, fr_from_dec, fr_to_dec};
use num_bigint::BigUint;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../testdata/babyjubjub_vectors.json");

fn big(s: &str) -> BigUint {
    BigUint::from_str(s).expect("decimal biguint")
}

fn point(xy: &[String; 2]) -> (Fr, Fr) {
    (fr_from_dec(&xy[0]), fr_from_dec(&xy[1]))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    field: String,
    sub_order: String,
    base8: [String; 2],
    add_point: Vec<AddVec>,
    mul_point_escalar: Vec<MulVec>,
    derive_secret_scalar: Vec<DssVec>,
    derive_public_key: Vec<PubVec>,
    sign_message: Vec<SignVec>,
}

#[derive(Deserialize)]
struct AddVec {
    p1: [String; 2],
    p2: [String; 2],
    sum: [String; 2],
}

#[derive(Deserialize)]
struct MulVec {
    scalar: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DssVec {
    private_key_hex: String,
    scalar: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PubVec {
    private_key_hex: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignVec {
    private_key_hex: String,
    message: String,
    #[serde(rename = "R8x")]
    r8x: String,
    #[serde(rename = "R8y")]
    r8y: String,
    #[serde(rename = "S")]
    s: String,
}

fn load() -> Vectors {
    serde_json::from_str(VECTORS_JSON).expect("babyjubjub_vectors.json must parse")
}

#[test]
fn curve_constants_match() {
    let v = load();
    assert_eq!(v.field, FIELD_MODULUS_DEC, "field modulus");
    assert_eq!(v.sub_order, SUB_ORDER.to_string(), "subgroup order");
    assert_eq!(point(&v.base8), *BASE8, "Base8 generator");
}

#[test]
fn add_point_matches_zk_kit() {
    let v = load();
    assert!(!v.add_point.is_empty());
    for (i, a) in v.add_point.iter().enumerate() {
        let (p1, p2, sum) = (point(&a.p1), point(&a.p2), point(&a.sum));
        assert!(
            is_on_curve(p1) && is_on_curve(p2),
            "addPoint {i} inputs on curve"
        );
        let got = add_point(p1, p2);
        assert!(is_on_curve(got), "addPoint {i} result on curve");
        assert_eq!(got, sum, "addPoint {i}");
    }
}

#[test]
fn mul_point_escalar_matches_zk_kit() {
    let v = load();
    assert!(!v.mul_point_escalar.is_empty());
    for (i, m) in v.mul_point_escalar.iter().enumerate() {
        let scalar = big(&m.scalar);
        let expected = (fr_from_dec(&m.x), fr_from_dec(&m.y));
        assert!(
            is_on_curve(expected),
            "mulPointEscalar {i} expected on curve"
        );
        assert_eq!(
            mul_point_escalar(*BASE8, &scalar),
            expected,
            "mulPointEscalar {i} (scalar {})",
            m.scalar
        );
        // Confirm the SDK wrapper uses the same operation.
        assert_eq!(
            ephemeral_pub_key(&scalar),
            expected,
            "ephemeralPubKey {i} (scalar {})",
            m.scalar
        );
    }
}

#[test]
fn derive_secret_scalar_matches_zk_kit() {
    let v = load();
    assert!(!v.derive_secret_scalar.is_empty());
    for (i, d) in v.derive_secret_scalar.iter().enumerate() {
        let got = derive_secret_scalar(&from_hex_lossy(&d.private_key_hex));
        assert_eq!(got, big(&d.scalar), "deriveSecretScalar {i}");
    }
}

#[test]
fn derive_public_key_matches_zk_kit() {
    let v = load();
    assert!(!v.derive_public_key.is_empty());
    for (i, p) in v.derive_public_key.iter().enumerate() {
        let (x, y) = derive_public_key(&from_hex_lossy(&p.private_key_hex));
        assert_eq!(fr_to_dec(&x), p.x, "derivePublicKey {i} x");
        assert_eq!(fr_to_dec(&y), p.y, "derivePublicKey {i} y");
    }
}

#[test]
fn sign_message_matches_zk_kit() {
    let v = load();
    assert!(!v.sign_message.is_empty());
    for (i, s) in v.sign_message.iter().enumerate() {
        let sig = sign_hex(&big(&s.message), &s.private_key_hex).unwrap();
        assert_eq!(fr_to_dec(&sig.r8.0), s.r8x, "signMessage {i} R8x");
        assert_eq!(fr_to_dec(&sig.r8.1), s.r8y, "signMessage {i} R8y");
        assert_eq!(sig.s.to_string(), s.s, "signMessage {i} S");
    }
}
