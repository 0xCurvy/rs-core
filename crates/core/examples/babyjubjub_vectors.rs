//! Regenerates outputs in `testdata/babyjubjub_vectors.json`.
//!
//! ```text
//! cargo run -p curvy-core --example babyjubjub_vectors \
//!   | diff crates/core/testdata/babyjubjub_vectors.json -
//! ```
//!
//! Inputs come from the committed corpus; outputs are recomputed by Rust.

use std::collections::BTreeMap;
use std::str::FromStr;

use curvy_core::babyjubjub::{BASE8, SUB_ORDER, add_point, mul_point_escalar};
use curvy_core::eddsa::{derive_public_key, derive_secret_scalar, sign_hex};
use curvy_core::encoding::from_hex_lossy;
use curvy_core::field::{FIELD_MODULUS_DEC, Fr, fr_from_dec, fr_to_dec};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    meta: Meta,
    field: String,
    sub_order: String,
    base8: [String; 2],
    add_point: Vec<AddVec>,
    mul_point_escalar: Vec<MulVec>,
    derive_secret_scalar: Vec<DssVec>,
    derive_public_key: Vec<PubVec>,
    sign_message: Vec<SignVec>,
}

#[derive(Serialize, Deserialize)]
struct Meta {
    description: String,
    reference: BTreeMap<String, String>,
    validation: BTreeMap<String, String>,
    regenerate: String,
}

#[derive(Serialize, Deserialize)]
struct AddVec {
    p1: [String; 2],
    p2: [String; 2],
    sum: [String; 2],
}

#[derive(Serialize, Deserialize)]
struct MulVec {
    scalar: String,
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DssVec {
    private_key_hex: String,
    scalar: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PubVec {
    private_key_hex: String,
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize)]
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

fn big(s: &str) -> BigUint {
    BigUint::from_str(s).expect("decimal biguint")
}

fn point(xy: &[String; 2]) -> (Fr, Fr) {
    (fr_from_dec(&xy[0]), fr_from_dec(&xy[1]))
}

fn coords((x, y): (Fr, Fr)) -> [String; 2] {
    [fr_to_dec(&x), fr_to_dec(&y)]
}

fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/babyjubjub_vectors.json"
    );
    let raw = std::fs::read_to_string(path).expect("read babyjubjub_vectors.json");
    let mut v: Vectors = serde_json::from_str(&raw).expect("parse babyjubjub_vectors.json");

    v.field = FIELD_MODULUS_DEC.to_string();
    v.sub_order = SUB_ORDER.to_string();
    v.base8 = coords(*BASE8);

    for a in &mut v.add_point {
        a.sum = coords(add_point(point(&a.p1), point(&a.p2)));
    }
    for m in &mut v.mul_point_escalar {
        let (x, y) = mul_point_escalar(*BASE8, &big(&m.scalar));
        m.x = fr_to_dec(&x);
        m.y = fr_to_dec(&y);
    }
    for d in &mut v.derive_secret_scalar {
        d.scalar = derive_secret_scalar(&from_hex_lossy(&d.private_key_hex)).to_string();
    }
    for p in &mut v.derive_public_key {
        let (x, y) = derive_public_key(&from_hex_lossy(&p.private_key_hex));
        p.x = fr_to_dec(&x);
        p.y = fr_to_dec(&y);
    }
    for s in &mut v.sign_message {
        let sig = sign_hex(&big(&s.message), &s.private_key_hex).expect("well-formed key hex");
        s.r8x = fr_to_dec(&sig.r8.0);
        s.r8y = fr_to_dec(&sig.r8.1);
        s.s = sig.s.to_string();
    }

    println!(
        "{}",
        serde_json::to_string_pretty(&v).expect("serialize vectors")
    );
}
