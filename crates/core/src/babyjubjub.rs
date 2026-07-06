//! BabyJubjub twisted Edwards curve over BN254 `Fr` (EIP-2494), matching the
//! `@zk-kit/baby-jubjub` reference. Only the two operations EdDSA needs are
//! implemented: point addition and scalar multiplication. The curve lives over the
//! same field as everything else (`Fr`), so no separate curve crate is required.
//!
//! Curve: `a·x² + y² = 1 + d·x²y²` with `a = 168700`, `d = 168696`.

use std::sync::LazyLock;

use ark_ff::{AdditiveGroup, Field};
use num_bigint::BigUint;

use crate::field::{fr_from_dec, Fr};

/// An affine BabyJubjub point `(x, y)`.
pub type Point = (Fr, Fr);

const COEFF_A_U64: u64 = 168700;
const COEFF_D_U64: u64 = 168696;

static COEFF_A: LazyLock<Fr> = LazyLock::new(|| Fr::from(COEFF_A_U64));
static COEFF_D: LazyLock<Fr> = LazyLock::new(|| Fr::from(COEFF_D_U64));

/// The BabyJubjub base point `Base8` (the prime-order subgroup generator).
pub static BASE8: LazyLock<Point> = LazyLock::new(|| {
    (
        fr_from_dec("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
        fr_from_dec("16950150798460657717958625567821834550301663161624707787222815936182638968203"),
    )
});

/// The large prime subgroup order `l` (`subOrder = order >> 3`). EdDSA scalars and
/// the signature `S` are reduced modulo this.
pub static SUB_ORDER: LazyLock<BigUint> = LazyLock::new(|| {
    BigUint::parse_bytes(
        b"2736030358979909402780800718157159386076813972158567259200215660948447373041",
        10,
    )
    .unwrap()
});

/// The neutral element `(0, 1)`.
#[inline]
pub fn identity() -> Point {
    (Fr::ZERO, Fr::ONE)
}

/// Twisted Edwards point addition:
///
/// ```text
/// x3 = (x1·y2 + y1·x2) / (1 + d·x1·x2·y1·y2)
/// y3 = (y1·y2 − a·x1·x2) / (1 − d·x1·x2·y1·y2)
/// ```
///
/// The addition law is complete on BabyJubjub, so the denominators never vanish.
pub fn add_point(p1: Point, p2: Point) -> Point {
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    let a = *COEFF_A;
    let d = *COEFF_D;

    let beta = x1 * y2;
    let gamma = y1 * x2;
    let delta = (y1 - a * x1) * (x2 + y2);
    let dtau = d * (beta * gamma);

    let x3 = (beta + gamma) * (Fr::ONE + dtau).inverse().expect("babyjubjub: x denominator nonzero");
    let y3 = (delta + a * beta - gamma) * (Fr::ONE - dtau).inverse().expect("babyjubjub: y denominator nonzero");
    (x3, y3)
}

/// Scalar multiplication `e · base` via LSB-first double-and-add.
/// `e` is consumed as a non-negative integer of any size (it need not be reduced
/// modulo the subgroup order - the result is identical either way).
pub fn mul_point_escalar(base: Point, e: &BigUint) -> Point {
    let mut res = identity();
    let mut exp = base;
    for i in 0..e.bits() {
        if e.bit(i) {
            res = add_point(res, exp);
        }
        exp = add_point(exp, exp);
    }
    res
}
