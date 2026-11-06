//! Square roots for point decompression, on arkworks' `Fq` and `Fq2` arithmetic.
//!
//! Recovering `y` from `x` is the whole cost of loading a compact zkey, and
//! arkworks computes these roots generically. Two things about BN254 make them
//! cheaper here, without a second field implementation - every operation below
//! is arkworks' own multiplication and squaring:
//!
//! - `p = 3 mod 4`, so a root in `Fq` is one exponentiation by a fixed 252-bit
//!   exponent. arkworks uses square-and-multiply: 252 squarings and 108
//!   multiplications. A sliding window over the fixed exponent needs the same
//!   squarings but about 56 multiplications, table included.
//! - `Fq2 = Fq[u] / (u^2 + 1)`. arkworks' complex method takes three
//!   exponentiations - the root of the norm, a Legendre symbol and a second
//!   root - plus an inversion. One power `t^((p-3)/4)` yields both `sqrt(t)`
//!   and `1/sqrt(t)` when `t` is a square, and the root of the other candidate
//!   when it is not, so two exponentiations and no inversion suffice.
//!
//! These are variable time. They only ever see public proving-key coordinates.

use std::sync::LazyLock;

use ark_bn254::{Fq, Fq2};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField, Zero};

/// Window width of the exponentiation. 4 and 5 differ by two multiplications.
const WINDOW: usize = 4;

/// `(p - 3) / 4` as a left-to-right sliding-window program: square `squarings`
/// times, then multiply by `base^(2 * power + 1)`; finish with `trailing`
/// squarings.
struct Schedule {
    steps: Vec<(u32, usize)>,
    trailing: u32,
}

static SCHEDULE: LazyLock<Schedule> = LazyLock::new(|| {
    // p = 3 mod 4, so (p - 3) / 4 is p >> 2.
    let mut exponent = Fq::MODULUS;
    exponent.div2();
    exponent.div2();
    let bits = exponent.to_bits_be();
    let bits = &bits[bits.iter().position(|bit| *bit).expect("non-zero exponent")..];

    let mut steps = Vec::new();
    let mut squarings = 0_u32;
    let mut index = 0;
    while index < bits.len() {
        if !bits[index] {
            squarings += 1;
            index += 1;
            continue;
        }
        // The longest window from here that ends in a one, so its value is odd.
        let mut end = (index + WINDOW).min(bits.len());
        while !bits[end - 1] {
            end -= 1;
        }
        let value = bits[index..end]
            .iter()
            .fold(0_usize, |value, bit| (value << 1) | usize::from(*bit));
        squarings += (end - index) as u32;
        steps.push((squarings, value >> 1));
        squarings = 0;
        index = end;
    }
    Schedule {
        steps,
        trailing: squarings,
    }
});

/// `a^((p - 3) / 4)`.
fn pow_p_minus_3_over_4(a: Fq) -> Fq {
    let mut odd_powers = [a; 1 << (WINDOW - 1)];
    let square = a.square();
    for index in 1..odd_powers.len() {
        odd_powers[index] = odd_powers[index - 1] * square;
    }
    let schedule = &*SCHEDULE;
    let (_, first) = schedule.steps[0];
    // The leading window's squarings would only square one.
    let mut result = odd_powers[first];
    for &(squarings, power) in &schedule.steps[1..] {
        for _ in 0..squarings {
            result.square_in_place();
        }
        result *= odd_powers[power];
    }
    for _ in 0..schedule.trailing {
        result.square_in_place();
    }
    result
}

/// `1/2`, so halving is one multiplication.
static HALF: LazyLock<Fq> = LazyLock::new(|| Fq::from(2_u64).inverse().expect("2 is invertible"));

/// The square root `Fq::sqrt` returns, `a^((p + 1) / 4)`, or `None` for a
/// non-residue.
pub(super) fn sqrt_fq(a: Fq) -> Option<Fq> {
    let root = a * pow_p_minus_3_over_4(a);
    (root.square() == a).then_some(root)
}

/// A square root of `a` in `Fq2`, or `None` when there is none. It may be the
/// negation of the one `Fq2::sqrt` returns; callers choose the sign.
pub(super) fn sqrt_fq2(a: Fq2) -> Option<Fq2> {
    if a.c1.is_zero() {
        // A root of a base-field element is c0 + 0u or 0 + c1 u; u^2 = -1.
        return match sqrt_fq(a.c0) {
            Some(root) => Some(Fq2::new(root, Fq::ZERO)),
            None => sqrt_fq(-a.c0).map(|root| Fq2::new(Fq::ZERO, root)),
        };
    }
    // x = x0 + x1 u squares to a when x0^2 = (a0 + s) / 2 for s = sqrt(N(a)),
    // or (a0 - s) / 2 - exactly one of the two is a square, since their product
    // is -a1^2 / 4 - and x1 = a1 / (2 x0).
    let norm = a.c0.square() + a.c1.square();
    let s = sqrt_fq(norm)?;
    let t = (a.c0 + s) * *HALF;
    // t is never zero here: that would need a1 = 0.
    let r = pow_p_minus_3_over_4(t);
    let tr = t * r;
    let root = if tr.square() == t {
        // r^2 = 1/t: x0 = t r and 1/x0 = r.
        Fq2::new(tr, a.c1 * r * *HALF)
    } else {
        // r^2 = -1/t: the other candidate is -a1^2 / 4t, whose root is a1 r / 2,
        // and x1 = a1 / (2 x0) = 1/r = -t r.
        Fq2::new(a.c1 * r * *HALF, -tr)
    };
    (root.square() == a).then_some(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;

    #[test]
    fn the_window_program_is_the_exponent() {
        let mut rng = ark_std::test_rng();
        let mut exponent = Fq::MODULUS;
        exponent.div2();
        exponent.div2();
        for _ in 0..200 {
            let a = Fq::rand(&mut rng);
            assert_eq!(pow_p_minus_3_over_4(a), a.pow(exponent));
        }
    }

    #[test]
    fn fq_roots_are_arkworks_roots() {
        let mut rng = ark_std::test_rng();
        let mut residues = 0;
        for _ in 0..2_000 {
            let a = Fq::rand(&mut rng);
            let root = sqrt_fq(a);
            assert_eq!(root, a.sqrt());
            residues += usize::from(root.is_some());
        }
        // Half of all elements are squares; both branches must be exercised.
        assert!((800..1_200).contains(&residues), "{residues}");
        assert_eq!(sqrt_fq(Fq::ZERO), Some(Fq::ZERO));
    }

    #[test]
    fn fq2_roots_exist_exactly_when_arkworks_finds_one() {
        let mut rng = ark_std::test_rng();
        let mut checked = 0;
        let mut cases = vec![Fq2::ZERO, Fq2::ONE, -Fq2::ONE];
        for _ in 0..2_000 {
            cases.push(Fq2::rand(&mut rng));
        }
        for _ in 0..200 {
            // c1 = 0 and c0 = 0 take their own branches.
            cases.push(Fq2::new(Fq::rand(&mut rng), Fq::ZERO));
            cases.push(Fq2::new(Fq::ZERO, Fq::rand(&mut rng)));
        }
        for a in cases {
            let root = sqrt_fq2(a);
            assert_eq!(root.is_some(), a.sqrt().is_some(), "{a}");
            if let Some(root) = root {
                assert_eq!(root.square(), a);
                checked += 1;
            }
        }
        assert!(checked > 1_000, "{checked}");
    }
}
