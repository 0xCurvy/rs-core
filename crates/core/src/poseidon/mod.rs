//! Poseidon hash over BN254 Fr - a faithful port of `poseidon-lite@0.2.1`
//! (the canonical HadesHash from the Poseidon whitepaper, as used by circomlib).
//! The default `poseidon-optimized` feature uses algebraically folded constants
//! and sparse partial-round matrices. Disabling default features selects the
//! direct schedule; both use identical state initialization and parameters and
//! produce bit-for-bit identical outputs. Both production schedules use
//! fixed-width field arithmetic and erase their owned state buffers.
//!
//! Reference: `node_modules/poseidon-lite/poseidon/index.js`.
//!
//! Uses (order matters), all via [`poseidon()`]:
//! - `ownerHash = poseidon([pub.x, pub.y, sharedSecret])`
//! - `id        = poseidon([ownerHash, amount, token])`
//! - `nullifier = poseidon([sharedSecret, pub.x, pub.y])`
//! - tree node  = `poseidon([left, right])`

#[cfg(any(not(feature = "poseidon-optimized"), test))]
mod constants;
#[cfg(feature = "poseidon-optimized")]
mod optimized_constants;

use crate::field::Fr;
use crate::secret_field::{self, Element as SecretField};
#[cfg(any(test, feature = "leakage"))]
use ark_ff::AdditiveGroup;
use std::ops::{Add, AddAssign, Mul};
use zeroize::{Zeroize, Zeroizing};

pub(super) trait Element:
    Copy + Zeroize + Add<Output = Self> + AddAssign + Mul<Output = Self>
{
    const ZERO: Self;
    fn from_ark(value: Fr) -> Self;
    fn into_ark(self) -> Fr;
}

impl Element for SecretField {
    const ZERO: Self = Self::ZERO;
    fn from_ark(value: Fr) -> Self {
        secret_field::from_ark(value)
    }
    fn into_ark(self) -> Fr {
        secret_field::into_ark(self)
    }
}

#[cfg(any(test, feature = "leakage"))]
impl Element for Fr {
    const ZERO: Self = <Self as AdditiveGroup>::ZERO;
    fn from_ark(value: Fr) -> Self {
        value
    }
    fn into_ark(self) -> Fr {
        self
    }
}

/// Number of full rounds (R_F) - split half before / half after the partial rounds.
const N_ROUNDS_F: usize = 8;

/// `v^5` S-box (BN254 Fr arithmetic reduces mod p automatically).
#[inline]
fn pow5<T: Element>(v: T) -> T {
    let v2 = v * v;
    v * v2 * v2
}

/// `out = M . state` over the field.
#[cfg(any(not(feature = "poseidon-optimized"), test))]
#[inline]
fn mix_into<T: Element>(state: &[T], m: &[Vec<T>], out: &mut [T]) {
    for (x, output) in out.iter_mut().enumerate() {
        let row = &m[x];
        let mut acc = T::ZERO;
        for (y, &s) in state.iter().enumerate() {
            acc += row[y] * s;
        }
        *output = acc;
    }
}

/// Poseidon hash of `1..=16` field elements. Input order is significant.
/// Field operations and state access follow a fixed schedule for each arity.
///
/// Panics on `0` or `> 16` inputs (matches `poseidon-lite`'s arity bounds).
pub fn poseidon(inputs: &[Fr]) -> Fr {
    let arity = inputs.len();
    assert!(arity >= 1, "poseidon: at least 1 input required");
    assert!(
        arity <= 16,
        "poseidon: at most 16 inputs supported, got {arity}"
    );

    #[cfg(feature = "poseidon-optimized")]
    return poseidon_optimized(inputs, optimized_constants::params(inputs.len()));
    #[cfg(not(feature = "poseidon-optimized"))]
    poseidon_reference(inputs, constants::params(inputs.len()))
}

#[cfg(any(not(feature = "poseidon-optimized"), test))]
fn poseidon_reference<T: Element>(inputs: &[Fr], p: &constants::Params<T>) -> Fr {
    let t = p.t; // == arity + 1
    let n_rounds_p = p.n_rounds_p;

    let mut state_storage = Zeroizing::new([T::ZERO; 17]);
    let mut mixed_storage = Zeroizing::new([T::ZERO; 17]);
    for (state, input) in state_storage[1..t].iter_mut().zip(inputs) {
        *state = T::from_ark(*input);
    }
    let mut state = &mut state_storage[..t];
    let mut mixed = &mut mixed_storage[..t];

    for x in 0..(N_ROUNDS_F + n_rounds_p) {
        // Full rounds: the first and last N_ROUNDS_F/2; partial rounds in between.
        let is_full = x < N_ROUNDS_F / 2 || x >= N_ROUNDS_F / 2 + n_rounds_p;
        let base = x * t; // state.len() == t
        for (y, sy) in state.iter_mut().enumerate() {
            *sy += p.c[base + y];
            if is_full || y == 0 {
                *sy = pow5(*sy);
            }
        }
        mix_into(state, &p.m, mixed);
        std::mem::swap(&mut state, &mut mixed);
    }

    state[0].into_ark()
}

#[cfg(feature = "poseidon-optimized")]
fn poseidon_optimized<T: Element>(inputs: &[Fr], p: &optimized_constants::Params<T>) -> Fr {
    let t = p.t;
    let mut state_storage = Zeroizing::new([T::ZERO; 17]);
    let mut mixed_storage = Zeroizing::new([T::ZERO; 17]);
    for (state, input) in state_storage[1..t].iter_mut().zip(inputs) {
        *state = T::from_ark(*input);
    }
    let mut state = &mut state_storage[..t];
    let mut mixed = &mut mixed_storage[..t];

    for (value, constant) in state.iter_mut().zip(&p.c[..t]) {
        *value += *constant;
    }

    // Three leading full rounds retain the ordinary dense MDS matrix.
    for round in 0..N_ROUNDS_F / 2 - 1 {
        state.iter_mut().for_each(|value| *value = pow5(*value));
        for (index, value) in state.iter_mut().enumerate() {
            *value += p.c[(round + 1) * t + index];
        }
        mix_row_vector_into(state, &p.m, mixed);
        std::mem::swap(&mut state, &mut mixed);
    }

    // The fourth full round transitions to the factored partial-round basis.
    state.iter_mut().for_each(|value| *value = pow5(*value));
    for (index, value) in state.iter_mut().enumerate() {
        *value += p.c[(N_ROUNDS_F / 2) * t + index];
    }
    mix_row_vector_into(state, &p.p, mixed);
    std::mem::swap(&mut state, &mut mixed);

    let partial_constants = (N_ROUNDS_F / 2 + 1) * t;
    for round in 0..p.n_rounds_p {
        state[0] = pow5(state[0]) + p.c[partial_constants + round];
        let nonlinear = state[0];
        let sparse = &p.s[round * (2 * t - 1)..(round + 1) * (2 * t - 1)];
        let new_first = state
            .iter()
            .zip(&sparse[..t])
            .fold(T::ZERO, |sum, (&value, &coefficient)| {
                sum + value * coefficient
            });
        for index in 1..t {
            state[index] += nonlinear * sparse[t + index - 1];
        }
        state[0] = new_first;
    }

    let trailing_constants = partial_constants + p.n_rounds_p;
    for round in 0..N_ROUNDS_F / 2 - 1 {
        state.iter_mut().for_each(|value| *value = pow5(*value));
        for (index, value) in state.iter_mut().enumerate() {
            *value += p.c[trailing_constants + round * t + index];
        }
        mix_row_vector_into(state, &p.m, mixed);
        std::mem::swap(&mut state, &mut mixed);
    }

    state.iter_mut().for_each(|value| *value = pow5(*value));
    mix_row_vector_into(state, &p.m, mixed);
    mixed[0].into_ark()
}

/// The generated matrices use row-vector coordinates: `out = state . M`.
#[cfg(feature = "poseidon-optimized")]
#[inline]
fn mix_row_vector_into<T: Element>(state: &[T], matrix: &[Vec<T>], out: &mut [T]) {
    for (column, output) in out.iter_mut().enumerate() {
        *output = state
            .iter()
            .enumerate()
            .fold(T::ZERO, |sum, (row, &value)| {
                sum + value * matrix[row][column]
            });
    }
}

#[cfg(all(test, feature = "poseidon-optimized"))]
mod optimized_tests {
    use ark_ff::{AdditiveGroup, PrimeField};

    use super::{Fr, constants, optimized_constants, poseidon_optimized, poseidon_reference};

    #[test]
    fn optimized_schedule_matches_reference_for_all_arities() {
        differential_cases(256);
    }

    #[test]
    #[ignore = "full release gate: 10,000 deterministic random inputs per arity"]
    fn optimized_schedule_matches_160k_reference_cases() {
        differential_cases(10_000);
    }

    fn differential_cases(random_cases: usize) {
        let mut seed = 0x243f_6a88_85a3_08d3_u64;
        for arity in 1..=16 {
            check(&vec![Fr::ZERO; arity]);
            check(&vec![Fr::from(1); arity]);
            check(&vec![-Fr::from(1); arity]);
            for basis in 0..arity {
                let mut inputs = vec![Fr::ZERO; arity];
                inputs[basis] = Fr::from(1);
                check(&inputs);
            }
            for _ in 0..random_cases {
                let inputs = (0..arity)
                    .map(|_| {
                        let mut bytes = [0_u8; 32];
                        for chunk in bytes.chunks_exact_mut(8) {
                            seed ^= seed << 13;
                            seed ^= seed >> 7;
                            seed ^= seed << 17;
                            chunk.copy_from_slice(&seed.to_le_bytes());
                        }
                        Fr::from_le_bytes_mod_order(&bytes)
                    })
                    .collect::<Vec<_>>();
                check(&inputs);
            }
        }
    }

    fn check(inputs: &[Fr]) {
        assert_eq!(
            poseidon_optimized(inputs, optimized_constants::params(inputs.len())),
            poseidon_reference(inputs, constants::public_params(inputs.len())),
            "optimized Poseidon mismatch at arity {}",
            inputs.len(),
        );
    }
}

/// Variable-time diagnostic control; unavailable in production builds.
#[cfg(feature = "leakage")]
pub(crate) fn poseidon_vartime(inputs: &[Fr]) -> Fr {
    assert!((1..=16).contains(&inputs.len()));
    #[cfg(feature = "poseidon-optimized")]
    return poseidon_optimized(inputs, optimized_constants::public_params(inputs.len()));
    #[cfg(not(feature = "poseidon-optimized"))]
    poseidon_reference(inputs, constants::public_params(inputs.len()))
}

#[cfg(test)]
mod schedule_tests {
    use super::*;
    #[test]
    fn fixed_field_schedule_matches_variable_field_reference_at_every_arity() {
        for arity in 1..=16 {
            let mut inputs = vec![Fr::from(0); arity];
            for pattern in 0..16_u64 {
                for (index, input) in inputs.iter_mut().enumerate() {
                    *input = if pattern == 0 {
                        Fr::from(0)
                    } else if pattern == 1 {
                        -Fr::from(1)
                    } else {
                        Fr::from(pattern * 173 + index as u64)
                    };
                }
                assert_eq!(
                    poseidon(&inputs),
                    poseidon_reference(&inputs, constants::public_params(arity))
                );
            }
        }
    }
}
