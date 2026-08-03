//! Poseidon hash over BN254 Fr — a faithful port of `poseidon-lite@0.2.1`
//! (the canonical *unoptimized* HadesHash from the Poseidon whitepaper, as used by
//! circomlib). Same round counts, same x^5 S-box, same `[0, ...inputs]` state init,
//! same round constants (`C`) and MDS matrix (`M`) — so outputs match bit-for-bit.
//!
//! Reference: `node_modules/poseidon-lite/poseidon/index.js`.
//!
//! Uses (order matters), all via [`poseidon()`]:
//! - `ownerHash = poseidon([pub.x, pub.y, sharedSecret])`
//! - `id        = poseidon([ownerHash, amount, token])`
//! - `nullifier = poseidon([sharedSecret, pub.x, pub.y])`
//! - tree node  = `poseidon([left, right])`

mod constants;

use crate::field::Fr;
use ark_ff::AdditiveGroup;

/// Number of full rounds (R_F) — split half before / half after the partial rounds.
const N_ROUNDS_F: usize = 8;

/// `v^5` S-box (BN254 Fr arithmetic reduces mod p automatically).
#[inline]
fn pow5(v: Fr) -> Fr {
    let v2 = v * v;
    v * v2 * v2
}

/// `out = M . state` over the field.
fn mix(state: &[Fr], m: &[Vec<Fr>]) -> Vec<Fr> {
    (0..state.len())
        .map(|x| {
            let row = &m[x];
            let mut acc = Fr::ZERO;
            for (y, &s) in state.iter().enumerate() {
                acc += row[y] * s;
            }
            acc
        })
        .collect()
}

/// Poseidon hash of `1..=16` field elements. Input order is significant.
///
/// Panics on `0` or `> 16` inputs (matches `poseidon-lite`'s arity bounds).
pub fn poseidon(inputs: &[Fr]) -> Fr {
    let arity = inputs.len();
    assert!(arity >= 1, "poseidon: at least 1 input required");
    assert!(
        arity <= 16,
        "poseidon: at most 16 inputs supported, got {arity}"
    );

    let p = constants::params(arity);
    let t = p.t; // == arity + 1
    let n_rounds_p = p.n_rounds_p;

    // state = [0, ...inputs]  (index 0 is the capacity element)
    let mut state: Vec<Fr> = Vec::with_capacity(t);
    state.push(Fr::ZERO);
    state.extend_from_slice(inputs);

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
        state = mix(&state, &p.m);
    }

    state[0]
}
