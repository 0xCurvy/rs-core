//! Poseidon round constants (`C`) and MDS matrices (`M`), one set per arity `1..=16`.
//!
//! These are the circomlib parameters, committed as decimal JSON so they are
//! human-auditable, compiled into the binary via `include_str!`, and parsed once
//! into field elements on first use (no runtime file I/O).

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::Deserialize;

use crate::field::{fr_from_dec, Fr};

const CONSTANTS_JSON: &str = include_str!("../../testdata/poseidon_constants.json");

#[derive(Deserialize)]
struct RawArity {
    t: usize,
    #[serde(rename = "nRoundsP")]
    n_rounds_p: usize,
    #[serde(rename = "C")]
    c: Vec<String>,
    #[serde(rename = "M")]
    m: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct RawFile {
    arities: BTreeMap<String, RawArity>,
}

/// Parsed Poseidon parameters for one arity.
pub struct Params {
    /// State width = arity + 1.
    pub t: usize,
    /// Number of partial rounds (R_P) for this width.
    pub n_rounds_p: usize,
    /// Flat round constants, length `(N_ROUNDS_F + n_rounds_p) * t`.
    pub c: Vec<Fr>,
    /// `t x t` MDS matrix.
    pub m: Vec<Vec<Fr>>,
}

static PARAMS: LazyLock<BTreeMap<usize, Params>> = LazyLock::new(|| {
    let raw: RawFile =
        serde_json::from_str(CONSTANTS_JSON).expect("poseidon_constants.json must parse");
    raw.arities
        .into_iter()
        .map(|(arity_str, a)| {
            let arity: usize = arity_str.parse().expect("arity key must be an integer");
            assert_eq!(a.t, arity + 1, "arity {arity}: t must be arity + 1");
            assert_eq!(
                a.c.len(),
                (super::N_ROUNDS_F + a.n_rounds_p) * a.t,
                "arity {arity}: unexpected C length",
            );
            assert_eq!(a.m.len(), a.t, "arity {arity}: M must be t x t");
            let c = a.c.iter().map(|s| fr_from_dec(s)).collect();
            let m = a
                .m
                .iter()
                .map(|row| {
                    assert_eq!(row.len(), a.t, "arity {arity}: M row must have t entries");
                    row.iter().map(|s| fr_from_dec(s)).collect()
                })
                .collect();
            (
                arity,
                Params {
                    t: a.t,
                    n_rounds_p: a.n_rounds_p,
                    c,
                    m,
                },
            )
        })
        .collect()
});

/// Parameters for the given arity (`1..=16`).
pub fn params(arity: usize) -> &'static Params {
    PARAMS
        .get(&arity)
        .unwrap_or_else(|| panic!("no Poseidon parameters for arity {arity}"))
}
