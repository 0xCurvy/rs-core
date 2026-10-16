//! The off-circuit side of the aggregator's calldata binding.
//!
//! The v2 aggregator takes the values a circuit used to expose as public signals as plain
//! calldata words. A bound circuit commits to those words and takes one public input, `x`, so its
//! public signals are `[commitment, y, x]`:
//!
//! - `commitment`: Poseidon calls chained over the words, 15 at a time, zero-padded, starting
//!   from the domain constant plus the word count. Computed by the circuit.
//! - `x`: `keccak256(word_0 ‖ … ‖ word_(n-1) ‖ commitment) mod r`, every value as 32 big-endian
//!   bytes. The contract derives it from the words it is sent, so it is fixed only after the
//!   words and the commitment are.
//! - `y`: the words read as polynomial coefficients and evaluated at `x`,
//!   `word_0 + word_1·x + … + word_(n-1)·x^(n-1) mod r`. Computed by both sides.
//!
//! A prover needs `commitment` and `x` before it proves; [`bind_calldata`] computes all three the
//! way the circuit and the contract do. Words are field elements, so a caller parsing untrusted
//! input must reject values at or above `r` rather than reduce them: a word and that word plus
//! `r` are the same value to the proof but not to the contract. [`bind_calldata_packed`] takes
//! words as canonical 32-byte values and does that check itself.

use std::fmt;

use ark_ff::AdditiveGroup;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

use crate::field::{
    Fr, PackedFieldsError, fr_from_be_32_packed, fr_from_be_bytes_mod, fr_to_be_32,
};
use crate::poseidon::poseidon;

/// The tag whose SHA-256, reduced modulo `r`, is the commitment's domain constant.
pub const CALLDATA_COMMITMENT_TAG: &[u8] = b"curvy.calldata.commitment.v1";

/// Words absorbed per Poseidon call; the chained state takes the sixteenth input.
pub const CALLDATA_WORDS_PER_HASH: usize = 15;

/// The most words one binding takes: more than any bound circuit binds. The
/// bindings size their input budgets from it.
pub const MAX_CALLDATA_WORDS: usize = 8192;

/// The three values that tie a proof to its words, in the order of the proof's
/// public signals, `[commitment, y, x]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CalldataBinding {
    pub commitment: Fr,
    pub y: Fr,
    pub x: Fr,
}

impl CalldataBinding {
    /// `[commitment, y, x]`, the proof's public signals.
    pub fn public_signals(&self) -> [Fr; 3] {
        [self.commitment, self.y, self.x]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CalldataError {
    /// The circuits bind at least one word.
    NoWords,
    /// More than [`MAX_CALLDATA_WORDS`] words.
    TooManyWords { count: usize },
    /// Packed words that are not canonical 32-byte field elements.
    PackedWords(PackedFieldsError),
}

impl fmt::Display for CalldataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWords => f.write_str("calldata binding needs at least one word"),
            Self::TooManyWords { count } => write!(
                f,
                "calldata binding takes at most {MAX_CALLDATA_WORDS} words; got {count}"
            ),
            Self::PackedWords(error) => write!(f, "calldata words: {error}"),
        }
    }
}

impl std::error::Error for CalldataError {}

fn check_word_count(words: &[Fr]) -> Result<(), CalldataError> {
    match words.len() {
        0 => Err(CalldataError::NoWords),
        count if count > MAX_CALLDATA_WORDS => Err(CalldataError::TooManyWords { count }),
        _ => Ok(()),
    }
}

/// `SHA-256("curvy.calldata.commitment.v1") mod r`: the circuit's `COMMITMENT_DOMAIN`.
pub fn calldata_commitment_domain() -> Fr {
    fr_from_be_bytes_mod(&Sha256::digest(CALLDATA_COMMITMENT_TAG))
}

/// The circuit's commitment to `words`.
pub fn calldata_commitment(words: &[Fr]) -> Result<Fr, CalldataError> {
    check_word_count(words)?;
    let mut state = calldata_commitment_domain() + Fr::from(words.len() as u64);
    let mut inputs = [Fr::ZERO; CALLDATA_WORDS_PER_HASH + 1];
    for chunk in words.chunks(CALLDATA_WORDS_PER_HASH) {
        inputs[0] = state;
        inputs[1..=chunk.len()].copy_from_slice(chunk);
        inputs[chunk.len() + 1..].fill(Fr::ZERO);
        state = poseidon(&inputs);
    }
    Ok(state)
}

/// The contract's challenge: `keccak256(word_0 ‖ … ‖ word_(n-1) ‖ commitment) mod r`.
pub fn calldata_challenge(words: &[Fr], commitment: &Fr) -> Result<Fr, CalldataError> {
    check_word_count(words)?;
    let mut hasher = Keccak256::new();
    for word in words {
        hasher.update(fr_to_be_32(word));
    }
    hasher.update(fr_to_be_32(commitment));
    Ok(fr_from_be_bytes_mod(&hasher.finalize()))
}

/// `words[0] + words[1]·x + … + words[n-1]·x^(n-1) mod r`, by Horner's rule.
pub fn calldata_evaluation(words: &[Fr], x: &Fr) -> Fr {
    words
        .iter()
        .rev()
        .fold(Fr::ZERO, |accumulator, word| accumulator * x + word)
}

/// Everything a prover and the contract need for one list of words.
pub fn bind_calldata(words: &[Fr]) -> Result<CalldataBinding, CalldataError> {
    let commitment = calldata_commitment(words)?;
    let x = calldata_challenge(words, &commitment)?;
    Ok(CalldataBinding {
        commitment,
        y: calldata_evaluation(words, &x),
        x,
    })
}

/// [`bind_calldata`] over words packed as canonical 32-byte big-endian values.
/// The length is checked before anything is decoded, and a word at or above `r`
/// is rejected.
pub fn bind_calldata_packed(words: &[u8]) -> Result<CalldataBinding, CalldataError> {
    if words.len() > MAX_CALLDATA_WORDS * 32 {
        return Err(CalldataError::TooManyWords {
            count: words.len().div_ceil(32),
        });
    }
    bind_calldata(&fr_from_be_32_packed(words).map_err(CalldataError::PackedWords)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fr_from_dec;

    #[test]
    fn domain_is_the_circuit_constant() {
        assert_eq!(
            calldata_commitment_domain(),
            fr_from_dec(
                "18300137031496085478185388970637918535872325576548268881419552869913137247915"
            )
        );
    }

    #[test]
    fn no_words_is_an_error() {
        assert_eq!(calldata_commitment(&[]), Err(CalldataError::NoWords));
        assert_eq!(
            calldata_challenge(&[], &Fr::ZERO),
            Err(CalldataError::NoWords)
        );
        assert_eq!(bind_calldata(&[]), Err(CalldataError::NoWords));
        assert_eq!(bind_calldata_packed(&[]), Err(CalldataError::NoWords));
    }

    #[test]
    fn more_than_the_maximum_word_count_is_an_error() {
        let words = vec![Fr::from(1u64); MAX_CALLDATA_WORDS + 1];
        let too_many = CalldataError::TooManyWords {
            count: MAX_CALLDATA_WORDS + 1,
        };
        assert_eq!(calldata_commitment(&words), Err(too_many));
        assert_eq!(calldata_challenge(&words, &Fr::ZERO), Err(too_many));
        assert_eq!(bind_calldata(&words), Err(too_many));
        assert_eq!(
            bind_calldata_packed(&vec![0; (MAX_CALLDATA_WORDS + 1) * 32]),
            Err(too_many)
        );
        assert!(bind_calldata(&words[..MAX_CALLDATA_WORDS]).is_ok());
    }

    #[test]
    fn packed_words_bind_like_field_words_and_must_be_canonical() {
        use crate::field::fr_to_be_32_packed;

        let words = [Fr::from(3u64), Fr::ZERO, -Fr::from(1u64)];
        assert_eq!(
            bind_calldata_packed(&fr_to_be_32_packed(&words)),
            bind_calldata(&words)
        );
        assert_eq!(
            bind_calldata_packed(&[0; 33]),
            Err(CalldataError::PackedWords(PackedFieldsError::Length(33)))
        );
        assert_eq!(
            bind_calldata_packed(&[0xff; 64]),
            Err(CalldataError::PackedWords(PackedFieldsError::NonCanonical(
                0
            )))
        );
    }

    #[test]
    fn public_signals_are_commitment_y_x() {
        let binding = bind_calldata(&[Fr::from(3u64), Fr::from(5u64)]).expect("words");
        assert_eq!(
            binding.public_signals(),
            [binding.commitment, binding.y, binding.x]
        );
    }

    #[test]
    fn evaluation_is_the_polynomial_at_x() {
        let words = [Fr::from(3u64), Fr::from(5u64), Fr::from(7u64)];
        let x = Fr::from(10u64);
        assert_eq!(calldata_evaluation(&words, &x), Fr::from(753u64));
    }

    #[test]
    fn commitment_absorbs_fifteen_words_per_call() {
        // Sixteen words take two calls: the second absorbs one word and fourteen zeros.
        let words: Vec<Fr> = (1..=16u64).map(Fr::from).collect();
        let first = poseidon(
            &std::iter::once(calldata_commitment_domain() + Fr::from(16u64))
                .chain(words[..15].iter().copied())
                .collect::<Vec<_>>(),
        );
        let mut second = vec![first, words[15]];
        second.resize(16, Fr::ZERO);
        assert_eq!(calldata_commitment(&words), Ok(poseidon(&second)));
    }
}
