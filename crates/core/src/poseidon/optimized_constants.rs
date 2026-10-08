//! Folded constants and sparse matrices for the optimized Poseidon schedule.
//! Regenerate with:
//! `cargo run --release -p curvy-benchmarks --bin generate_poseidon_optimized`.
//!
//! A shared index validates framing and dimensions for all arities. Each arity
//! authenticates its four tables before decoding them into the field backend,
//! then caches the decoded parameters. The tables are compiled into the binary.

use std::sync::{LazyLock, OnceLock};

use ark_ff::{BigInt, PrimeField};
use sha2::{Digest, Sha256};

use super::Element;
use crate::{field::Fr, secret_field::Element as SecretField};

const CONSTANTS: &[u8] = include_bytes!("../../testdata/poseidon_constants_optimized.bin");
const FIELD_BYTES: usize = 32;
const DIGEST_BYTES: usize = 32;
const TABLES_PER_ARITY: usize = 4;
const MAX_ARITY: usize = 16;
const SOURCE_DIGEST: [u8; 32] = [
    0x60, 0x23, 0x96, 0x53, 0x6f, 0x13, 0x20, 0x9e, 0x9b, 0xdc, 0x4d, 0xd0, 0x26, 0xfc, 0x08, 0xe5,
    0x20, 0x62, 0x9c, 0xc2, 0x8d, 0x0a, 0x06, 0x3e, 0x3d, 0x4a, 0x5f, 0x02, 0x2d, 0x9a, 0x09, 0x02,
];

pub struct Params<T> {
    pub t: usize,
    pub n_rounds_p: usize,
    pub c: Vec<T>,
    pub m: Vec<Vec<T>>,
    pub p: Vec<Vec<T>>,
    pub s: Vec<T>,
}

/// One arity's validated framing: where its four tables live in `CONSTANTS`
/// and what each must hash to. Borrowing the encoded bytes keeps this index
/// allocation-free.
struct Block {
    t: usize,
    n_rounds_p: usize,
    digests: [&'static [u8]; TABLES_PER_ARITY],
    tables: [&'static [u8]; TABLES_PER_ARITY],
}

/// Table framing for every arity, validated once. Walking the 16 block headers
/// only reads dimensions and slices the payloads, so this stays cheap enough to
/// keep every structural check eager.
static INDEX: LazyLock<[Block; MAX_ARITY]> = LazyLock::new(|| {
    let mut reader = TableReader::new(CONSTANTS);
    assert_eq!(reader.take(4), b"CPOS", "optimized constants magic");
    assert_eq!(reader.u32(), 1, "optimized constants format version");
    assert_eq!(reader.u32() as usize, super::N_ROUNDS_F);
    assert_eq!(
        reader.u32() as usize,
        MAX_ARITY,
        "optimized constants arity count"
    );
    assert_eq!(
        reader.take(DIGEST_BYTES),
        SOURCE_DIGEST,
        "optimized tables were not generated from the committed canonical constants",
    );

    let index = std::array::from_fn::<_, MAX_ARITY, _>(|position| {
        let arity = reader.u32() as usize;
        let t = reader.u32() as usize;
        let n_rounds_p = reader.u32() as usize;
        let lengths = std::array::from_fn::<_, TABLES_PER_ARITY, _>(|_| reader.u32() as usize);
        let digests = std::array::from_fn::<_, TABLES_PER_ARITY, _>(|_| reader.take(DIGEST_BYTES));
        let tables = std::array::from_fn::<_, TABLES_PER_ARITY, _>(|table| {
            reader.take(
                lengths[table]
                    .checked_mul(FIELD_BYTES)
                    .expect("optimized table byte length overflow"),
            )
        });

        // Blocks are addressed by position rather than by the recorded arity,
        // so pin the two together. The generator emits ascending arities.
        assert_eq!(
            arity,
            position + 1,
            "optimized arities must be ordered 1..={MAX_ARITY}",
        );
        assert_eq!(t, arity + 1);
        assert_eq!(lengths[0], super::N_ROUNDS_F * t + n_rounds_p);
        assert_eq!(lengths[1], t * t);
        assert_eq!(lengths[2], t * t);
        assert_eq!(lengths[3], n_rounds_p * (2 * t - 1));

        Block {
            t,
            n_rounds_p,
            digests,
            tables,
        }
    });
    assert!(
        reader.remaining().is_empty(),
        "trailing optimized table data"
    );
    index
});

/// Per-arity decoded parameters, populated on the first hash at that arity.
static DECODED: [OnceLock<Params<SecretField>>; MAX_ARITY] = [const { OnceLock::new() }; MAX_ARITY];

pub fn params(arity: usize) -> &'static Params<SecretField> {
    let index = arity
        .checked_sub(1)
        .filter(|index| *index < MAX_ARITY)
        .unwrap_or_else(|| panic!("no optimized Poseidon parameters for arity {arity}"));
    DECODED[index].get_or_init(|| decode(&INDEX[index]))
}

#[cfg(feature = "leakage")]
static PUBLIC_DECODED: [OnceLock<Params<Fr>>; MAX_ARITY] = [const { OnceLock::new() }; MAX_ARITY];

#[cfg(feature = "leakage")]
pub fn public_params(arity: usize) -> &'static Params<Fr> {
    assert!((1..=MAX_ARITY).contains(&arity));
    PUBLIC_DECODED[arity - 1].get_or_init(|| decode(&INDEX[arity - 1]))
}

/// Authenticate and decode one arity's tables. Dimensions were already checked
/// when the block was indexed, so this only has to bind the bytes to their
/// digests before converting them.
fn decode<T: Element>(block: &Block) -> Params<T> {
    let tables = std::array::from_fn::<_, TABLES_PER_ARITY, _>(|table| {
        let encoded = block.tables[table];
        assert_eq!(
            Sha256::digest(encoded).as_slice(),
            block.digests[table],
            "optimized Poseidon table digest mismatch",
        );
        decode_fields(encoded)
    });
    let [c, m_flat, p_flat, s] = tables;

    Params {
        t: block.t,
        n_rounds_p: block.n_rounds_p,
        c,
        m: rows(m_flat, block.t),
        p: rows(p_flat, block.t),
        s,
    }
}

/// Decode canonically. A table value at or above the modulus means a corrupt
/// artifact, not something to silently reduce, so reject it rather than let
/// `from_le_bytes_mod_order` fold it into range. Skipping that reduction also
/// makes decoding cheaper, which is the bulk of per-arity load cost.
fn decode_fields<T: Element>(encoded: &[u8]) -> Vec<T> {
    encoded
        .chunks_exact(FIELD_BYTES)
        .map(|value| {
            let mut limbs = [0_u64; FIELD_BYTES / size_of::<u64>()];
            for (limb, encoded_limb) in limbs.iter_mut().zip(value.chunks_exact(size_of::<u64>())) {
                *limb = u64::from_le_bytes(encoded_limb.try_into().expect("64-bit limb"));
            }
            T::from_ark(
                Fr::from_bigint(BigInt::new(limbs))
                    .expect("optimized table value must be canonical"),
            )
        })
        .collect()
}

fn rows<T: Copy>(values: Vec<T>, width: usize) -> Vec<Vec<T>> {
    values.chunks_exact(width).map(<[T]>::to_vec).collect()
}

struct TableReader<'a> {
    remaining: &'a [u8],
}

impl<'a> TableReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(
            self.take(size_of::<u32>())
                .try_into()
                .expect("u32 table field"),
        )
    }

    fn take(&mut self, length: usize) -> &'a [u8] {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .expect("truncated optimized Poseidon tables");
        self.remaining = remaining;
        value
    }

    fn remaining(&self) -> &[u8] {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_ARITY, params};

    /// Deferred decoding means an arity nobody hashes at never has its table
    /// digests checked. Touch every arity so the committed artifact stays fully
    /// authenticated under `cargo test`.
    #[test]
    fn every_arity_decodes_and_matches_its_digests() {
        for arity in 1..=MAX_ARITY {
            let params = params(arity);
            assert_eq!(params.t, arity + 1);
            assert_eq!(
                params.c.len(),
                crate::poseidon::N_ROUNDS_F * params.t + params.n_rounds_p,
            );
            assert_eq!(params.m.len(), params.t);
            assert_eq!(params.p.len(), params.t);
            assert!(params.m.iter().all(|row| row.len() == params.t));
            assert!(params.p.iter().all(|row| row.len() == params.t));
            assert_eq!(params.s.len(), params.n_rounds_p * (2 * params.t - 1));
        }
    }

    #[test]
    #[should_panic(expected = "no optimized Poseidon parameters for arity 0")]
    fn arity_zero_is_rejected() {
        params(0);
    }

    #[test]
    #[should_panic(expected = "no optimized Poseidon parameters for arity 17")]
    fn arity_above_the_maximum_is_rejected() {
        params(MAX_ARITY + 1);
    }
}
