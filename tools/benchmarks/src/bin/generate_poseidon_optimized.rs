//! Regenerate the optimized Poseidon tables from curvy-core's canonical C/M
//! parameters. The output is deterministic; pass `--check` to make drift a
//! failing CI check instead of rewriting the committed artifact.
//! The algebraic construction follows the Poseidon efficient-implementation
//! appendix and was cross-checked against circomlibjs commit
//! `48b3ab37013c5ed21e9ff8a80a5b010795c97094` for every arity.

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use curvy_core::field::fr_from_dec;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const INPUT: &str = include_str!("../../../../crates/core/testdata/poseidon_constants.json");
const DEFAULT_OUTPUT: &str = "crates/core/testdata/poseidon_constants_optimized.bin";

#[derive(Deserialize)]
struct SourceFile {
    field: String,
    #[serde(rename = "nRoundsF")]
    n_rounds_f: usize,
    arities: BTreeMap<String, SourceArity>,
}

#[derive(Deserialize)]
struct SourceArity {
    t: usize,
    #[serde(rename = "nRoundsP")]
    n_rounds_p: usize,
    #[serde(rename = "C")]
    c: Vec<String>,
    #[serde(rename = "M")]
    m: Vec<Vec<String>>,
}

struct OptimizedArity {
    t: usize,
    n_rounds_p: usize,
    c: Vec<Fr>,
    m: Vec<Vec<Fr>>,
    p: Vec<Vec<Fr>>,
    s: Vec<Fr>,
}

fn main() {
    let mut check = false;
    let mut output = PathBuf::from(DEFAULT_OUTPUT);
    for argument in env::args().skip(1) {
        if argument == "--check" {
            check = true;
        } else {
            output = PathBuf::from(argument);
        }
    }

    let source: SourceFile = serde_json::from_str(INPUT).expect("canonical constants must parse");
    assert_eq!(source.n_rounds_f, 8, "generator is specified for R_F=8");
    assert_eq!(
        source.field,
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    );
    let mut arities = source
        .arities
        .into_iter()
        .map(|(arity, source)| {
            (
                arity.parse::<usize>().expect("arity key must be numeric"),
                optimize(source),
            )
        })
        .collect::<Vec<_>>();
    arities.sort_by_key(|(arity, _)| *arity);
    let encoded = encode_tables(&arities);

    if check {
        let committed = fs::read(&output).expect("committed optimized constants must exist");
        assert_eq!(committed, encoded, "optimized Poseidon tables are stale");
    } else {
        fs::write(&output, encoded).expect("optimized constants must be writable");
    }
}

fn optimize(source: SourceArity) -> OptimizedArity {
    let t = source.t;
    let c = source
        .c
        .iter()
        .map(|value| fr_from_dec(value))
        .collect::<Vec<_>>();
    let canonical_m = source
        .m
        .iter()
        .map(|row| row.iter().map(|value| fr_from_dec(value)).collect())
        .collect::<Vec<Vec<_>>>();
    assert_eq!(c.len(), (8 + source.n_rounds_p) * t);
    assert_square(&canonical_m);

    // The optimized derivation uses row-vector states. Transposing here makes
    // `state * M` identical to curvy-core's canonical column-vector `M * state`.
    let m = transpose(&canonical_m);
    let folded_c = fold_round_constants(t, source.n_rounds_p, &c, &m);
    let (p, s) = derive_sparse_matrices(source.n_rounds_p, &m);

    OptimizedArity {
        t,
        n_rounds_p: source.n_rounds_p,
        c: folded_c,
        m,
        p,
        s,
    }
}

fn encode_tables(arities: &[(usize, OptimizedArity)]) -> Vec<u8> {
    let mut encoded = b"CPOS".to_vec();
    write_u32(&mut encoded, 1); // format version
    write_u32(&mut encoded, 8); // full rounds
    write_u32(&mut encoded, arities.len());
    encoded.extend_from_slice(&Sha256::digest(INPUT.as_bytes()));

    for (arity, params) in arities {
        assert_eq!(*arity + 1, params.t);
        let tables = [
            encode_fields(&params.c),
            encode_matrix(&params.m),
            encode_matrix(&params.p),
            encode_fields(&params.s),
        ];
        write_u32(&mut encoded, *arity);
        write_u32(&mut encoded, params.t);
        write_u32(&mut encoded, params.n_rounds_p);
        for table in &tables {
            write_u32(&mut encoded, table.len() / 32);
        }
        for table in &tables {
            encoded.extend_from_slice(&Sha256::digest(table));
        }
        for table in tables {
            encoded.extend_from_slice(&table);
        }
    }
    encoded
}

fn encode_fields(values: &[Fr]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(values.len() * 32);
    for value in values {
        let bytes = value.into_bigint().to_bytes_le();
        assert_eq!(bytes.len(), 32);
        encoded.extend_from_slice(&bytes);
    }
    encoded
}

fn encode_matrix(matrix: &[Vec<Fr>]) -> Vec<u8> {
    encode_fields(&matrix.iter().flatten().copied().collect::<Vec<_>>())
}

fn write_u32(encoded: &mut Vec<u8>, value: usize) {
    encoded.extend_from_slice(
        &u32::try_from(value)
            .expect("optimized table dimension must fit u32")
            .to_le_bytes(),
    );
}

fn fold_round_constants(t: usize, partial_rounds: usize, c: &[Fr], m: &[Vec<Fr>]) -> Vec<Fr> {
    const HALF_FULL: usize = 4;
    let inverse = inverse(m);
    let mut folded = c[..t].to_vec();

    for round in 0..HALF_FULL - 1 {
        folded.extend(row_vector_times_matrix(
            &c[(round + 1) * t..(round + 2) * t],
            &inverse,
        ));
    }

    let mut accumulator = c[(HALF_FULL + partial_rounds) * t..][..t].to_vec();
    let mut partial_constants = Vec::with_capacity(partial_rounds);
    for round in (HALF_FULL..HALF_FULL + partial_rounds).rev() {
        let mut moved = row_vector_times_matrix(&accumulator, &inverse);
        partial_constants.push(moved[0]);
        moved[0] = Fr::zero();
        for column in 0..t {
            accumulator[column] = moved[column] + c[round * t + column];
        }
    }
    folded.extend(row_vector_times_matrix(&accumulator, &inverse));
    folded.extend(partial_constants.into_iter().rev());

    for round in HALF_FULL + partial_rounds..8 + partial_rounds - 1 {
        folded.extend(row_vector_times_matrix(
            &c[(round + 1) * t..(round + 2) * t],
            &inverse,
        ));
    }
    assert_eq!(folded.len(), 8 * t + partial_rounds);
    folded
}

fn derive_sparse_matrices(partial_rounds: usize, m: &[Vec<Fr>]) -> (Vec<Vec<Fr>>, Vec<Fr>) {
    let mut dense = m.to_vec();
    let mut sparse_rounds = Vec::with_capacity(partial_rounds);
    for _ in 0..partial_rounds {
        let (factor, sparse) = factor_sparse(&dense);
        sparse_rounds.push(sparse);
        dense = matrix_product(m, &factor);
    }
    let sparse = sparse_rounds.into_iter().rev().flatten().collect();
    (dense, sparse)
}

fn factor_sparse(matrix: &[Vec<Fr>]) -> (Vec<Vec<Fr>>, Vec<Fr>) {
    let t = matrix.len();
    let lower_right = (1..t)
        .map(|row| (1..t).map(|column| matrix[row][column]).collect())
        .collect::<Vec<Vec<_>>>();
    let first_column = (1..t).map(|row| matrix[row][0]).collect::<Vec<_>>();
    let adjusted_column = matrix_times_vector(&inverse(&lower_right), &first_column);

    let mut factor = vec![vec![Fr::zero(); t]; t];
    factor[0][0] = Fr::one();
    for row in 1..t {
        for column in 1..t {
            factor[row][column] = matrix[row][column];
        }
    }

    let mut sparse = Vec::with_capacity(2 * t - 1);
    sparse.push(matrix[0][0]);
    sparse.extend(adjusted_column);
    sparse.extend_from_slice(&matrix[0][1..]);
    (factor, sparse)
}

fn inverse(matrix: &[Vec<Fr>]) -> Vec<Vec<Fr>> {
    assert_square(matrix);
    let n = matrix.len();
    let mut augmented = vec![vec![Fr::zero(); 2 * n]; n];
    for row in 0..n {
        augmented[row][..n].copy_from_slice(&matrix[row]);
        augmented[row][n + row] = Fr::one();
    }

    for column in 0..n {
        let pivot = (column..n)
            .find(|&row| !augmented[row][column].is_zero())
            .expect("Poseidon matrix must be invertible");
        augmented.swap(column, pivot);
        let scale = augmented[column][column]
            .inverse()
            .expect("nonzero pivot must be invertible");
        for value in &mut augmented[column] {
            *value *= scale;
        }
        let pivot_row = augmented[column].clone();
        for (row, values) in augmented.iter_mut().enumerate() {
            if row == column {
                continue;
            }
            let factor = values[column];
            for index in 0..2 * n {
                values[index] -= factor * pivot_row[index];
            }
        }
    }
    augmented.into_iter().map(|row| row[n..].to_vec()).collect()
}

fn transpose(matrix: &[Vec<Fr>]) -> Vec<Vec<Fr>> {
    assert_square(matrix);
    (0..matrix.len())
        .map(|row| {
            (0..matrix.len())
                .map(|column| matrix[column][row])
                .collect()
        })
        .collect()
}

fn row_vector_times_matrix(vector: &[Fr], matrix: &[Vec<Fr>]) -> Vec<Fr> {
    (0..vector.len())
        .map(|column| {
            vector
                .iter()
                .enumerate()
                .fold(Fr::zero(), |sum, (row, value)| {
                    sum + *value * matrix[row][column]
                })
        })
        .collect()
}

fn matrix_times_vector(matrix: &[Vec<Fr>], vector: &[Fr]) -> Vec<Fr> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(vector)
                .fold(Fr::zero(), |sum, (a, b)| sum + *a * b)
        })
        .collect()
}

fn matrix_product(left: &[Vec<Fr>], right: &[Vec<Fr>]) -> Vec<Vec<Fr>> {
    (0..left.len())
        .map(|row| {
            (0..left.len())
                .map(|column| {
                    (0..left.len()).fold(Fr::zero(), |sum, inner| {
                        sum + left[row][inner] * right[inner][column]
                    })
                })
                .collect()
        })
        .collect()
}

fn assert_square(matrix: &[Vec<Fr>]) {
    assert!(!matrix.is_empty());
    assert!(matrix.iter().all(|row| row.len() == matrix.len()));
}
