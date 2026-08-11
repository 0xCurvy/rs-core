//! Exact SIGNET v1/v2 parity over a deployment's postcard graph inventory.
//!
//! The input JSON is intentionally a deployment-owned manifest: large circuit
//! graphs and their private test inputs do not belong in this crate. Paths are
//! resolved relative to the manifest so the same checked-in inventory works on
//! developer machines and CI artifact jobs.

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use curvy_signet::{Envelope, FormatVersion, Graph, OperationSchema, decode_sha256, encode, hex};
use curvy_witness::{Limits, WitnessGraph};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Matrix {
    profiles: Vec<Profile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Profile {
    id: String,
    postcard: PathBuf,
    input: PathBuf,
    r1cs_sha256: String,
    #[serde(default = "patched")]
    operation_schema: String,
}

fn patched() -> String {
    "patched".to_owned()
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "v2_parity_matrix".to_owned());
    let manifest = arguments
        .next()
        .ok_or_else(|| format!("usage: {program} <parity-matrix.json>"))?;
    if arguments.next().is_some() {
        return Err(format!("usage: {program} <parity-matrix.json>").into());
    }

    let manifest = PathBuf::from(manifest);
    let manifest_bytes = fs::read(&manifest)?;
    let matrix: Matrix = serde_json::from_slice(&manifest_bytes)?;
    if matrix.profiles.is_empty() {
        return Err("parity matrix must contain at least one profile".into());
    }
    let base = manifest.parent().unwrap_or_else(|| Path::new("."));

    println!("profile\tnodes\tsignals\tv1_bytes\tv2_bytes\tassignment_sha256");
    for profile in matrix.profiles {
        let postcard_path = resolve(base, &profile.postcard);
        let input_path = resolve(base, &profile.input);
        let postcard = fs::read(&postcard_path)
            .map_err(|error| format!("{}: {error}", postcard_path.display()))?;
        let input = fs::read_to_string(&input_path)
            .map_err(|error| format!("{}: {error}", input_path.display()))?;
        let schema = OperationSchema::parse(&profile.operation_schema)?;
        let graph = Graph::from_postcard(&postcard, schema)?;
        let r1cs_sha256 = decode_sha256(&profile.r1cs_sha256)?;
        let v1 = encode(&graph, r1cs_sha256, Envelope::Signet, FormatVersion::V1)?;
        let v1_bytes = v1.len();
        let v1_assignment = evaluate(&v1, &input)?;
        drop(v1);
        let v2 = encode(&graph, r1cs_sha256, Envelope::Signet, FormatVersion::V2)?;
        let v2_bytes = v2.len();
        let v2_assignment = evaluate(&v2, &input)?;
        drop(v2);
        if v1_assignment != v2_assignment {
            let mismatch = v1_assignment
                .iter()
                .zip(&v2_assignment)
                .position(|(left, right)| left != right)
                .unwrap_or(v1_assignment.len().min(v2_assignment.len()));
            return Err(format!(
                "{}: v1/v2 assignment mismatch at signal {mismatch} ({} vs {} signals)",
                profile.id,
                v1_assignment.len(),
                v2_assignment.len()
            )
            .into());
        }
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            profile.id,
            graph.nodes.len(),
            v1_assignment.len(),
            v1_bytes,
            v2_bytes,
            assignment_digest(&v1_assignment),
        );
    }
    Ok(())
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        base.join(path)
    }
}

fn evaluate(bytes: &[u8], input: &str) -> Result<Vec<Fr>, Box<dyn Error>> {
    let digest = hex(&Sha256::digest(bytes));
    Ok(
        WitnessGraph::from_bytes_with_limits(bytes, &digest, Limits::batch_prover())?
            .calculate_json(input)?,
    )
}

fn assignment_digest(assignment: &[Fr]) -> String {
    let mut hasher = Sha256::new();
    for value in assignment {
        let encoded = value.into_bigint().to_bytes_le();
        hasher.update((encoded.len() as u32).to_le_bytes());
        hasher.update(encoded);
    }
    hex(&hasher.finalize())
}
