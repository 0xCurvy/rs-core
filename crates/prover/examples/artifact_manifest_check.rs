//! Release-time validator and manifest generator for a Circom artifact bundle.
//!
//! This validates local parsing, all proving-key points, the CRS relations those
//! points must satisfy, and exact verification-key equality. A release pipeline
//! must additionally run `snarkjs zkey verify` with the ceremony PTAU and
//! `snarkjs wtns check` against this same R1CS; those checks establish transcript
//! and constraint-system semantics that this parser cannot. Point validity alone
//! does not make a key well formed, so the CRS check runs here too - a key can be
//! built from perfectly good points and still be malformed.

use std::{
    env,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom},
};

use ark_bn254::{Fq, Fq2, Fr};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;
use curvy_prover::zkey::{read_zkey, validate_crs_consistency, validate_proving_key};
use curvy_prover::{
    artifacts::{read_file_bounded, read_graph_file_bounded},
    wtns::read_wtns,
};
use curvy_witness::{Limits, WitnessGraph};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn u32_le<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut bytes = [0_u8; 4];
    reader.read_exact(&mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn u64_le<R: Read>(reader: &mut R) -> io::Result<u64> {
    let mut bytes = [0_u8; 8];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hash_file(path: &str) -> io::Result<(u64, String)> {
    let mut file = File::open(path)?;
    let mut size = 0_u64;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        hasher.update(&buffer[..count]);
    }
    Ok((size, hex(&hasher.finalize())))
}

fn graph_metadata(bytes: &[u8], digest: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // Parse the body as well as the header, using the artifact pipeline's size
    // budget. Metadata comes from the decoded graph, including for zstd files.
    let graph = WitnessGraph::from_bytes_with_limits(bytes, digest, Limits::batch_prover())?;
    let metadata = graph.metadata();
    Ok(json!({
        "magic": String::from_utf8_lossy(&metadata.magic),
        "formatVersion": metadata.format_version,
        "fieldIdentifier": metadata.field_identifier,
        "r1csSha256": hex(&metadata.r1cs_sha256),
        "nodeCount": metadata.node_count,
        "signalCount": metadata.signal_count,
        "inputMappingCount": metadata.input_mapping_count,
        "inputBufferLength": metadata.input_buffer_len,
    }))
}

fn zkey_metadata(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let mut file = Cursor::new(bytes);
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)?;
    let version = u32_le(&mut file)?;
    if &magic != b"zkey" || version != 1 {
        return Err("unsupported zkey".into());
    }
    let section_count = u32_le(&mut file)?;
    let mut groth_header = None;
    let mut a_query = None;
    for _ in 0..section_count {
        let id = u32_le(&mut file)?;
        let size = u64_le(&mut file)?;
        let offset = file.stream_position()?;
        match id {
            2 => groth_header = Some((offset, size)),
            5 => a_query = Some((offset, size)),
            _ => {}
        }
        file.seek(SeekFrom::Start(
            offset.checked_add(size).ok_or("section overflow")?,
        ))?;
    }
    let (header_offset, header_size) = groth_header.ok_or("missing Groth16 header")?;
    if header_size < 84 {
        return Err("short Groth16 header".into());
    }
    file.seek(SeekFrom::Start(header_offset + 72))?;
    let n_vars = u32_le(&mut file)?;
    let n_public = u32_le(&mut file)?;
    let domain_size = u32_le(&mut file)?;
    let (_, a_query_size) = a_query.ok_or("missing A query")?;
    if a_query_size % 64 != 0 || a_query_size / 64 != u64::from(n_vars) {
        return Err("A-query size does not match zkey variable count".into());
    }
    Ok(json!({
        "formatVersion": version,
        "sectionCount": section_count,
        "variableCount": n_vars,
        "publicInputCount": n_public,
        "domainSize": domain_size,
    }))
}

fn wtns_count(bytes: &[u8]) -> Result<u32, Box<dyn std::error::Error>> {
    let assignment = read_wtns(bytes)?;
    if assignment.first() != Some(&Fr::from(1_u64)) {
        return Err("WTNS assignment must start with the constant one signal".into());
    }
    Ok(u32::try_from(assignment.len())?)
}

fn fq_dec(value: &Fq) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn g1_json(point: &ark_bn254::G1Affine) -> Value {
    if point.is_zero() {
        return json!(["0", "1", "0"]);
    }
    json!([fq_dec(&point.x), fq_dec(&point.y), "1"])
}

fn fq2_json(value: &Fq2) -> Value {
    json!([fq_dec(&value.c0), fq_dec(&value.c1)])
}

fn g2_json(point: &ark_bn254::G2Affine) -> Value {
    if point.is_zero() {
        return json!([["0", "0"], ["1", "0"], ["0", "0"]]);
    }
    json!([fq2_json(&point.x), fq2_json(&point.y), ["1", "0"]])
}

fn validate_verification_key(
    parsed: &VerifyingKey<ark_bn254::Bn254>,
    published: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = [
        ("protocol", json!("groth16")),
        ("curve", json!("bn128")),
        (
            "nPublic",
            json!(parsed.gamma_abc_g1.len().saturating_sub(1)),
        ),
        ("vk_alpha_1", g1_json(&parsed.alpha_g1)),
        ("vk_beta_2", g2_json(&parsed.beta_g2)),
        ("vk_gamma_2", g2_json(&parsed.gamma_g2)),
        ("vk_delta_2", g2_json(&parsed.delta_g2)),
        (
            "IC",
            Value::Array(parsed.gamma_abc_g1.iter().map(g1_json).collect()),
        ),
    ];
    for (field, expected) in expected {
        let actual = published
            .get(field)
            .ok_or_else(|| format!("verification key is missing {field}"))?;
        if actual != &expected {
            return Err(format!("verification key field {field} does not match the zkey").into());
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<_>>();
    if args.len() != 6 && args.len() != 7 {
        return Err(
            "usage: artifact_manifest_check <zkey> <graph> <wtns> <verification-key-json> <r1cs> [input-json]"
                .into(),
        );
    }
    let graph_contents = read_graph_file_bounded(&args[2], Limits::batch_prover())?;
    let (graph_bytes, graph_sha256, graph) = {
        let bytes = &graph_contents;
        let digest = hex(&Sha256::digest(bytes));
        let metadata = graph_metadata(bytes, &digest)?;
        (bytes.len(), digest, metadata)
    };
    // Validate, describe, and hash the exact same owned bytes. An open file
    // descriptor alone would still allow in-place writes during validation.
    let zkey_contents = read_file_bounded(&args[1], 4_usize.saturating_mul(1024 * 1024 * 1024))?;
    let zkey = zkey_metadata(&zkey_contents)?;
    let wtns_contents = read_file_bounded(&args[3], Limits::batch_prover().signals * 32 + 512)?;
    let (wtns_bytes, wtns_sha256, witness_count) = {
        let bytes = &wtns_contents;
        let count = wtns_count(bytes)?;
        (bytes.len(), hex(&Sha256::digest(bytes)), count)
    };
    let verification_key_contents = read_file_bounded(&args[4], 16 * 1024 * 1024)?;
    let verification_key: Value = serde_json::from_slice(&verification_key_contents)?;
    let (proving_key, _) = read_zkey(&mut Cursor::new(&zkey_contents))?;
    validate_proving_key(&proving_key)?;
    validate_crs_consistency(&proving_key)?;
    validate_verification_key(&proving_key.vk, &verification_key)?;
    let (r1cs_bytes, r1cs_sha256) = hash_file(&args[5])?;
    if graph["r1csSha256"].as_str() != Some(r1cs_sha256.as_str()) {
        return Err("graph source R1CS digest does not match the supplied R1CS".into());
    }

    let signal_count = graph["signalCount"]
        .as_u64()
        .ok_or("invalid graph signal count")?;
    let variable_count = zkey["variableCount"]
        .as_u64()
        .ok_or("invalid zkey variable count")?;
    let public_count = zkey["publicInputCount"]
        .as_u64()
        .ok_or("invalid zkey public count")?;
    let verification_public_count = verification_key["nPublic"]
        .as_u64()
        .ok_or("verification key is missing nPublic")?;
    if signal_count != variable_count || signal_count != u64::from(witness_count) {
        return Err(format!(
            "assignment mismatch: graph={signal_count}, zkey={variable_count}, wtns={witness_count}"
        )
        .into());
    }
    if public_count != verification_public_count {
        return Err(format!(
            "public-input mismatch: zkey={public_count}, verification-key={verification_public_count}"
        )
        .into());
    }

    let mut witness_reference = "notRun";
    let mut sage_reference = "notBuilt";
    let mut input_metadata = Value::Null;
    if let Some(path) = args.get(6) {
        let input = read_file_bounded(path, Limits::batch_prover().input_json_bytes)?;
        let input_json = std::str::from_utf8(&input)?;
        validate_witness_reference(&graph_contents, &graph_sha256, input_json, &wtns_contents)?;
        witness_reference = "passed";
        if cfg!(feature = "sage") {
            sage_reference = "passed";
        }
        input_metadata = json!({"bytes": input.len(), "sha256": hex(&Sha256::digest(&input))});
    }

    let (zkey_bytes, zkey_sha256) = (zkey_contents.len(), hex(&Sha256::digest(&zkey_contents)));
    let (verification_key_bytes, verification_key_sha256) = (
        verification_key_contents.len(),
        hex(&Sha256::digest(&verification_key_contents)),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schemaVersion": 1,
            "protocol": "groth16",
            "curve": "bn254",
            "zkey": { "bytes": zkey_bytes, "sha256": zkey_sha256, "metadata": zkey },
            "graph": { "bytes": graph_bytes, "sha256": graph_sha256, "metadata": graph },
            "wtnsFixture": { "bytes": wtns_bytes, "sha256": wtns_sha256, "fieldCount": witness_count },
            "verificationKey": {
                "bytes": verification_key_bytes,
                "sha256": verification_key_sha256,
                "publicInputCount": verification_public_count,
            },
            "r1cs": { "bytes": r1cs_bytes, "sha256": r1cs_sha256 },
            "inputFixture": input_metadata,
            "compatibilityChecks": "passed",
            "fullPointValidation": "passed",
            "crsConsistency": "passed",
            "verificationKeyEquality": "passed",
            "witnessReference": witness_reference,
            "sageWitnessReference": sage_reference,
        }))?
    );
    Ok(())
}

fn validate_witness_reference(
    graph: &[u8],
    pin: &str,
    input: &str,
    wtns: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let expected = read_wtns(wtns)?;
    let limits = Limits::batch_prover();
    let parsed = WitnessGraph::from_bytes_with_limits(graph, pin, limits)?;
    if parsed.calculate_json(input)? != expected {
        return Err("graph witness differs from the reference WTNS".into());
    }
    #[cfg(feature = "sage")]
    {
        use curvy_witness::sage::SageGraph;
        let sage = SageGraph::from_bytes_with_limits(graph, pin, limits)?;
        if sage.calculate_json(input)? != expected {
            return Err("SAGE witness differs from the reference WTNS".into());
        }
        let program = sage.to_compiled_bytes()?;
        let cached = SageGraph::from_compiled_bytes_with_limits(
            &program,
            &hex(&Sha256::digest(&program)),
            pin,
            limits,
        )?;
        if cached.calculate_json(input)? != expected {
            return Err("compiled SAGE witness differs from the reference WTNS".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_key_infinity_uses_snarkjs_projective_encoding() {
        assert_eq!(
            g1_json(&ark_bn254::G1Affine::identity()),
            json!(["0", "1", "0"])
        );
        assert_eq!(
            g2_json(&ark_bn254::G2Affine::identity()),
            json!([["0", "0"], ["1", "0"], ["0", "0"]])
        );
    }

    fn graph() -> Vec<u8> {
        let mut bytes = b"SIGNET01".to_vec();
        bytes.extend(1_u16.to_le_bytes());
        bytes.extend(1_u16.to_le_bytes());
        bytes.extend(64_u32.to_le_bytes());
        bytes.extend([7; 32]);
        for count in [1_u32, 1, 0, 1] {
            bytes.extend(count.to_le_bytes());
        }
        bytes.push(0); // Input node for the constant one signal.
        bytes.extend(0_u32.to_le_bytes());
        bytes.extend(0_u32.to_le_bytes()); // Output references node zero.
        bytes
    }

    fn witness() -> Vec<u8> {
        let mut bytes = b"wtns".to_vec();
        bytes.extend(2_u32.to_le_bytes());
        bytes.extend(2_u32.to_le_bytes());
        bytes.extend(1_u32.to_le_bytes());
        bytes.extend(40_u64.to_le_bytes());
        bytes.extend(32_u32.to_le_bytes());
        bytes.extend(Fr::MODULUS.to_bytes_le());
        bytes.extend(1_u32.to_le_bytes());
        bytes.extend(2_u32.to_le_bytes());
        bytes.extend(32_u64.to_le_bytes());
        bytes.extend(Fr::from(1_u64).into_bigint().to_bytes_le());
        bytes
    }

    #[test]
    fn manifest_requires_a_complete_valid_graph() {
        let valid = graph();
        let metadata = graph_metadata(&valid, &hex(&Sha256::digest(&valid))).unwrap();
        assert_eq!(metadata["nodeCount"], 1);
        assert_eq!(metadata["signalCount"], 1);
        assert_eq!(metadata["magic"], "SIGNET01");

        let truncated = valid[..64].to_vec();
        let mut bad_reference = valid.clone();
        bad_reference[69..73].copy_from_slice(&1_u32.to_le_bytes());
        let mut trailing = valid;
        trailing.push(0);
        for invalid in [truncated, bad_reference, trailing] {
            assert!(graph_metadata(&invalid, &hex(&Sha256::digest(&invalid))).is_err());
        }
    }

    #[test]
    fn manifest_requires_complete_canonical_witness_data() {
        let valid = witness();
        assert_eq!(wtns_count(&valid).unwrap(), 1);
        let mut header_only = valid[..64].to_vec();
        header_only[8..12].copy_from_slice(&1_u32.to_le_bytes());
        let truncated = valid[..valid.len() - 1].to_vec();
        let mut wrong_field = valid.clone();
        wrong_field[28] ^= 1;
        let mut noncanonical = valid.clone();
        noncanonical[76..108].copy_from_slice(&Fr::MODULUS.to_bytes_le());
        let mut missing_one = valid;
        missing_one[76] = 0;
        for invalid in [
            header_only,
            truncated,
            wrong_field,
            noncanonical,
            missing_one,
        ] {
            assert!(wtns_count(&invalid).is_err());
        }
    }
}
