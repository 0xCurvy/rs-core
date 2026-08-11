//! Release-time validator and manifest generator for a Circom artifact bundle.
//!
//! This validates local parsing, all proving-key points, and exact verification-key
//! equality. A release pipeline must additionally run `snarkjs zkey verify` with
//! the ceremony PTAU and `snarkjs wtns check` against this same R1CS; those checks
//! establish transcript and constraint-system semantics that this parser cannot.

use std::{
    env,
    fs::File,
    io::{self, Read, Seek, SeekFrom},
};

use ark_bn254::{Fq, Fq2};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;
use curvy_prover::zkey::{read_zkey, validate_proving_key};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn u16_le<R: Read>(reader: &mut R) -> io::Result<u16> {
    let mut bytes = [0_u8; 2];
    reader.read_exact(&mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

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
    let size = file.metadata()?.len();
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok((size, hex(&hasher.finalize())))
}

fn graph_metadata(path: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)?;
    if &magic != b"SIGNET01" && &magic != b"CVYWIT01" {
        return Err("unsupported graph magic".into());
    }
    let version = u16_le(&mut file)?;
    let field = u16_le(&mut file)?;
    if u32_le(&mut file)? != 64 {
        return Err("unexpected graph header size".into());
    }
    let mut r1cs_sha256 = [0_u8; 32];
    file.read_exact(&mut r1cs_sha256)?;
    Ok(json!({
        "magic": String::from_utf8_lossy(&magic),
        "formatVersion": version,
        "fieldIdentifier": field,
        "r1csSha256": hex(&r1cs_sha256),
        "nodeCount": u32_le(&mut file)?,
        "signalCount": u32_le(&mut file)?,
        "inputMappingCount": u32_le(&mut file)?,
        "inputBufferLength": u32_le(&mut file)?,
    }))
}

fn zkey_metadata(path: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
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

fn wtns_count(path: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut magic = [0_u8; 4];
    file.read_exact(&mut magic)?;
    if &magic != b"wtns" || u32_le(&mut file)? != 2 {
        return Err("unsupported WTNS".into());
    }
    let section_count = u32_le(&mut file)?;
    for _ in 0..section_count {
        let id = u32_le(&mut file)?;
        let size = u64_le(&mut file)?;
        let offset = file.stream_position()?;
        if id == 1 {
            let width = u32_le(&mut file)?;
            file.seek(SeekFrom::Current(i64::from(width)))?;
            return Ok(u32_le(&mut file)?);
        }
        file.seek(SeekFrom::Start(
            offset.checked_add(size).ok_or("section overflow")?,
        ))?;
    }
    Err("missing WTNS header".into())
}

fn fq_dec(value: &Fq) -> String {
    BigUint::from_bytes_be(&value.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn g1_json(point: &ark_bn254::G1Affine) -> Value {
    json!([fq_dec(&point.x), fq_dec(&point.y), "1"])
}

fn fq2_json(value: &Fq2) -> Value {
    json!([fq_dec(&value.c0), fq_dec(&value.c1)])
}

fn g2_json(point: &ark_bn254::G2Affine) -> Value {
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
    if args.len() != 6 {
        return Err(
            "usage: artifact_manifest_check <zkey> <graph> <wtns> <verification-key-json> <r1cs>"
                .into(),
        );
    }
    let graph = graph_metadata(&args[2])?;
    let zkey = zkey_metadata(&args[1])?;
    let witness_count = wtns_count(&args[3])?;
    let verification_key: Value = serde_json::from_reader(File::open(&args[4])?)?;
    let (proving_key, _) = read_zkey(&mut File::open(&args[1])?)?;
    validate_proving_key(&proving_key)?;
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

    let (zkey_bytes, zkey_sha256) = hash_file(&args[1])?;
    let (graph_bytes, graph_sha256) = hash_file(&args[2])?;
    let (wtns_bytes, wtns_sha256) = hash_file(&args[3])?;
    let (verification_key_bytes, verification_key_sha256) = hash_file(&args[4])?;
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
            "compatibilityChecks": "passed",
            "fullPointValidation": "passed",
            "verificationKeyEquality": "passed",
        }))?
    );
    Ok(())
}
