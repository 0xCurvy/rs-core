//! Cross-checks Rust crypto primitives against the SDK's reference libraries.

use std::str::FromStr;

use curvy_core::blake512::blake512;
use curvy_core::cipher::{decrypt_amount_token, encrypt_amount_token};
use curvy_core::eddsa::{derive_public_key, derive_secret_scalar, ephemeral_pub_key, sign_hex};
use curvy_core::encoding::from_hex_lossy;
use curvy_core::field::{Fr, fr_from_dec, fr_to_dec};
use curvy_core::hash_utils::sha256_bigint;
use curvy_core::note::{note_id, nullifier, owner_hash};
use num_bigint::BigUint;
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("../testdata/phase2_vectors.json");

fn fr(s: &str) -> Fr {
    fr_from_dec(s)
}
fn big(s: &str) -> BigUint {
    BigUint::from_str(s).expect("decimal biguint")
}
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Deserialize)]
struct Vectors {
    cipher: Vec<CipherVec>,
    blake512: Vec<BlakeVec>,
    #[serde(rename = "deriveSecretScalar")]
    derive_secret_scalar: Vec<DssVec>,
    #[serde(rename = "pubFromPrivateKey")]
    pub_from_private_key: Vec<PubVec>,
    #[serde(rename = "ephemeralPubKey")]
    ephemeral_pub_key: Vec<EphVec>,
    sign: Vec<SignVec>,
    #[serde(rename = "noteCommitments")]
    note_commitments: Vec<NoteVec>,
    #[serde(rename = "sha256BigInt")]
    sha256_bigint: Vec<Sha256Vec>,
}

#[derive(Deserialize)]
struct CipherVec {
    amount: String,
    token: String,
    #[serde(rename = "sharedSecret")]
    shared_secret: String,
    #[serde(rename = "ephemeralKey")]
    ephemeral_key: [String; 2],
    #[serde(rename = "encryptedAmount")]
    encrypted_amount: String,
    #[serde(rename = "encryptedToken")]
    encrypted_token: String,
}

#[derive(Deserialize)]
struct BlakeVec {
    input: String,
    digest: String,
}

#[derive(Deserialize)]
struct DssVec {
    #[serde(rename = "privateKeyHex")]
    private_key_hex: String,
    scalar: String,
}

#[derive(Deserialize)]
struct PubVec {
    #[serde(rename = "privateKeyHex")]
    private_key_hex: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct EphVec {
    scalar: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct SignVec {
    #[serde(rename = "privateKeyHex")]
    private_key_hex: String,
    message: String,
    #[serde(rename = "R8x")]
    r8x: String,
    #[serde(rename = "R8y")]
    r8y: String,
    #[serde(rename = "S")]
    s: String,
}

#[derive(Deserialize)]
struct NoteVec {
    #[serde(rename = "pubX")]
    pub_x: String,
    #[serde(rename = "pubY")]
    pub_y: String,
    #[serde(rename = "sharedSecret")]
    shared_secret: String,
    amount: String,
    token: String,
    #[serde(rename = "ownerHash")]
    owner_hash: String,
    id: String,
    nullifier: String,
}

#[derive(Deserialize)]
struct Sha256Vec {
    inputs: Vec<String>,
    output: String,
}

fn load() -> Vectors {
    serde_json::from_str(VECTORS_JSON).expect("phase2_vectors.json must parse")
}

#[test]
fn cipher_matches_balance_cipher() {
    let v = load();
    assert!(!v.cipher.is_empty());
    for (i, c) in v.cipher.iter().enumerate() {
        let ss = big(&c.shared_secret);
        let eph_x = big(&c.ephemeral_key[0]);
        let eph_y = big(&c.ephemeral_key[1]);
        let eph = (&eph_x, &eph_y);
        let out = encrypt_amount_token(fr(&c.amount), fr(&c.token), &ss, eph);
        assert_eq!(
            fr_to_dec(&out.encrypted_amount),
            c.encrypted_amount,
            "cipher {i} amount"
        );
        assert_eq!(
            fr_to_dec(&out.encrypted_token),
            c.encrypted_token,
            "cipher {i} token"
        );

        // round-trip
        let (amount, token) =
            decrypt_amount_token(out.encrypted_amount, out.encrypted_token, &ss, eph);
        assert_eq!(fr_to_dec(&amount), c.amount, "cipher {i} decrypt amount");
        assert_eq!(fr_to_dec(&token), c.token, "cipher {i} decrypt token");
    }
}

#[test]
fn blake512_matches_zk_kit() {
    let v = load();
    assert!(!v.blake512.is_empty());
    for (i, b) in v.blake512.iter().enumerate() {
        let digest = blake512(&from_hex_lossy(&b.input));
        assert_eq!(
            to_hex(&digest),
            b.digest,
            "blake512 vector {i} (input len {})",
            b.input.len() / 2
        );
    }
}

#[test]
fn derive_secret_scalar_matches() {
    let v = load();
    assert!(!v.derive_secret_scalar.is_empty());
    for (i, d) in v.derive_secret_scalar.iter().enumerate() {
        let got = derive_secret_scalar(&from_hex_lossy(&d.private_key_hex));
        assert_eq!(got, big(&d.scalar), "deriveSecretScalar {i}");
    }
}

#[test]
fn pub_from_private_key_matches() {
    let v = load();
    assert!(!v.pub_from_private_key.is_empty());
    for (i, p) in v.pub_from_private_key.iter().enumerate() {
        // Replay the reference's lossy decoding; strict APIs have separate tests.
        let (x, y) = derive_public_key(&from_hex_lossy(&p.private_key_hex));
        assert_eq!(fr_to_dec(&x), p.x, "pubFromPrivateKey {i} x");
        assert_eq!(fr_to_dec(&y), p.y, "pubFromPrivateKey {i} y");
    }
}

#[test]
fn ephemeral_pub_key_matches() {
    let v = load();
    assert!(!v.ephemeral_pub_key.is_empty());
    for (i, e) in v.ephemeral_pub_key.iter().enumerate() {
        let (x, y) = ephemeral_pub_key(&big(&e.scalar));
        assert_eq!(fr_to_dec(&x), e.x, "ephemeralPubKey {i} x");
        assert_eq!(fr_to_dec(&y), e.y, "ephemeralPubKey {i} y");
    }
}

#[test]
fn sign_matches_zk_kit() {
    let v = load();
    assert!(!v.sign.is_empty());
    for (i, s) in v.sign.iter().enumerate() {
        let sig = sign_hex(&big(&s.message), &s.private_key_hex).unwrap();
        assert_eq!(fr_to_dec(&sig.r8.0), s.r8x, "sign {i} R8x");
        assert_eq!(fr_to_dec(&sig.r8.1), s.r8y, "sign {i} R8y");
        assert_eq!(sig.s.to_string(), s.s, "sign {i} S");
    }
}

#[test]
fn note_commitments_match() {
    let v = load();
    assert!(!v.note_commitments.is_empty());
    for (i, n) in v.note_commitments.iter().enumerate() {
        let pk = (fr(&n.pub_x), fr(&n.pub_y));
        let oh = owner_hash(pk, fr(&n.shared_secret));
        assert_eq!(fr_to_dec(&oh), n.owner_hash, "note {i} ownerHash");
        assert_eq!(
            fr_to_dec(&note_id(oh, fr(&n.amount), fr(&n.token))),
            n.id,
            "note {i} id"
        );
        assert_eq!(
            fr_to_dec(&nullifier(fr(&n.shared_secret), pk)),
            n.nullifier,
            "note {i} nullifier"
        );
    }
}

#[test]
fn sha256_bigint_matches() {
    let v = load();
    assert!(!v.sha256_bigint.is_empty());
    for (i, s) in v.sha256_bigint.iter().enumerate() {
        let inputs: Vec<BigUint> = s.inputs.iter().map(|x| big(x)).collect();
        assert_eq!(
            sha256_bigint(&inputs).to_string(),
            s.output,
            "sha256BigInt {i}"
        );
    }
}
