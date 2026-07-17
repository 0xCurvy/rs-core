//! Compatibility gate: replace a deployed-circuit withdrawal fixture's legacy
//! seed signature with a scalar-native signature for the same owner point, then
//! calculate the witness with the real pinned Curvy evaluation graph.

use curvy_core::babyjubjub::BabyJubSecretScalar;
use curvy_core::eddsa::{derive_secret_scalar, ScalarSigningKey};
use curvy_core::encoding::from_hex;
use curvy_core::field::{fr_from_dec, fr_to_dec, Bn254Fr, Fr};
use curvy_core::note::nullifier;
use curvy_core::poseidon::poseidon;
use curvy_witnesscalc::{Circuit, WitnessCalculator};
use serde_json::Value;

const INPUT: &str = include_str!("../../../spikes/m1-prove-verify/fixtures/input.json");
const EXPECTED_PUBLIC: &str =
    include_str!("../../../spikes/m1-prove-verify/fixtures/expected-public.json");
const WITNESS_VECTORS: &str = include_str!("../../../crates/core/testdata/witness_vectors.json");

fn fr(value: &Value) -> Fr {
    fr_from_dec(value.as_str().expect("decimal string"))
}

fn scalar_native_input() -> Value {
    let vectors: Value = serde_json::from_str(WITNESS_VECTORS).unwrap();
    let seed_hex = vectors["withdrawal"]["key"].as_str().unwrap();
    let scalar = derive_secret_scalar(&from_hex(seed_hex));
    let key = ScalarSigningKey::from_secret(BabyJubSecretScalar::try_from_biguint(scalar).unwrap());

    let mut input: Value = serde_json::from_str(INPUT).unwrap();
    let notes = input["inputNotes"].as_array().unwrap();
    let mut message_inputs = Vec::with_capacity(notes.len() + 3);
    let mut total = Fr::from(0u64);
    for note in notes {
        let owner = (fr(&note[0]), fr(&note[1]));
        let shared_secret = fr(&note[2]);
        let amount = fr(&note[3]);
        message_inputs.push(nullifier(shared_secret, owner));
        total += amount;
    }
    let destination = fr(&input["destinationAddress"]);
    let token = fr(&input["tokenId"]);
    message_inputs.extend([destination, total, token]);
    let message = Bn254Fr::from_fr(poseidon(&message_inputs));
    let signature = key.sign_curvy_v1(message).unwrap();

    assert_eq!(
        input["publicKey"][0].as_str().unwrap(),
        fr_to_dec(&key.verifying_key().x())
    );
    assert_eq!(
        input["publicKey"][1].as_str().unwrap(),
        fr_to_dec(&key.verifying_key().y())
    );

    input["signature"] = serde_json::json!([
        signature.s.to_dec(),
        fr_to_dec(&signature.r8.x()),
        fr_to_dec(&signature.r8.y())
    ]);
    input
}

#[test]
fn real_withdrawal_graph_accepts_scalar_native_signature() {
    let input = scalar_native_input();
    let calculator = Circuit::withdrawal().load_calculator().unwrap();
    let assignment = calculator.calculate(&serde_json::to_string(&input).unwrap()).unwrap();
    let actual_public: Vec<String> = assignment[1..=6].iter().map(fr_to_dec).collect();
    let expected_public: Vec<String> = serde_json::from_str(EXPECTED_PUBLIC).unwrap();
    assert_eq!(actual_public, expected_public);
}

#[test]
#[ignore = "requires CURVY_WITHDRAWAL_ZKEY or CURVY_ZK_KEYS_DIR"]
fn real_withdrawal_zkey_proves_scalar_native_signature() {
    let input = scalar_native_input();
    let bundle = Circuit::withdrawal()
        .prove(&serde_json::to_string(&input).unwrap())
        .unwrap();
    let expected_public: Vec<String> = serde_json::from_str(EXPECTED_PUBLIC).unwrap();
    assert_eq!(bundle.public_signals, expected_public);
    let proof: Value = serde_json::from_str(&bundle.proof_json).unwrap();
    assert_eq!(proof["protocol"], "groth16");
    assert_eq!(proof["curve"], "bn128");
}
