use curvy_core::babyjubjub::{BabyJubPoint, BabyJubScalar};
use curvy_core::eddsa::{verify_scalar_compat, ScalarSignature, ScalarSigningKey};
use curvy_core::field::{fr_from_dec, fr_to_dec, Bn254Fr, Fr};
use curvy_core::poseidon::poseidon;
use curvy_core::witness::{build_withdrawal_with_signer, KnownOwner, Proof};

#[test]
fn scalar_signer_builds_a_compatible_withdrawal_witness() {
    let key = ScalarSigningKey::from_decimal("123456789012345678901234567890123456789").unwrap();
    let owner = KnownOwner::new(
        *key.verifying_key(),
        Bn254Fr::try_from_dec("777").unwrap(),
    );
    let note = owner.note(
        Fr::from(100u64),
        Fr::from(1u64),
        (Fr::from(11u64), Fr::from(12u64)),
        Fr::from(0u64),
    );
    let destination = Fr::from(42u64);
    let token = Fr::from(1u64);
    let witness = build_withdrawal_with_signer(
        std::slice::from_ref(&note),
        &key,
        &[Proof { leaf_index: 0, siblings: vec![] }],
        Fr::from(9u64),
        destination,
        token,
    )
    .unwrap();

    assert_eq!(witness.public_key[0], fr_to_dec(&key.verifying_key().x()));
    assert_eq!(witness.public_key[1], fr_to_dec(&key.verifying_key().y()));

    // Circuit witness order is [S, R8.x, R8.y].
    let signature = ScalarSignature {
        s: BabyJubScalar::try_from_dec(&witness.signature[0]).unwrap(),
        r8: BabyJubPoint::try_from_dec(&witness.signature[1], &witness.signature[2]).unwrap(),
    };
    let message = Bn254Fr::from_fr(poseidon(&[
        note.nullifier(),
        destination,
        Fr::from(100u64),
        token,
    ]));
    assert!(verify_scalar_compat(message, key.verifying_key(), &signature));

    // The KnownOwner path preserves the independently supplied shared secret.
    assert_eq!(note.shared_secret, fr_from_dec("777"));
}
