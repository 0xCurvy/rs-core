use curvy_core::babyjubjub::{BabyJubError, BabyJubPoint, BabyJubScalar, BabyJubSecretScalar, SUB_ORDER};
use curvy_core::eddsa::{verify_scalar_compat, ScalarSigningKey};
use curvy_core::field::{fr_to_dec, Bn254Fr, Bn254FrError, FIELD_MODULUS_DEC};
use serde::Deserialize;

const JSON: &str = include_str!("../testdata/scalar_signature_vectors.json");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    scheme: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    scalar: String,
    message: String,
    public_key: Point,
    nonce_counter: u32,
    nonce_hmac_sha512: String,
    nonce: String,
    #[serde(rename = "R8")]
    r8: Point,
    challenge: String,
    #[serde(rename = "S")]
    s: String,
}

#[derive(Deserialize)]
struct Point {
    x: String,
    y: String,
}

#[test]
fn scalar_signature_matches_cross_language_vector() {
    let vectors: Vectors = serde_json::from_str(JSON).unwrap();
    assert_eq!(vectors.scheme, "CURVY_BABYJUB_SCALAR_SIG_V1");
    let v = &vectors.vectors[0];
    assert_eq!(v.nonce_counter, 0);
    assert_eq!(
        v.nonce_hmac_sha512,
        "8f4243d148f091c5c1684370c4bfe67668e0fe35b3bbcb330e578df9469fbe74fecb38d7435186071b0c1d787b7802d6590aa2577e85a9690ca9d92545470367"
    );
    assert_eq!(
        v.nonce,
        "191032259456556451718566993943153344409163578624511951912212321164019663779"
    );
    assert_eq!(
        v.challenge,
        "13404336863685515831803892786211586853841266788206282671979251356930237019563"
    );

    let key = ScalarSigningKey::from_decimal(&v.scalar).unwrap();
    assert_eq!(fr_to_dec(&key.verifying_key().x()), v.public_key.x);
    assert_eq!(fr_to_dec(&key.verifying_key().y()), v.public_key.y);

    let message = Bn254Fr::try_from_dec(&v.message).unwrap();
    let signature = key.sign_curvy_v1(message).unwrap();
    assert_eq!(fr_to_dec(&signature.r8.x()), v.r8.x);
    assert_eq!(fr_to_dec(&signature.r8.y()), v.r8.y);
    assert_eq!(signature.s.to_dec(), v.s);
    assert!(verify_scalar_compat(message, key.verifying_key(), &signature));
}

#[test]
fn scalar_and_field_boundaries_do_not_reduce() {
    assert_eq!(BabyJubSecretScalar::try_from_dec("0").err(), Some(BabyJubError::ZeroSecretScalar));
    assert_eq!(BabyJubScalar::try_from_dec("00"), Err(BabyJubError::NonCanonicalScalarDecimal));
    assert_eq!(BabyJubScalar::try_from_dec(&SUB_ORDER.to_string()), Err(BabyJubError::ScalarOutOfRange));
    assert_eq!(Bn254Fr::try_from_dec(FIELD_MODULUS_DEC), Err(Bn254FrError::OutOfRange));
}

#[test]
fn point_boundaries_reject_identity_off_curve_and_noncanonical_coordinates() {
    assert_eq!(BabyJubPoint::try_from_dec("0", "1"), Err(BabyJubError::IdentityPoint));
    assert_eq!(BabyJubPoint::try_from_dec("0", "0"), Err(BabyJubError::PointNotOnCurve));
    assert!(matches!(
        BabyJubPoint::try_from_dec(FIELD_MODULUS_DEC, "1"),
        Err(BabyJubError::InvalidCoordinate(Bn254FrError::OutOfRange))
    ));
}

#[test]
fn wrong_message_does_not_verify() {
    let key = ScalarSigningKey::from_decimal("123456789012345678901234567890123456789").unwrap();
    let message = Bn254Fr::try_from_dec("424242").unwrap();
    let wrong_message = Bn254Fr::try_from_dec("424243").unwrap();
    let signature = key.sign_curvy_v1(message).unwrap();
    assert!(!verify_scalar_compat(wrong_message, key.verifying_key(), &signature));
}
