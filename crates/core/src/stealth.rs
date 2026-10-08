//! Domain A - stealth addressing core. Native Rust port of `curvy-core` (Go/gnark).
//!
//! Dual-curve & pairing-based:
//! - **secp256k1** spending keys: `s` (priv), `S = s·G` (pub).
//! - **BN254** viewing keys + ephemerals: `v`/`V`, `r`/`R`, with a pairing.
//!
//! Sender: `R = r·G_bn`, `secret = e(r·V, G2)`, `b = secret.c0.c0.c0 (mod secp order)`,
//! `spendingPubKey = b·S`, `viewTag = hex(rV.x)[:2]`.
//! Recipient: for each `(R_i, viewTag_i)`, compute `v·R_i`, match the view tag, then
//! derive `b`, `spendingPubKey = b·S`, `spendingPrivKey = s·b`.
//!
//! Points cross the boundary as `"X.Y"` big-endian **decimal** strings; private keys
//! as big-endian hex.
//!
//! Parity hazard (validated by golden vectors): gnark's GT field
//! tower `C0.B0.A0` must equal arkworks' `Fq12.c0.c0.c0`, and the BN254 G1/G2 + the
//! secp256k1 generators must match gnark's.

use ark_bn254::{Bn254, Fq as BnFq, Fq12, Fr as BnFr, G1Affine as BnG1, G2Affine as BnG2};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_secp256k1::{Affine as SecpG1, Fq as SecpFq, Fr as SecpFr};
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::encoding::from_hex_exact;
use crate::field::Bn254Fr;

// Map announcements → the SPARSE list of matches (the closure returns
// `Option<Match>`), in input order. With the `parallel` feature the work fans
// out over rayon (each item is an independent G1 mul +, on a tag match, one
// pairing - embarrassingly parallel); rayon's `collect` preserves the input
// order even through `filter_map`, so both arms are output-identical.
macro_rules! map_announcements {
    ($rs:expr, $tags:expr, $f:expr) => {{
        #[cfg(feature = "parallel")]
        {
            $rs.par_iter()
                .zip($tags.par_iter())
                .enumerate()
                .filter_map($f)
                .collect::<Vec<_>>()
        }
        #[cfg(not(feature = "parallel"))]
        {
            $rs.iter()
                .zip($tags.iter())
                .enumerate()
                .filter_map($f)
                .collect::<Vec<_>>()
        }
    }};
}

/// Boundary-validation failure: malformed, off-curve, or degenerate input to the
/// stealth core. Own-key problems are hard errors; per-announcement problems in
/// [`scan`]/[`viewer_scan`] are treated as non-matches instead (see there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StealthError(String);

impl core::fmt::Display for StealthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "stealth core: {}", self.0)
    }
}
impl std::error::Error for StealthError {}

fn err(msg: impl Into<String>) -> StealthError {
    StealthError(msg.into())
}

fn fp_to_biguint<F: PrimeField>(x: F) -> BigUint {
    BigUint::from_bytes_be(&x.into_bigint().to_bytes_be())
}
fn fp_dec<F: PrimeField>(x: F) -> String {
    fp_to_biguint(x).to_str_radix(10)
}

// The identity has no affine `"X.Y"` encoding, so these return `None` for it
// rather than panicking; callers decide whether that is an error or a skip.
fn xy_bn(p: &BnG1) -> Option<String> {
    p.xy().map(|(x, y)| format!("{}.{}", fp_dec(x), fp_dec(y)))
}
fn xy_secp(p: &SecpG1) -> Option<String> {
    p.xy().map(|(x, y)| format!("{}.{}", fp_dec(x), fp_dec(y)))
}
fn identity_err(what: &str) -> StealthError {
    err(format!("{what} is the point at infinity"))
}

fn parse_xy<F: PrimeField>(s: &str) -> Result<(F, F), StealthError> {
    if s.len() > 160 {
        return Err(err("point encoding exceeds 160 characters"));
    }
    let (x, y) = s.split_once('.').ok_or_else(|| err("point must be X.Y"))?;
    let coordinate = |s: &str| {
        if s.is_empty()
            || s.len() > 78
            || !s.bytes().all(|b| b.is_ascii_digit())
            || (s.len() > 1 && s.starts_with('0'))
        {
            return Err(err("point coordinates must be unsigned canonical decimals"));
        }
        let value = BigUint::parse_bytes(s.as_bytes(), 10)
            .ok_or_else(|| err("invalid point coordinate"))?;
        if value >= BigUint::from_bytes_le(&F::MODULUS.to_bytes_le()) {
            return Err(err("point coordinate exceeds field modulus"));
        }
        F::from_str(s).map_err(|_| err("invalid point coordinate"))
    };
    Ok((coordinate(x)?, coordinate(y)?))
}

// Both BN254 G1 and secp256k1 have cofactor 1, so on-curve already implies the
// prime-order subgroup - no separate subgroup check is needed. arkworks encodes
// the identity of both curves as affine (0, 0) and `is_on_curve` ACCEPTS it, so
// the identity must be rejected explicitly: it is never a valid key or
// announcement point, and it has no affine coordinates to format.
fn parse_bn(s: &str, what: &str) -> Result<BnG1, StealthError> {
    let (x, y) = parse_xy::<BnFq>(s)?;
    let p = BnG1::new_unchecked(x, y);
    if p.is_zero() {
        return Err(identity_err(what));
    }
    if !p.is_on_curve() {
        return Err(err(format!("{what} is not on BN254 G1")));
    }
    Ok(p)
}
fn parse_secp(s: &str, what: &str) -> Result<SecpG1, StealthError> {
    let (x, y) = parse_xy::<SecpFq>(s)?;
    let p = SecpG1::new_unchecked(x, y);
    if p.is_zero() {
        return Err(identity_err(what));
    }
    if !p.is_on_curve() {
        return Err(err(format!("{what} is not on secp256k1")));
    }
    Ok(p)
}

/// Private scalar from big-endian hex, rejecting a zero reduction (a zero spend or
/// view key would put every derived point at the identity).
fn parse_secp_scalar(hex: &str, what: &str) -> Result<SecpFr, StealthError> {
    let s = SecpFr::from_be_bytes_mod_order(
        &zeroize::Zeroizing::new(
            from_hex_exact::<32>(hex)
                .map_err(|_| err(format!("{what} must be exactly 32 bytes of unprefixed hex")))?,
        )[..],
    );
    if s.is_zero() {
        return Err(err(format!("{what} reduces to zero")));
    }
    Ok(s)
}
fn parse_bn_scalar(hex: &str, what: &str) -> Result<BnFr, StealthError> {
    let v = BnFr::from_be_bytes_mod_order(
        &zeroize::Zeroizing::new(
            from_hex_exact::<32>(hex)
                .map_err(|_| err(format!("{what} must be exactly 32 bytes of unprefixed hex")))?,
        )[..],
    );
    if v.is_zero() {
        return Err(err(format!("{what} reduces to zero")));
    }
    Ok(v)
}

fn bn_mul(p: BnG1, scalar: BnFr) -> BnG1 {
    (p.into_group() * scalar).into_affine()
}
fn secp_mul(p: SecpG1, scalar: SecpFr) -> SecpG1 {
    (p.into_group() * scalar).into_affine()
}

/// `compute_b_asElement`: `e(rV, G2).c0.c0.c0` reduced into the secp256k1 scalar field.
fn compute_b(secret: &Fq12) -> SecpFr {
    let a0: BnFq = secret.c0.c0.c0; // gnark GT.C0.B0.A0
    SecpFr::from_le_bytes_mod_order(&a0.into_bigint().to_bytes_le())
}

/// `viewTag` ("v1-1byte"): first 2 hex chars of the point's X coordinate, or
/// `None` for the identity (which has no X coordinate).
fn view_tag(p: &BnG1) -> Option<String> {
    p.x()
        .map(|x| fp_to_biguint(x).to_str_radix(16).chars().take(2).collect())
}

/// Compare a computed `v·R` tag against an announcement's tag. Matching means the
/// tag's first 2 chars equal the computed tag exactly (a computed 1-char tag - a
/// tiny X coordinate - never matches a 2-char one, same as before). A malformed
/// tag (shorter than 2 chars, or a non-char-boundary prefix) is a NON-MATCH, not
/// a panic - the Go core panicked here on 1-char tags, which turned one bad
/// announcement into a dead scan.
fn tag_matches(vri: &BnG1, vt: &str) -> bool {
    vt.get(..2)
        .is_some_and(|prefix| view_tag(vri).is_some_and(|tag| tag == prefix))
}

/// `get_meta`: derive the public meta-keys `(K, V)` from the private `(k, v)` hex.
pub fn get_meta(k_hex: &str, v_hex: &str) -> Result<(String, String), StealthError> {
    let s = parse_secp_scalar(k_hex, "spend private key")?;
    let big_s = secp_mul(SecpG1::generator(), s);
    let v = parse_bn_scalar(v_hex, "view private key")?;
    let big_v = bn_mul(BnG1::generator(), v);
    Ok((
        xy_secp(&big_s).ok_or_else(|| identity_err("spend public key"))?,
        xy_bn(&big_v).ok_or_else(|| identity_err("view public key"))?,
    ))
}

/// `send` output `{R, viewTag, spendingPubKey}` for a **given** ephemeral `r`
/// (canonical decimal in `[1, p)` of the BN254 scalar field). The Go `send`
/// picks `r` randomly; pass the recorded `r` to reproduce.
pub struct SendOutput {
    pub big_r: String,
    pub view_tag: String,
    pub spending_pub_key: String,
}

pub fn send_with_r(r_dec: &str, big_k: &str, big_v: &str) -> Result<SendOutput, StealthError> {
    // Canonical BN254 scalar: no leading zeros and no reduction of values at or
    // above the group order, so each ephemeral `r` has exactly one encoding.
    let r = Bn254Fr::try_from_dec(r_dec)
        .map_err(|error| err(format!("invalid ephemeral scalar r: {error}")))?
        .into_inner();
    if r.is_zero() {
        return Err(err("ephemeral r must be nonzero"));
    }
    // The recipient meta-keys come from the registry - validate hard. A send
    // computed from an off-curve K/V would announce a garbage spendingPubKey:
    // funds committed to an address nobody can ever derive the key for.
    let big_v_pt = parse_bn(big_v, "recipient view key V")?;
    let big_k_pt = parse_secp(big_k, "recipient spend key K")?;
    let big_r = bn_mul(BnG1::generator(), r);
    let rv = bn_mul(big_v_pt, r);
    let secret = Bn254::pairing(rv, BnG2::generator());
    let b = compute_b(&secret.0);
    let spk = secp_mul(big_k_pt, b);
    // r ≠ 0 and V ≠ O in a prime-order group, so R and r·V are never the
    // identity; b·K is the identity only if b reduces to zero. Error rather
    // than panic either way.
    Ok(SendOutput {
        big_r: xy_bn(&big_r).ok_or_else(|| identity_err("ephemeral R"))?,
        view_tag: view_tag(&rv).ok_or_else(|| identity_err("shared point r·V"))?,
        spending_pub_key: xy_secp(&spk).ok_or_else(|| identity_err("spending public key"))?,
    })
}

/// One matched announcement: `index` into the input `rs`/`view_tags` arrays,
/// plus the derived one-time keys. A tag match is a CANDIDATE, not proof of
/// ownership - the 1-byte viewTag false-positives at ~1/256, and the caller's
/// note-commitment recompute (`discoverOwnedNotes`) is what confirms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanMatch {
    pub index: u32,
    pub spending_pub_key: String,
    pub spending_priv_key: String,
}

/// A viewer-scan candidate: derived spending PUBLIC key only (no spend key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewerMatch {
    pub index: u32,
    pub spending_pub_key: String,
}

/// Returns the SPARSE, input-ordered list of tag-matching announcements.
/// Announcements (`R_i`, `viewTag_i`) come off the network, so a malformed,
/// off-curve or identity `R_i` (or malformed tag) is simply not a match - one
/// hostile or corrupt announcement must not abort a whole wallet scan. Errors
/// are reserved for the caller's own inputs (keys, mismatched array lengths).
pub fn scan(
    k_hex: &str,
    v_hex: &str,
    rs: &[String],
    view_tags: &[String],
) -> Result<Vec<ScanMatch>, StealthError> {
    if rs.len() != view_tags.len() {
        return Err(err(format!(
            "Rs.len ({}) != viewTags.len ({})",
            rs.len(),
            view_tags.len()
        )));
    }
    let s = parse_secp_scalar(k_hex, "spend private key")?;
    let big_s = secp_mul(SecpG1::generator(), s);
    let v = parse_bn_scalar(v_hex, "view private key")?;

    Ok(map_announcements!(rs, view_tags, |(i, (ri_str, vt)): (
        usize,
        (&String, &String)
    )| {
        let ri = parse_bn(ri_str, "announcement R").ok()?;
        // v ≠ 0 and parse_bn rejects the identity, so in the prime-order G1 v·R
        // is never the identity. An identity v·R (tag) or b·S (b reducing to
        // zero) would be skipped as a non-match rather than panic.
        let vri = bn_mul(ri, v);
        if !tag_matches(&vri, vt) {
            return None;
        }
        let b = compute_b(&Bn254::pairing(vri, BnG2::generator()).0);
        let sb = s * b;
        Some(ScanMatch {
            index: i as u32,
            spending_pub_key: xy_secp(&secp_mul(big_s, b))?,
            spending_priv_key: format!("0x{:064x}", fp_to_biguint(sb)),
        })
    }))
}

/// `viewerScan`: like [`scan`] but the viewer holds only `v` + the spend pubkey `S`
/// (no `k`), so it recovers spending PUBLIC keys only. Same sparse shape and
/// skip semantics for per-announcement inputs; own inputs (`v`, `S`) error hard.
pub fn viewer_scan(
    v_hex: &str,
    big_s: &str,
    rs: &[String],
    view_tags: &[String],
) -> Result<Vec<ViewerMatch>, StealthError> {
    if rs.len() != view_tags.len() {
        return Err(err(format!(
            "Rs.len ({}) != viewTags.len ({})",
            rs.len(),
            view_tags.len()
        )));
    }
    let v = parse_bn_scalar(v_hex, "view private key")?;
    let s = parse_secp(big_s, "spend public key S")?;
    Ok(map_announcements!(rs, view_tags, |(i, (ri_str, vt)): (
        usize,
        (&String, &String)
    )| {
        let ri = parse_bn(ri_str, "announcement R").ok()?;
        let vri = bn_mul(ri, v);
        if !tag_matches(&vri, vt) {
            return None;
        }
        let b = compute_b(&Bn254::pairing(vri, BnG2::generator()).0);
        Some(ViewerMatch {
            index: i as u32,
            spending_pub_key: xy_secp(&secp_mul(s, b))?,
        })
    }))
}

fn random_scalar_bytes() -> Result<[u8; 32], StealthError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b)
        .map_err(|error| err(format!("secure randomness unavailable: {error}")))?;
    Ok(b)
}

fn random_nonzero<F: PrimeField>() -> Result<F, StealthError> {
    // A zero draw has probability ~2⁻²⁵⁴; redraw rather than emit a degenerate key.
    loop {
        let mut bytes = zeroize::Zeroizing::new(random_scalar_bytes()?);
        // Mask unused top bits, then reject rather than reduce: every accepted
        // nonzero field element has exactly one equally likely encoding.
        let bits = F::MODULUS_BIT_SIZE as usize;
        if bits < 256 {
            bytes[bits / 8] &= (1u8 << (bits % 8)) - 1;
            bytes[bits / 8 + 1..].fill(0);
        }
        let x = F::from_le_bytes_mod_order(&bytes[..]);
        if x.into_bigint().to_bytes_le() != bytes[..] {
            continue;
        }
        if !x.is_zero() {
            return Ok(x);
        }
    }
}

/// `new_meta`: generate a fresh random meta-key pair. Returns `(k, v, K, V)` -
/// private keys as big-endian hex, public keys as `"X.Y"` decimal.
pub fn new_meta() -> Result<(String, String, String, String), StealthError> {
    let s = random_nonzero::<SecpFr>()?;
    let v = random_nonzero::<BnFr>()?;
    let k_hex = format!("{:064x}", fp_to_biguint(s));
    let v_hex = format!("{:064x}", fp_to_biguint(v));
    Ok((
        k_hex,
        v_hex,
        xy_secp(&secp_mul(SecpG1::generator(), s))
            .ok_or_else(|| identity_err("spend public key"))?,
        xy_bn(&bn_mul(BnG1::generator(), v)).ok_or_else(|| identity_err("view public key"))?,
    ))
}

/// `send`: pick a fresh ephemeral `r` and produce the announcement.
/// Returns `(r_dec, output)`. Errors on malformed / off-curve / identity recipient keys.
pub fn send(big_k: &str, big_v: &str) -> Result<(String, SendOutput), StealthError> {
    let r = random_nonzero::<BnFr>()?;
    let r_dec = fp_to_biguint(r).to_str_radix(10);
    let out = send_with_r(&r_dec, big_k, big_v)?;
    Ok((r_dec, out))
}

/// `dbg_isValidBN254Point`: is `"X.Y"` a valid point on BN254 G1?
pub fn is_valid_bn254_point(point: &str) -> bool {
    parse_bn(point, "point").is_ok()
}

/// `dbg_isValidSECP256k1Point`: is `"X.Y"` a valid point on secp256k1?
pub fn is_valid_secp256k1_point(point: &str) -> bool {
    parse_secp(point, "point").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_hex_is_exact_and_generated_keys_are_fixed_width() {
        let (k, v, _, _) = new_meta().unwrap();
        assert_eq!(k.len(), 64);
        assert_eq!(v.len(), 64);
        for bad in [
            "aabbZ".to_owned() + &"00".repeat(29),
            "aabb".into(),
            "ab".repeat(31),
            "ab".repeat(33),
            "ab".repeat(32) + "f",
            "0x".to_owned() + &k,
        ] {
            assert!(get_meta(&bad, &v).is_err());
            assert!(get_meta(&k, &bad).is_err());
            assert!(scan(&bad, &v, &[], &[]).is_err());
        }
    }

    #[test]
    fn new_meta_round_trips_through_get_meta() {
        // The derived publics must match what get_meta recomputes from the privates,
        // and a self-send must be discoverable by a self-scan.
        let (k, v, big_k, big_v) = new_meta().unwrap();
        let (rk, rv) = get_meta(&k, &v).unwrap();
        assert_eq!((rk, rv), (big_k.clone(), big_v.clone()));

        let (_r, sent) = send(&big_k, &big_v).unwrap();
        let found = scan(&k, &v, &[sent.big_r], &[sent.view_tag]).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].index, 0);
        assert_eq!(found[0].spending_pub_key, sent.spending_pub_key);
        assert!(found[0].spending_priv_key.starts_with("0x"));
    }

    // (1, 2) is the BN254 G1 generator; (1, 3) is on neither curve.
    const OFF_CURVE: &str = "1.3";

    #[test]
    fn scan_skips_bad_announcements_without_aborting() {
        let (k, v, big_k, big_v) = new_meta().unwrap();
        let (_r, sent) = send(&big_k, &big_v).unwrap();

        let rs = vec![
            OFF_CURVE.to_string(),     // off-curve point
            "not-a-point".to_string(), // unparseable
            sent.big_r.clone(),        // real match
            sent.big_r.clone(),        // real point, malformed 1-char tag
        ];
        let tags = vec!["ab".into(), "cd".into(), sent.view_tag.clone(), "a".into()];

        let found = scan(&k, &v, &rs, &tags).unwrap();
        assert_eq!(found.len(), 1, "only the real announcement matches");
        assert_eq!(found[0].index, 2);
        assert_eq!(found[0].spending_pub_key, sent.spending_pub_key);

        let seen = viewer_scan(&v, &big_k, &rs, &tags).unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            (seen[0].index, seen[0].spending_pub_key.as_str()),
            (2, sent.spending_pub_key.as_str())
        );
    }

    #[test]
    fn send_rejects_malformed_recipient_keys() {
        let (_k, _v, big_k, big_v) = new_meta().unwrap();
        assert!(
            send(OFF_CURVE, &big_v).is_err(),
            "off-curve K must be rejected"
        );
        assert!(
            send(&big_k, OFF_CURVE).is_err(),
            "off-curve V must be rejected"
        );
        assert!(send("garbage", &big_v).is_err());
        assert!(
            send_with_r("0", &big_k, &big_v).is_err(),
            "zero ephemeral r must be rejected"
        );
    }

    #[test]
    fn own_key_and_shape_errors_are_hard() {
        let (k, v, _big_k, _big_v) = new_meta().unwrap();
        assert!(get_meta("00", &v).is_err(), "zero spend key");
        assert!(get_meta(&k, "00").is_err(), "zero view key");
        assert!(
            scan(&k, &v, &["1.2".into()], &[]).is_err(),
            "length mismatch"
        );
        assert!(viewer_scan(&v, OFF_CURVE, &[], &[]).is_err(), "off-curve S");
    }

    #[test]
    fn point_validators_reject_off_curve_and_garbage() {
        assert!(is_valid_bn254_point("1.2")); // the BN254 G1 generator
        assert!(!is_valid_bn254_point(OFF_CURVE));
        assert!(!is_valid_bn254_point("1.2.3"));
        assert!(!is_valid_secp256k1_point("1.3"));
        assert!(!is_valid_secp256k1_point(""));
    }

    // arkworks' affine encoding of the point at infinity on both curves. It is
    // NOT on either curve equation, but `is_on_curve` accepts it.
    const IDENTITY: &str = "0.0";

    #[test]
    fn identity_point_is_rejected_at_every_boundary() {
        assert!(!is_valid_bn254_point(IDENTITY));
        assert!(!is_valid_secp256k1_point(IDENTITY));

        let (k, v, big_k, big_v) = new_meta().unwrap();
        assert!(
            send(IDENTITY, &big_v).is_err(),
            "identity K must be rejected"
        );
        assert!(
            send(&big_k, IDENTITY).is_err(),
            "identity V must be rejected"
        );
        assert!(
            viewer_scan(&v, IDENTITY, &[], &[]).is_err(),
            "identity S must be rejected"
        );

        // A hostile identity announcement must be skipped, not panic the scan.
        let (_r, sent) = send(&big_k, &big_v).unwrap();
        let rs = vec![IDENTITY.to_string(), sent.big_r.clone()];
        let tags = vec!["00".to_string(), sent.view_tag.clone()];
        let found = scan(&k, &v, &rs, &tags).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].index, 1);
        assert_eq!(found[0].spending_pub_key, sent.spending_pub_key);
        let seen = viewer_scan(&v, &big_k, &rs, &tags).unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].index, 1);
    }

    #[test]
    fn identity_formatting_is_none_not_a_panic() {
        assert_eq!(xy_bn(&BnG1::identity()), None);
        assert_eq!(xy_secp(&SecpG1::identity()), None);
        assert_eq!(view_tag(&BnG1::identity()), None);
        assert!(!tag_matches(&BnG1::identity(), "00"));
        assert_eq!(xy_bn(&BnG1::generator()).as_deref(), Some("1.2"));
    }

    #[test]
    fn point_coordinates_reject_leading_zeros() {
        for bad in ["01.2", "1.02", "0001.2", "00.0", "1.00"] {
            assert!(!is_valid_bn254_point(bad), "{bad}");
            assert!(!is_valid_secp256k1_point(bad), "{bad}");
        }
        let (_k, v, big_k, big_v) = new_meta().unwrap();
        let (kx, ky) = big_k.split_once('.').unwrap();
        let (vx, vy) = big_v.split_once('.').unwrap();
        assert!(send(&format!("0{kx}.{ky}"), &big_v).is_err());
        assert!(send(&big_k, &format!("{vx}.0{vy}")).is_err());
        assert!(viewer_scan(&v, &format!("0{kx}.{ky}"), &[], &[]).is_err());
    }

    #[test]
    fn send_with_r_requires_a_canonical_scalar() {
        use crate::field::FIELD_MODULUS_DEC;
        let (_k, _v, big_k, big_v) = new_meta().unwrap();
        let five = send_with_r("5", &big_k, &big_v).unwrap();
        // p - 1 is the largest accepted scalar.
        let p_minus_1 = (BigUint::parse_bytes(FIELD_MODULUS_DEC.as_bytes(), 10).unwrap() - 1u8)
            .to_str_radix(10);
        assert!(send_with_r(&p_minus_1, &big_k, &big_v).is_ok());

        let p_plus_5 = (BigUint::parse_bytes(FIELD_MODULUS_DEC.as_bytes(), 10).unwrap() + 5u8)
            .to_str_radix(10);
        for bad in [
            "05",
            "005",
            "+5",
            "-5",
            " 5",
            "",
            "0",
            "00",
            FIELD_MODULUS_DEC,
            &p_plus_5,
            &"9".repeat(78),
        ] {
            assert!(
                send_with_r(bad, &big_k, &big_v).is_err(),
                "r = {bad:?} must be rejected"
            );
        }
        // The canonical encoding still yields R = 5·G.
        assert_eq!(
            five.big_r,
            xy_bn(&bn_mul(BnG1::generator(), BnFr::from(5u8))).unwrap()
        );
    }
}
