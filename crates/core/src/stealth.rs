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

use core::str::FromStr;

use ark_bn254::{Bn254, Fq as BnFq, Fq12, Fr as BnFr, G1Affine as BnG1, G2Affine as BnG2};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_secp256k1::{Affine as SecpG1, Fq as SecpFq, Fr as SecpFr};
use num_bigint::BigUint;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::encoding::from_hex_lossy;

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

fn xy_bn(p: &BnG1) -> String {
    format!("{}.{}", fp_dec(p.x().unwrap()), fp_dec(p.y().unwrap()))
}
fn xy_secp(p: &SecpG1) -> String {
    format!("{}.{}", fp_dec(p.x().unwrap()), fp_dec(p.y().unwrap()))
}

fn parse_xy<F: PrimeField>(s: &str) -> Result<(F, F), StealthError> {
    let (x, y) = s
        .split_once('.')
        .ok_or_else(|| err(format!("point must be \"X.Y\", got {s:?}")))?;
    Ok((
        F::from_str(x).map_err(|_| err(format!("bad point X: {x:?}")))?,
        F::from_str(y).map_err(|_| err(format!("bad point Y: {y:?}")))?,
    ))
}

// Both BN254 G1 and secp256k1 have cofactor 1, so on-curve already implies the
// prime-order subgroup - no separate subgroup check is needed. The check also
// excludes (0, 0) (off-curve for both), so a parsed point is never the identity
// and downstream `x()/y().unwrap()` on it cannot fire.
fn parse_bn(s: &str, what: &str) -> Result<BnG1, StealthError> {
    let (x, y) = parse_xy::<BnFq>(s)?;
    let p = BnG1::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(err(format!("{what} is not on BN254 G1: {s:?}")));
    }
    Ok(p)
}
fn parse_secp(s: &str, what: &str) -> Result<SecpG1, StealthError> {
    let (x, y) = parse_xy::<SecpFq>(s)?;
    let p = SecpG1::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(err(format!("{what} is not on secp256k1: {s:?}")));
    }
    Ok(p)
}

/// Private scalar from big-endian hex, rejecting a zero reduction (a zero spend or
/// view key would put every derived point at the identity).
fn parse_secp_scalar(hex: &str, what: &str) -> Result<SecpFr, StealthError> {
    let s = SecpFr::from_be_bytes_mod_order(&from_hex_lossy(hex));
    if s.is_zero() {
        return Err(err(format!("{what} reduces to zero")));
    }
    Ok(s)
}
fn parse_bn_scalar(hex: &str, what: &str) -> Result<BnFr, StealthError> {
    let v = BnFr::from_be_bytes_mod_order(&from_hex_lossy(hex));
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

/// `viewTag` ("v1-1byte"): first 2 hex chars of the point's X coordinate.
fn view_tag(p: &BnG1) -> String {
    fp_to_biguint(p.x().unwrap())
        .to_str_radix(16)
        .chars()
        .take(2)
        .collect()
}

/// Compare a computed `v·R` tag against an announcement's tag. Matching means the
/// tag's first 2 chars equal the computed tag exactly (a computed 1-char tag - a
/// tiny X coordinate - never matches a 2-char one, same as before). A malformed
/// tag (shorter than 2 chars, or a non-char-boundary prefix) is a NON-MATCH, not
/// a panic - the Go core panicked here on 1-char tags, which turned one bad
/// announcement into a dead scan.
fn tag_matches(vri: &BnG1, vt: &str) -> bool {
    vt.get(..2).is_some_and(|prefix| view_tag(vri) == prefix)
}

/// `get_meta`: derive the public meta-keys `(K, V)` from the private `(k, v)` hex.
pub fn get_meta(k_hex: &str, v_hex: &str) -> Result<(String, String), StealthError> {
    let s = parse_secp_scalar(k_hex, "spend private key")?;
    let big_s = secp_mul(SecpG1::generator(), s);
    let v = parse_bn_scalar(v_hex, "view private key")?;
    let big_v = bn_mul(BnG1::generator(), v);
    Ok((xy_secp(&big_s), xy_bn(&big_v)))
}

/// `send` output `{R, viewTag, spendingPubKey}` for a **given** ephemeral `r`
/// (decimal). The Go `send` picks `r` randomly; pass the recorded `r` to reproduce.
pub struct SendOutput {
    pub big_r: String,
    pub view_tag: String,
    pub spending_pub_key: String,
}

pub fn send_with_r(r_dec: &str, big_k: &str, big_v: &str) -> Result<SendOutput, StealthError> {
    let r = BnFr::from_str(r_dec).map_err(|_| err(format!("bad ephemeral r: {r_dec:?}")))?;
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
    Ok(SendOutput {
        big_r: xy_bn(&big_r),
        view_tag: view_tag(&rv),
        spending_pub_key: xy_secp(&spk),
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
/// Announcements (`R_i`, `viewTag_i`) come off the network, so a malformed or
/// off-curve `R_i` (or malformed tag) is simply not a match - one hostile or
/// corrupt announcement must not abort a whole wallet scan. Errors are reserved
/// for the caller's own inputs (keys, mismatched array lengths).
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
        // v ≠ 0 and R is a valid affine point of the prime-order G1, so v·R is
        // never the identity - view_tag/xy on it cannot panic.
        let vri = bn_mul(ri, v);
        if !tag_matches(&vri, vt) {
            return None;
        }
        let b = compute_b(&Bn254::pairing(vri, BnG2::generator()).0);
        let sb = s * b;
        Some(ScanMatch {
            index: i as u32,
            spending_pub_key: xy_secp(&secp_mul(big_s, b)),
            spending_priv_key: format!("0x{}", fp_to_biguint(sb).to_str_radix(16)),
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
            spending_pub_key: xy_secp(&secp_mul(s, b)),
        })
    }))
}

fn random_scalar_bytes() -> Result<[u8; 32], StealthError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b)
        .map_err(|error| err(format!("secure randomness unavailable: {error}")))?;
    Ok(b)
}

fn pad_even(s: &str) -> String {
    if s.len().is_multiple_of(2) {
        s.to_string()
    } else {
        format!("0{s}")
    }
}

fn random_nonzero<F: PrimeField>() -> Result<F, StealthError> {
    // A zero draw has probability ~2⁻²⁵⁴; redraw rather than emit a degenerate key.
    loop {
        let x = F::from_le_bytes_mod_order(&random_scalar_bytes()?);
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
    let k_hex = pad_even(&fp_to_biguint(s).to_str_radix(16));
    let v_hex = pad_even(&fp_to_biguint(v).to_str_radix(16));
    Ok((
        k_hex,
        v_hex,
        xy_secp(&secp_mul(SecpG1::generator(), s)),
        xy_bn(&bn_mul(BnG1::generator(), v)),
    ))
}

/// `send`: pick a fresh ephemeral `r` and produce the announcement.
/// Returns `(r_dec, output)`. Errors on malformed / off-curve recipient keys.
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
}
