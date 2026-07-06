//! wasm-bindgen bindings for the Curvy crypto core.
//!
//! Everything crosses the boundary as **decimal strings** (and `Vec<String>` for
//! points / signatures) — the wire shape the JavaScript SDK consumes.
//!
//! Field-element inputs reduce mod the field (`fr_from_dec`); raw 256-bit inputs
//! (cipher key material, EdDSA message, `sha256BigInt`) are parsed without
//! reduction (`dec_to_biguint`) — see the core crate for why.

use curvy_core::cipher::{decrypt_amount_token, encrypt_amount_token};
use curvy_core::eddsa::{ephemeral_pub_key, pub_from_private_key_hex, sign_hex};
use curvy_core::encoding::dec_to_biguint;
use curvy_core::field::{fr_from_dec, fr_to_dec};
use curvy_core::hash_utils::sha256_bigint as core_sha256_bigint;
use curvy_core::note;
use curvy_core::poseidon::poseidon as core_poseidon;
use curvy_core::stealth;
use wasm_bindgen::prelude::*;

// Threaded builds export `initThreadPool(n)` — call it once (after `init()`)
// on a cross-origin-isolated page before any scan for rayon-parallel scanning.
#[cfg(feature = "wasm-threads")]
pub use wasm_bindgen_rayon::init_thread_pool;

/// Poseidon hash of `1..=16` decimal field elements.
#[wasm_bindgen]
pub fn poseidon(inputs: Vec<String>) -> String {
    let fes: Vec<_> = inputs.iter().map(|s| fr_from_dec(s)).collect();
    fr_to_dec(&core_poseidon(&fes))
}

/// `ownerHash = Poseidon([pub.x, pub.y, sharedSecret])`.
#[wasm_bindgen(js_name = ownerHash)]
pub fn owner_hash(pub_x: String, pub_y: String, shared_secret: String) -> String {
    fr_to_dec(&note::owner_hash((fr_from_dec(&pub_x), fr_from_dec(&pub_y)), fr_from_dec(&shared_secret)))
}

/// `id = Poseidon([ownerHash, amount, token])`.
#[wasm_bindgen(js_name = noteId)]
pub fn note_id(owner_hash: String, amount: String, token: String) -> String {
    fr_to_dec(&note::note_id(fr_from_dec(&owner_hash), fr_from_dec(&amount), fr_from_dec(&token)))
}

/// `nullifier = Poseidon([sharedSecret, pub.x, pub.y])`.
#[wasm_bindgen]
pub fn nullifier(shared_secret: String, pub_x: String, pub_y: String) -> String {
    fr_to_dec(&note::nullifier(fr_from_dec(&shared_secret), (fr_from_dec(&pub_x), fr_from_dec(&pub_y))))
}

/// BabyJubjub public key `[x, y]` from a hex private key (`pubFromPrivateKey`).
#[wasm_bindgen(js_name = pubFromPrivateKey)]
pub fn pub_from_private_key(private_key_hex: String) -> Vec<String> {
    let (x, y) = pub_from_private_key_hex(&private_key_hex);
    vec![fr_to_dec(&x), fr_to_dec(&y)]
}

/// Ephemeral public key `R = scalar · Base8` as `[x, y]` (`ephemeralPubKey`).
#[wasm_bindgen(js_name = ephemeralPubKey)]
pub fn ephemeral_pub_key_wasm(scalar: String) -> Vec<String> {
    let (x, y) = ephemeral_pub_key(&dec_to_biguint(&scalar));
    vec![fr_to_dec(&x), fr_to_dec(&y)]
}

/// EdDSA-Poseidon signature `[R8.x, R8.y, S]` (`sign`).
#[wasm_bindgen]
pub fn sign(message: String, private_key_hex: String) -> Vec<String> {
    let sig = sign_hex(&dec_to_biguint(&message), &private_key_hex);
    vec![fr_to_dec(&sig.r8.0), fr_to_dec(&sig.r8.1), sig.s.to_string()]
}

/// Encrypt `(amount, token)` -> `[encryptedAmount, encryptedToken]`.
#[wasm_bindgen(js_name = encryptAmountToken)]
pub fn encrypt_amount_token_wasm(
    amount: String,
    token: String,
    shared_secret: String,
    ephemeral_key_x: String,
    ephemeral_key_y: String,
) -> Vec<String> {
    let ss = dec_to_biguint(&shared_secret);
    let ex = dec_to_biguint(&ephemeral_key_x);
    let ey = dec_to_biguint(&ephemeral_key_y);
    let out = encrypt_amount_token(fr_from_dec(&amount), fr_from_dec(&token), &ss, (&ex, &ey));
    vec![fr_to_dec(&out.encrypted_amount), fr_to_dec(&out.encrypted_token)]
}

/// Decrypt `(encryptedAmount, encryptedToken)` -> `[amount, token]`.
#[wasm_bindgen(js_name = decryptAmountToken)]
pub fn decrypt_amount_token_wasm(
    encrypted_amount: String,
    encrypted_token: String,
    shared_secret: String,
    ephemeral_key_x: String,
    ephemeral_key_y: String,
) -> Vec<String> {
    let ss = dec_to_biguint(&shared_secret);
    let ex = dec_to_biguint(&ephemeral_key_x);
    let ey = dec_to_biguint(&ephemeral_key_y);
    let (amount, token) = decrypt_amount_token(fr_from_dec(&encrypted_amount), fr_from_dec(&encrypted_token), &ss, (&ex, &ey));
    vec![fr_to_dec(&amount), fr_to_dec(&token)]
}

/// `sha256BigInt`: raw 256-bit decimal inputs -> decimal digest (no field reduction).
#[wasm_bindgen(js_name = sha256BigInt)]
pub fn sha256_bigint(inputs: Vec<String>) -> String {
    let ints: Vec<_> = inputs.iter().map(|s| dec_to_biguint(s)).collect();
    core_sha256_bigint(&ints).to_string()
}

// ── Stealth core. Typed params in, plain decimal/hex string values out (no JSON
// envelope). Multi-value results use `Vec<String>` — the same positional
// convention used above for points and signatures — except `scan`, which returns
// its matches via a small typed result. Point/tag/key formats ("x.y" points, hex
// view tags and private keys) match the rest of the API.

#[wasm_bindgen]
pub fn version() -> String {
    "v1.0.2".to_string()
}

/// Fresh random meta-keys `[k, v, K, V]` = spend priv, view priv, spend pub, view pub.
#[wasm_bindgen]
pub fn new_meta() -> Vec<String> {
    let (k, v, big_k, big_v) = stealth::new_meta();
    vec![k, v, big_k, big_v]
}

/// Public meta-keys `[k, v, K, V]` for the given private spend (`k`) / view (`v`) keys.
/// Throws on degenerate keys (zero reduction).
#[wasm_bindgen]
pub fn get_meta(k: String, v: String) -> Result<Vec<String>, JsError> {
    let (big_k, big_v) = stealth::get_meta(&k, &v)?;
    Ok(vec![k, v, big_k, big_v])
}

/// Announce a payment to recipient `(K, V)` → `[r, R, viewTag, spendingPubKey]`.
/// Throws on malformed / off-curve recipient keys (an unspendable announcement
/// must never be produced).
#[wasm_bindgen]
pub fn send(big_k: String, big_v: String) -> Result<Vec<String>, JsError> {
    let (r, out) = stealth::send(&big_k, &big_v)?;
    Ok(vec![r, out.big_r, out.view_tag, out.spending_pub_key])
}

/// Recipient scan → the SPARSE list of tag-matching announcements, in input
/// order: each match carries its `index` into the input arrays plus the derived
/// one-time keys. Matches are CANDIDATES (1-byte viewTag ⇒ ~1/256 false
/// positives) — the caller's note-commitment recompute confirms ownership.
/// Malformed / off-curve announcements are non-matches (skipped), never fatal;
/// throws only on the caller's own inputs (keys, mismatched array lengths).
#[wasm_bindgen]
pub fn scan(k: String, v: String, rs: Vec<String>, view_tags: Vec<String>) -> Result<Vec<ScanMatch>, JsError> {
    Ok(stealth::scan(&k, &v, &rs, &view_tags)?.into_iter().map(ScanMatch).collect())
}

/// Viewer scan (view key `v` + recipient spend pub `K`, no spend key): the same
/// sparse candidate list, spending PUBLIC keys only.
#[wasm_bindgen(js_name = viewerScan)]
pub fn viewer_scan(v: String, big_k: String, rs: Vec<String>, view_tags: Vec<String>) -> Result<Vec<ViewerMatch>, JsError> {
    Ok(stealth::viewer_scan(&v, &big_k, &rs, &view_tags)?.into_iter().map(ViewerMatch).collect())
}

/// One [`scan`] candidate: `index` into the input arrays + the derived keys.
#[wasm_bindgen]
pub struct ScanMatch(stealth::ScanMatch);

#[wasm_bindgen]
impl ScanMatch {
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.0.index
    }
    #[wasm_bindgen(getter, js_name = spendingPubKey)]
    pub fn spending_pub_key(&self) -> String {
        self.0.spending_pub_key.clone()
    }
    #[wasm_bindgen(getter, js_name = spendingPrivKey)]
    pub fn spending_priv_key(&self) -> String {
        self.0.spending_priv_key.clone()
    }
}

/// One [`viewer_scan`] candidate: `index` + the derived spending PUBLIC key.
#[wasm_bindgen]
pub struct ViewerMatch(stealth::ViewerMatch);

#[wasm_bindgen]
impl ViewerMatch {
    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.0.index
    }
    #[wasm_bindgen(getter, js_name = spendingPubKey)]
    pub fn spending_pub_key(&self) -> String {
        self.0.spending_pub_key.clone()
    }
}

#[wasm_bindgen(js_name = dbg_isValidBN254Point)]
pub fn dbg_is_valid_bn254_point(point: String) -> bool {
    stealth::is_valid_bn254_point(&point)
}

#[wasm_bindgen(js_name = dbg_isValidSECP256k1Point)]
pub fn dbg_is_valid_secp256k1_point(point: String) -> bool {
    stealth::is_valid_secp256k1_point(&point)
}
