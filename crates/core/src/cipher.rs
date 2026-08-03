//! Note-data cipher — a faithful port of `balanceCipher.ts`.
//!
//! The encrypted amount/token are two PUBLIC field signals (each `< r`), so there
//! is no room for an AEAD tag/IV. We use AES-256-CTR as a keystream and add it into
//! the value **in the field** (an additive field-OTP):
//!
//! ```text
//! enc = (value + keystream_field) mod r        dec = (enc − keystream_field) mod r
//! ```
//!
//! Integrity comes from the on-chain `noteId = Poseidon([ownerHash, amount, token])`,
//! not the cipher (the recipient recomputes it and rejects on mismatch).
//!
//! - key   = HKDF-SHA256(ikm = BE32(sharedSecret), salt, info) → 32-byte AES key
//! - nonce = SHA-256(BE32(ephX) ‖ BE32(ephY))[0..16], used as a **64-bit** CTR
//!   counter block (`Ctr64BE`, matching WebCrypto `AES-CTR` with `length: 64`)
//! - keystream = `AES-256-CTR.encrypt(zeros[64])`; `ks[0..32]` → amount, `ks[32..64]` → token

use aes::Aes256;
use ctr::Ctr64BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::encoding::biguint_to_be_32;
use crate::field::{Fr, fr_from_be_bytes_mod};

const NOTE_KEY_SALT: &[u8] = b"curvy/agg-note/v1";
const NOTE_KEY_INFO: &[u8] = b"curvy/agg-note/v1:amount+token";
const KEYSTREAM_BYTES: usize = 64;

type Aes256Ctr64BE = Ctr64BE<Aes256>;

// The `sharedSecret` and `ephemeralKey` coordinates are used purely as key material
// and are packed as RAW 256-bit big-endian integers (no field reduction), matching
// the TS `bigIntToBytes(value, 32)`. In production they are always BabyJubjub field
// coordinates (`< r`), but typing them as `BigUint` keeps the cipher byte-identical
// to the TS for the whole `[0, 2^256)` input domain.
fn derive_note_key(shared_secret: &BigUint) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(NOTE_KEY_SALT), &biguint_to_be_32(shared_secret));
    let mut okm = [0u8; 32];
    hk.expand(NOTE_KEY_INFO, &mut okm)
        .expect("hkdf expand to 32 bytes");
    okm
}

fn derive_counter_block(ephemeral_key: (&BigUint, &BigUint)) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(biguint_to_be_32(ephemeral_key.0));
    h.update(biguint_to_be_32(ephemeral_key.1));
    let digest = h.finalize();
    let mut counter = [0u8; 16];
    counter.copy_from_slice(&digest[0..16]);
    counter
}

/// The two field-element keystream pads `(ksAmount, ksToken)`.
fn ctr_keystream_fields(shared_secret: &BigUint, ephemeral_key: (&BigUint, &BigUint)) -> (Fr, Fr) {
    let key = derive_note_key(shared_secret);
    let counter = derive_counter_block(ephemeral_key);

    let mut ks = [0u8; KEYSTREAM_BYTES];
    let mut cipher =
        Aes256Ctr64BE::new_from_slices(&key, &counter).expect("valid AES-256 key + 16-byte IV");
    cipher.apply_keystream(&mut ks);

    (
        fr_from_be_bytes_mod(&ks[0..32]),
        fr_from_be_bytes_mod(&ks[32..64]),
    )
}

/// The two encrypted `EncryptedNoteData` field slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptedAmountToken {
    pub encrypted_amount: Fr,
    pub encrypted_token: Fr,
}

/// Encrypt `(amount, token)` into the two field slots (`encryptAmountToken`).
/// `amount`/`token` are field elements; `shared_secret`/`ephemeral_key` are raw
/// 256-bit key material (see the module note).
pub fn encrypt_amount_token(
    amount: Fr,
    token: Fr,
    shared_secret: &BigUint,
    ephemeral_key: (&BigUint, &BigUint),
) -> EncryptedAmountToken {
    let (ks_amount, ks_token) = ctr_keystream_fields(shared_secret, ephemeral_key);
    EncryptedAmountToken {
        encrypted_amount: amount + ks_amount,
        encrypted_token: token + ks_token,
    }
}

/// Inverse of [`encrypt_amount_token`] (`decryptAmountToken`). The caller MUST
/// verify the recomputed `noteId`.
pub fn decrypt_amount_token(
    encrypted_amount: Fr,
    encrypted_token: Fr,
    shared_secret: &BigUint,
    ephemeral_key: (&BigUint, &BigUint),
) -> (Fr, Fr) {
    let (ks_amount, ks_token) = ctr_keystream_fields(shared_secret, ephemeral_key);
    (encrypted_amount - ks_amount, encrypted_token - ks_token)
}
