//! Note sealing (stealth send → an on-chain-shaped note), padding notes, the fee
//! note, and the value math — all mirroring the TS `witnessFromNotes` /
//! `buildAggregateRequest`.

use anyhow::Result;
use curvy_core::field::{fr_from_biguint, Fr};
use curvy_core::{eddsa, stealth};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

use crate::account::{parse_xy, Identity, OwnedNote};

/// Seal an output note to `recipient` via a real stealth send. The note's owner is
/// the recipient's account BabyJubJub key; `sharedSecret` is the x-coordinate of the
/// stealth spending pubkey, `ephemeralKey` is the announcement `R`, and `viewTag` is
/// the 2-hex-char stealth tag as a `u16`. This is the real ECDH the recipient's scan
/// rediscovers.
pub fn seal_note(recipient: &Identity, amount: Fr, token: Fr) -> Result<OwnedNote> {
    let (_r, out) = stealth::send(&recipient.big_k, &recipient.big_v)
        .map_err(|e| anyhow::anyhow!("stealth send: {e}"))?;
    let ss_x = out.spending_pub_key.split('.').next().unwrap_or("0");
    let shared_secret = curvy_core::field::fr_from_dec(ss_x);
    let ephemeral_key = parse_xy(&out.big_r)?;
    let view_tag = u16::from_str_radix(&out.view_tag, 16).unwrap_or(0);
    Ok(OwnedNote { owner_pub: recipient.bjj_pub, shared_secret, ephemeral_key, view_tag, amount, token })
}

/// A deterministic-but-run-fresh scalar from `(seed, counter)`. Seeded with the
/// shield note's random `sharedSecret`, so pads/fee-notes differ every run (avoiding
/// noteId collisions) while staying reproducible within a run for debugging.
fn fresh_scalar(seed: &[u8], counter: u64) -> BigUint {
    let mut h = Keccak256::new();
    h.update(seed);
    h.update(counter.to_le_bytes());
    BigUint::from_bytes_be(&h.finalize())
}

/// A zero-amount padding note owned by `owner_pub` (fresh secret + real ephemeral so
/// its nullifier/noteId are distinct and it is indistinguishable on-chain). Used to
/// pad inputs/outputs to the circuit's fixed arity; the circuit skips its inclusion
/// proof (amount 0).
pub fn zero_pad_note(owner_pub: (Fr, Fr), token: Fr, seed: &[u8], counter: u64) -> OwnedNote {
    OwnedNote {
        owner_pub,
        shared_secret: fr_from_biguint(&fresh_scalar(seed, counter)),
        ephemeral_key: eddsa::ephemeral_pub_key(&fresh_scalar(seed, counter.wrapping_add(1 << 20))),
        view_tag: 0,
        amount: Fr::from(0u64),
        token,
    }
}

/// The protocol fee note, owned by the on-chain `feeNotePublicKey` (BabyJubJub). Its
/// `owner_pub` MUST equal `feeNotePublicKey` (circuit constraint); its secret is a
/// fresh throwaway (the fee collector is not a party we drive in the PoC).
pub fn fee_note(fee_pub: (Fr, Fr), amount: Fr, token: Fr, seed: &[u8]) -> OwnedNote {
    OwnedNote {
        owner_pub: fee_pub,
        shared_secret: fr_from_biguint(&fresh_scalar(seed, 0xFEE1)),
        ephemeral_key: eddsa::ephemeral_pub_key(&fresh_scalar(seed, 0xFEE2)),
        view_tag: 0,
        amount,
        token,
    }
}

/// The net note amount an `autoShield` will commit, mirroring the contract exactly:
/// `net = gross − (gross*depositFeeBps/10000 + portalDeployment + pendingNoteCommitment)`
/// (integer floor). Panics only if the gross is too small to cover fees (caller picks it).
pub fn shield_net_amount(
    gross: u128,
    deposit_fee_bps: u64,
    portal_deployment: u128,
    pending_note_commitment: u128,
) -> u128 {
    let deposit_fee = gross * deposit_fee_bps as u128 / 10_000;
    let fee_amount = deposit_fee + portal_deployment + pending_note_commitment;
    gross.checked_sub(fee_amount).expect("shield gross must exceed fees")
}
