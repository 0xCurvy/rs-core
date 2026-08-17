//! Circuit witness builders for withdrawal, aggregation, and pending commitments.
//!
//! Outputs follow flat snarkjs field order and accept supplied inclusion proofs.

use ark_ff::AdditiveGroup;
use num_bigint::BigUint;
use serde::Serialize;
use zeroize::Zeroize;

use crate::cipher::encrypt_amount_token;
use crate::eddsa::{ScalarSignatureError, ScalarSigningKey, Signature, derive_public_key};
use crate::encoding::{HexDecodeError, from_hex_exact};
use crate::field::{Bn254Fr, Fr, fr_to_biguint, fr_to_dec};
use crate::hash_utils::sha256_bigint;
use crate::imt::Imt;
use crate::note as commitments;
use crate::poseidon::poseidon;

/// A note as the witness builders see it. `shared_secret`/`ephemeral_key` are
/// BabyJubjub field coordinates (`< r`); they convert to raw `BigUint` for the
/// cipher (where `< r` values pack identically).
#[derive(Clone)]
pub struct Note {
    pub amount: Fr,
    pub token: Fr,
    pub owner_pub: (Fr, Fr),
    pub shared_secret: Fr,
    pub ephemeral_key: (Fr, Fr),
    pub view_tag: Fr,
}

/// Explicit note-owner construction for profiles that already know the checked
/// BabyJubJub owner point and shared secret. Neither value is derived from the
/// other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownOwner {
    pub owner: crate::babyjubjub::BabyJubPoint,
    pub shared_secret: Bn254Fr,
}

impl KnownOwner {
    pub fn new(owner: crate::babyjubjub::BabyJubPoint, shared_secret: Bn254Fr) -> Self {
        Self {
            owner,
            shared_secret,
        }
    }

    pub fn note(self, amount: Fr, token: Fr, ephemeral_key: (Fr, Fr), view_tag: Fr) -> Note {
        Note {
            amount,
            token,
            owner_pub: self.owner.as_tuple(),
            shared_secret: self.shared_secret.into_inner(),
            ephemeral_key,
            view_tag,
        }
    }
}

impl Note {
    pub fn owner_hash(&self) -> Fr {
        commitments::owner_hash(self.owner_pub, self.shared_secret)
    }
    pub fn id(&self) -> Fr {
        commitments::note_id(self.owner_hash(), self.amount, self.token)
    }
    pub fn nullifier(&self) -> Fr {
        commitments::nullifier(self.shared_secret, self.owner_pub)
    }
    /// `flatNote`: `[owner.x, owner.y, sharedSecret, amount, token]`.
    fn flat(&self) -> Vec<String> {
        vec![
            fr_to_dec(&self.owner_pub.0),
            fr_to_dec(&self.owner_pub.1),
            fr_to_dec(&self.shared_secret),
            fr_to_dec(&self.amount),
            fr_to_dec(&self.token),
        ]
    }
    /// `(encryptedAmount, encryptedToken)` for this note's amount/token.
    fn encrypted(&self) -> (Fr, Fr) {
        let out = encrypt_amount_token(
            self.amount,
            self.token,
            &fr_to_biguint(&self.shared_secret),
            (
                &fr_to_biguint(&self.ephemeral_key.0),
                &fr_to_biguint(&self.ephemeral_key.1),
            ),
        );
        (out.encrypted_amount, out.encrypted_token)
    }
    /// `flatEncrypted`: `[encAmount, encToken, eph.x, eph.y, viewTag]`.
    fn flat_encrypted(&self) -> Vec<String> {
        let (ea, et) = self.encrypted();
        vec![
            fr_to_dec(&ea),
            fr_to_dec(&et),
            fr_to_dec(&self.ephemeral_key.0),
            fr_to_dec(&self.ephemeral_key.1),
            fr_to_dec(&self.view_tag),
        ]
    }
}

/// A supplied inclusion proof: `(leaf_index, siblings)`.
pub struct Proof {
    pub leaf_index: u64,
    pub siblings: Vec<Fr>,
}

impl Proof {
    /// `flatInclusion`: `[leafIndex, ...siblings]`.
    fn flat(&self) -> Vec<String> {
        let mut out = vec![self.leaf_index.to_string()];
        out.extend(self.siblings.iter().map(fr_to_dec));
        out
    }
}

fn flat_signature(r8: (Fr, Fr), s: &BigUint) -> [String; 3] {
    [s.to_string(), fr_to_dec(&r8.0), fr_to_dec(&r8.1)]
}

/// Source of a BabyJubJub public key and Curvy-compatible signature. Witness
/// builders consume both from the same object so a caller cannot accidentally
/// pair a signature with a different public key.
pub trait NoteSigner {
    fn public_key(&self) -> (Fr, Fr);
    fn sign(&self, message: Fr) -> Result<Signature, ScalarSignatureError>;
}

/// Seed-backed signer using BLAKE/prune key derivation.
///
/// Validates and decodes the seed at construction, so later signing is infallible.
pub struct SeedNoteSigner {
    private_key: [u8; 32],
    public_key: (Fr, Fr),
}

impl SeedNoteSigner {
    /// Derives the public point from a validated seed.
    pub fn new(private_key_hex: &str) -> Result<Self, HexDecodeError> {
        let private_key = from_hex_exact::<32>(private_key_hex)?;
        Ok(Self {
            public_key: derive_public_key(&private_key),
            private_key,
        })
    }

    /// Restores callers that store the public point separately. Prefer [`Self::new`].
    fn from_parts(private_key_hex: &str, public_key: (Fr, Fr)) -> Result<Self, HexDecodeError> {
        Ok(Self {
            private_key: from_hex_exact::<32>(private_key_hex)?,
            public_key,
        })
    }
}

impl Drop for SeedNoteSigner {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl NoteSigner for SeedNoteSigner {
    fn public_key(&self) -> (Fr, Fr) {
        self.public_key
    }

    fn sign(&self, message: Fr) -> Result<Signature, ScalarSignatureError> {
        Ok(crate::eddsa::sign(
            &fr_to_biguint(&message),
            &self.private_key,
        ))
    }
}

impl NoteSigner for ScalarSigningKey {
    fn public_key(&self) -> (Fr, Fr) {
        self.verifying_key().as_tuple()
    }

    fn sign(&self, message: Fr) -> Result<Signature, ScalarSignatureError> {
        Ok(self
            .sign_curvy_v1(Bn254Fr::from_fr(message))?
            .to_signature())
    }
}

// Withdrawal

#[derive(Serialize, PartialEq, Eq, Debug)]
pub struct WithdrawalWitness {
    #[serde(rename = "inputNotes")]
    pub input_notes: Vec<Vec<String>>,
    #[serde(rename = "publicKey")]
    pub public_key: [String; 2],
    #[serde(rename = "inputNoteInclusionProofs")]
    pub input_note_inclusion_proofs: Vec<Vec<String>>,
    pub signature: [String; 3],
    #[serde(rename = "notesRoot")]
    pub notes_root: String,
    #[serde(rename = "destinationAddress")]
    pub destination_address: String,
    #[serde(rename = "tokenId")]
    pub token_id: String,
}

/// `generateWithdrawalCircuitInputsFromNotes` + `flattenWithdrawalCircuitInputs`.
/// Signing message: `Poseidon([...nullifiers, destinationAddress, withdrawnAmount, tokenId])`.
pub fn build_withdrawal(
    notes: &[Note],
    owner_key_hex: &str,
    public_key: (Fr, Fr),
    proofs: &[Proof],
    notes_root: Fr,
    destination_address: Fr,
    token_id: Fr,
) -> Result<WithdrawalWitness, ScalarSignatureError> {
    let signer = SeedNoteSigner::from_parts(owner_key_hex, public_key)?;
    build_withdrawal_with_signer(
        notes,
        &signer,
        proofs,
        notes_root,
        destination_address,
        token_id,
    )
}

/// Build a withdrawal witness using either a seed-backed or scalar-backed signer.
/// The witness public key is always obtained from the signer.
pub fn build_withdrawal_with_signer(
    notes: &[Note],
    signer: &impl NoteSigner,
    proofs: &[Proof],
    notes_root: Fr,
    destination_address: Fr,
    token_id: Fr,
) -> Result<WithdrawalWitness, ScalarSignatureError> {
    let total: Fr = notes.iter().fold(Fr::ZERO, |a, n| a + n.amount);
    let mut msg: Vec<Fr> = notes.iter().map(|n| n.nullifier()).collect();
    msg.push(destination_address);
    msg.push(total);
    msg.push(token_id);
    let sig = signer.sign(poseidon(&msg))?;
    let public_key = signer.public_key();

    Ok(WithdrawalWitness {
        input_notes: notes.iter().map(|n| n.flat()).collect(),
        public_key: [fr_to_dec(&public_key.0), fr_to_dec(&public_key.1)],
        input_note_inclusion_proofs: proofs.iter().map(|p| p.flat()).collect(),
        signature: flat_signature(sig.r8, &sig.s),
        notes_root: fr_to_dec(&notes_root),
        destination_address: fr_to_dec(&destination_address),
        token_id: fr_to_dec(&token_id),
    })
}

// Aggregation

#[derive(Serialize, PartialEq, Eq, Debug)]
pub struct AggregationWitness {
    #[serde(rename = "inputNotes")]
    pub input_notes: Vec<Vec<String>>,
    #[serde(rename = "inputNoteInclusionProofs")]
    pub input_note_inclusion_proofs: Vec<Vec<String>>,
    #[serde(rename = "outputNotes")]
    pub output_notes: Vec<Vec<String>>,
    #[serde(rename = "publicKey")]
    pub public_key: [String; 2],
    pub signature: [String; 3],
    #[serde(rename = "feeNote")]
    pub fee_note: Vec<String>,
    #[serde(rename = "encryptedNoteData")]
    pub encrypted_note_data: Vec<Vec<String>>,
    #[serde(rename = "notesRoot")]
    pub notes_root: String,
    #[serde(rename = "protocolFeePerThousand")]
    pub protocol_fee_per_thousand: String,
    #[serde(rename = "gasFee")]
    pub gas_fee: String,
    #[serde(rename = "feeNotePublicKey")]
    pub fee_note_public_key: [String; 2],
}

/// `buildAggregationWitnessBundle` (deterministic tail) + `flattenAggregationCircuitInputs`.
/// `input_notes`/`output_notes` are already resolved + padded (no randomness here).
/// Signing message: `Poseidon([ Poseidon(outputNoteIds), Poseidon(encNoteData flat amount/token) ])`.
#[allow(clippy::too_many_arguments)]
pub fn build_aggregation(
    input_notes: &[Note],
    input_proofs: &[Proof],
    output_notes: &[Note],
    fee_note: &Note,
    owner_key_hex: &str,
    public_key: (Fr, Fr),
    notes_root: Fr,
    protocol_fee_per_thousand: Fr,
    gas_fee: Fr,
    fee_note_public_key: (Fr, Fr),
) -> Result<AggregationWitness, ScalarSignatureError> {
    let signer = SeedNoteSigner::from_parts(owner_key_hex, public_key)?;
    build_aggregation_with_signer(
        input_notes,
        input_proofs,
        output_notes,
        fee_note,
        &signer,
        notes_root,
        protocol_fee_per_thousand,
        gas_fee,
        fee_note_public_key,
    )
}

/// Build an aggregation witness using either a seed-backed or scalar-backed
/// signer. The witness public key is always obtained from the signer.
#[allow(clippy::too_many_arguments)]
pub fn build_aggregation_with_signer(
    input_notes: &[Note],
    input_proofs: &[Proof],
    output_notes: &[Note],
    fee_note: &Note,
    signer: &impl NoteSigner,
    notes_root: Fr,
    protocol_fee_per_thousand: Fr,
    gas_fee: Fr,
    fee_note_public_key: (Fr, Fr),
) -> Result<AggregationWitness, ScalarSignatureError> {
    let enc_notes: Vec<Note> = output_notes
        .iter()
        .chain(std::iter::once(fee_note))
        .cloned()
        .collect();
    let encrypted: Vec<(Fr, Fr)> = enc_notes.iter().map(|n| n.encrypted()).collect();

    let output_note_hash = poseidon(&output_notes.iter().map(|n| n.id()).collect::<Vec<_>>());
    let mut enc_flat: Vec<Fr> = Vec::with_capacity(encrypted.len() * 2);
    for (ea, et) in &encrypted {
        enc_flat.push(*ea);
        enc_flat.push(*et);
    }
    let encrypted_note_data_hash = poseidon(&enc_flat);
    let signing_hash = poseidon(&[output_note_hash, encrypted_note_data_hash]);
    let sig = signer.sign(signing_hash)?;
    let public_key = signer.public_key();

    Ok(AggregationWitness {
        input_notes: input_notes.iter().map(|n| n.flat()).collect(),
        input_note_inclusion_proofs: input_proofs.iter().map(|p| p.flat()).collect(),
        output_notes: output_notes.iter().map(|n| n.flat()).collect(),
        public_key: [fr_to_dec(&public_key.0), fr_to_dec(&public_key.1)],
        signature: flat_signature(sig.r8, &sig.s),
        fee_note: fee_note.flat(),
        encrypted_note_data: enc_notes.iter().map(|n| n.flat_encrypted()).collect(),
        notes_root: fr_to_dec(&notes_root),
        protocol_fee_per_thousand: fr_to_dec(&protocol_fee_per_thousand),
        gas_fee: fr_to_dec(&gas_fee),
        fee_note_public_key: [
            fr_to_dec(&fee_note_public_key.0),
            fr_to_dec(&fee_note_public_key.1),
        ],
    })
}

// Pending-notes commitment

#[derive(Serialize, PartialEq, Eq, Debug)]
pub struct PendingCommitmentWitness {
    #[serde(rename = "currentNoteIndex")]
    pub current_note_index: String,
    #[serde(rename = "inputHash")]
    pub input_hash: String,
    #[serde(rename = "currentNotesRoot")]
    pub current_notes_root: String,
    #[serde(rename = "pendingNoteIds")]
    pub pending_note_ids: Vec<String>,
    pub siblings: Vec<Vec<String>>,
    #[serde(rename = "newNotesRoot")]
    pub new_notes_root: String,
}

/// `generatePendingNotesCommitmentCircuitInputs`. Mutates a copy of the tree: each
/// non-zero pending id is inserted (zero ids are skip slots with zero siblings).
/// `inputHash = sha256BigInt([...paddedIds, currentRoot, newRoot, currentIndex, newIndex])`.
pub fn build_pending_commitment(
    tree: &Imt,
    tree_depth: usize,
    batch_size: usize,
    pending_note_ids: &[Fr],
) -> PendingCommitmentWitness {
    assert!(
        pending_note_ids.len() <= batch_size,
        "pending ids exceed batch size"
    );
    let current_notes_root = tree.root();
    let current_note_index = tree.leaf_count() as u64;

    let mut padded = pending_note_ids.to_vec();
    padded.resize(batch_size, Fr::ZERO);

    let mut work = tree.clone();
    let mut siblings: Vec<Vec<Fr>> = Vec::with_capacity(batch_size);
    for &id in &padded {
        if id == Fr::ZERO {
            siblings.push(vec![Fr::ZERO; tree_depth]);
            continue;
        }
        work.insert(id);
        let idx = work.leaf_count() - 1;
        siblings.push(work.create_proof(idx).siblings);
    }

    let new_notes_root = work.root();
    let new_note_index = work.leaf_count() as u64;

    let mut hash_inputs: Vec<BigUint> = padded.iter().map(fr_to_biguint).collect();
    hash_inputs.push(fr_to_biguint(&current_notes_root));
    hash_inputs.push(fr_to_biguint(&new_notes_root));
    hash_inputs.push(BigUint::from(current_note_index));
    hash_inputs.push(BigUint::from(new_note_index));
    let input_hash = sha256_bigint(&hash_inputs);

    PendingCommitmentWitness {
        current_note_index: current_note_index.to_string(),
        input_hash: input_hash.to_string(),
        current_notes_root: fr_to_dec(&current_notes_root),
        pending_note_ids: padded.iter().map(fr_to_dec).collect(),
        siblings: siblings
            .iter()
            .map(|row| row.iter().map(fr_to_dec).collect())
            .collect(),
        new_notes_root: fr_to_dec(&new_notes_root),
    }
}

#[cfg(test)]
mod seed_signer_tests {
    use super::*;
    use crate::encoding::HexDecodeError;

    const GOOD_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    /// Malformed seeds return errors without exposing key material in Debug output.
    // Use `.err()` because `SeedNoteSigner` intentionally omits `Debug`.
    #[test]
    fn malformed_seeds_are_rejected_not_panicked_on() {
        let error = SeedNoteSigner::new("0xab")
            .err()
            .expect("prefix is rejected");
        assert!(error.to_string().contains("remove the leading 0x"));

        assert_eq!(
            SeedNoteSigner::new("ab")
                .err()
                .expect("short hex is rejected"),
            HexDecodeError::WrongLength {
                expected: 32,
                actual: 1,
            }
        );
    }

    /// A constructed signer can sign without parsing again.
    #[test]
    fn a_constructed_signer_signs_infallibly() {
        let signer = SeedNoteSigner::new(GOOD_SEED).expect("well-formed seed");
        assert!(signer.sign(Fr::from(42_u8)).is_ok());
        assert_eq!(
            signer.public_key(),
            crate::eddsa::pub_from_private_key_hex(GOOD_SEED).expect("well-formed seed")
        );
    }

    /// Seed-keyed builders return parsing errors instead of panicking.
    #[test]
    fn builders_surface_malformed_seed_keys() {
        let error = build_withdrawal(
            &[],
            "0xab",
            (Fr::ZERO, Fr::ZERO),
            &[],
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
        )
        .unwrap_err();
        assert!(
            matches!(error, ScalarSignatureError::InvalidSeedKey(_)),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("invalid seed-backed signing key")
        );
    }
}
