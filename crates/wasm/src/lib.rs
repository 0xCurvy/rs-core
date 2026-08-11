#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
//!
//! ## Boundary conventions
//!
//! Seed-backed and direct-scalar signing are both supported. Scalar crypto
//! operations cross the boundary as **decimal strings** (and `Vec<String>` for
//! points / signatures), matching every existing TS wire shape.
//! Bulk Merkle operations instead use concatenated canonical 32-byte field
//! elements so thousands of nodes stay inside wasm.
//!
//! Field-element inputs reduce mod the field (`fr_from_dec`); raw 256-bit inputs
//! (cipher key material, EdDSA message, `sha256BigInt`) are parsed without
//! reduction (`dec_to_biguint`) - see the core crate for why.

use curvy_core::babyjubjub::{BabyJubPoint, BabyJubScalar};
use curvy_core::cipher::{decrypt_amount_token, encrypt_amount_token};
use curvy_core::eddsa::{
    ScalarSignature, ScalarSigningKey, ephemeral_pub_key, pub_from_private_key_hex, sign_hex,
    verify_scalar_compat,
};
use curvy_core::encoding::dec_to_biguint;
use curvy_core::field::{Bn254Fr, Fr, fr_from_be_32_checked, fr_from_dec, fr_to_be_32, fr_to_dec};
use curvy_core::hash_utils::sha256_bigint as core_sha256_bigint;
use curvy_core::imt::{
    CompletedShard, FrontierAppend, InclusionProof, IndexedMerkleTree,
    NotesFrontier as CoreNotesFrontier, OrderedMerkleTree, OwnedNoteWitness,
    ShardedNotesTree as CoreShardedNotesTree, TreeError, verify_proof,
};
use curvy_core::note;
use curvy_core::poseidon::poseidon as core_poseidon;
use curvy_core::stealth;
use wasm_bindgen::prelude::*;

// Threaded builds export `initThreadPool(n)` - call it once (after `init()`)
// on a cross-origin-isolated page before scans or bulk tree construction.
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
    fr_to_dec(&note::owner_hash(
        (fr_from_dec(&pub_x), fr_from_dec(&pub_y)),
        fr_from_dec(&shared_secret),
    ))
}

/// `id = Poseidon([ownerHash, amount, token])`.
#[wasm_bindgen(js_name = noteId)]
pub fn note_id(owner_hash: String, amount: String, token: String) -> String {
    fr_to_dec(&note::note_id(
        fr_from_dec(&owner_hash),
        fr_from_dec(&amount),
        fr_from_dec(&token),
    ))
}

/// `nullifier = Poseidon([sharedSecret, pub.x, pub.y])`.
#[wasm_bindgen]
pub fn nullifier(shared_secret: String, pub_x: String, pub_y: String) -> String {
    fr_to_dec(&note::nullifier(
        fr_from_dec(&shared_secret),
        (fr_from_dec(&pub_x), fr_from_dec(&pub_y)),
    ))
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
    vec![
        fr_to_dec(&sig.r8.0),
        fr_to_dec(&sig.r8.1),
        sig.s.to_string(),
    ]
}

/// BabyJubJub public key `[x, y] = scalar * Base8` from a canonical subgroup
/// scalar. This path performs no seed hashing, pruning, or clamping.
#[wasm_bindgen(js_name = pubFromScalar)]
pub fn pub_from_scalar(scalar: String) -> Result<Vec<String>, JsError> {
    let key = ScalarSigningKey::from_decimal(&scalar).map_err(|e| JsError::new(&e.to_string()))?;
    let public = key.verifying_key();
    Ok(vec![fr_to_dec(&public.x()), fr_to_dec(&public.y())])
}

/// Curvy-compatible direct-scalar signature `[R8.x, R8.y, S]` from a canonical
/// BabyJubjub subgroup scalar and canonical BN254 field message.
#[wasm_bindgen(js_name = signWithScalar)]
pub fn sign_with_scalar(message: String, scalar: String) -> Result<Vec<String>, JsError> {
    let message = Bn254Fr::try_from_dec(&message).map_err(|e| JsError::new(&e.to_string()))?;
    let key = ScalarSigningKey::from_decimal(&scalar).map_err(|e| JsError::new(&e.to_string()))?;
    let signature = key
        .sign_curvy_v1(message)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(vec![
        fr_to_dec(&signature.r8.x()),
        fr_to_dec(&signature.r8.y()),
        signature.s.to_dec(),
    ])
}

/// Verify a scalar-native Curvy signature. Malformed or non-canonical boundary
/// values throw; a well-formed but invalid signature returns `false`.
#[wasm_bindgen(js_name = verifyScalarSignature)]
pub fn verify_scalar_signature(
    message: String,
    public_x: String,
    public_y: String,
    r8_x: String,
    r8_y: String,
    s: String,
) -> Result<bool, JsError> {
    let message = Bn254Fr::try_from_dec(&message).map_err(|e| JsError::new(&e.to_string()))?;
    let public = BabyJubPoint::try_from_dec(&public_x, &public_y)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let r8 = BabyJubPoint::try_from_dec(&r8_x, &r8_y).map_err(|e| JsError::new(&e.to_string()))?;
    let s = BabyJubScalar::try_from_dec(&s).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(verify_scalar_compat(
        message,
        &public,
        &ScalarSignature { r8, s },
    ))
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
    vec![
        fr_to_dec(&out.encrypted_amount),
        fr_to_dec(&out.encrypted_token),
    ]
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
    let (amount, token) = decrypt_amount_token(
        fr_from_dec(&encrypted_amount),
        fr_from_dec(&encrypted_token),
        &ss,
        (&ex, &ey),
    );
    vec![fr_to_dec(&amount), fr_to_dec(&token)]
}

/// `sha256BigInt`: raw 256-bit decimal inputs -> decimal digest (no field reduction).
#[wasm_bindgen(js_name = sha256BigInt)]
pub fn sha256_bigint(inputs: Vec<String>) -> String {
    let ints: Vec<_> = inputs.iter().map(|s| dec_to_biguint(s)).collect();
    core_sha256_bigint(&ints).to_string()
}

// ── Stateful sharded notes tree ──────────────────────────────────────────────

/// Generic incremental Merkle tree with a reverse leaf index.
#[wasm_bindgen(js_name = MerkleTree)]
pub struct WasmMerkleTree {
    inner: IndexedMerkleTree,
}

#[wasm_bindgen(js_class = MerkleTree)]
impl WasmMerkleTree {
    #[wasm_bindgen(constructor)]
    pub fn new(depth: u32) -> Result<WasmMerkleTree, JsError> {
        Ok(Self {
            inner: IndexedMerkleTree::new(depth as usize).map_err(js_tree_error)?,
        })
    }

    #[wasm_bindgen(js_name = fromLeaves)]
    pub fn from_leaves(depth: u32, packed_leaves: &[u8]) -> Result<WasmMerkleTree, JsError> {
        Ok(Self {
            inner: IndexedMerkleTree::from_leaves(
                depth as usize,
                &decode_fields(packed_leaves, "leaves")?,
            )
            .map_err(js_tree_error)?,
        })
    }

    pub fn insert(&mut self, leaf: &[u8]) -> Result<u32, JsError> {
        let index = self
            .inner
            .insert(decode_field(leaf, "leaf")?)
            .map_err(js_tree_error)?;
        Ok(index as u32)
    }

    #[wasm_bindgen(js_name = insertMany)]
    pub fn insert_many(&mut self, packed_leaves: &[u8]) -> Result<(), JsError> {
        self.inner
            .insert_many(&decode_fields(packed_leaves, "leaves")?)
            .map_err(js_tree_error)
    }

    #[wasm_bindgen(js_name = getIndex)]
    pub fn get_index(&self, leaf: &[u8]) -> Result<Option<u32>, JsError> {
        Ok(self
            .inner
            .get_index(decode_field(leaf, "leaf")?)
            .map(|index| index as u32))
    }

    pub fn proof(&self, leaf: &[u8]) -> Result<WasmInclusionProof, JsError> {
        Ok(WasmInclusionProof(
            self.inner
                .create_proof(decode_field(leaf, "leaf")?)
                .map_err(js_tree_error)?,
        ))
    }

    #[wasm_bindgen(js_name = proofAt)]
    pub fn proof_at(&self, index: u32) -> Result<WasmInclusionProof, JsError> {
        Ok(WasmInclusionProof(
            self.inner
                .create_proof_at(index as usize)
                .map_err(js_tree_error)?,
        ))
    }

    pub fn truncate(&mut self, leaf_count: u32) -> Result<(), JsError> {
        self.inner
            .truncate(leaf_count as usize)
            .map_err(js_tree_error)
    }

    pub fn root(&self) -> Vec<u8> {
        fr_to_be_32(&self.inner.root()).to_vec()
    }

    pub fn leaves(&self) -> Vec<u8> {
        pack_fields(self.inner.leaves())
    }

    #[wasm_bindgen(getter)]
    pub fn depth(&self) -> u32 {
        self.inner.depth() as u32
    }

    #[wasm_bindgen(getter, js_name = leafCount)]
    pub fn leaf_count(&self) -> u32 {
        self.inner.leaf_count() as u32
    }
}

/// Position-addressed tree for public vectors whose values may repeat.
#[wasm_bindgen(js_name = OrderedMerkleTree)]
pub struct WasmOrderedMerkleTree {
    inner: OrderedMerkleTree,
}

#[wasm_bindgen(js_class = OrderedMerkleTree)]
impl WasmOrderedMerkleTree {
    #[wasm_bindgen(constructor)]
    pub fn new(depth: u32) -> Result<WasmOrderedMerkleTree, JsError> {
        Ok(Self {
            inner: OrderedMerkleTree::new(depth as usize).map_err(js_tree_error)?,
        })
    }

    #[wasm_bindgen(js_name = fromLeaves)]
    pub fn from_leaves(depth: u32, packed_leaves: &[u8]) -> Result<WasmOrderedMerkleTree, JsError> {
        Ok(Self {
            inner: OrderedMerkleTree::from_leaves(
                depth as usize,
                &decode_fields(packed_leaves, "leaves")?,
            )
            .map_err(js_tree_error)?,
        })
    }

    pub fn insert(&mut self, leaf: &[u8]) -> Result<u32, JsError> {
        let index = self
            .inner
            .insert(decode_field(leaf, "leaf")?)
            .map_err(js_tree_error)?;
        Ok(index as u32)
    }

    #[wasm_bindgen(js_name = insertMany)]
    pub fn insert_many(&mut self, packed_leaves: &[u8]) -> Result<(), JsError> {
        self.inner
            .insert_many(&decode_fields(packed_leaves, "leaves")?)
            .map_err(js_tree_error)
    }

    #[wasm_bindgen(js_name = proofAt)]
    pub fn proof_at(&self, index: u32) -> Result<WasmInclusionProof, JsError> {
        Ok(WasmInclusionProof(
            self.inner
                .create_proof_at(index as usize)
                .map_err(js_tree_error)?,
        ))
    }

    pub fn root(&self) -> Vec<u8> {
        fr_to_be_32(&self.inner.root()).to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn depth(&self) -> u32 {
        self.inner.depth() as u32
    }

    #[wasm_bindgen(getter, js_name = leafCount)]
    pub fn leaf_count(&self) -> u32 {
        self.inner.leaf_count() as u32
    }
}

/// Verify a packed conventional inclusion proof without reimplementing
/// Poseidon/path ordering in JavaScript.
#[wasm_bindgen(js_name = verifyMerkleProof)]
pub fn verify_merkle_proof(
    leaf: &[u8],
    index: u32,
    packed_siblings: &[u8],
    root: &[u8],
) -> Result<bool, JsError> {
    Ok(verify_proof(&InclusionProof {
        leaf: decode_field(leaf, "leaf")?,
        index: index as usize,
        siblings: decode_fields(packed_siblings, "siblings")?,
        root: decode_field(root, "root")?,
    }))
}

/// Constant-space append frontier. It retains no
/// leaves or witnesses and emits a shard descriptor only at an exact boundary.
#[wasm_bindgen(js_name = NotesFrontier)]
pub struct WasmNotesFrontier {
    inner: CoreNotesFrontier,
}

#[wasm_bindgen(js_class = NotesFrontier)]
impl WasmNotesFrontier {
    #[wasm_bindgen(constructor)]
    pub fn new(depth: u32, shard_height: u32) -> Result<WasmNotesFrontier, JsError> {
        Ok(Self {
            inner: CoreNotesFrontier::new(depth as usize, shard_height as usize)
                .map_err(js_tree_error)?,
        })
    }

    /// An empty frontier with the production notes-tree geometry, so callers
    /// stop restating `depth = 30` / `shardHeight = 14` on the JS side.
    #[wasm_bindgen(js_name = production)]
    pub fn production() -> WasmNotesFrontier {
        Self {
            inner: CoreNotesFrontier::production(),
        }
    }

    #[wasm_bindgen(js_name = restore)]
    pub fn restore(snapshot: &[u8]) -> Result<WasmNotesFrontier, JsError> {
        Ok(Self {
            inner: CoreNotesFrontier::from_snapshot_bytes(snapshot).map_err(js_tree_error)?,
        })
    }

    pub fn append(&mut self, leaf: &[u8]) -> Result<WasmFrontierAppend, JsError> {
        Ok(WasmFrontierAppend(
            self.inner
                .append(decode_field(leaf, "leaf")?)
                .map_err(js_tree_error)?,
        ))
    }

    #[wasm_bindgen(js_name = appendMany)]
    pub fn append_many(
        &mut self,
        packed_leaves: &[u8],
    ) -> Result<Vec<WasmCompletedShard>, JsError> {
        Ok(self
            .inner
            .append_many(&decode_fields(packed_leaves, "leaves")?)
            .map_err(js_tree_error)?
            .into_iter()
            .map(WasmCompletedShard)
            .collect())
    }

    pub fn root(&self) -> Vec<u8> {
        fr_to_be_32(&self.inner.root()).to_vec()
    }

    pub fn snapshot(&self) -> Vec<u8> {
        self.inner.encode_snapshot()
    }

    #[wasm_bindgen(getter)]
    pub fn depth(&self) -> u32 {
        self.inner.depth() as u32
    }

    #[wasm_bindgen(getter, js_name = shardHeight)]
    pub fn shard_height(&self) -> u32 {
        self.inner.shard_height() as u32
    }

    #[wasm_bindgen(getter, js_name = shardSize)]
    pub fn shard_size(&self) -> u32 {
        self.inner.shard_size() as u32
    }

    #[wasm_bindgen(getter, js_name = leafCount)]
    pub fn leaf_count(&self) -> u32 {
        self.inner.leaf_count() as u32
    }

    #[wasm_bindgen(getter, js_name = shardCount)]
    pub fn shard_count(&self) -> u32 {
        self.inner.shard_count() as u32
    }
}

/// Protocol notes-tree parameters, exported so JavaScript consumers read them
/// from the core rather than hardcoding a second copy.
#[wasm_bindgen(js_name = notesTreeDepth)]
pub fn notes_tree_depth() -> u32 {
    curvy_core::NOTES_TREE_DEPTH as u32
}

#[wasm_bindgen(js_name = notesShardHeight)]
pub fn notes_shard_height() -> u32 {
    curvy_core::NOTES_SHARD_HEIGHT as u32
}

#[wasm_bindgen(js_name = notesShardSize)]
pub fn notes_shard_size() -> u32 {
    curvy_core::NOTES_SHARD_SIZE as u32
}

#[wasm_bindgen(js_name = notesTreeVersion)]
pub fn notes_tree_version() -> u32 {
    curvy_core::NOTES_TREE_VERSION
}

#[wasm_bindgen(js_name = NotesFrontierAppend)]
pub struct WasmFrontierAppend(FrontierAppend);

#[wasm_bindgen(js_class = NotesFrontierAppend)]
impl WasmFrontierAppend {
    #[wasm_bindgen(getter, js_name = leafIndex)]
    pub fn leaf_index(&self) -> u32 {
        self.0.leaf_index as u32
    }

    #[wasm_bindgen(getter, js_name = hasCompletedShard)]
    pub fn has_completed_shard(&self) -> bool {
        self.0.completed_shard.is_some()
    }

    #[wasm_bindgen(getter, js_name = completedShardIndex)]
    pub fn completed_shard_index(&self) -> Option<u32> {
        self.0
            .completed_shard
            .as_ref()
            .map(|shard| shard.shard_index as u32)
    }

    #[wasm_bindgen(getter, js_name = completedShardRoot)]
    pub fn completed_shard_root(&self) -> Vec<u8> {
        self.0
            .completed_shard
            .as_ref()
            .map(|shard| fr_to_be_32(&shard.root).to_vec())
            .unwrap_or_default()
    }
}

#[wasm_bindgen(js_name = NotesFrontierCompletedShard)]
pub struct WasmCompletedShard(CompletedShard);

#[wasm_bindgen(js_class = NotesFrontierCompletedShard)]
impl WasmCompletedShard {
    #[wasm_bindgen(getter, js_name = shardIndex)]
    pub fn shard_index(&self) -> u32 {
        self.0.shard_index as u32
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        fr_to_be_32(&self.0.root).to_vec()
    }
}

/// Rust-owned sharded notes tree. Field elements cross this bulk boundary as
/// canonical packed 32-byte big-endian values, avoiding one JS↔wasm call and one
/// decimal-string allocation per Poseidon node.
#[wasm_bindgen(js_name = ShardedNotesTree)]
pub struct WasmShardedNotesTree {
    inner: CoreShardedNotesTree,
}

#[wasm_bindgen(js_class = ShardedNotesTree)]
impl WasmShardedNotesTree {
    #[wasm_bindgen(constructor)]
    pub fn new(depth: u32, shard_height: u32) -> Result<WasmShardedNotesTree, JsError> {
        Ok(Self {
            inner: CoreShardedNotesTree::new(depth as usize, shard_height as usize)
                .map_err(js_tree_error)?,
        })
    }

    /// Restore a versioned snapshot previously returned by [`Self::snapshot`].
    #[wasm_bindgen(js_name = restore)]
    pub fn restore(snapshot: &[u8]) -> Result<WasmShardedNotesTree, JsError> {
        Ok(Self {
            inner: CoreShardedNotesTree::from_snapshot_bytes(snapshot).map_err(js_tree_error)?,
        })
    }

    /// Restore public tree state from storage tables before account-scoped
    /// witnesses are marked/adopted.
    #[wasm_bindgen(js_name = restoreParts)]
    pub fn restore_parts(
        depth: u32,
        shard_height: u32,
        packed_completed_roots: &[u8],
        packed_live_leaves: &[u8],
    ) -> Result<WasmShardedNotesTree, JsError> {
        Ok(Self {
            inner: CoreShardedNotesTree::from_parts(
                depth as usize,
                shard_height as usize,
                decode_fields(packed_completed_roots, "completed shard roots")?,
                decode_fields(packed_live_leaves, "live leaves")?,
            )
            .map_err(js_tree_error)?,
        })
    }

    /// Append one canonical 32-byte note commitment.
    pub fn append(&mut self, note_id: &[u8]) -> Result<(), JsError> {
        self.inner
            .append(decode_field(note_id, "note id")?)
            .map_err(js_tree_error)
    }

    /// Append `N` concatenated 32-byte note commitments in one wasm call.
    #[wasm_bindgen(js_name = appendMany)]
    pub fn append_many(&mut self, packed_note_ids: &[u8]) -> Result<(), JsError> {
        let note_ids = decode_fields(packed_note_ids, "note ids")?;
        self.inner.append_many(&note_ids).map_err(js_tree_error)
    }

    #[wasm_bindgen(js_name = markOwned)]
    pub fn mark_owned(&mut self, note_id: &[u8], leaf_index: u32) -> Result<(), JsError> {
        self.inner
            .mark_owned(decode_field(note_id, "note id")?, leaf_index as usize)
            .map_err(js_tree_error)
    }

    #[wasm_bindgen(js_name = unmarkOwned)]
    pub fn unmark_owned(&mut self, note_id: &[u8]) -> Result<bool, JsError> {
        Ok(self.inner.unmark_owned(decode_field(note_id, "note id")?))
    }

    #[wasm_bindgen(js_name = adoptFrozenWitness)]
    pub fn adopt_frozen_witness(
        &mut self,
        note_id: &[u8],
        leaf_index: u32,
        packed_siblings: &[u8],
    ) -> Result<(), JsError> {
        self.inner
            .adopt_frozen_witness(
                decode_field(note_id, "note id")?,
                leaf_index as usize,
                decode_fields(packed_siblings, "within-shard siblings")?,
            )
            .map_err(js_tree_error)
    }

    pub fn witness(&self, note_id: &[u8]) -> Result<WasmInclusionProof, JsError> {
        Ok(WasmInclusionProof(
            self.inner
                .witness(decode_field(note_id, "note id")?)
                .map_err(js_tree_error)?,
        ))
    }

    /// Rewind only within the current live shard. Restore an earlier persisted
    /// snapshot when a rollback crosses a completed-shard boundary.
    #[wasm_bindgen(js_name = rewindLiveTo)]
    pub fn rewind_live_to(&mut self, leaf_count: u32) -> Result<Vec<u8>, JsError> {
        let removed = self
            .inner
            .rewind_live_to(leaf_count as usize)
            .map_err(js_tree_error)?;
        Ok(pack_fields(&removed))
    }

    pub fn root(&self) -> Vec<u8> {
        fr_to_be_32(&self.inner.root()).to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn depth(&self) -> u32 {
        self.inner.depth() as u32
    }

    #[wasm_bindgen(getter, js_name = shardHeight)]
    pub fn shard_height(&self) -> u32 {
        self.inner.shard_height() as u32
    }

    #[wasm_bindgen(getter, js_name = shardSize)]
    pub fn shard_size(&self) -> u32 {
        self.inner.shard_size() as u32
    }

    #[wasm_bindgen(getter, js_name = leafCount)]
    pub fn leaf_count(&self) -> u32 {
        self.inner.leaf_count() as u32
    }

    #[wasm_bindgen(getter, js_name = completedShardCount)]
    pub fn completed_shard_count(&self) -> u32 {
        self.inner.completed_shard_count() as u32
    }

    #[wasm_bindgen(getter, js_name = ownedNoteCount)]
    pub fn owned_note_count(&self) -> u32 {
        self.inner.owned_note_count() as u32
    }

    #[wasm_bindgen(js_name = completedShardRoots)]
    pub fn completed_shard_roots(&self) -> Vec<u8> {
        pack_fields(self.inner.completed_roots())
    }

    #[wasm_bindgen(js_name = completedShardRoot)]
    pub fn completed_shard_root(&self, shard_index: u32) -> Result<Vec<u8>, JsError> {
        Ok(fr_to_be_32(
            &self
                .inner
                .completed_shard_root(shard_index as usize)
                .map_err(js_tree_error)?,
        )
        .to_vec())
    }

    #[wasm_bindgen(js_name = liveLeaves)]
    pub fn live_leaves(&self) -> Vec<u8> {
        pack_fields(self.inner.live_leaves())
    }

    #[wasm_bindgen(js_name = drainDirtyOwnedNotes)]
    pub fn drain_dirty_owned_notes(&mut self) -> Vec<WasmOwnedNoteWitness> {
        self.inner
            .drain_dirty_owned_notes()
            .into_iter()
            .map(WasmOwnedNoteWitness)
            .collect()
    }

    #[wasm_bindgen(js_name = ownedNotes)]
    pub fn owned_notes(&self) -> Vec<WasmOwnedNoteWitness> {
        self.inner
            .owned_notes()
            .into_iter()
            .map(WasmOwnedNoteWitness)
            .collect()
    }

    /// Deterministic versioned binary state. Storage layers should associate
    /// chain/deployment/block metadata with this opaque tree blob.
    pub fn snapshot(&self) -> Result<Vec<u8>, JsError> {
        self.inner.encode_snapshot().map_err(js_tree_error)
    }
}

#[wasm_bindgen(js_name = ShardedInclusionProof)]
pub struct WasmInclusionProof(InclusionProof);

#[wasm_bindgen(js_class = ShardedInclusionProof)]
impl WasmInclusionProof {
    #[wasm_bindgen(getter)]
    pub fn leaf(&self) -> Vec<u8> {
        fr_to_be_32(&self.0.leaf).to_vec()
    }

    #[wasm_bindgen(getter)]
    pub fn index(&self) -> u32 {
        self.0.index as u32
    }

    #[wasm_bindgen(getter)]
    pub fn siblings(&self) -> Vec<u8> {
        pack_fields(&self.0.siblings)
    }

    #[wasm_bindgen(getter)]
    pub fn root(&self) -> Vec<u8> {
        fr_to_be_32(&self.0.root).to_vec()
    }
}

#[wasm_bindgen(js_name = ShardedOwnedNoteWitness)]
pub struct WasmOwnedNoteWitness(OwnedNoteWitness);

#[wasm_bindgen(js_class = ShardedOwnedNoteWitness)]
impl WasmOwnedNoteWitness {
    #[wasm_bindgen(getter, js_name = noteId)]
    pub fn note_id(&self) -> Vec<u8> {
        fr_to_be_32(&self.0.note_id).to_vec()
    }

    #[wasm_bindgen(getter, js_name = leafIndex)]
    pub fn leaf_index(&self) -> u32 {
        self.0.leaf_index as u32
    }

    #[wasm_bindgen(getter)]
    pub fn frozen(&self) -> bool {
        self.0.within_shard_siblings.is_some()
    }

    #[wasm_bindgen(getter, js_name = withinShardSiblings)]
    pub fn within_shard_siblings(&self) -> Vec<u8> {
        self.0
            .within_shard_siblings
            .as_deref()
            .map(pack_fields)
            .unwrap_or_default()
    }
}

fn decode_field(bytes: &[u8], what: &str) -> Result<Fr, JsError> {
    fr_from_be_32_checked(bytes).ok_or_else(|| {
        JsError::new(&format!(
            "sharded tree: {what} must be one canonical 32-byte big-endian field element",
        ))
    })
}

fn decode_fields(bytes: &[u8], what: &str) -> Result<Vec<Fr>, JsError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(JsError::new(&format!(
            "sharded tree: packed {what} length {} is not divisible by 32",
            bytes.len(),
        )));
    }
    bytes
        .chunks_exact(32)
        .map(|raw| decode_field(raw, what))
        .collect()
}

fn pack_fields(fields: &[Fr]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(fields.len() * 32);
    for field in fields {
        packed.extend_from_slice(&fr_to_be_32(field));
    }
    packed
}

fn js_tree_error(error: TreeError) -> JsError {
    JsError::new(&error.to_string())
}

// ── Domain A: the stealth core. Typed params in, plain decimal/hex string values
// out - NO JSON envelope; wasm-bindgen passes structured values directly.
// Multi-value results use `Vec<String>` - the same positional convention Domain B
// uses for points and signatures - except `scan`, which returns its two PAIRED
// arrays via a small typed result. Points are "x.y"; view tags and private keys
// are hex.

#[wasm_bindgen]
pub fn version() -> String {
    "v1.0.2".to_string()
}

/// Fresh random meta-keys `[k, v, K, V]` = spend priv, view priv, spend pub, view pub.
#[wasm_bindgen]
pub fn new_meta() -> Result<Vec<String>, JsError> {
    let (k, v, big_k, big_v) = stealth::new_meta()?;
    Ok(vec![k, v, big_k, big_v])
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
/// positives) - the caller's note-commitment recompute confirms ownership.
/// Malformed / off-curve announcements are non-matches (skipped), never fatal;
/// throws only on the caller's own inputs (keys, mismatched array lengths).
#[wasm_bindgen]
pub fn scan(
    k: String,
    v: String,
    rs: Vec<String>,
    view_tags: Vec<String>,
) -> Result<Vec<ScanMatch>, JsError> {
    Ok(stealth::scan(&k, &v, &rs, &view_tags)?
        .into_iter()
        .map(ScanMatch)
        .collect())
}

/// Viewer scan (view key `v` + recipient spend pub `K`, no spend key): the same
/// sparse candidate list, spending PUBLIC keys only.
#[wasm_bindgen(js_name = viewerScan)]
pub fn viewer_scan(
    v: String,
    big_k: String,
    rs: Vec<String>,
    view_tags: Vec<String>,
) -> Result<Vec<ViewerMatch>, JsError> {
    Ok(stealth::viewer_scan(&v, &big_k, &rs, &view_tags)?
        .into_iter()
        .map(ViewerMatch)
        .collect())
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
