//! `CurvyClient` — the thin facade that drives shield → commit → aggregate → scan
//! over the L2 trait objects, `curvy-abi` calldata/signing, and `curvy-witnesscalc`
//! proving. All crypto/proving runs under `spawn_blocking` so tokio is never blocked.
//! Minimal in-memory storage (the mirrored global IMT leaf log).

use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use curvy_core::cipher::decrypt_amount_token;
use curvy_core::field::{fr_from_biguint, fr_from_dec, fr_to_biguint, fr_to_dec, Fr};
use curvy_core::imt::Imt;
use curvy_core::note::{note_id, owner_hash};
use curvy_core::stealth;
use curvy_core::witness::{build_aggregation, build_pending_commitment, Proof};
use curvy_types::{FeeConfig, OnchainNote, TxOutcome};
use num_bigint::BigUint;

use curvy_chain_api::{
    BalanceReader, FeeConfigSource, NoteIndexSource, PortalDirectory, RootAnchor, TxSubmitter,
};

use crate::account::{Account, Identity, OwnedNote};
use crate::send::{fee_note, seal_note, shield_net_amount, zero_pad_note};

const TREE_DEPTH: usize = 30;
const BATCH_SIZE: usize = 5;
const MAX_INPUTS: u64 = 2;
const MAX_OUTPUTS: u64 = 3;

// value ⇄ Fr helpers
fn u128_fr(x: u128) -> Fr {
    fr_from_biguint(&BigUint::from(x))
}
fn fr_u128(x: &Fr) -> Result<u128> {
    fr_to_biguint(x).try_into().context("field element does not fit in u128")
}

/// Which submitter to route a tx through.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// blokli `sendTransactionSync` (the primary M2 path).
    Blokli,
    /// direct `eth_sendRawTransaction` (the fallback / operator path).
    Direct,
}

/// A discovered note (post integrity-gate).
#[derive(Clone, Debug)]
pub struct Discovered {
    pub note_id: Fr,
    pub amount: Fr,
    pub token: Fr,
    pub shared_secret: Fr,
    pub is_plaintext: bool,
}

/// A per-tx ledger entry.
#[derive(Clone, Debug)]
pub struct TxLedger {
    pub label: String,
    pub backend: String,
    pub tx_hash: String,
}

#[derive(Default)]
struct Storage {
    /// The committed global-IMT leaf log (note ids in insertion order) — mirrors chain.
    tree_leaves: Vec<Fr>,
}

/// The injected adapter mix. Kept as separate `Arc<dyn …>` so the seam is real: the
/// same `RpcChain` can back several of these, but the client only ever sees traits.
pub struct CurvyClient {
    pub blokli: Arc<dyn TxSubmitter>,
    pub direct: Arc<dyn TxSubmitter>,
    pub notes: Arc<dyn NoteIndexSource>,
    pub anchor: Arc<dyn RootAnchor>,
    pub fees: Arc<dyn FeeConfigSource>,
    pub balances: Arc<dyn BalanceReader>,
    pub portals: Arc<dyn PortalDirectory>,
    pub aggregator: String,
    pub portal_factory: String,
    pub chain_id: u64,
    storage: Mutex<Storage>,
}

impl CurvyClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        blokli: Arc<dyn TxSubmitter>,
        direct: Arc<dyn TxSubmitter>,
        notes: Arc<dyn NoteIndexSource>,
        anchor: Arc<dyn RootAnchor>,
        fees: Arc<dyn FeeConfigSource>,
        balances: Arc<dyn BalanceReader>,
        portals: Arc<dyn PortalDirectory>,
        aggregator: String,
        portal_factory: String,
        chain_id: u64,
    ) -> Self {
        Self {
            blokli,
            direct,
            notes,
            anchor,
            fees,
            balances,
            portals,
            aggregator,
            portal_factory,
            chain_id,
            storage: Mutex::new(Storage::default()),
        }
    }

    /// The aggregator's live tree state (trust anchor), as an anyhow result.
    pub async fn anchor_state(&self) -> Result<curvy_types::AggregatorState> {
        self.anchor.state().await.map_err(|e| anyhow::anyhow!(e))
    }

    /// An EOA's native balance in wei (for end-of-flow asserts).
    pub async fn eth_balance(&self, addr: &str) -> Result<u128> {
        let dec = self.balances.eth_balance(&addr.to_string()).await.map_err(|e| anyhow::anyhow!(e))?;
        dec.parse().context("parse eth balance")
    }

    fn submitter(&self, route: Route) -> &Arc<dyn TxSubmitter> {
        match route {
            Route::Blokli => &self.blokli,
            Route::Direct => &self.direct,
        }
    }

    /// Build, locally sign, and submit a call. Nonce/gas-price read via `BalanceReader`;
    /// signing in `curvy-abi` (no alloy here). Returns the outcome + a ledger row.
    async fn submit_call(
        &self,
        signer_priv: &str,
        to: &str,
        calldata: Vec<u8>,
        value: &str,
        gas_limit: u64,
        route: Route,
        label: &str,
    ) -> Result<(TxOutcome, TxLedger)> {
        let signer_addr = curvy_abi::address_of(signer_priv)?;
        let nonce = self.balances.tx_count(&signer_addr).await?;
        let gas_price = self.balances.gas_price().await?.saturating_mul(2);
        let raw = curvy_abi::sign_call_tx(
            signer_priv, to, calldata, value, nonce, gas_limit, gas_price, self.chain_id,
        )?;
        let sub = self.submitter(route);
        let outcome = sub.submit(&raw).await.with_context(|| format!("{label} submit"))?;
        if !outcome.status {
            bail!("{label}: tx {} reverted", outcome.tx_hash);
        }
        let ledger = TxLedger {
            label: label.to_string(),
            backend: sub.backend().to_string(),
            tx_hash: outcome.tx_hash.clone(),
        };
        Ok((outcome, ledger))
    }

    // ── Step 1: shield ──────────────────────────────────────────────────────────

    /// Enter the pool: pre-fund the deterministic entry portal, then
    /// `deployShieldPortal` (which forwards the ETH to `autoShield`). Returns the
    /// committed note (amount = the net after on-chain fees) and the ledger rows.
    pub async fn shield(
        &self,
        recipient: &Account,
        gross: u128,
        token: u64,
        operator_priv: &str,
        recovery: &str,
        route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        let fees = self.fees.fees().await?;
        let token_fr = Fr::from(token);
        let token_dec = token.to_string();

        // Seal a note to the recipient (ownerHash depends only on owner+sharedSecret,
        // not amount — so the gross here does not affect it).
        let sealed = seal_note(&recipient.identity(), u128_fr(gross), token_fr)?;
        let owner_hash_dec = fr_to_dec(&sealed.owner_hash());

        let portal_deployment = fees
            .per_token_gas_fees
            .iter()
            .find(|g| g.token_id == token_dec)
            .map(|g| g.portal_deployment.parse::<u128>().unwrap_or(0))
            .unwrap_or(0);
        let pending_commit = fees.gas_fee_for(&token_dec).parse::<u128>().unwrap_or(0);
        let net = shield_net_amount(gross, fees.deposit_fee_bps, portal_deployment, pending_commit);

        let onchain = OnchainNote {
            owner_hash: owner_hash_dec.clone(),
            token: token_dec,
            amount: gross.to_string(),
            ephemeral_key: [
                fr_to_dec(&sealed.ephemeral_key.0),
                fr_to_dec(&sealed.ephemeral_key.1),
            ],
            view_tag: sealed.view_tag as u64,
        };

        // Pre-fund the predicted entry-portal address with the gross ETH.
        let portal_addr = self.portals.entry_portal_address(&owner_hash_dec, &recovery.to_string()).await?;
        let mut ledger = Vec::new();
        let (_f, l1) = self
            .submit_call(operator_priv, &portal_addr, vec![], &gross.to_string(), 60_000, route, "shield:fund-portal")
            .await?;
        ledger.push(l1);

        // Deploy + shield (operator holds OPERATOR_ROLE).
        let calldata = curvy_abi::encode_deploy_shield_portal(&onchain, recovery)?;
        let (_d, l2) = self
            .submit_call(operator_priv, &self.portal_factory, calldata, "0", 2_000_000, route, "shield:deploy+shield")
            .await?;
        ledger.push(l2);

        // The committed note carries the NET amount (what autoShield's noteId hashes).
        let committed = OwnedNote { amount: u128_fr(net), ..sealed };

        // Verify: the aggregator emitted a PendingNotes with this noteId.
        let head = self.notes.head_block().await?;
        let want = fr_to_dec(&committed.note_id());
        let seen = self
            .notes
            .pending_notes(0, head)
            .await?
            .iter()
            .any(|e| e.note_ids.iter().any(|n| *n == want));
        if !seen {
            bail!("shield: PendingNotes for noteId {want} not found on-chain");
        }
        Ok((committed, ledger))
    }

    // ── sync: rebuild the mirrored IMT from CommittedNotes + reconcile the root ───

    /// Fold `CommittedNotes` into the local IMT and reconcile against the chain root
    /// (the trust anchor). Tolerates index-ahead-of-root on fast blocks (plan risk 8)
    /// with a short retry. Returns the reconciled leaf log.
    pub async fn sync(&self) -> Result<Vec<Fr>> {
        let head = self.notes.head_block().await?;
        let mut committed = self.notes.committed_notes(0, head).await?;
        committed.sort_by_key(|e| e.batch_index);
        let mut leaves = Vec::new();
        for ev in &committed {
            for id in &ev.note_ids {
                let f = fr_from_dec(id);
                if f != Fr::from(0u64) {
                    leaves.push(f);
                }
            }
        }
        // Reconcile with the on-chain root (retry a few times for index/root lag).
        let local_root = fr_to_dec(&Imt::from_leaves(TREE_DEPTH, &leaves).root());
        let mut reconciled = false;
        for _ in 0..5 {
            let state = self.anchor.state().await?;
            if state.current_notes_root == local_root {
                reconciled = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
        if !reconciled {
            bail!(
                "sync: local IMT root {local_root} does not reconcile with chain root after retries"
            );
        }
        self.storage.lock().unwrap().tree_leaves = leaves.clone();
        Ok(leaves)
    }

    // ── Step 2: commit pending notes ──────────────────────────────────────────────

    /// Commit a batch of pending note ids into the notes tree (batch-prover role,
    /// client-side). Proves the pending-commitment circuit, calls `commitPendingNotes`,
    /// and verifies the chain root advanced to the new root.
    pub async fn commit(
        &self,
        pending_ids: &[Fr],
        operator_priv: &str,
        route: Route,
    ) -> Result<Vec<TxLedger>> {
        let leaves = self.sync().await?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);

        let witness = build_pending_commitment(&tree, TREE_DEPTH, BATCH_SIZE, pending_ids);
        let note_ids = witness.pending_note_ids.clone(); // padded batch (order matters on-chain)
        let new_root = witness.new_notes_root.clone();
        let (input_json, _reduced) = curvy_witnesscalc::pending::to_circuit_input(&witness)?;

        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::pending().prove(&input_json)
        })
        .await
        .context("join prove")??;
        let proof = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;

        let calldata =
            curvy_abi::encode_commit_pending_notes(BATCH_SIZE as u64, &note_ids, &new_root, &proof)?;
        let (_o, ledger) = self
            .submit_call(operator_priv, &self.aggregator, calldata, "0", 2_000_000, route, "commit")
            .await?;

        // Verify the chain advanced to new_root and it is now a valid root.
        let state = self.anchor.state().await?;
        if state.current_notes_root != new_root {
            bail!("commit: chain root {} != new root {new_root}", state.current_notes_root);
        }
        if !self.anchor.is_valid_notes_root(&new_root).await? {
            bail!("commit: new root {new_root} not marked valid");
        }
        Ok(vec![ledger])
    }

    // ── Step 3: aggregate (spend note → recipient + change + fee) ─────────────────

    /// Spend `note_a` (owned by `spender`) against the committed notes root, sending
    /// `amount_to_b` to `recipient` (real stealth send) with change back to the
    /// spender and the protocol fee note. Proves aggregation(2,3,30,6), submits
    /// `submitAggregationRequest` through the chosen route (blokli for the M2 exit),
    /// and returns the sealed B-note (for the scan step) + the ledger.
    #[allow(clippy::too_many_arguments)]
    pub async fn aggregate(
        &self,
        spender: &Account,
        note_a: &OwnedNote,
        recipient: &Identity,
        amount_to_b: u128,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(OwnedNote, Vec<TxLedger>)> {
        let fees = self.fees.fees().await?;
        let token = note_a.token;
        let token_dec = fr_to_dec(&token);

        // Inclusion proof for note_a against the committed root.
        let leaves = self.sync().await?;
        let note_a_id = note_a.note_id();
        let idx = leaves
            .iter()
            .position(|l| *l == note_a_id)
            .context("aggregate: note A not found in committed tree (commit first?)")?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);
        let notes_root = tree.root();
        let a_proof = Proof { leaf_index: idx as u64, siblings: tree.create_proof(idx).siblings };

        // Value math (mirror the circuit + TS witnessFromNotes).
        let net = fr_u128(&note_a.amount)?;
        let gas_fee: u128 = fees.gas_fee_for(&token_dec).parse().unwrap_or(0);
        let protocol_fee_per_thousand: u128 = fees.protocol_fee_per_thousand.parse().unwrap_or(0);
        let spent_to_others = amount_to_b; // B != spender
        let fee_amount = gas_fee + spent_to_others * protocol_fee_per_thousand / 1000;
        let change = net
            .checked_sub(amount_to_b + fee_amount)
            .context("aggregate: note value too small for amount+fee")?;

        // Seed pads/fee-note off the (random) note_a secret so they differ each run.
        let seed = curvy_core::field::fr_to_be_32(&note_a.shared_secret);

        // Outputs: [recipient, change→self, zero-pad→self]; inputs: [note_a, zero-pad→self].
        let b_note = seal_note(recipient, u128_fr(amount_to_b), token)?;
        let change_note = seal_note(&spender.identity(), u128_fr(change), token)?;
        let pad_out = zero_pad_note(spender.bjj_pub, token, &seed, 1);
        let output_notes = vec![b_note.to_core(), change_note.to_core(), pad_out.to_core()];

        let pad_in = zero_pad_note(spender.bjj_pub, token, &seed, 2);
        let input_notes = vec![note_a.to_core(), pad_in.to_core()];
        let input_proofs = vec![a_proof, Proof { leaf_index: 0, siblings: vec![Fr::from(0u64); TREE_DEPTH] }];

        // Fee note owned by the on-chain feeNotePublicKey.
        let fee_pub = (
            fr_from_dec(&fees.fee_note_public_key[0]),
            fr_from_dec(&fees.fee_note_public_key[1]),
        );
        let fee_n = fee_note(fee_pub, u128_fr(fee_amount), token, &seed);

        // Build the witness, then patch in the REAL depth-6 gas-fee tree proof (the
        // core builder synthesizes its own root; the circuit binds gasFee under the
        // on-chain commitmentFeeRoot, so it must be the real one).
        let mut w = build_aggregation(
            &input_notes,
            &input_proofs,
            &output_notes,
            &fee_n.to_core(),
            &spender.k,
            spender.bjj_pub,
            notes_root,
            fr_from_dec(&fees.protocol_fee_per_thousand),
            u128_fr(gas_fee),
            fee_pub,
        );
        let (siblings, gas_root) = real_gas_fee_proof(&fees, &token_dec)?;
        if gas_root != fees.commitment_fee_root {
            bail!(
                "aggregate: rebuilt gas-fee root {gas_root} != on-chain commitmentFeeRoot {}",
                fees.commitment_fee_root
            );
        }
        w.gas_fee_siblings = siblings;
        w.commit_pending_notes_gas_fee_root = gas_root;

        let input_json = serde_json::to_string(&w)?;
        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::aggregation().prove(&input_json)
        })
        .await
        .context("join prove")??;
        let proof = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;

        let calldata = curvy_abi::encode_submit_aggregation(
            MAX_INPUTS,
            MAX_OUTPUTS,
            &proof,
            &bundle.public_signals,
        )?;
        let (_o, ledger) = self
            .submit_call(submitter_priv, &self.aggregator, calldata, "0", 3_000_000, route, "aggregate")
            .await?;

        // Verify: the B output note is now PENDING on-chain.
        let want = fr_to_dec(&b_note.note_id());
        if self.anchor.note_status(&want).await? != 1 {
            bail!("aggregate: B output note {want} not in PENDING status after submit");
        }
        Ok((b_note, vec![ledger]))
    }

    // ── Stretch: withdraw a committed note to an EOA ──────────────────────────────

    /// Withdraw a **committed** note owned by `spender` to a plain `destination` EOA.
    /// Proves withdrawal(2,30) (note + zero-pad), calls `submitWithdrawalRequest`, and
    /// returns the amount the vault delivers to the destination (net of the vault's
    /// `withdrawalFee` and the per-token withdrawal gas that reimburses the relayer).
    pub async fn withdraw(
        &self,
        spender: &Account,
        note: &OwnedNote,
        destination: &str,
        submitter_priv: &str,
        route: Route,
    ) -> Result<(u128, Vec<TxLedger>)> {
        let fees = self.fees.fees().await?;
        let token = note.token;
        let token_dec = fr_to_dec(&token);

        let leaves = self.sync().await?;
        let nid = note.note_id();
        let idx = leaves
            .iter()
            .position(|l| *l == nid)
            .context("withdraw: note not found in committed tree (commit it first)")?;
        let tree = Imt::from_leaves(TREE_DEPTH, &leaves);
        let notes_root = tree.root();
        let proof = Proof { leaf_index: idx as u64, siblings: tree.create_proof(idx).siblings };

        let dest_dec = curvy_abi::address_to_u160_dec(destination)?;
        let destination_fr = fr_from_dec(&dest_dec);

        let seed = curvy_core::field::fr_to_be_32(&note.shared_secret);
        let pad = zero_pad_note(spender.bjj_pub, token, &seed, 7);
        let inputs = vec![note.to_core(), pad.to_core()];
        let proofs = vec![proof, Proof { leaf_index: 0, siblings: vec![Fr::from(0u64); TREE_DEPTH] }];

        let w = curvy_core::witness::build_withdrawal(
            &inputs,
            &spender.k,
            spender.bjj_pub,
            &proofs,
            notes_root,
            destination_fr,
            token,
        );
        let input_json = serde_json::to_string(&w)?;
        let bundle = tokio::task::spawn_blocking(move || {
            curvy_witnesscalc::Circuit::withdrawal().prove(&input_json)
        })
        .await
        .context("join prove")??;
        let proof_oc = curvy_abi::proof_from_snarkjs(&bundle.proof_json)?;
        let calldata = curvy_abi::encode_submit_withdrawal(MAX_INPUTS, &proof_oc, &bundle.public_signals)?;
        let (_o, ledger) = self
            .submit_call(submitter_priv, &self.aggregator, calldata, "0", 2_000_000, route, "withdraw")
            .await?;

        let amount = fr_u128(&note.amount)?;
        let wfee = amount * fees.withdrawal_fee_bps as u128 / 10_000;
        let gas: u128 = fees
            .per_token_gas_fees
            .iter()
            .find(|g| g.token_id == token_dec)
            .map(|g| g.withdrawal.parse().unwrap_or(0))
            .unwrap_or(0);
        let delivered = amount.saturating_sub(wfee).saturating_sub(gas);
        Ok((delivered, vec![ledger]))
    }

    // ── Step 4: scan / receive ────────────────────────────────────────────────────

    /// Scan all `PendingNotes` for notes owned by `account`: real stealth discovery
    /// (ECDH + view-tag prefilter), `decrypt_amount_token` for encrypted leaves, then
    /// the integrity gate (recompute noteId; drop mismatches).
    pub async fn scan(&self, account: &Account) -> Result<Vec<Discovered>> {
        let head = self.notes.head_block().await?;
        let events = self.notes.pending_notes(0, head).await?;

        let mut rs = Vec::new();
        let mut tags = Vec::new();
        // (note_id, enc_amount, enc_token, is_plaintext, eph_x, eph_y)
        let mut meta: Vec<(String, String, String, bool, String, String)> = Vec::new();
        for ev in &events {
            for i in 0..ev.note_ids.len() {
                let ex = ev.ephemeral_keys[0].get(i).cloned().unwrap_or_default();
                let ey = ev.ephemeral_keys[1].get(i).cloned().unwrap_or_default();
                rs.push(format!("{ex}.{ey}"));
                tags.push(format!("{:02x}", ev.view_tags.get(i).copied().unwrap_or(0)));
                meta.push((
                    ev.note_ids[i].clone(),
                    ev.amounts.get(i).cloned().unwrap_or_default(),
                    ev.tokens.get(i).cloned().unwrap_or_default(),
                    ev.is_plaintext.get(i).copied().unwrap_or(false),
                    ex,
                    ey,
                ));
            }
        }

        let matches = stealth::scan(&account.k, &account.v, &rs, &tags)
            .map_err(|e| anyhow::anyhow!("stealth scan: {e}"))?;

        let mut out = Vec::new();
        for m in matches {
            let (note_id_dec, enc_amount, enc_token, is_plain, ex, ey) = &meta[m.index as usize];
            let shared_secret = fr_from_dec(m.spending_pub_key.split('.').next().unwrap_or("0"));

            let (amount, token) = if *is_plain {
                (fr_from_dec(enc_amount), fr_from_dec(enc_token))
            } else {
                let ss = fr_to_biguint(&shared_secret);
                let ebx = fr_to_biguint(&fr_from_dec(ex));
                let eby = fr_to_biguint(&fr_from_dec(ey));
                decrypt_amount_token(
                    fr_from_dec(enc_amount),
                    fr_from_dec(enc_token),
                    &ss,
                    (&ebx, &eby),
                )
            };

            // Integrity gate: recompute ownerHash + noteId, drop on mismatch.
            let oh = owner_hash(account.bjj_pub, shared_secret);
            let nid = note_id(oh, amount, token);
            if fr_to_dec(&nid) == *note_id_dec {
                out.push(Discovered {
                    note_id: nid,
                    amount,
                    token,
                    shared_secret,
                    is_plaintext: *is_plain,
                });
            }
        }
        Ok(out)
    }
}

/// Rebuild the real depth-6 per-token gas-fee tree and return `(siblings, root)` for
/// `token`. Leaf[tokenId] = that token's `pendingNoteCommitment`; the root must equal
/// the on-chain `commitmentFeeRoot`.
fn real_gas_fee_proof(fees: &FeeConfig, token_dec: &str) -> Result<(Vec<String>, String)> {
    const GAS_TREE_DEPTH: usize = 6;
    let n = 1usize << GAS_TREE_DEPTH;
    let mut leaves = vec![Fr::from(0u64); n];
    for g in &fees.per_token_gas_fees {
        let tid: usize = g.token_id.parse().context("gas-fee token id")?;
        if tid < n {
            leaves[tid] = fr_from_dec(&g.pending_note_commitment);
        }
    }
    let token_index: usize = token_dec.parse().context("token id")?;
    let tree = Imt::from_leaves(GAS_TREE_DEPTH, &leaves);
    let proof = tree.create_proof(token_index);
    Ok((
        proof.siblings.iter().map(fr_to_dec).collect(),
        fr_to_dec(&tree.root()),
    ))
}
