//! The calldata binding and the calldata-bound pending-notes commitment against real
//! proofs of Curvy's bound circuits: each vector records the words a proof was made for
//! and the `[commitment, y, x]` it verified with. Word counts and tree states no proof
//! covers come from an independent implementation that reproduces those proofs.

use ark_ff::AdditiveGroup;
use curvy_core::calldata::{MAX_CALLDATA_WORDS, bind_calldata, bind_calldata_packed};
use curvy_core::encoding::from_hex_lossy;
use curvy_core::field::{Fr, PackedFieldsError, fr_from_dec, fr_to_be_32_packed, fr_to_dec};
use curvy_core::imt::{IndexedMerkleTree, NotesFrontier, TreeError};
use curvy_core::witness::{
    AppendableNotesTree, BoundPendingCommitment, MAX_PENDING_BATCH_SIZE, PendingCommitmentError,
    build_bound_pending_commitment, build_bound_pending_commitment_packed,
};
use serde::Deserialize;

const JSON: &str = include_str!("../testdata/calldata_binding_vectors.json");

#[derive(Deserialize)]
struct Vectors {
    spend: Vec<SpendVector>,
    #[serde(rename = "pendingNotesCommitment")]
    pending_notes_commitment: PendingVectors,
    binding: Vec<BindingVector>,
    #[serde(rename = "pendingNotesCommitmentFromState")]
    pending_from_state: PendingFromState,
}

#[derive(Deserialize)]
struct BindingVector {
    name: String,
    words: Vec<String>,
    commitment: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct PendingFromState {
    #[serde(rename = "batchSize")]
    batch_size: usize,
    #[serde(rename = "treeDepth")]
    tree_depth: usize,
    #[serde(rename = "shardHeight")]
    shard_height: usize,
    cases: Vec<PendingCase>,
}

#[derive(Deserialize)]
struct PendingCase {
    name: String,
    snapshot: String,
    #[serde(rename = "currentNoteIndex")]
    current_note_index: String,
    #[serde(rename = "currentNotesRoot")]
    current_notes_root: String,
    frontier: Vec<String>,
    #[serde(rename = "noteIds")]
    note_ids: Vec<String>,
    #[serde(rename = "newNotesRoot")]
    new_notes_root: String,
    #[serde(rename = "newNoteIndex")]
    new_note_index: String,
    commitment: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct SpendVector {
    circuit: String,
    words: Vec<String>,
    commitment: String,
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct PendingVectors {
    #[serde(rename = "batchSize")]
    batch_size: usize,
    #[serde(rename = "treeDepth")]
    tree_depth: usize,
    commits: Vec<PendingCommit>,
}

#[derive(Deserialize)]
struct PendingCommit {
    #[serde(rename = "noteIds")]
    note_ids: Vec<String>,
    #[serde(rename = "newNotesRoot")]
    new_notes_root: String,
    #[serde(rename = "newNoteIndex")]
    new_note_index: String,
    commitment: String,
    x: String,
    y: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(JSON).expect("calldata binding vectors parse")
}

fn frs(values: &[String]) -> Vec<Fr> {
    values.iter().map(|value| fr_from_dec(value)).collect()
}

fn leaves(range: std::ops::Range<u64>) -> Vec<Fr> {
    range.map(|i| Fr::from(1_000 + i)).collect()
}

fn assert_binding(words: &[String], commitment: &str, x: &str, y: &str, name: &str) {
    let words = frs(words);
    let binding = bind_calldata(&words).expect("words are not empty");
    assert_eq!(fr_to_dec(&binding.commitment), commitment, "{name}");
    assert_eq!(fr_to_dec(&binding.x), x, "{name}");
    assert_eq!(fr_to_dec(&binding.y), y, "{name}");
    assert_eq!(
        binding.public_signals(),
        [fr_from_dec(commitment), fr_from_dec(y), fr_from_dec(x)],
        "{name}"
    );
    assert_eq!(
        bind_calldata_packed(&fr_to_be_32_packed(&words)),
        Ok(binding),
        "{name}"
    );
}

#[test]
fn binding_matches_the_spend_circuits() {
    for vector in vectors().spend {
        assert_binding(
            &vector.words,
            &vector.commitment,
            &vector.x,
            &vector.y,
            &vector.circuit,
        );
    }
}

/// One word, one full Poseidon call, and two, with zero, `r - 1` and large words.
#[test]
fn binding_matches_an_independent_implementation() {
    let vectors = vectors().binding;
    assert_eq!(
        vectors
            .iter()
            .map(|vector| vector.words.len())
            .collect::<Vec<_>>(),
        [1, 15, 30]
    );
    for vector in vectors {
        assert_binding(
            &vector.words,
            &vector.commitment,
            &vector.x,
            &vector.y,
            &vector.name,
        );
    }
}

/// Three commits in a row into the empty production tree, from both tree forms.
#[test]
fn bound_commitment_matches_the_pending_notes_circuit() {
    let pending = vectors().pending_notes_commitment;
    let mut frontier = NotesFrontier::production();
    let mut indexed = IndexedMerkleTree::new(pending.tree_depth).expect("depth is valid");
    assert_eq!(frontier.depth(), pending.tree_depth);

    for commit in &pending.commits {
        let note_ids = frs(&commit.note_ids);
        let from_frontier =
            build_bound_pending_commitment(&mut frontier, pending.batch_size, &note_ids)
                .expect("commit builds");
        let from_indexed =
            build_bound_pending_commitment(&mut indexed, pending.batch_size, &note_ids)
                .expect("commit builds");
        assert_eq!(from_frontier, from_indexed);

        assert_eq!(
            fr_to_dec(&from_frontier.new_notes_root),
            commit.new_notes_root
        );
        assert_eq!(
            from_frontier.new_note_index.to_string(),
            commit.new_note_index
        );
        assert_eq!(
            fr_to_dec(&from_frontier.binding.commitment),
            commit.commitment
        );
        assert_eq!(fr_to_dec(&from_frontier.binding.x), commit.x);
        assert_eq!(fr_to_dec(&from_frontier.binding.y), commit.y);
        assert_eq!(from_frontier.note_ids(), note_ids.as_slice());
        assert_eq!(from_frontier.pending_note_ids.len(), pending.batch_size);
    }
}

fn assert_commitment(commitment: &BoundPendingCommitment, case: &PendingCase) {
    let name = &case.name;
    assert_eq!(
        commitment.current_note_index.to_string(),
        case.current_note_index,
        "{name}"
    );
    assert_eq!(
        fr_to_dec(&commitment.current_notes_root),
        case.current_notes_root,
        "{name}"
    );
    assert_eq!(commitment.frontier, frs(&case.frontier), "{name}");
    assert_eq!(
        commitment.note_ids(),
        frs(&case.note_ids).as_slice(),
        "{name}"
    );
    assert_eq!(
        fr_to_dec(&commitment.new_notes_root),
        case.new_notes_root,
        "{name}"
    );
    assert_eq!(
        commitment.new_note_index.to_string(),
        case.new_note_index,
        "{name}"
    );
    assert_eq!(
        fr_to_dec(&commitment.binding.commitment),
        case.commitment,
        "{name}"
    );
    assert_eq!(fr_to_dec(&commitment.binding.x), case.x, "{name}");
    assert_eq!(fr_to_dec(&commitment.binding.y), case.y, "{name}");
}

/// Commits that end and start at a shard boundary, cross one, and fill the
/// production tree, each from the frontier snapshot of the tree before it.
#[test]
fn bound_commitment_matches_from_given_tree_states() {
    let pending = vectors().pending_from_state;
    assert_eq!(pending.cases.len(), 5);
    for case in &pending.cases {
        let restored = NotesFrontier::from_snapshot_bytes(&from_hex_lossy(&case.snapshot))
            .expect("snapshot restores");
        assert_eq!(restored.depth(), pending.tree_depth, "{}", case.name);
        assert_eq!(
            restored.shard_height(),
            pending.shard_height,
            "{}",
            case.name
        );
        assert_eq!(
            fr_to_dec(&restored.root()),
            case.current_notes_root,
            "{}",
            case.name
        );
        assert_eq!(
            restored.next_leaf_frontier(),
            Ok(frs(&case.frontier)),
            "{}",
            case.name
        );

        let note_ids = frs(&case.note_ids);
        let mut frontier = restored.clone();
        let commitment =
            build_bound_pending_commitment(&mut frontier, pending.batch_size, &note_ids)
                .expect("commit builds");
        assert_commitment(&commitment, case);
        assert_eq!(fr_to_dec(&frontier.root()), case.new_notes_root);

        let mut packed = restored.clone();
        assert_eq!(
            build_bound_pending_commitment_packed(
                &mut packed,
                pending.batch_size,
                &fr_to_be_32_packed(&note_ids)
            ),
            Ok(commitment)
        );
    }

    // After the last case the tree is full: the next batch is refused, and so is
    // reading the next leaf's frontier.
    let last = pending.cases.last().expect("cases");
    let mut full = NotesFrontier::from_snapshot_bytes(&from_hex_lossy(&last.snapshot))
        .expect("snapshot restores");
    full.append_all(&frs(&last.note_ids))
        .expect("the batch fits");
    assert_eq!(full.leaf_count(), 1 << pending.tree_depth);
    let depth = pending.tree_depth;
    assert_eq!(
        full.next_leaf_frontier(),
        Err(TreeError::TreeFull { depth })
    );
    assert_refused(
        &mut full,
        pending.batch_size,
        &[Fr::from(1u64)],
        PendingCommitmentError::Tree(TreeError::TreeFull { depth }),
    );
}

/// The frontier is the next leaf's sibling wherever its path turns right: what an
/// inclusion proof of that leaf gives once it is in the tree.
#[test]
fn frontier_is_the_next_leafs_left_hand_siblings() {
    let depth = 8;
    for existing in 0..40u64 {
        let tree = IndexedMerkleTree::from_leaves(depth, &leaves(0..existing)).expect("leaves fit");
        let frontier = tree.next_leaf_frontier().expect("tree is not full");

        let mut appended = tree.clone();
        appended.insert(Fr::from(7u64)).expect("not a duplicate");
        let siblings = appended
            .create_proof_at(existing as usize)
            .expect("leaf exists")
            .siblings;
        let expected: Vec<Fr> = siblings
            .iter()
            .enumerate()
            .map(|(level, sibling)| {
                if (existing >> level) & 1 == 1 {
                    *sibling
                } else {
                    Fr::ZERO
                }
            })
            .collect();
        assert_eq!(frontier, expected, "{existing} leaves");

        let mut notes_frontier = NotesFrontier::new(depth, 3).expect("geometry is valid");
        notes_frontier
            .append_many(&leaves(0..existing))
            .expect("leaves fit");
        assert_eq!(
            notes_frontier
                .next_leaf_frontier()
                .expect("tree is not full"),
            expected
        );
    }
}

#[test]
fn appends_like_the_tree_from_every_start() {
    let depth = 6;
    for existing in 0..20u64 {
        for count in 1..=5u64 {
            let mut tree =
                IndexedMerkleTree::from_leaves(depth, &leaves(0..existing)).expect("leaves fit");
            let batch = leaves(existing..existing + count);
            let commitment =
                build_bound_pending_commitment(&mut tree, 8, &batch).expect("commit builds");
            let reference = IndexedMerkleTree::from_leaves(depth, &leaves(0..existing + count))
                .expect("leaves fit");
            assert_eq!(commitment.new_notes_root, reference.root());
            assert_eq!(commitment.current_note_index, existing);
            assert_eq!(commitment.new_note_index, existing + count);
            assert_eq!(
                &commitment.pending_note_ids[count as usize..],
                &[Fr::ZERO; 8][count as usize..]
            );
            assert_eq!(
                bind_calldata(&commitment.words()).expect("words are not empty"),
                commitment.binding
            );
        }
    }
}

#[test]
fn circuit_input_names_the_circuit_signals() {
    let mut tree = NotesFrontier::new(4, 2).expect("geometry is valid");
    let commitment =
        build_bound_pending_commitment(&mut tree, 3, &leaves(0..2)).expect("commit builds");
    let input = serde_json::to_value(commitment.circuit_input()).expect("serializes");
    assert_eq!(input["currentNoteIndex"], "0");
    assert_eq!(input["pendingNoteIds"].as_array().map(Vec::len), Some(3));
    assert_eq!(input["pendingNoteIds"][2], "0");
    assert_eq!(input["frontier"].as_array().map(Vec::len), Some(4));
    assert_eq!(input["x"], fr_to_dec(&commitment.binding.x));
    assert_eq!(
        input.as_object().map(|object| object.len()),
        Some(5),
        "currentNoteIndex, currentNotesRoot, pendingNoteIds, frontier, x"
    );
}

fn assert_refused<T: AppendableNotesTree>(
    tree: &mut T,
    batch_size: usize,
    note_ids: &[Fr],
    expected: PendingCommitmentError,
) {
    let (root, leaf_count) = (tree.root(), tree.leaf_count());
    assert_eq!(
        build_bound_pending_commitment(tree, batch_size, note_ids),
        Err(expected)
    );
    assert_eq!((tree.root(), tree.leaf_count()), (root, leaf_count));
}

#[test]
fn refuses_before_changing_the_tree() {
    let depth = 6;
    let existing = leaves(0..5);
    let mut indexed = IndexedMerkleTree::from_leaves(depth, &existing).expect("leaves fit");
    let mut frontier = NotesFrontier::new(depth, 3).expect("geometry is valid");
    frontier.append_many(&existing).expect("leaves fit");

    let cases = [
        (vec![], PendingCommitmentError::NoNotes),
        (
            leaves(10..14),
            PendingCommitmentError::BatchTooLarge {
                count: 4,
                batch_size: 3,
            },
        ),
        (
            vec![Fr::from(10u64), Fr::ZERO],
            PendingCommitmentError::ZeroNoteId,
        ),
        (
            vec![Fr::from(10u64), Fr::from(10u64)],
            PendingCommitmentError::DuplicateNoteId,
        ),
    ];
    for (note_ids, expected) in cases {
        assert!(expected.is_caller_error(), "{expected}");
        assert_refused(&mut indexed, 3, &note_ids, expected.clone());
        assert_refused(&mut frontier, 3, &note_ids, expected);
    }

    // Only the indexed tree knows its leaves, so only it refuses one again.
    let present = PendingCommitmentError::Tree(TreeError::DuplicateLeaf);
    assert!(present.is_caller_error());
    assert_refused(&mut indexed, 3, &[Fr::from(10u64), existing[0]], present);
}

/// A batch size out of range is refused before the tree changes or the padded
/// batch is allocated, however large it is.
#[test]
fn refuses_a_batch_size_out_of_range_before_changing_the_tree() {
    let depth = 6;
    let existing = leaves(0..5);
    let mut indexed = IndexedMerkleTree::from_leaves(depth, &existing).expect("leaves fit");
    let mut frontier = NotesFrontier::new(depth, 3).expect("geometry is valid");
    frontier.append_many(&existing).expect("leaves fit");
    let batch = leaves(10..12);

    for batch_size in [0, MAX_PENDING_BATCH_SIZE + 1, usize::MAX / 32, usize::MAX] {
        let expected = PendingCommitmentError::InvalidBatchSize { batch_size };
        assert!(expected.is_caller_error());
        assert_refused(&mut indexed, batch_size, &batch, expected.clone());
        assert_refused(&mut frontier, batch_size, &batch, expected.clone());
        assert_refused_packed(
            &mut indexed,
            batch_size,
            &fr_to_be_32_packed(&batch),
            expected.clone(),
        );
        assert_refused_packed(
            &mut frontier,
            batch_size,
            &fr_to_be_32_packed(&batch),
            expected,
        );
    }

    // The largest batch size is accepted and padded.
    let commitment = build_bound_pending_commitment(&mut frontier, MAX_PENDING_BATCH_SIZE, &batch)
        .expect("commit builds");
    assert_eq!(commitment.pending_note_ids.len(), MAX_PENDING_BATCH_SIZE);
    assert_eq!(commitment.words().len(), MAX_PENDING_BATCH_SIZE + 4);
    assert!(commitment.words().len() <= MAX_CALLDATA_WORDS);
}

fn assert_refused_packed<T: AppendableNotesTree>(
    tree: &mut T,
    batch_size: usize,
    packed_note_ids: &[u8],
    expected: PendingCommitmentError,
) {
    let (root, leaf_count) = (tree.root(), tree.leaf_count());
    assert_eq!(
        build_bound_pending_commitment_packed(tree, batch_size, packed_note_ids),
        Err(expected)
    );
    assert_eq!((tree.root(), tree.leaf_count()), (root, leaf_count));
}

#[test]
fn packed_ids_build_like_field_ids_and_are_checked_before_decoding() {
    let depth = 6;
    let existing = leaves(0..5);
    let mut indexed = IndexedMerkleTree::from_leaves(depth, &existing).expect("leaves fit");
    let mut frontier = NotesFrontier::new(depth, 3).expect("geometry is valid");
    frontier.append_many(&existing).expect("leaves fit");
    let batch = leaves(10..12);
    let packed = fr_to_be_32_packed(&batch);

    let cases = [
        (
            fr_to_be_32_packed(&leaves(10..14)),
            PendingCommitmentError::BatchTooLarge {
                count: 4,
                batch_size: 3,
            },
        ),
        (
            vec![0xff; 3 * 32 + 1],
            PendingCommitmentError::BatchTooLarge {
                count: 4,
                batch_size: 3,
            },
        ),
        (
            packed[..40].to_vec(),
            PendingCommitmentError::PackedNoteIds(PackedFieldsError::Length(40)),
        ),
        (
            [packed.as_slice(), &[0xff; 32]].concat(),
            PendingCommitmentError::PackedNoteIds(PackedFieldsError::NonCanonical(2)),
        ),
        (Vec::new(), PendingCommitmentError::NoNotes),
    ];
    for (bytes, expected) in cases {
        assert!(expected.is_caller_error(), "{expected}");
        assert_refused_packed(&mut indexed, 3, &bytes, expected.clone());
        assert_refused_packed(&mut frontier, 3, &bytes, expected);
    }

    let mut reference = indexed.clone();
    assert_eq!(
        build_bound_pending_commitment_packed(&mut indexed, 3, &packed),
        build_bound_pending_commitment(&mut reference, 3, &batch)
    );
    assert_eq!(indexed.root(), reference.root());
}

#[test]
fn a_full_tree_is_not_a_caller_error() {
    let depth = 3;
    assert!(!PendingCommitmentError::Tree(TreeError::TreeFull { depth }).is_caller_error());
    assert!(
        !PendingCommitmentError::Tree(TreeError::InvalidSnapshot("corrupt".to_owned()))
            .is_caller_error()
    );
}

#[test]
fn refuses_a_batch_past_the_last_leaf() {
    let depth = 3;
    let mut indexed = IndexedMerkleTree::from_leaves(depth, &leaves(0..7)).expect("leaves fit");
    let mut frontier = NotesFrontier::new(depth, 1).expect("geometry is valid");
    frontier.append_many(&leaves(0..7)).expect("leaves fit");
    let batch = leaves(10..12);
    let full = PendingCommitmentError::Tree(TreeError::TreeFull { depth });
    assert_refused(&mut indexed, 4, &batch, full.clone());
    assert_refused(&mut frontier, 4, &batch, full);
}
