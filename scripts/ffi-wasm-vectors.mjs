import * as core from "../crates/wasm/pkg-node/curvy_wasm.js";

const hex = (bytes) =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const fieldBytes = (value) => {
  const buffer = new Uint8Array(32);
  new DataView(buffer.buffer).setBigUint64(24, BigInt(value));
  return buffer;
};

const report = {};
report.poseidon_1_2_3 = core.poseidon(["1", "2", "3"]);
report.poseidon_42 = core.poseidon(["42"]);
report.sha256_bigint_1_2 = core.sha256BigInt(["1", "2"]);
report.owner_hash = core.ownerHash("1", "2", "3");
report.note_id = core.noteId("7", "1000000", "5");
report.nullifier = core.nullifier("3", "1", "2");

const privateKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const scalar = "2736030358979909402780800718157159386076813972158567259200215660948447373040";
report.pub_from_private_key = JSON.stringify(core.pubFromPrivateKey(privateKey));
report.pub_from_scalar = JSON.stringify(core.pubFromScalar(scalar));
report.ephemeral_pub_key = JSON.stringify(core.ephemeralPubKey("12345"));
report.sign = JSON.stringify(core.sign("1234567890", privateKey));
report.sign_with_scalar = JSON.stringify(core.signWithScalar("1234567890", scalar));

const encrypted = core.encryptAmountToken("1000000", "5", "999", "111", "222");
report.encrypt_amount_token = JSON.stringify(encrypted);
report.decrypt_amount_token = JSON.stringify(
  core.decryptAmountToken(encrypted[0], encrypted[1], "999", "111", "222"),
);

report.get_meta = JSON.stringify(
  core.get_meta(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
  ),
);

report.notes_tree_depth = core.notesTreeDepth();
report.notes_tree_version = core.notesTreeVersion();
report.notes_shard_height = core.notesShardHeight();
report.notes_shard_size = core.notesShardSize();

const tree = new core.MerkleTree(8);
for (let leaf = 1; leaf <= 5; leaf++) tree.insert(fieldBytes(leaf));
report.merkle_root_depth8_leaves1to5 = hex(tree.root());
const proof = tree.proof(fieldBytes(3));
report.merkle_proof_leaf3_siblings = hex(proof.siblings);
report.merkle_proof_verifies = core.verifyMerkleProof(
  fieldBytes(3),
  2,
  proof.siblings,
  tree.root(),
);

const packed = new Uint8Array(9 * 32);
for (let note = 1; note <= 9; note++) packed.set(fieldBytes(note), (note - 1) * 32);
const sharded = new core.ShardedNotesTree(10, 2);
sharded.appendMany(packed);
report.sharded_root_depth10_shard2_9notes = hex(sharded.root());
report.sharded_completed_shard_count = sharded.completedShardCount;

const frontier = new core.NotesFrontier(10, 2);
frontier.appendMany(packed);
report.frontier_root_depth10_shard2_9notes = hex(frontier.root());
report.version = core.version();

console.log(JSON.stringify(report));
