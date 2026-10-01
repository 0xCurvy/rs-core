// Proves the Rust core, compiled to wasm and called from the JS runtime, produces
// byte-identical results to the TS oracle (the committed golden vectors).
// Run: node crates/wasm/smoke-test.cjs

const assert = require("node:assert/strict");
const path = require("node:path");
const wasm = require("./pkg-node/curvy_wasm.js");

const TD = path.join(__dirname, "../core/testdata");
const poseidonVectors = require(path.join(TD, "poseidon_vectors.json"));
const p2 = require(path.join(TD, "phase2_vectors.json"));
const scalarSignatures = require(path.join(TD, "scalar_signature_vectors.json"));

let checks = 0;
const eq = (a, b, msg) => {
  assert.strictEqual(a, b, msg);
  checks++;
};

// Poseidon
for (const v of poseidonVectors) eq(wasm.poseidon(v.inputs), v.output, `poseidon arity ${v.arity}`);

// Note commitments
for (const n of p2.noteCommitments) {
  const oh = wasm.ownerHash(n.pubX, n.pubY, n.sharedSecret);
  eq(oh, n.ownerHash, "ownerHash");
  eq(wasm.noteId(oh, n.amount, n.token), n.id, "noteId");
  eq(wasm.nullifier(n.sharedSecret, n.pubX, n.pubY), n.nullifier, "nullifier");
}

// pubFromPrivateKey
// Reject malformed corpus keys instead of reproducing lossy Buffer decoding.
const isStrictKey = (hex) => /^[0-9a-fA-F]{64}$/.test(hex);
for (const p of p2.pubFromPrivateKey) {
  if (!isStrictKey(p.privateKeyHex)) {
    assert.throws(
      () => wasm.pubFromPrivateKey(p.privateKeyHex),
      /invalid EdDSA private key/,
      `pubFromPrivateKey must reject ${JSON.stringify(p.privateKeyHex)}`,
    );
    checks++;
    continue;
  }
  const [x, y] = wasm.pubFromPrivateKey(p.privateKeyHex);
  eq(x, p.x, "pubFromPrivateKey.x");
  eq(y, p.y, "pubFromPrivateKey.y");
}

// ephemeralPubKey
for (const e of p2.ephemeralPubKey) {
  const [x, y] = wasm.ephemeralPubKey(e.scalar);
  eq(x, e.x, "ephemeralPubKey.x");
  eq(y, e.y, "ephemeralPubKey.y");
}

// sign
for (const s of p2.sign) {
  const [r8x, r8y, S] = wasm.sign(s.message, s.privateKeyHex);
  eq(r8x, s.R8x, "sign.R8x");
  eq(r8y, s.R8y, "sign.R8y");
  eq(S, s.S, "sign.S");
}

// Direct-scalar public key, signature, and verification.
for (const v of scalarSignatures.vectors) {
  const [x, y] = wasm.pubFromScalar(v.scalar);
  eq(x, v.publicKey.x, "pubFromScalar.x");
  eq(y, v.publicKey.y, "pubFromScalar.y");
  const [r8x, r8y, S] = wasm.signWithScalar(v.message, v.scalar);
  eq(r8x, v.R8.x, "signWithScalar.R8x");
  eq(r8y, v.R8.y, "signWithScalar.R8y");
  eq(S, v.S, "signWithScalar.S");
  eq(wasm.verifyScalarSignature(v.message, x, y, r8x, r8y, S), true, "verifyScalarSignature");
}

// cipher (encrypt + decrypt round-trip)
for (const c of p2.cipher) {
  const [ea, et] = wasm.encryptAmountToken(c.amount, c.token, c.sharedSecret, c.ephemeralKey[0], c.ephemeralKey[1]);
  eq(ea, c.encryptedAmount, "encryptAmountToken.amount");
  eq(et, c.encryptedToken, "encryptAmountToken.token");
  const [a, t] = wasm.decryptAmountToken(c.encryptedAmount, c.encryptedToken, c.sharedSecret, c.ephemeralKey[0], c.ephemeralKey[1]);
  eq(a, c.amount, "decryptAmountToken.amount");
  eq(t, c.token, "decryptAmountToken.token");
}

// sha256BigInt
for (const s of p2.sha256BigInt) eq(wasm.sha256BigInt(s.inputs), s.output, "sha256BigInt");

// Stateful sharded tree: packed boundary, rollover, proof, snapshot and rewind.
const be32 = (n) => Buffer.from(n.toString(16).padStart(64, "0"), "hex");
const packed = (values) => Buffer.concat(values.map(be32));
const field = (bytes) => BigInt(`0x${Buffer.from(bytes).toString("hex")}`);
const leaves = Array.from({ length: 21 }, (_, i) => BigInt(i + 1));
const generic = wasm.MerkleTree.fromLeaves(8, packed(leaves));
eq(generic.leafCount, leaves.length, "generic Merkle leaf count");
eq(generic.getIndex(be32(leaves[9])), 9, "generic Merkle reverse index");
const genericProof = generic.proof(be32(leaves[9]));
assert.equal(
  wasm.verifyMerkleProof(generic.depth, genericProof.leaf, genericProof.index, genericProof.siblings, genericProof.root),
  true,
);
checks++;
eq(
  wasm.verifyMerkleProof(generic.depth, genericProof.leaf, genericProof.index + 2 ** generic.depth, genericProof.siblings, genericProof.root),
  false,
  "Merkle proof rejects index above its capacity",
);
// The expected depth, not the sibling count, fixes the tree height.
for (const depth of [generic.depth - 1, generic.depth + 1]) {
  eq(
    wasm.verifyMerkleProof(depth, genericProof.leaf, genericProof.index, genericProof.siblings, genericProof.root),
    false,
    `Merkle proof rejects expected depth ${depth}`,
  );
}
const firstPair = [field(genericProof.leaf), field(genericProof.siblings.slice(0, 32))].map(String);
if (genericProof.index % 2 === 1) firstPair.reverse();
const internalNode = be32(BigInt(wasm.poseidon(firstPair)));
const truncated = [internalNode, genericProof.index >> 1, genericProof.siblings.slice(32), genericProof.root];
eq(wasm.verifyMerkleProof(generic.depth - 1, ...truncated), true, "truncated proof is a valid shallower proof");
eq(wasm.verifyMerkleProof(generic.depth, ...truncated), false, "Merkle proof rejects an internal node posing as a leaf");
eq(
  wasm.verifyMerkleProof(generic.depth, genericProof.root, 0, new Uint8Array(0), genericProof.root),
  false,
  "Merkle proof rejects the root posing as a zero-sibling leaf",
);
// Positional misuse of the old four-argument form throws instead of passing.
assert.throws(() => wasm.verifyMerkleProof(genericProof.leaf, genericProof.index, genericProof.siblings, genericProof.root));
checks++;
genericProof.free();
generic.free();

const singleton = new wasm.MerkleTree(0);
eq(singleton.leafCount, 0, "depth-zero tree starts empty");
eq(field(singleton.root()), 0n, "empty depth-zero root");
eq(singleton.insert(be32(7n)), 0, "depth-zero first insertion");
const singletonProof = singleton.proofAt(0);
eq(singletonProof.siblings.length, 0, "depth-zero proof has no siblings");
eq(wasm.verifyMerkleProof(0, singletonProof.leaf, 0, singletonProof.siblings, singletonProof.root), true, "depth-zero proof verifies");
eq(wasm.verifyMerkleProof(0, singletonProof.leaf, 1, singletonProof.siblings, singletonProof.root), false, "depth-zero proof rejects nonzero index");
assert.throws(() => singleton.insert(be32(8n)), /full/);
checks++;
singleton.truncate(0);
eq(singleton.leafCount, 0, "depth-zero truncate empties the tree");
eq(singleton.insert(be32(8n)), 0, "depth-zero insertion after truncate");
singletonProof.free();
singleton.free();

const tree = new wasm.ShardedNotesTree(8, 3);
for (const i of [2, 9, 19]) tree.markOwned(be32(leaves[i]), i);
tree.appendMany(packed(leaves));
eq(tree.leafCount, 21, "sharded leaf count");
eq(tree.completedShardCount, 2, "sharded completed count");

const frontier = new wasm.NotesFrontier(8, 3);
const completed = frontier.appendMany(packed(leaves));
eq(frontier.leafCount, 21, "frontier leaf count");
eq(completed.length, 2, "frontier completed shard count");
eq(completed[0].shardIndex, 0, "frontier first shard index");
eq(completed[1].shardIndex, 1, "frontier second shard index");
assert.deepEqual(Buffer.from(frontier.root()), Buffer.from(tree.root()));
checks++;
completed.forEach((shard) => shard.free());

const frontierSnapshot = frontier.snapshot();
const restoredFrontier = wasm.NotesFrontier.restore(frontierSnapshot);
assert.deepEqual(Buffer.from(restoredFrontier.snapshot()), Buffer.from(frontierSnapshot));
checks++;
const frontierAppend = restoredFrontier.append(be32(22n));
eq(frontierAppend.leafIndex, 21, "restored frontier next leaf index");
eq(frontierAppend.hasCompletedShard, false, "restored frontier does not emit an early shard");
frontierAppend.free();

const proof = tree.witness(be32(leaves[2]));
let proofNode = field(proof.leaf);
let proofIndex = proof.index;
for (let level = 0; level < tree.depth; level++) {
  const sibling = field(proof.siblings.slice(level * 32, (level + 1) * 32));
  proofNode = BigInt(
    proofIndex % 2 === 0
      ? wasm.poseidon([proofNode.toString(), sibling.toString()])
      : wasm.poseidon([sibling.toString(), proofNode.toString()]),
  );
  proofIndex >>= 1;
}
eq(proofNode.toString(), field(tree.root()).toString(), "sharded proof verifies");

const dirty = tree.drainDirtyOwnedNotes();
assert.deepEqual(
  dirty.map((w) => [w.leafIndex, w.frozen]),
  [
    [2, true],
    [9, true],
    [19, false],
  ],
);
checks++;
dirty.forEach((w) => w.free());

const snapshot = tree.snapshot();
const restored = wasm.ShardedNotesTree.restore(snapshot);
assert.deepEqual(Buffer.from(restored.snapshot()), Buffer.from(snapshot));
checks++;
const restoredParts = wasm.ShardedNotesTree.restoreParts(8, 3, tree.completedShardRoots(), tree.liveLeaves());
const owned = tree.ownedNotes();
for (const witness of owned) {
  if (witness.frozen) {
    restoredParts.adoptFrozenWitness(witness.noteId, witness.leafIndex, witness.withinShardSiblings);
  } else {
    restoredParts.markOwned(witness.noteId, witness.leafIndex);
  }
  witness.free();
}
assert.deepEqual(Buffer.from(restoredParts.snapshot()), Buffer.from(snapshot));
checks++;
assert.deepEqual(Buffer.from(restored.rewindLiveTo(19)), be32(leaves[19]));
checks++;
assert.throws(
  () => restored.append(be32(21888242871839275222246405745257275088548364400416034343698204186575808495617n)),
  /canonical 32-byte/,
);
checks++;

proof.free();
restoredFrontier.free();
frontier.free();
restoredParts.free();
restored.free();
tree.free();

console.log(`WASM parity smoke test: ${checks} checks passed (Rust→wasm→JS == TS oracle)`);

// Malformed boundary inputs throw JS Errors, preserve the module, and redact values.
const healthyPoseidon = wasm.poseidon(["1"]);
const secretSentinel = "PRIVATE_SENTINEL_1e+21";
for (const invoke of [
  () => wasm.ownerHash("1", "2", "1e+21"),
  () => wasm.ownerHash("1", "2", secretSentinel),
  () => wasm.poseidon([]), () => wasm.poseidon(Array(17).fill("1")),
  () => wasm.poseidon([secretSentinel]), () => wasm.noteId(secretSentinel, "1", "1"),
  () => wasm.nullifier(secretSentinel,"1","1"), () => wasm.ephemeralPubKey(secretSentinel),
  () => wasm.ephemeralPubKey((1n << 256n).toString()),
  () => wasm.sign(secretSentinel,"ab".repeat(32)), () => wasm.sign("9".repeat(79),"ab".repeat(32)),
  () => wasm.sha256BigInt([secretSentinel]), () => wasm.sha256BigInt(["9".repeat(79)]),
  () => wasm.encryptAmountToken("1","1",secretSentinel,"1","1"),
  () => wasm.decryptAmountToken("1","1",secretSentinel,"1","1"),
]) {
  assert.throws(invoke, error => error instanceof Error && !(error instanceof WebAssembly.RuntimeError) && !error.message.includes(secretSentinel));
  assert.equal(wasm.poseidon(["1"]), healthyPoseidon);
  checks++;
}
console.log(`Boundary and parity checks: ${checks}`);

// Raw ephemeral scalars include zero and values above the subgroup order.
assert.deepEqual(wasm.ephemeralPubKey("0"), ["0", "1"]);
assert.deepEqual(wasm.ephemeralPubKey("1"), wasm.pubFromScalar("1"));
const babyjubVectors = require("../core/testdata/babyjubjub_vectors.json");
for (const vector of babyjubVectors.mulPointEscalar) {
  assert.deepEqual(wasm.ephemeralPubKey(vector.scalar), [vector.x, vector.y]);
}
console.log(`Ephemeral scalar regressions: ${babyjubVectors.mulPointEscalar.length + 2} checks passed`);

const assertBoundaryError = invoke => assert.throws(invoke, error =>
  error instanceof Error && !(error instanceof WebAssembly.RuntimeError));
const importedSeed = new Uint8Array(32).fill(1);
const importedScalar = new Uint8Array(32);
importedScalar[0] = 7;
const seedSigner = new wasm.SeedSigner(importedSeed);
const scalarSigner = new wasm.ScalarSigner(importedScalar);
importedSeed.fill(0);
importedScalar.fill(0);
try {
  assert.deepEqual(seedSigner.publicKey(), wasm.pubFromPrivateKey("01".repeat(32)));
  assert.deepEqual(scalarSigner.publicKey(), wasm.pubFromScalar("7"));
  for (const message of ["0", "42", "123456789"]) {
    assert.deepEqual(seedSigner.sign(message), wasm.sign(message, "01".repeat(32)));
    assert.deepEqual(scalarSigner.sign(message), wasm.signWithScalar(message, "7"));
  }
  assertBoundaryError(() => seedSigner.sign((1n << 256n).toString()));
  assertBoundaryError(() => scalarSigner.sign("invalid"));
} finally {
  seedSigner.free();
  scalarSigner.free();
}
assertBoundaryError(() => seedSigner.sign("42"));
assertBoundaryError(() => scalarSigner.publicKey());
for (const size of [0, 1, 31, 33, 100000]) {
  assertBoundaryError(() => new wasm.SeedSigner(new Uint8Array(size)));
  assertBoundaryError(() => new wasm.ScalarSigner(new Uint8Array(size)));
  assertBoundaryError(() => wasm.ephemeralPubKeyBytes(new Uint8Array(size)));
}
assertBoundaryError(() => new wasm.ScalarSigner(new Uint8Array(32)));
assertBoundaryError(() => new wasm.ScalarSigner(new Uint8Array(32).fill(255)));
for (const invalid of [null, undefined, "1".repeat(32), Array(32).fill(1)]) {
  assertBoundaryError(() => new wasm.SeedSigner(invalid));
  assertBoundaryError(() => new wasm.ScalarSigner(invalid));
  assertBoundaryError(() => wasm.ephemeralPubKeyBytes(invalid));
}
assert.deepEqual(wasm.ephemeralPubKeyBytes(new Uint8Array(32)), ["0", "1"]);
assert.deepEqual(wasm.ephemeralPubKeyBytes(new Uint8Array(32).fill(255)), wasm.ephemeralPubKey(((1n << 256n) - 1n).toString()));
assert.equal(wasm.poseidon(["1"]), healthyPoseidon);
console.log("Byte-input and signer lifecycle regressions passed");

// The point at infinity ("0.0") is never a key or announcement: scans skip it,
// sends throw an ordinary Error, and the validators refuse it.
const [metaK, metaV, metaBigK, metaBigV] = wasm.get_meta(
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
);
assert.equal(wasm.dbg_isValidBN254Point("0.0"), false);
assert.equal(wasm.dbg_isValidSECP256k1Point("0.0"), false);
assert.deepEqual(wasm.scan(metaK, metaV, ["0.0"], ["00"]), []);
assert.deepEqual(wasm.viewerScan(metaV, metaBigK, ["0.0"], ["00"]), []);
assertBoundaryError(() => wasm.send("0.0", metaBigV));
assertBoundaryError(() => wasm.send(metaBigK, "0.0"));
assertBoundaryError(() => wasm.viewerScan(metaV, "0.0", [], []));
assert.equal(wasm.poseidon(["1"]), healthyPoseidon);
console.log("Identity-point regressions passed");
