// Smoke test: the core compiled to wasm and called from the JS runtime produces
// the expected results for the committed reference vectors.
// Run: node crates/curvy-wasm/smoke-test.cjs

const assert = require("node:assert/strict");
const path = require("node:path");
const wasm = require("./pkg-node/curvy_wasm.js");

const TD = path.join(__dirname, "../curvy-core/testdata");
const poseidonVectors = require(path.join(TD, "poseidon_vectors.json"));
const p2 = require(path.join(TD, "phase2_vectors.json"));

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
for (const p of p2.pubFromPrivateKey) {
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

console.log(`WASM parity smoke test: ${checks} checks passed (Rust→wasm→JS == TS oracle)`);
