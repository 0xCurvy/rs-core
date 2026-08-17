import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const binding = require("../index.js");
const zkeyPath = resolve(here, "../../../crates/prover/testdata/multiplier.zkey");
const zkeySha256 = "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";

test("proves an authenticated generic circuit with one worker", async () => {
  const directory = await mkdtemp(join(tmpdir(), "curvy-node-test-"));
  const graph = multiplierGraph();
  const graphPath = join(directory, "multiplier.graph.bin");
  await writeFile(graphPath, graph);

  const prover = new binding.CircuitProver({
    zkeyPath,
    zkeySha256,
    witnessGraphPath: graphPath,
    witnessGraphSha256: digest(graph),
    threads: 1,
  });

  assert.equal(binding.rsCoreVersion(), "0.1.0-rc.5");
  assert.equal(prover.threads, 1);
  assert.equal(prover.numConstraints, 1);
  assert.equal(prover.numPublic, 1);
  assert.match(prover.r1csSha256, /^[0-9a-f]{64}$/);

  const result = await prover.prove(JSON.stringify({ a: "3", b: "11" }));
  assert.deepEqual(JSON.parse(result.publicSignalsJson), ["33"]);
  assert.equal(JSON.parse(result.proofJson).protocol, "groth16");
  assert.ok(result.witnessCalculationMs >= 0);
  assert.ok(result.proofGenerationMs >= 0);
});

test("defaults to one worker and rejects unsafe thread counts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "curvy-node-test-"));
  const graph = multiplierGraph();
  const graphPath = join(directory, "multiplier.graph.bin");
  await writeFile(graphPath, graph);
  const options = {
    zkeyPath,
    zkeySha256,
    witnessGraphPath: graphPath,
    witnessGraphSha256: digest(graph),
  };

  assert.equal(new binding.CircuitProver(options).threads, 1);
  assert.throws(() => new binding.CircuitProver({ ...options, threads: 0 }), /between 1 and 64/);
  assert.throws(() => new binding.CircuitProver({ ...options, threads: 65 }), /between 1 and 64/);
});

test("constructs pending-commitment input with the native indexed tree", () => {
  const tree = new binding.IndexedMerkleTree(4, JSON.stringify([]));
  const previousRoot = tree.root();
  const result = tree.buildPendingCommitment(2, JSON.stringify(["1"]));
  const input = JSON.parse(result.circuitInputJson);

  assert.equal(tree.leafCount, 1);
  assert.notEqual(result.newNotesRoot, previousRoot);
  assert.equal(tree.root(), result.newNotesRoot);
  assert.deepEqual(result.paddedNoteIds, ["1", "0"]);
  assert.deepEqual(input.pendingNoteIds, ["1", "0"]);
  assert.equal(input.siblings.length, 2);
  assert.equal(input.siblings[0].length, 4);
});

function multiplierGraph() {
  const chunks = [];
  const pushU16 = (value) => {
    const bytes = Buffer.alloc(2);
    bytes.writeUInt16LE(value);
    chunks.push(bytes);
  };
  const pushU32 = (value) => {
    const bytes = Buffer.alloc(4);
    bytes.writeUInt32LE(value);
    chunks.push(bytes);
  };
  const pushU64 = (value) => {
    const bytes = Buffer.alloc(8);
    bytes.writeBigUInt64LE(value);
    chunks.push(bytes);
  };

  chunks.push(Buffer.from("CVYWIT01"));
  pushU16(1);
  pushU16(1);
  pushU32(64);
  chunks.push(Buffer.alloc(32));
  pushU32(4);
  pushU32(4);
  pushU32(2);
  pushU32(3);

  for (let input = 0; input <= 2; input++) {
    chunks.push(Buffer.from([0]));
    pushU32(input);
  }
  chunks.push(Buffer.from([2, 0]));
  pushU32(1);
  pushU32(2);

  for (const signal of [0, 3, 1, 2]) pushU32(signal);
  for (const [name, signal] of [
    ["a", 1],
    ["b", 2],
  ]) {
    pushU64(fnv1a(name));
    pushU32(signal);
    pushU32(1);
  }
  return Buffer.concat(chunks);
}

function fnv1a(value) {
  let hash = 0xcbf29ce484222325n;
  for (const byte of Buffer.from(value)) {
    hash = BigInt.asUintN(64, (hash ^ BigInt(byte)) * 0x100000001b3n);
  }
  return hash;
}

function digest(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
