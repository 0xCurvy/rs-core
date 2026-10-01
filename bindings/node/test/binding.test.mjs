import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, writeFile, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const binding = require("../index.js");
const zkeyPath = resolve(here, "../../../crates/prover/testdata/multiplier.zkey");
const zkeySha256 = "320819c1761ecd5edc2d0f6978889457ea402e28d984c42b29153d0f7e81b21f";

test("exports only the resident prover name", () => {
  assert.equal(typeof binding.ResidentProver, "function");
  assert.equal(binding["Circuit" + "Prover"], undefined);
});

test("proves an authenticated generic circuit with one worker", async () => {
  const directory = await mkdtemp(join(tmpdir(), "curvy-node-test-"));
  const graph = multiplierGraph();
  const graphPath = join(directory, "multiplier.graph.bin");
  await writeFile(graphPath, graph);

  const prover = new binding.ResidentProver({
    zkeyPath,
    zkeySha256,
    witnessGraphPath: graphPath,
    witnessGraphSha256: digest(graph),
    threads: 1,
  });

  assert.equal(binding.rsCoreVersion(), "0.1.0-rc.5");
  assert.equal(prover.mode, "resident");
  assert.equal(prover.profile, "HAWK");
  assert.equal(prover.threads, 1);
  assert.equal(prover.numConstraints, 1);
  assert.equal(prover.numPublic, 1);
  assert.match(prover.r1csSha256, /^[0-9a-f]{64}$/);

  const result = await prover.prove(JSON.stringify({ a: "3", b: "11" }));
  assert.deepEqual(JSON.parse(result.publicSignalsJson), ["33"]);

  await assert.rejects(
    binding.ResidentProver.create({
      zkeyPath,
      zkeySha256,
      witnessGraphPath: graphPath,
      witnessGraphSha256: digest(graph),
      threads: 0,
    }),
    /between 1 and 64/,
  );
  assert.equal(JSON.parse(result.proofJson).protocol, "groth16");
  assert.ok(result.witnessCalculationMs >= 0);
  assert.ok(result.proofGenerationMs >= 0);
});

test("initializes an authenticated prover through the async factory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "curvy-node-test-"));
  const graph = multiplierGraph();
  const graphPath = join(directory, "multiplier.graph.bin");
  await writeFile(graphPath, graph);

  const initialization = binding.ResidentProver.create({
    zkeyPath,
    zkeySha256,
    witnessGraphPath: graphPath,
    witnessGraphSha256: digest(graph),
    threads: 1,
  });
  assert.ok(initialization instanceof Promise);

  const prover = await initialization;
  assert.ok(prover instanceof binding.ResidentProver);
  assert.equal(prover.numConstraints, 1);
  const result = await prover.prove(JSON.stringify({ a: "3", b: "11" }));
  assert.deepEqual(JSON.parse(result.publicSignalsJson), ["33"]);
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

  assert.equal(new binding.ResidentProver(options).threads, 1);
  assert.throws(() => new binding.ResidentProver({ ...options, threads: 0 }), /between 1 and 64/);
  assert.throws(() => new binding.ResidentProver({ ...options, threads: 65 }), /between 1 and 64/);
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

test("accepts canonical packed tree fields without decimal JSON arrays", () => {
  const tree = binding.IndexedMerkleTree.fromPackedLeaves(4, packFields([]));
  const previousRoot = tree.rootPacked();
  const result = tree.buildPendingCommitmentPacked(2, packFields([1n]));

  assert.ok(Buffer.isBuffer(previousRoot));
  assert.equal(previousRoot.length, 32);
  assert.equal(tree.rootPacked().length, 32);
  assert.notDeepEqual(tree.rootPacked(), previousRoot);
  assert.deepEqual(result.paddedNoteIds, ["1", "0"]);
  assert.throws(
    () => binding.IndexedMerkleTree.fromPackedLeaves(4, Buffer.alloc(31)),
    /multiple of 32/,
  );
  assert.throws(
    () => binding.IndexedMerkleTree.fromPackedLeaves(
      4,
      Buffer.from("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", "hex"),
    ),
    /not canonical/,
  );
});

async function fixtureOptions() {
  const directory = await mkdtemp(join(tmpdir(), "curvy-node-paths-"));
  const graph = multiplierGraph();
  const witnessGraphPath = join(directory, "graph.bin");
  await writeFile(witnessGraphPath, graph);
  return { zkeyPath, zkeySha256, witnessGraphPath, witnessGraphSha256: digest(graph), threads: 1 };
}

test("rejects oversized artifact files before authentication or whole-file allocation", async () => {
  const options = await fixtureOptions();
  const directory = dirname(options.witnessGraphPath);
  try {
    for (const [field, pin, limit, prefix] of [
      ["witnessGraphPath", "witnessGraphSha256", 64 * 1024 * 1024, Buffer.from("CVYW")],
      ["witnessGraphPath", "witnessGraphSha256", 32 * 1024 * 1024, Buffer.from([0x28, 0xb5, 0x2f, 0xfd])],
      ["sageProgramPath", "sageProgramSha256", 64 * 1024 * 1024, Buffer.alloc(4)],
      ["zkeyManifestPath", "zkeyManifestSha256", 4 * 1024 * 1024, Buffer.alloc(4)],
    ]) {
      const path = join(directory, "oversized.bin");
      const file = await open(path, "w");
      try { await file.write(prefix); await file.truncate(limit + 1); } finally { await file.close(); }
      const oversized = { ...options, [field]: path, [pin]: "00".repeat(32) };
      const error = new RegExp(`exceeds ${limit} byte limit`);
      assert.throws(() => new binding.ResidentProver(oversized), error);
      await assert.rejects(binding.ResidentProver.create(oversized), error);
    }
  } finally { await rm(directory, { recursive: true, force: true, maxRetries: 3 }); }
});

test("SAGE and manifest loading produce verified proofs", async () => {
  const options = await fixtureOptions();
  const zkey = await readFile(zkeyPath);
  const header = Buffer.alloc(60);
  header.write("CVYZKM01");
  header.writeUInt32LE(1, 8);
  header.writeUInt32LE(65536, 12);
  header.writeBigUInt64LE(BigInt(zkey.length), 16);
  Buffer.from(zkeySha256, "hex").copy(header, 24);
  header.writeUInt32LE(1, 56);
  const manifest = Buffer.concat([header, Buffer.from(zkeySha256, "hex")]);
  const zkeyManifestPath = join(dirname(options.witnessGraphPath), "manifest.bin");
  await writeFile(zkeyManifestPath, manifest);
  const prover = await binding.ResidentProver.create({ ...options, useSage: true,
    zkeyManifestPath, zkeyManifestSha256: digest(manifest) });
  assert.equal(prover.witnessBackend, "sage");
  assert.deepEqual(JSON.parse((await prover.prove('{"a":"7","b":"5"}')).publicSignalsJson), ["35"]);
  await assert.rejects(binding.ResidentProver.create({ ...options, zkeyManifestPath }), /together/);
  await assert.rejects(binding.ResidentProver.create({ ...options, zkeyManifestPath,
    zkeyManifestSha256: "00".repeat(32) }), /SHA-256 mismatch/);
  await assert.rejects(binding.ResidentProver.create({ ...options, sageProgramPath: "unused" }), /together/);
});

test("loads a compiled SAGE cache without the source graph file", async () => {
  const options = await fixtureOptions();
  // Generated by derive_sage_cache from multiplierGraph(); deterministic SAGEPC01.
  const program = Buffer.from("U0FHRVBDMDEBAAAAbAAAAIEcAj2XphAPvRxzqyNKoDX6R7rfXcVa9FwjJpHXCW0YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAACAAAAAwAAAAQAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAABAAAAAwAAAAAAAAAAAAAAAQAAAAIAAAACAAAAAwAAAAMAAAABAAAAjOwBhkzcY68BAAAAAQAAAKXxAYZM32OvAgAAAAEAAAA=", "base64");
  const sageProgramPath = join(dirname(options.witnessGraphPath), "program.bin");
  await writeFile(sageProgramPath, program);
  const cachedOptions = { ...options, witnessGraphPath: undefined, sageProgramPath, sageProgramSha256: digest(program) };
  const prover = await binding.ResidentProver.create(cachedOptions);
  assert.equal(prover.witnessBackend, "sage");
  assert.deepEqual(JSON.parse((await prover.prove('{"a":"3","b":"11"}')).publicSignalsJson), ["33"]);
  await assert.rejects(binding.ResidentProver.create({ ...cachedOptions, witnessGraphSha256: "00".repeat(32) }), /source hash mismatch/);
  await assert.rejects(binding.ResidentProver.create({ ...cachedOptions, sageProgramSha256: "00".repeat(32) }), /SHA-256 mismatch/);
});

test("bounded proof queue rejects overload and recovers after errors", async () => {
  const options = await fixtureOptions();
  for (const maxPendingProofs of [0, 65]) {
    assert.throws(() => new binding.ResidentProver({ ...options, maxPendingProofs }), /between 1 and 64/);
  }
  const prover = new binding.ResidentProver({ ...options, maxPendingProofs: 1 });
  const results = await Promise.allSettled(Array.from({ length: 32 }, () => prover.prove('{"a":"3","b":"11"}')));
  assert.equal(results[0].status, "fulfilled");
  assert.ok(results.some(result => result.status === "rejected" && /queue is full/.test(result.reason.message)));
  await assert.rejects(prover.prove("{"));
  for (let i = 0; i < 3; i++) {
    assert.deepEqual(JSON.parse((await prover.prove('{"a":"3","b":"11"}')).publicSignalsJson), ["33"]);
  }
});

test("waiting proofs leave the shared libuv pool available", async () => {
  const options = await fixtureOptions();
  const { stdout } = await promisify(execFile)(process.execPath,
    [join(here, "queue-child.mjs"), JSON.stringify(options)],
    { env: { ...process.env, UV_THREADPOOL_SIZE: "1" }, timeout: 30000 });
  const result = JSON.parse(stdout);
  assert.equal(result.completed, 32);
  assert.ok(result.completedAtIO < 32, JSON.stringify(result));
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

function packFields(values) {
  return Buffer.concat(
    values.map((value) => {
      const encoded = value.toString(16).padStart(64, "0");
      return Buffer.from(encoded, "hex");
    }),
  );
}

test("pending batches reject resource-exhausting sizes without changing the tree", () => {
  const tree = new binding.IndexedMerkleTree(30, "[]");
  const before = tree.root();
  for (const count of [0,4097,200000,0xffffffff]) {
    assert.throws(()=>tree.buildPendingCommitment(count,'["1"]'), /batchSize must be between/);
    assert.throws(()=>tree.buildPendingCommitmentPacked(count,Buffer.alloc(32)), /batchSize must be between/);
    assert.equal(tree.root(),before);
    assert.equal(tree.leafCount,0);
  }
});

test("pending batches that fail mid-insert leave the live tree unchanged", () => {
  // Depth 2 holds four leaves. Each failing batch inserts at least one note
  // into the working copy before the error, so only clone-and-swap keeps the
  // live tree intact.
  const tree = new binding.IndexedMerkleTree(2, JSON.stringify(["5"]));
  const before = tree.root();
  for (const [build, error] of [
    [() => tree.buildPendingCommitment(4, JSON.stringify(["7", "5"])), /leaf already exists/],
    [() => tree.buildPendingCommitment(4, JSON.stringify(["7", "7"])), /leaf already exists/],
    [() => tree.buildPendingCommitment(4, JSON.stringify(["6", "7", "8", "9"])), /tree is full/],
    [() => tree.buildPendingCommitmentPacked(4, packFields([7n, 5n])), /leaf already exists/],
    [() => tree.buildPendingCommitmentPacked(4, packFields([6n, 7n, 8n, 9n])), /tree is full/],
  ]) {
    assert.throws(build, error);
    assert.equal(tree.root(), before);
    assert.equal(tree.leafCount, 1);
  }
  const result = tree.buildPendingCommitment(4, JSON.stringify(["6", "7"]));
  const input = JSON.parse(result.circuitInputJson);
  assert.equal(input.currentNotesRoot, before);
  assert.equal(input.currentNoteIndex, "1");
  assert.equal(tree.leafCount, 3);
  assert.equal(tree.root(), result.newNotesRoot);
});

test("close lets accepted proofs settle, then rejects new work", async () => {
  const prover = new binding.ResidentProver({ ...(await fixtureOptions()), maxPendingProofs: 4 });
  assert.equal(prover.closed, false);
  const accepted = [
    prover.prove('{"a":"3","b":"11"}'),
    prover.prove('{"a":"7","b":"5"}'),
    prover.prove("{"),
  ];
  const closing = prover.close();
  assert.equal(prover.closed, true);
  await assert.rejects(prover.prove('{"a":"3","b":"11"}'), /prover is closed/);
  assert.equal(typeof prover.numConstraints, "number");

  // Accepted before close(): each settles exactly as it would have otherwise.
  const [first, second, invalid] = await Promise.allSettled(accepted);
  assert.deepEqual(JSON.parse(first.value.publicSignalsJson), ["33"]);
  assert.deepEqual(JSON.parse(second.value.publicSignalsJson), ["35"]);
  assert.equal(invalid.status, "rejected");
  assert.doesNotMatch(invalid.reason.message, /closed/);
  assert.equal(await closing, undefined);
  assert.equal(await prover.close(), undefined);
  assert.equal(prover.closed, true);
});

test("an idle prover closes immediately; proving fails but metadata stays readable", async () => {
  const prover = await binding.ResidentProver.create(await fixtureOptions());
  const getters = [
    "artifactLoadMs", "artifactInitializationMs", "numConstraints", "numPublic", "threads",
    "mode", "profile", "witnessBackend", "verifyingKeyDigest", "r1csSha256",
  ];
  const before = Object.fromEntries(getters.map((getter) => [getter, prover[getter]]));
  await prover.close();
  await assert.rejects(
    prover.prove('{"a":"3","b":"11"}'),
    (error) => error.code === "Closing" && error.message === "prover is closed",
  );
  for (const getter of getters) {
    assert.equal(prover[getter], before[getter], getter);
  }
  await Promise.all([prover.close(), prover.close()]);
  assert.equal(prover.closed, true);
});

test("explicit resource management closes the prover", async () => {
  const options = await fixtureOptions();
  const awaited = new binding.ResidentProver(options);
  assert.equal(await awaited[Symbol.asyncDispose](), undefined);
  assert.equal(awaited.closed, true);

  const synchronous = new binding.ResidentProver(options);
  assert.equal(synchronous[Symbol.dispose](), undefined);
  assert.equal(synchronous.closed, true);
  await synchronous.close();
});


test("witness errors redact invalid values and reject duplicate signals", async () => {
  const prover = new binding.ResidentProver(await fixtureOptions());
  for (const input of ['{"a":"PRIVATE_SENTINEL!","b":"11"}', '{"a":"3","a":"4","b":"11"}']) {
    await assert.rejects(prover.prove(input), error => !error.message.includes("PRIVATE_SENTINEL"));
  }
  assert.deepEqual(JSON.parse((await prover.prove('{"a":"3","b":"11"}')).publicSignalsJson),["33"]);
});

test("zkey file size is bounded before hashing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "curvy-node-size-test-"));
  const path = join(directory, "oversized.zkey");
  try {
    const file = await open(path, "w");
    try { await file.truncate(4 * 1024 ** 3 + 1); } finally { await file.close(); }
    assert.throws(() => new binding.ResidentProver({
      zkeyPath: path, zkeySha256, witnessGraphPath: zkeyPath, witnessGraphSha256: zkeySha256,
    }), /byte limit/);
  } finally { await rm(directory, { recursive: true, force: true, maxRetries: 3 }); }
});
