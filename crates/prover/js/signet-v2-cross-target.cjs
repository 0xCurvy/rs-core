"use strict";

// Native tests build the same four-node graph through curvy-signet. This
// independent byte builder makes the generated WebAssembly package prove that
// both SIGNET body versions decode to the same complete assignment, and that
// authentication/truncation failures survive the wasm-bindgen boundary.

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");

const wasm = require("../pkg-node/curvy_prover.js");

run();

function run() {
  const v1 = graph(1);
  const v2 = graph(2);
  const input = '{"a":"5"}';
  const v1Graph = new wasm.WasmWitnessGraph(v1, sha256(v1), false);
  assert.equal(v1Graph.assignmentSize, 2);
  assert.deepEqual(JSON.parse(v1Graph.calculate(input)), ["1", "7"]);

  if (process.argv.includes("--expect-v2-disabled")) {
    assert.throws(() => new wasm.WasmWitnessGraph(v2, sha256(v2), false));
    console.log("default portable WASM accepts SIGNET v1 and refuses v2");
    return;
  }

  const v2Graph = new wasm.WasmWitnessGraph(v2, sha256(v2), false);
  assert.equal(v2Graph.assignmentSize, 2);
  assert.equal(v1Graph.calculate(input), v2Graph.calculate(input));

  const corrupted = v2.slice();
  corrupted[100] ^= 1;
  assert.throws(() => new wasm.WasmWitnessGraph(corrupted, sha256(v2), false));

  const truncated = v2.subarray(0, v2.byteLength - 1);
  assert.throws(() => new wasm.WasmWitnessGraph(truncated, sha256(truncated), false));

  console.log("SIGNET v1/v2 portable-WASM parity and negative cases passed");
}

function graph(version) {
  const bytes = [];
  pushBytes(bytes, Buffer.from("SIGNET01", "ascii"));
  pushU16(bytes, version);
  pushU16(bytes, 1); // BN254 scalar field
  pushU32(bytes, 64);
  pushBytes(bytes, new Uint8Array(32).fill(7)); // source R1CS provenance
  pushU32(bytes, 4); // nodes
  pushU32(bytes, 2); // signals
  pushU32(bytes, 1); // mappings
  pushU32(bytes, 2); // input buffer

  if (version === 1) {
    bytes.push(1); pushField(bytes, 1);        // node 0: constant one
    bytes.push(0); pushU32(bytes, 1);          // node 1: input a
    bytes.push(1); pushField(bytes, 2);         // node 2: constant two
    bytes.push(2, 2); pushU32(bytes, 1); pushU32(bytes, 2); // node 3: add
    pushU32(bytes, 0); pushU32(bytes, 3);
  } else {
    bytes.push(0x81); pushField(bytes, 1);      // v2 constant
    bytes.push(0x80, 1);                       // v2 input
    bytes.push(0x81); pushField(bytes, 2);
    bytes.push(2, 2, 1);                       // add; backward distances
    bytes.push(0, 6);                          // ZigZag deltas: 0, +3
  }

  pushU64(bytes, fnv1a("a"));
  pushU32(bytes, 1);
  pushU32(bytes, 1);
  return Uint8Array.from(bytes);
}

function pushField(bytes, value) {
  pushU64(bytes, BigInt(value));
  pushBytes(bytes, new Uint8Array(24));
}

function pushU16(bytes, value) {
  bytes.push(value & 0xff, (value >>> 8) & 0xff);
}

function pushU32(bytes, value) {
  for (let shift = 0; shift < 32; shift += 8) bytes.push((value >>> shift) & 0xff);
}

function pushU64(bytes, value) {
  let remaining = BigInt(value);
  for (let index = 0; index < 8; index += 1) {
    bytes.push(Number(remaining & 0xffn));
    remaining >>= 8n;
  }
}

function pushBytes(bytes, value) {
  bytes.push(...value);
}

function fnv1a(value) {
  let hash = 0xcbf29ce484222325n;
  for (const byte of Buffer.from(value)) {
    hash ^= BigInt(byte);
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }
  return hash;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
