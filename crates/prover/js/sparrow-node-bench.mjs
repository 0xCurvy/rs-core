import { createReadStream } from "node:fs";
import { readFile } from "node:fs/promises";
import { Readable } from "node:stream";
import { performance } from "node:perf_hooks";

import wasm from "../pkg-node/curvy_prover.js";
import { authenticateResponse, proveResponse } from "./sparrow-cache-api.mjs";

if (process.argv.length !== 8) {
  throw new Error("usage: node sparrow-node-bench.mjs <zkey> <zkey-sha256> <graph> <graph-sha256> <input-json> <client|batch>");
}

const [, , zkeyPath, zkeyHash, graphPath, graphHash, inputPath, profile] = process.argv;
let peakRss = process.memoryUsage().rss;
const observe = () => { peakRss = Math.max(peakRss, process.memoryUsage().rss); };
const response = () => new Response(Readable.toWeb(createReadStream(zkeyPath, { highWaterMark: 1024 * 1024 })));

const totalStarted = performance.now();
const graph = await readFile(graphPath);
const graphStarted = performance.now();
const prover = new wasm.WasmSparrowProver(
  graph,
  graphHash,
  zkeyHash,
  profile === "batch",
);
observe();
const graphCompileMs = performance.now() - graphStarted;
const input = await readFile(inputPath, "utf8");

const authStarted = performance.now();
const authenticatedBytes = await authenticateResponse(prover, response(), observe);
const authMs = performance.now() - authStarted;
const proofStarted = performance.now();
const result = await proveResponse(prover, input, response(), observe, true);
const proofMs = performance.now() - proofStarted;
observe();

console.log(`runtime=rust-wasm-node-single-thread`);
console.log(`authenticated_bytes=${authenticatedBytes}`);
console.log(`sage_slots=${prover.sageSlots}`);
console.log(`assignment_size=${prover.assignmentSize}`);
console.log(`graph_compile_ms=${graphCompileMs.toFixed(3)}`);
console.log(`zkey_auth_pass_ms=${authMs.toFixed(3)}`);
console.log(`sparrow_proof_and_verify_ms=${proofMs.toFixed(3)}`);
console.log(`total_ms=${(performance.now() - totalStarted).toFixed(3)}`);
console.log(`peak_rss_bytes=${peakRss}`);
console.log(`proof_protocol=${result.proof.protocol}`);
