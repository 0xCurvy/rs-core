import assert from "node:assert/strict";
import test from "node:test";

import {
  ExactStreamReader,
  cachedSageProgramMetadata,
  deleteCachedSagePrograms,
  loadOrCompileSageProver,
} from "./sparrow-cache-api.mjs";

const SOURCE_HASH = "11".repeat(32);
const ZKEY_HASH = "22".repeat(32);
const GRAPH_URL = "https://curvy.test/circuit.signet";
const PROGRAM = Uint8Array.of(83, 65, 71, 69, 80, 67, 48, 49, 1, 2, 3, 4);

test("zero-length stream values are neither EOF nor trailing bytes", async () => {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(Uint8Array.of(1, 2));
      controller.enqueue(new Uint8Array());
      controller.enqueue(Uint8Array.of(3, 4));
      controller.enqueue(new Uint8Array());
      controller.close();
    },
  });
  const reader = new ExactStreamReader(stream.getReader());
  assert.deepEqual(await reader.readExact(4), Uint8Array.of(1, 2, 3, 4));
  assert.equal(await reader.atEnd(), true);
  reader.release();
});

test("SAGE is compiled once, round-trip checked, and reused from the derived cache", async () => {
  const cache = new MemoryCache();
  await cache.put(GRAPH_URL, new Response(Uint8Array.of(7, 8, 9)));
  const wasm = fakeWasm();

  const cold = await loadOrCompileSageProver(options(wasm, cache));
  assert.equal(cold.cacheHit, false);
  assert.equal(cold.cacheStored, true);
  assert.equal(cold.programBytes, PROGRAM.byteLength);
  assert.equal(wasm.calls.source, 1);
  assert.equal(wasm.calls.compiled, 1, "cold use round-trips through the cache decoder");
  assert.equal(wasm.calls.freed, 1, "compiler instance is released before decoding");

  const metadata = await cachedSageProgramMetadata(cache, SOURCE_HASH, false);
  assert.equal(metadata.bytes, PROGRAM.byteLength);
  assert.equal(metadata.sourceHash, SOURCE_HASH);
  assert.equal(metadata.compilerVersion, 7);

  const warm = await loadOrCompileSageProver(options(wasm, cache));
  assert.equal(warm.cacheHit, true);
  assert.equal(wasm.calls.source, 1, "warm use must not read or compile the source graph");
  assert.equal(wasm.calls.compiled, 2);

  await deleteCachedSagePrograms(cache, SOURCE_HASH, false);
  assert.equal(await cachedSageProgramMetadata(cache, SOURCE_HASH, false), null);
});

test("a corrupted SAGE cache entry is evicted and rebuilt from the authenticated graph", async () => {
  const cache = new MemoryCache();
  await cache.put(GRAPH_URL, new Response(Uint8Array.of(7, 8, 9)));
  const wasm = fakeWasm();
  await loadOrCompileSageProver(options(wasm, cache));

  const derivedRequest = (await cache.keys()).find((request) =>
    new URL(request.url).pathname.startsWith("/__curvy_derived/sage/"),
  );
  const response = await cache.match(derivedRequest);
  await cache.put(
    derivedRequest,
    new Response(Uint8Array.of(0), { headers: response.headers }),
  );

  const messages = [];
  const rebuilt = await loadOrCompileSageProver({
    ...options(wasm, cache),
    onStatus: (message) => messages.push(message),
  });
  assert.equal(rebuilt.cacheHit, false);
  assert.equal(wasm.calls.source, 2);
  assert.ok(messages.some((message) => message.includes("failed its stored digest or size")));
});

function options(wasm, cache) {
  return {
    wasm,
    cache,
    graphUrl: GRAPH_URL,
    expectedSourceGraphSha256: SOURCE_HASH,
    expectedZkeySha256: ZKEY_HASH,
    batchProfile: false,
    windowBits: 10,
    msmChunkPoints: 65_536,
  };
}

function fakeWasm() {
  const calls = { source: 0, compiled: 0, freed: 0 };
  class Prover {
    static fromSignetWithConfig(
      graph,
      sourceHash,
      zkeyHash,
      batchProfile,
      windowBits,
      msmChunkPoints,
    ) {
      assert.deepEqual(graph, Uint8Array.of(7, 8, 9));
      assert.equal(sourceHash, SOURCE_HASH);
      assert.equal(zkeyHash, ZKEY_HASH);
      assert.equal(batchProfile, false);
      assert.equal(windowBits, 10);
      assert.equal(msmChunkPoints, 65_536);
      calls.source += 1;
      return new Prover(true);
    }

    static fromCompiledSageWithConfig(
      program,
      programHash,
      sourceHash,
      zkeyHash,
      batchProfile,
      windowBits,
      msmChunkPoints,
    ) {
      assert.deepEqual(program, PROGRAM);
      assert.match(programHash, /^[0-9a-f]{64}$/);
      assert.equal(sourceHash, SOURCE_HASH);
      assert.equal(zkeyHash, ZKEY_HASH);
      assert.equal(batchProfile, false);
      assert.equal(windowBits, 10);
      assert.equal(msmChunkPoints, 65_536);
      calls.compiled += 1;
      return new Prover(false);
    }

    constructor(source) {
      this.source = source;
    }

    compiledSageProgram() {
      assert.equal(this.source, true);
      return PROGRAM.slice();
    }

    free() {
      calls.freed += 1;
    }
  }
  return {
    calls,
    sageCacheVersion: () => 7,
    WasmSparrowProver: Prover,
  };
}

class MemoryCache {
  constructor() {
    this.entries = new Map();
  }

  async put(request, response) {
    const key = requestUrl(request);
    this.entries.set(key, {
      body: new Uint8Array(await response.arrayBuffer()),
      headers: [...response.headers],
      status: response.status,
      statusText: response.statusText,
    });
  }

  async match(request) {
    const entry = this.entries.get(requestUrl(request));
    if (!entry) return undefined;
    return new Response(entry.body.slice(), {
      headers: entry.headers,
      status: entry.status,
      statusText: entry.statusText,
    });
  }

  async delete(request) {
    return this.entries.delete(requestUrl(request));
  }

  async keys() {
    return [...this.entries.keys()].map((url) => new Request(url));
  }
}

function requestUrl(request) {
  return request instanceof Request ? request.url : new Request(request).url;
}
