import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";

import {
  ExactStreamReader,
  authenticateResponse,
  cachedArtifactBytes,
  cachedSageProgramMetadata,
  deleteCachedSagePrograms,
  loadOrCompileStreamingProver,
  proveCachedZkey,
  proveManifestResponse,
  proveResponse,
} from "./sparrow-cache-api.mjs";

const SOURCE_HASH = "11".repeat(32);
const ZKEY_HASH = "22".repeat(32);
const GRAPH_URL = "https://curvy.test/circuit.signet";
const GRAPH = Uint8Array.of(7, 8, 9);
const PROGRAM = Uint8Array.of(83, 65, 71, 69, 80, 67, 48, 49, 1, 2, 3, 4);
const PROGRAM_HASH = sha256(PROGRAM);

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
  await cache.put(GRAPH_URL, new Response(GRAPH));
  const wasm = fakeWasm();

  const cold = await loadOrCompileStreamingProver(options(wasm, cache));
  assert.equal(cold.cacheHit, false);
  assert.equal(cold.cacheStored, true);
  assert.equal(cold.programPinned, true);
  assert.equal(cold.prover.mode, "streaming");
  assert.equal(cold.prover.profile, "SPARROW");
  assert.equal(cold.programBytes, PROGRAM.byteLength);
  assert.equal(wasm.calls.source, 1);
  assert.equal(wasm.calls.compiled, 1, "cold use round-trips through the cache decoder");
  assert.equal(wasm.calls.freed, 1, "compiler instance is released before decoding");

  const metadata = await cachedSageProgramMetadata(cache, SOURCE_HASH, false);
  assert.equal(metadata.bytes, PROGRAM.byteLength);
  assert.equal(metadata.sourceHash, SOURCE_HASH);
  assert.equal(metadata.compilerVersion, 7);

  const warm = await loadOrCompileStreamingProver(options(wasm, cache));
  assert.equal(warm.cacheHit, true);
  assert.equal(wasm.calls.source, 1, "warm use must not read or compile the source graph");
  assert.equal(wasm.calls.compiled, 2);

  await deleteCachedSagePrograms(cache, SOURCE_HASH, false);
  assert.equal(await cachedSageProgramMetadata(cache, SOURCE_HASH, false), null);
});

test("a corrupted SAGE cache entry is evicted and rebuilt from the authenticated graph", async () => {
  const cache = new MemoryCache();
  await cache.put(GRAPH_URL, new Response(GRAPH));
  const wasm = fakeWasm();
  await loadOrCompileStreamingProver(options(wasm, cache));

  const derivedRequest = (await cache.keys()).find((request) =>
    new URL(request.url).pathname.startsWith("/__curvy_derived/sage/"),
  );
  const response = await cache.match(derivedRequest);
  await cache.put(
    derivedRequest,
    new Response(Uint8Array.of(0), { headers: response.headers }),
  );

  const messages = [];
  const rebuilt = await loadOrCompileStreamingProver({
    ...options(wasm, cache),
    onStatus: (message) => messages.push(message),
  });
  assert.equal(rebuilt.cacheHit, false);
  assert.equal(wasm.calls.source, 2);
  assert.ok(messages.some((message) => message.includes("failed its stored digest or size")));
});

test("a cache-controlled digest is not a trusted compiled-program pin", async () => {
  const cache = new MemoryCache();
  await cache.put(GRAPH_URL, new Response(GRAPH));
  const wasm = fakeWasm();
  await loadOrCompileStreamingProver(options(wasm, cache));
  const result = await loadOrCompileStreamingProver({
    ...options(wasm, cache),
    expectedSageProgramSha256: null,
  });
  assert.equal(result.cacheHit, false);
  assert.equal(wasm.calls.source, 2);
});

test("without a trusted program pin the derived cache is neither read nor written", async () => {
  const cache = new MemoryCache();
  await cache.put(GRAPH_URL, new Response(GRAPH));
  const wasm = fakeWasm();
  const messages = [];
  const unpinned = {
    ...options(wasm, cache),
    expectedSageProgramSha256: null,
    onStatus: (message) => messages.push(message),
  };

  const first = await loadOrCompileStreamingProver(unpinned);
  assert.equal(first.cacheHit, false);
  assert.equal(first.cacheStored, false, "an entry no warm load may read must not be reported stored");
  assert.equal(first.programPinned, false);
  assert.equal(first.cacheWriteError, null);
  assert.equal(await cachedSageProgramMetadata(cache, SOURCE_HASH, false), null);
  assert.ok(messages.some((message) => message.includes("not cached")));

  // An entry written by a pinned load survives later unpinned loads.
  await loadOrCompileStreamingProver(options(wasm, cache));
  const stored = await cachedSageProgramMetadata(cache, SOURCE_HASH, false);
  assert.equal(stored.programHash, PROGRAM_HASH);
  const second = await loadOrCompileStreamingProver(unpinned);
  assert.equal(second.cacheStored, false);
  assert.deepEqual(await cachedSageProgramMetadata(cache, SOURCE_HASH, false), stored);
});

test("a poisoned cached graph is evicted and refetched once from the network", async (t) => {
  const cache = new MemoryCache();
  await cache.put(GRAPH_URL, new Response(Uint8Array.of(6, 6, 6)));
  const fetches = mockFetch(t, () => new Response(GRAPH));
  const wasm = fakeWasm();
  const messages = [];

  const result = await loadOrCompileStreamingProver({
    ...options(wasm, cache),
    onStatus: (message) => messages.push(message),
  });
  assert.equal(result.cacheHit, false);
  assert.equal(fetches.length, 1);
  assert.equal(fetches[0].url, GRAPH_URL);
  assert.equal(fetches[0].init?.cache, "no-store", "the retry must bypass the HTTP cache");
  assert.equal(wasm.calls.rejectedGraphs, 1);
  assert.ok(messages.some((message) => message.includes("rejected; refetching")));
  assert.deepEqual(await cachedBody(cache, GRAPH_URL), GRAPH, "authenticated bytes replace the poisoned entry");

  // The repaired entry is used without another network request.
  await loadOrCompileStreamingProver({ ...options(wasm, cache), expectedSageProgramSha256: null });
  assert.equal(fetches.length, 1);
});

test("a graph that fails authentication is never cached and is refetched at most once", async (t) => {
  const cache = new MemoryCache();
  const fetches = mockFetch(t, () => new Response(Uint8Array.of(5, 5, 5)));
  const wasm = fakeWasm();

  await assert.rejects(loadOrCompileStreamingProver(options(wasm, cache)), /SIGNET graph SHA-256 mismatch/);
  assert.equal(fetches.length, 1);
  assert.equal(fetches[0].init, undefined, "a cache miss uses the default fetch");
  assert.equal(await cache.match(GRAPH_URL), undefined);

  await cache.put(GRAPH_URL, new Response(Uint8Array.of(6, 6, 6)));
  await assert.rejects(loadOrCompileStreamingProver(options(wasm, cache)), /SIGNET graph SHA-256 mismatch/);
  assert.equal(fetches.length, 2, "one refetch after the poisoned cache entry, no more");
  assert.equal(await cache.match(GRAPH_URL), undefined, "neither poisoned copy is left cached");
});

test("a pinned artifact read evicts a poisoned cache entry and refetches once", async (t) => {
  const url = "https://curvy.test/zkey-manifest.bin";
  const good = Uint8Array.of(1, 2, 3, 4);
  const cache = new MemoryCache();
  await cache.put(url, new Response(Uint8Array.of(9, 9, 9, 9)));
  const fetches = mockFetch(t, () => new Response(good));

  const bytes = await cachedArtifactBytes(cache, url, { maxBytes: 16, expectedSha256: sha256(good) });
  assert.deepEqual(bytes, good);
  assert.equal(fetches.length, 1);
  assert.deepEqual(await cachedBody(cache, url), good);

  // A hit that matches its pin is returned without touching the network.
  assert.deepEqual(await cachedArtifactBytes(cache, url, { expectedSha256: sha256(good) }), good);
  assert.equal(fetches.length, 1);

  await assert.rejects(
    cachedArtifactBytes(cache, url, { expectedSha256: "33".repeat(32) }),
    /artifact digest mismatch/,
  );
  assert.equal(fetches.length, 2);
  assert.equal(await cache.match(url), undefined);
});

test("artifact reads are capped before an oversized body is buffered", async (t) => {
  const url = "https://curvy.test/input.json";
  const cache = new MemoryCache();

  // A declared length above the cap is rejected without reading the body.
  let pulls = 0;
  mockFetch(t, () => new Response(
    new ReadableStream({ pull(controller) { pulls += 1; controller.enqueue(new Uint8Array(4)); } }),
    { headers: { "content-length": "1000" } },
  ));
  await assert.rejects(cachedArtifactBytes(cache, url, { maxBytes: 8 }), /declares 1000 bytes/);
  assert.ok(pulls <= 1, "the declared length is checked before streaming");
  assert.equal(await cache.match(url), undefined);
  t.mock.restoreAll();

  // An undeclared stream stops at the first chunk that crosses the cap.
  pulls = 0;
  let cancelled = false;
  mockFetch(t, () => new Response(new ReadableStream({
    pull(controller) { pulls += 1; controller.enqueue(new Uint8Array(4)); },
    cancel() { cancelled = true; },
  })));
  await assert.rejects(cachedArtifactBytes(cache, url, { maxBytes: 8 }), /exceeds the 8-byte limit/);
  assert.ok(pulls <= 4, `stream was drained (${pulls} pulls)`);
  assert.equal(cancelled, true);
  assert.equal(await cache.match(url), undefined);
  t.mock.restoreAll();

  // A cached copy over the cap is evicted and replaced from the network.
  const good = Uint8Array.of(1, 2, 3, 4, 5, 6, 7);
  await cache.put(url, new Response(new Uint8Array(32)));
  const fetches = mockFetch(t, () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(good.subarray(0, 3));
      controller.enqueue(new Uint8Array());
      controller.enqueue(good.subarray(3));
      controller.close();
    },
  })));
  assert.deepEqual(await cachedArtifactBytes(cache, url, { maxBytes: 8 }), good);
  assert.equal(fetches.length, 1);
  assert.deepEqual(await cachedBody(cache, url), good);

  await assert.rejects(cachedArtifactBytes(cache, url, { maxBytes: 0 }), /maxBytes/);
});

test("a redundant authentication neither wedges the prover nor rereads the zkey", async () => {
  const zkey = syntheticZkey();
  const prover = new FakeStreamingProver(sha256(zkey));
  const first = await authenticateResponse(prover, new Response(zkey));
  assert.equal(first, BigInt(zkey.byteLength));
  const chunks = prover.calls.authChunks;
  assert.ok(chunks > 1);

  const second = await authenticateResponse(prover, new Response(zkey));
  assert.equal(second, first);
  assert.equal(prover.calls.authChunks, chunks, "the redundant call must not feed Rust again");
  assert.equal(prover.zkeyAuthenticated, true);
  assert.deepEqual((await proveResponse(prover, "{}", new Response(zkey))).publicSignals, ["6"]);
});

test("proveCachedZkey can be called repeatedly on a reusable prover", async () => {
  const zkey = syntheticZkey();
  const request = "https://curvy.test/circuit.zkey";
  const cache = new MemoryCache();
  await cache.put(request, new Response(zkey));
  const prover = new FakeStreamingProver(sha256(zkey));

  for (let run = 0; run < 3; run += 1) {
    const result = await proveCachedZkey({ prover, inputJson: "{}", cache, request });
    assert.equal(result.proof.protocol, "groth16");
  }
  assert.equal(prover.calls.resets, 1, "only the first proof runs the authentication pass");
  assert.equal(prover.calls.authChunks, Math.ceil(zkey.byteLength / (64 * 1024)));
});

test("a failed or partial authentication pass can be retried from byte 0", async () => {
  const zkey = syntheticZkey();
  const prover = new FakeStreamingProver(sha256(zkey));

  const corrupted = zkey.slice();
  corrupted[corrupted.length - 1] ^= 1;
  await assert.rejects(authenticateResponse(prover, new Response(corrupted)), /mismatch/);
  assert.equal(prover.zkeyAuthenticated, false);

  // The stream fails after one chunk reached Rust, leaving a partial digest.
  const partial = new ReadableStream({
    start(controller) { controller.enqueue(zkey.subarray(0, 64 * 1024)); },
    pull(controller) { controller.error(new Error("network reset")); },
  });
  await assert.rejects(authenticateResponse(prover, new Response(partial)), /network reset/);
  assert.equal(prover.zkeyAuthenticated, false);

  assert.equal(await authenticateResponse(prover, new Response(zkey)), BigInt(zkey.byteLength));
  assert.equal(prover.zkeyAuthenticated, true);
  assert.equal((await proveResponse(prover, "{}", new Response(zkey))).proof.protocol, "groth16");
});

test("a failed proof stream is aborted and the reusable prover proves again", async () => {
  const zkey = syntheticZkey();
  const prover = new FakeStreamingProver(sha256(zkey));
  await authenticateResponse(prover, new Response(zkey));

  await assert.rejects(
    proveResponse(prover, "{}", new Response(zkey.subarray(0, zkey.length - 10))),
    /zkey changed after authentication/,
  );
  assert.equal(prover.proofActive, false);
  assert.equal(prover.graphReleased, false);

  prover.failNextPush = true;
  await assert.rejects(proveResponse(prover, "{}", new Response(zkey)), /injected section parse failure/);
  assert.equal(prover.proofActive, false);

  await assert.rejects(
    proveResponse(prover, "{}", new Response(zkey), () => { throw new Error("benchmark stopped by user"); }),
    /stopped by user/,
  );
  assert.equal(prover.proofActive, false);

  const result = await proveResponse(prover, "{}", new Response(zkey));
  assert.equal(result.proof.protocol, "groth16");
  assert.equal(prover.calls.begin, 4);
});

test("a failed one-shot stream leaves a clearly released prover, not a wedged one", async () => {
  const zkey = syntheticZkey();
  const prover = new FakeStreamingProver(sha256(zkey));
  await authenticateResponse(prover, new Response(zkey));

  await assert.rejects(
    proveResponse(prover, "{}", new Response(zkey.subarray(0, 100)), () => {}, true),
    /zkey changed after authentication|ended early/,
  );
  assert.equal(prover.proofActive, false);
  assert.equal(prover.graphReleased, true);
  await assert.rejects(
    proveResponse(prover, "{}", new Response(zkey), () => {}, true),
    /SAGE graph has already been released/,
  );
  assert.equal(prover.proofActive, false);
});

test("invalid one-shot input keeps the graph and the prover retryable", async () => {
  const zkey = syntheticZkey();
  const prover = new FakeStreamingProver(sha256(zkey));
  await authenticateResponse(prover, new Response(zkey));
  await assert.rejects(proveResponse(prover, "{", new Response(zkey), () => {}, true), SyntaxError);
  assert.equal(prover.graphReleased, false);
  assert.equal((await proveResponse(prover, "{}", new Response(zkey), () => {}, true)).proof.protocol, "groth16");
  assert.equal(prover.graphReleased, true);
});

test("proving checks authentication before any begin can release the graph", async () => {
  const zkey = syntheticZkey();
  const prover = new FakeStreamingProver(sha256(zkey));
  for (const oneShot of [false, true]) {
    await assert.rejects(
      proveResponse(prover, "{}", new Response(zkey), () => {}, oneShot),
      /authenticate this zkey response before proving/,
    );
  }
  assert.equal(prover.calls.begin, 0);
  assert.equal(prover.graphReleased, false);

  // Retained hashes do not stand in for a Rust pass that was reset.
  await authenticateResponse(prover, new Response(zkey));
  prover.resetZkeyAuthentication();
  await assert.rejects(
    proveResponse(prover, "{}", new Response(zkey), () => {}, true),
    /authenticate this zkey response before proving/,
  );
  assert.equal(prover.calls.begin, 0);
  assert.equal(prover.graphReleased, false);
  await authenticateResponse(prover, new Response(zkey));
  assert.equal(prover.zkeyAuthenticated, true);
});

test("a replaced stream is rejected before any changed header reaches Rust", async () => {
  const zkey = syntheticZkey();
  const prover = new FakeStreamingProver(sha256(zkey));
  let began = false;
  prover.beginZkey = () => { began = true; throw new Error("parser must not see changed bytes"); };
  await authenticateResponse(prover, new Response(zkey));
  const replaced = zkey.slice();
  replaced[0] ^= 1;
  await assert.rejects(proveResponse(prover, "{}", new Response(replaced)), /changed after authentication/);
  assert.equal(began, false);
  assert.equal(prover.proofActive, false, "the rejected proof is aborted");
});

test("manifest proofs succeed, and a failed manifest stream is aborted", async () => {
  const zkey = syntheticZkey();
  const { manifest, manifestHash } = syntheticManifest(zkey);
  const success = new FakeStreamingProver(sha256(zkey));
  const result = await proveManifestResponse(success, "{}", manifest, manifestHash, new Response(zkey));
  assert.equal(result.proof.protocol, "groth16");
  assert.equal(success.graphReleased, true);

  const prover = new FakeStreamingProver(sha256(zkey));
  await assert.rejects(
    proveManifestResponse(prover, "{}", manifest, manifestHash, new Response(zkey.subarray(0, 70_000))),
    /ended early/,
  );
  assert.equal(prover.proofActive, false);
  assert.equal(prover.graphReleased, true);
  await assert.rejects(
    proveManifestResponse(prover, "{}", manifest, manifestHash, new Response(zkey)),
    /SAGE graph has already been released/,
  );

  const wrongPin = new FakeStreamingProver(sha256(zkey));
  await assert.rejects(
    proveManifestResponse(wrongPin, "{}", manifest, "44".repeat(32), new Response(zkey)),
    /manifest SHA-256 mismatch/,
  );
  assert.equal(wrongPin.graphReleased, false, "a rejected manifest does not release the graph");
});

function options(wasm, cache) {
  return {
    wasm,
    cache,
    graphUrl: GRAPH_URL,
    expectedSourceGraphSha256: SOURCE_HASH,
    expectedZkeySha256: ZKEY_HASH,
    expectedSageProgramSha256: PROGRAM_HASH,
    batchProfile: false,
    windowBits: 10,
    msmChunkPoints: 65_536,
  };
}

function fakeWasm() {
  const calls = { source: 0, compiled: 0, freed: 0, rejectedGraphs: 0 };
  class Prover {
    static fromSignetWithConfig(
      graph,
      sourceHash,
      zkeyHash,
      batchProfile,
      windowBits,
      msmChunkPoints,
    ) {
      // Stands in for SIGNET authentication against the pinned source digest.
      if (!bytesEqual(graph, GRAPH)) {
        calls.rejectedGraphs += 1;
        throw new Error("SIGNET graph SHA-256 mismatch");
      }
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
      this.mode = "streaming";
      this.profile = "SPARROW";
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
    WasmStreamingProver: Prover,
  };
}

// Mirrors the WasmStreamingProver state machine in src/wasm_api.rs: one
// whole-file authenticator that restarts on a failed digest, at most one
// active proof, abortProof, and one-shot begins that release the graph only
// after witness calculation succeeds.
const AUTHENTICATION_COMPLETE =
  "zkey authentication pass is already complete; call resetZkeyAuthentication to authenticate again";
const GRAPH_RELEASED =
  "the one-shot SAGE graph has already been released; construct a new WasmStreamingProver";

class FakeStreamingProver {
  constructor(expectedZkeySha256) {
    this.expectedZkeySha256 = expectedZkeySha256;
    this.graph = true;
    this.authenticator = freshAuthenticator();
    this.authenticated = false;
    this.authenticatedBytes = 0n;
    this.proof = null;
    this.manifestProof = null;
    this.failNextPush = false;
    this.calls = { authChunks: 0, begin: 0, resets: 0 };
  }

  get zkeyAuthenticated() { return this.authenticated; }
  get proofActive() { return Boolean(this.proof || this.manifestProof); }
  get graphReleased() { return !this.graph; }

  authenticateZkeyChunk(bytes) {
    if (!this.authenticator) throw new Error(AUTHENTICATION_COMPLETE);
    this.authenticator.hash.update(bytes);
    this.authenticator.bytes += BigInt(bytes.byteLength);
    this.calls.authChunks += 1;
  }

  finishZkeyAuthentication() {
    const authenticator = this.authenticator;
    if (!authenticator) throw new Error(AUTHENTICATION_COMPLETE);
    this.authenticator = null;
    const actual = authenticator.hash.digest("hex");
    if (actual !== this.expectedZkeySha256) {
      this.authenticator = freshAuthenticator();
      throw new Error(
        `zkey SHA-256 mismatch: expected ${this.expectedZkeySha256}, got ${actual}; ` +
        "zkey authentication restarted, feed the zkey again from byte 0",
      );
    }
    this.authenticated = true;
    this.authenticatedBytes = authenticator.bytes;
    return authenticator.bytes;
  }

  resetZkeyAuthentication() {
    if (this.proofActive) {
      throw new Error("cannot reset zkey authentication while a SPARROW proof is active; call abortProof first");
    }
    this.calls.resets += 1;
    this.authenticator = freshAuthenticator();
    this.authenticated = false;
    this.authenticatedBytes = 0n;
  }

  abortProof() {
    this.proof = null;
    this.manifestProof = null;
  }

  beginProof(inputJson) {
    this.#checkCanBegin(true);
    JSON.parse(inputJson);
    this.calls.begin += 1;
    this.proof = new FakeFramedProof(this.authenticatedBytes);
  }

  beginOneShotProof(inputJson) {
    this.#checkCanBegin(true);
    JSON.parse(inputJson);
    this.calls.begin += 1;
    this.graph = false;
    this.proof = new FakeFramedProof(this.authenticatedBytes);
  }

  beginOneShotManifestProof(inputJson, manifestBytes, expectedManifestSha256) {
    this.#checkCanBegin(false);
    if (sha256(manifestBytes) !== expectedManifestSha256) throw new Error("zkey manifest SHA-256 mismatch");
    const view = new DataView(manifestBytes.buffer, manifestBytes.byteOffset, manifestBytes.byteLength);
    if (Buffer.from(manifestBytes.subarray(24, 56)).toString("hex") !== this.expectedZkeySha256) {
      throw new Error("zkey manifest identifies a different zkey");
    }
    JSON.parse(inputJson);
    const hashes = [];
    for (let offset = 60; offset < manifestBytes.byteLength; offset += 32) {
      hashes.push(Buffer.from(manifestBytes.subarray(offset, offset + 32)).toString("hex"));
    }
    this.calls.begin += 1;
    this.graph = false;
    this.manifestProof = { hashes, index: 0, chunkBytes: view.getUint32(12, true) };
  }

  pushManifestZkeyChunk(bytes) {
    const proof = this.manifestProof;
    if (!proof) throw new Error("no manifest-authenticated proof is active");
    if (proof.index >= proof.hashes.length || sha256(bytes) !== proof.hashes[proof.index]) {
      throw new Error(`zkey chunk ${proof.index} SHA-256 mismatch`);
    }
    proof.index += 1;
  }

  finishManifestProof() {
    const proof = this.manifestProof;
    if (!proof) throw new Error("no manifest-authenticated proof is active");
    this.manifestProof = null;
    if (proof.index !== proof.hashes.length) throw new Error("zkey stream ended early");
    return PROOF_JSON;
  }

  beginZkey(header) { this.#active().beginZkey(header); }
  beginZkeySection(header) { this.#active().beginSection(header); }
  pushZkeySectionChunk(bytes) {
    const proof = this.#active();
    if (this.failNextPush) {
      this.failNextPush = false;
      throw new Error("injected section parse failure");
    }
    proof.push(bytes);
  }
  endZkeySection() { this.#active().endSection(); }

  finishProof() {
    const proof = this.#active();
    this.proof = null;
    return proof.finish();
  }

  #active() {
    if (!this.proof) throw new Error("no SPARROW proof is active");
    return this.proof;
  }

  #checkCanBegin(requiresAuthentication) {
    if (this.proofActive) throw new Error("a SPARROW proof is already active; finish it or call abortProof");
    if (!this.graph) throw new Error(GRAPH_RELEASED);
    if (requiresAuthentication && !this.authenticated) {
      throw new Error("authenticate the zkey before beginning a proof");
    }
  }
}

const PROOF_JSON = JSON.stringify({ proof: { protocol: "groth16" }, publicSignals: ["6"] });

class FakeFramedProof {
  constructor(authenticatedBytes) {
    this.authenticatedBytes = authenticatedBytes;
    this.consumed = 0n;
    this.sections = null;
    this.remaining = null;
  }

  beginZkey(header) {
    if (this.sections !== null || Buffer.from(header.subarray(0, 4)).toString() !== "zkey") {
      throw new Error("invalid zkey header");
    }
    this.sections = new DataView(header.buffer, header.byteOffset, 12).getUint32(8, true);
    this.consumed += 12n;
  }

  beginSection(header) {
    if (this.sections === null || this.remaining !== null || this.sections === 0) {
      throw new Error("unexpected zkey section");
    }
    this.remaining = new DataView(header.buffer, header.byteOffset, 12).getBigUint64(4, true);
    this.consumed += 12n;
  }

  push(bytes) {
    if (this.remaining === null || BigInt(bytes.byteLength) > this.remaining) {
      throw new Error("zkey section overrun");
    }
    this.remaining -= BigInt(bytes.byteLength);
    this.consumed += BigInt(bytes.byteLength);
  }

  endSection() {
    if (this.remaining !== 0n) throw new Error("zkey section ended early");
    this.remaining = null;
    this.sections -= 1;
  }

  finish() {
    if (this.sections !== 0 || this.remaining !== null || this.consumed !== this.authenticatedBytes) {
      throw new Error("zkey stream ended early");
    }
    return PROOF_JSON;
  }
}

function freshAuthenticator() {
  return { hash: createHash("sha256"), bytes: 0n };
}

// "zkey", version 1, two sections whose payloads span several 64 KiB
// authentication chunks.
function syntheticZkey() {
  const payloads = [new Uint8Array(70_000).fill(1), new Uint8Array(100_003).fill(2)];
  const length = 12 + payloads.reduce((sum, payload) => sum + 12 + payload.byteLength, 0);
  const bytes = new Uint8Array(length);
  const view = new DataView(bytes.buffer);
  bytes.set(Buffer.from("zkey"), 0);
  view.setUint32(4, 1, true);
  view.setUint32(8, payloads.length, true);
  let offset = 12;
  payloads.forEach((payload, index) => {
    view.setUint32(offset, index + 1, true);
    view.setBigUint64(offset + 4, BigInt(payload.byteLength), true);
    bytes.set(payload, offset + 12);
    offset += 12 + payload.byteLength;
  });
  return bytes;
}

function syntheticManifest(zkey, chunkBytes = 64 * 1024) {
  const count = Math.ceil(zkey.byteLength / chunkBytes);
  const manifest = new Uint8Array(60 + 32 * count);
  const view = new DataView(manifest.buffer);
  manifest.set(Buffer.from("CVYZKM01"), 0);
  view.setUint32(8, 1, true);
  view.setUint32(12, chunkBytes, true);
  view.setBigUint64(16, BigInt(zkey.byteLength), true);
  manifest.set(Buffer.from(sha256(zkey), "hex"), 24);
  view.setUint32(56, count, true);
  for (let index = 0; index < count; index += 1) {
    const chunk = zkey.subarray(index * chunkBytes, (index + 1) * chunkBytes);
    manifest.set(Buffer.from(sha256(chunk), "hex"), 60 + 32 * index);
  }
  return { manifest, manifestHash: sha256(manifest) };
}

function mockFetch(t, respond) {
  const fetches = [];
  t.mock.method(globalThis, "fetch", async (request, init) => {
    fetches.push({ url: requestUrl(request), init });
    return respond(request, init);
  });
  return fetches;
}

async function cachedBody(cache, url) {
  const response = await cache.match(url);
  return response ? new Uint8Array(await response.arrayBuffer()) : undefined;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function bytesEqual(left, right) {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
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
