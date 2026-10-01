// Cache API adapter for WasmStreamingProver. The large zkey paths never
// call Response.arrayBuffer(): only framing records or browser-supplied body
// chunks cross the JS/WASM boundary. Small graphs, derived SAGE programs, and
// manifests use byte slices because their Rust parsers currently do the same;
// source artifacts are buffered only up to ARTIFACT_BYTE_LIMITS.

const SAGE_CACHE_LAYOUT_VERSION = 1;
const SAGE_CACHE_PREFIX = "/__curvy_derived/sage/";
const SOURCE_HASH_HEADER = "x-curvy-source-graph-sha256";
const PROGRAM_HASH_HEADER = "x-curvy-sage-program-sha256";
const PROGRAM_BYTES_HEADER = "x-curvy-sage-program-bytes";
const COMPILER_VERSION_HEADER = "x-curvy-sage-compiler-version";
const PROFILE_HEADER = "x-curvy-sage-limits-profile";
const MIB = 1024 * 1024;

/**
 * Ceilings for artifacts this adapter reads into memory. They mirror the Rust
 * limits (`curvy_witness::Limits` graph and input JSON bytes for the client and
 * batch profiles) so an oversized response is rejected while it streams rather
 * than after it has been buffered. A chunk manifest is 60 bytes plus 32 per
 * chunk; 4 MiB covers an 8 GiB zkey at the smallest 64 KiB chunk size.
 */
export const ARTIFACT_BYTE_LIMITS = Object.freeze({
  clientGraph: 64 * MIB,
  batchGraph: 96 * MIB,
  manifest: 4 * MIB,
  inputJson: 16 * MIB,
});
const DEFAULT_ARTIFACT_MAX_BYTES = ARTIFACT_BYTE_LIMITS.clientGraph;

/**
 * Read a small artifact through Cache API, fetching it on a miss.
 *
 * The body is streamed under `maxBytes`. With `expectedSha256`, a cached copy
 * that fails the pin is evicted and fetched once from the network, and network
 * bytes are cached only after they match. Without a pin the bytes are not
 * authenticated here: pass them to an authenticating parser, or use
 * `authenticatedCachedArtifact` so a rejected cache entry is replaced.
 */
export async function cachedArtifactBytes(
  cache,
  url,
  { maxBytes = DEFAULT_ARTIFACT_MAX_BYTES, expectedSha256 = null, onStatus = () => {} } = {},
) {
  const pin = expectedSha256 == null ? null : normalizeSha256(expectedSha256, "artifact SHA-256");
  return authenticatedCachedArtifact(
    cache,
    url,
    async (bytes) => {
      if (pin) {
        const actual = await sha256Hex(bytes);
        if (actual !== pin) throw new Error(`artifact digest mismatch: expected ${pin}, got ${actual}`);
      }
      return bytes;
    },
    { maxBytes, onStatus },
  );
}

/**
 * Read an artifact through Cache API and return `authenticate(bytes)`.
 *
 * A cached copy that exceeds `maxBytes` or that `authenticate` rejects is
 * evicted and fetched once from the network. Network bytes are stored only
 * after `authenticate` accepts them, so a failed check never leaves them
 * cached.
 */
export async function authenticatedCachedArtifact(
  cache,
  url,
  authenticate,
  { maxBytes = DEFAULT_ARTIFACT_MAX_BYTES, onStatus = () => {} } = {},
) {
  const limit = byteLimit(maxBytes);
  const request = new Request(url);
  const cached = await cache.match(request);
  if (cached) {
    try {
      return await authenticate(await boundedBytes(cached, limit, url));
    } catch (error) {
      onStatus(`Cached artifact was rejected; refetching (${errorMessage(error)}): ${url}`);
      await cache.delete(request);
    }
  }

  // After an eviction, bypass the HTTP cache as well: this is the one retry.
  const response = await fetch(request, cached ? { cache: "no-store" } : undefined);
  if (!response.ok) {
    await response.body?.cancel().catch(() => {});
    throw new Error(`artifact fetch failed (${response.status}): ${url}`);
  }
  const bytes = await boundedBytes(response, limit, url);
  const result = await authenticate(bytes);
  try {
    await cache.put(
      request,
      new Response(bytes, {
        headers: {
          "content-length": String(bytes.byteLength),
          "content-type": response.headers.get("content-type") || "application/octet-stream",
        },
      }),
    );
  } catch (error) {
    onStatus(`Artifact was authenticated but could not be cached (${errorMessage(error)}): ${url}`);
  }
  return result;
}

/**
 * Buffer a response body, rejecting a declared or streamed length above
 * `maxBytes` before the excess is retained.
 */
async function boundedBytes(response, maxBytes, label) {
  const declared = response.headers.get("content-length");
  let capacity = Math.min(maxBytes, 64 * 1024);
  if (declared !== null && /^\d+$/.test(declared.trim())) {
    const length = Number(declared);
    if (length > maxBytes) {
      await response.body?.cancel().catch(() => {});
      throw new Error(`artifact declares ${length} bytes, above the ${maxBytes}-byte limit: ${label}`);
    }
    capacity = length;
  }
  if (!response.body) return new Uint8Array();

  const reader = response.body.getReader();
  let buffer = new Uint8Array(capacity);
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > maxBytes - length) {
        throw new Error(`artifact exceeds the ${maxBytes}-byte limit: ${label}`);
      }
      if (length + value.byteLength > buffer.byteLength) {
        const grown = new Uint8Array(
          Math.min(maxBytes, Math.max(length + value.byteLength, buffer.byteLength * 2)),
        );
        grown.set(buffer.subarray(0, length));
        buffer = grown;
      }
      buffer.set(value, length);
      length += value.byteLength;
    }
  } catch (error) {
    await reader.cancel(error).catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return length === buffer.byteLength ? buffer : buffer.slice(0, length);
}

function byteLimit(maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error("maxBytes must be a positive safe integer");
  }
  return maxBytes;
}

/**
 * Load a locally derived SAGE program or compile and cache one from the
 * authenticated source graph on the first use.
 *
 * The cache is deliberately keyed by source digest, compiler-cache version,
 * and limits profile. Its stored digest detects truncation/storage corruption;
 * Warm loads require expectedSageProgramSha256 from trusted deployment metadata
 * or retained trusted process state. Without it, compile the authenticated graph
 * again and leave the derived cache untouched (`cacheStored: false`): an entry
 * that no warm load may read is not worth its quota or its write. The embedded
 * source digest does not prove correct compilation.
 *
 * A cached source graph that fails SIGNET authentication or `graphMaxBytes`
 * (by default the Rust graph limit for the selected profile) is evicted and
 * fetched once from the network.
 */
export async function loadOrCompileStreamingProver({
  wasm,
  cache,
  graphUrl,
  expectedSourceGraphSha256,
  expectedZkeySha256,
  expectedSageProgramSha256 = null,
  batchProfile = false,
  windowBits = 13,
  msmChunkPoints = 65_536,
  graphMaxBytes = batchProfile ? ARTIFACT_BYTE_LIMITS.batchGraph : ARTIFACT_BYTE_LIMITS.clientGraph,
  onStatus = () => {},
}) {
  const sourceHash = normalizeSha256(expectedSourceGraphSha256, "source graph SHA-256");
  // Validated up front so a malformed pin is not mistaken for a rejected graph
  // and does not evict a good cached copy.
  normalizeSha256(expectedZkeySha256, "zkey SHA-256");
  const compilerVersion = cacheVersion(wasm);
  const profile = batchProfile ? "batch" : "client";
  const request = sageCacheRequest(sourceHash, compilerVersion, profile);
  const trustedProgramHash = expectedSageProgramSha256 == null ? null
    : normalizeSha256(expectedSageProgramSha256, "SAGE program SHA-256");
  const cached = trustedProgramHash ? await cache.match(request) : null;
  if (cached) {
    const metadata = sageResponseMetadata(cached);
    if (
      metadata.sourceHash === sourceHash &&
      metadata.compilerVersion === compilerVersion &&
      metadata.profile === profile
    ) {
      const program = new Uint8Array(await cached.arrayBuffer());
      const actualHash = await sha256Hex(program);
      if (metadata.bytes === program.byteLength && metadata.programHash === actualHash && actualHash === trustedProgramHash) {
        try {
          const prover = constructCompiledProver({
            wasm,
            program,
            programHash: actualHash,
            sourceHash,
            expectedZkeySha256,
            batchProfile,
            windowBits,
            msmChunkPoints,
          });
          return {
            prover,
            cacheHit: true,
            cacheStored: true,
            programPinned: true,
            programBytes: program.byteLength,
            programSha256: actualHash,
            compilerVersion,
          };
        } catch (error) {
          onStatus(`Cached SAGE program was rejected; recompiling (${errorMessage(error)})`);
        }
      } else {
        onStatus("Cached SAGE program failed its stored digest or size; recompiling");
      }
    } else {
      onStatus("Cached SAGE metadata is stale; recompiling");
    }
    await cache.delete(request);
  }

  onStatus("Compiling SAGE from the authenticated source graph");
  let prover = await authenticatedCachedArtifact(
    cache,
    graphUrl,
    (graphBytes) =>
      wasm.WasmStreamingProver.fromSignetWithConfig(
        graphBytes,
        sourceHash,
        expectedZkeySha256,
        batchProfile,
        windowBits,
        msmChunkPoints,
      ),
    { maxBytes: graphMaxBytes, onStatus },
  );

  let program;
  try {
    program = prover.compiledSageProgram();
  } catch (error) {
    prover.free?.();
    throw error;
  }
  const programHash = await sha256Hex(program);
  if (trustedProgramHash && programHash !== trustedProgramHash) {
    prover.free?.();
    throw new Error("compiled SAGE program does not match the trusted program pin");
  }

  // The first proof uses the same decoder as every warm load. Explicitly free
  // the compiler-produced instance before decoding so both SAGE graphs are not
  // retained together on memory-constrained devices.
  prover.free?.();
  prover = constructCompiledProver({
    wasm,
    program,
    programHash,
    sourceHash,
    expectedZkeySha256,
    batchProfile,
    windowBits,
    msmChunkPoints,
  });

  let cacheStored = false;
  let cacheWriteError = null;
  if (!trustedProgramHash) {
    onStatus("No trusted SAGE program pin was supplied; the derived program is not cached");
  } else {
    try {
      await deleteCachedSagePrograms(cache, sourceHash, batchProfile);
      await cache.put(
        request,
        new Response(program, {
          headers: {
            "cache-control": "private, max-age=31536000, immutable",
            "content-type": "application/octet-stream",
            [SOURCE_HASH_HEADER]: sourceHash,
            [PROGRAM_HASH_HEADER]: programHash,
            [PROGRAM_BYTES_HEADER]: String(program.byteLength),
            [COMPILER_VERSION_HEADER]: String(compilerVersion),
            [PROFILE_HEADER]: profile,
          },
        }),
      );
      cacheStored = true;
    } catch (error) {
      cacheWriteError = errorMessage(error);
      onStatus(`SAGE compiled successfully but could not be cached (${cacheWriteError})`);
    }
  }

  return {
    prover,
    cacheHit: false,
    cacheStored,
    programPinned: Boolean(trustedProgramHash),
    cacheWriteError,
    programBytes: program.byteLength,
    programSha256: programHash,
    compilerVersion,
  };
}

export async function deleteCachedSagePrograms(cache, expectedSourceGraphSha256, batchProfile) {
  const sourceHash = normalizeSha256(expectedSourceGraphSha256, "source graph SHA-256");
  const profile = batchProfile ? "batch" : "client";
  const requests = await cache.keys();
  await Promise.all(
    requests
      .filter((request) => isSageCacheRequest(request, sourceHash, profile))
      .map((request) => cache.delete(request)),
  );
}

export async function cachedSageProgramMetadata(
  cache,
  expectedSourceGraphSha256,
  batchProfile,
) {
  const sourceHash = normalizeSha256(expectedSourceGraphSha256, "source graph SHA-256");
  const profile = batchProfile ? "batch" : "client";
  for (const request of await cache.keys()) {
    if (!isSageCacheRequest(request, sourceHash, profile)) continue;
    const response = await cache.match(request);
    if (!response) continue;
    const metadata = sageResponseMetadata(response);
    if (metadata.sourceHash === sourceHash && metadata.profile === profile) return metadata;
  }
  return null;
}

function constructCompiledProver({
  wasm,
  program,
  programHash,
  sourceHash,
  expectedZkeySha256,
  batchProfile,
  windowBits,
  msmChunkPoints,
}) {
  return wasm.WasmStreamingProver.fromCompiledSageWithConfig(
    program,
    programHash,
    sourceHash,
    expectedZkeySha256,
    batchProfile,
    windowBits,
    msmChunkPoints,
  );
}

function sageCacheRequest(sourceHash, compilerVersion, profile) {
  const path = `${SAGE_CACHE_PREFIX}v${SAGE_CACHE_LAYOUT_VERSION}-c${compilerVersion}/${profile}/${sourceHash}.sage`;
  const origin = globalThis.location?.origin || "https://curvy.invalid";
  return new Request(new URL(path, origin));
}

function isSageCacheRequest(request, sourceHash, profile) {
  const pathname = new URL(request.url).pathname;
  return (
    pathname.startsWith(SAGE_CACHE_PREFIX) &&
    pathname.endsWith(`/${profile}/${sourceHash}.sage`)
  );
}

function sageResponseMetadata(response) {
  const compilerVersion = Number(response.headers.get(COMPILER_VERSION_HEADER));
  const bytes = Number(response.headers.get(PROGRAM_BYTES_HEADER));
  return {
    sourceHash: response.headers.get(SOURCE_HASH_HEADER),
    programHash: response.headers.get(PROGRAM_HASH_HEADER),
    compilerVersion: Number.isSafeInteger(compilerVersion) ? compilerVersion : null,
    bytes: Number.isSafeInteger(bytes) && bytes >= 0 ? bytes : null,
    profile: response.headers.get(PROFILE_HEADER),
  };
}

function cacheVersion(wasm) {
  const version = Number(wasm.sageCacheVersion?.());
  if (!Number.isSafeInteger(version) || version <= 0 || version > 0xffff_ffff) {
    throw new Error("WASM module returned an invalid SAGE cache version");
  }
  return version;
}

export async function sha256Hex(bytes) {
  if (!globalThis.crypto?.subtle) throw new Error("WebCrypto SHA-256 is unavailable");
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function normalizeSha256(value, label) {
  const normalized = String(value).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) throw new Error(`${label} must be 64 hexadecimal characters`);
  return normalized;
}

function errorMessage(error) {
  return error?.message || String(error);
}

// Kept outside CacheStorage: only a successful whole-file authentication
// authorizes these fixed-size chunk hashes for the following parse pass.
const authenticatedResponses = new WeakMap();
const AUTH_CHUNK_BYTES = 64 * 1024;
async function* fixedChunks(response) {
  requireBody(response);
  const reader = response.body.getReader();
  let buffer = new Uint8Array(AUTH_CHUNK_BYTES);
  let filled = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      let offset = 0;
      while (offset < value.length) {
        const count = Math.min(buffer.length - filled, value.length - offset);
        buffer.set(value.subarray(offset, offset + count), filled);
        filled += count;
        offset += count;
        if (filled === buffer.length) {
          yield buffer;
          buffer = new Uint8Array(AUTH_CHUNK_BYTES);
          filled = 0;
        }
      }
    }
    if (filled) yield buffer.slice(0, filled);
  } finally { reader.releaseLock(); }
}

/**
 * Run the whole-file zkey authentication pass and retain its chunk hashes for
 * `proveResponse`.
 *
 * A prover is pinned to one zkey digest, so once a pass has succeeded another
 * one could only reproduce the same hashes: a redundant call leaves the
 * authenticated state intact, does not read `response`, and returns the
 * recorded byte count. Otherwise any partial or failed earlier pass is reset
 * and this one starts from byte 0. Retained hashes are replaced only after the
 * new pass succeeds.
 */
export async function authenticateResponse(prover, response, observe = () => {}) {
  const recorded = authenticatedResponses.get(prover);
  if (recorded && prover.zkeyAuthenticated) {
    await response?.body?.cancel().catch(() => {});
    return recorded.bytes;
  }
  requireBody(response);
  prover.resetZkeyAuthentication();
  const hashes = [];
  for await (const chunk of fixedChunks(response)) {
    hashes.push(await sha256Hex(chunk));
    prover.authenticateZkeyChunk(chunk);
    observe();
  }
  const bytes = prover.finishZkeyAuthentication();
  authenticatedResponses.set(prover, { hashes, bytes });
  return bytes;
}

function authenticatedChunkHashes(prover) {
  const recorded = authenticatedResponses.get(prover);
  if (!recorded || !prover.zkeyAuthenticated) {
    throw new Error("authenticate this zkey response before proving");
  }
  return recorded.hashes;
}

function checkedResponse(hashes, response) {
  const chunks = fixedChunks(response);
  let index = 0;
  return new Response(new ReadableStream({
    async pull(controller) {
      try {
        const { done, value } = await chunks.next();
        if (done) {
          if (index !== hashes.length) throw new Error("zkey changed after authentication: truncated");
          controller.close();
        } else {
          if (index >= hashes.length || await sha256Hex(value) !== hashes[index++]) {
            throw new Error("zkey changed after authentication: chunk mismatch");
          }
          controller.enqueue(value);
        }
      } catch (error) { await chunks.return(); controller.error(error); }
    },
    async cancel() { await chunks.return(); },
  }));
}

/**
 * Parse an authenticated zkey response into a proof. Any failure after the
 * proof begins aborts it, so a reusable prover can prove again. After a
 * one-shot begin the SAGE graph is already released and a new prover is
 * required (`prover.graphReleased`).
 */
export async function proveResponse(
  prover,
  inputJson,
  response,
  observe = () => {},
  oneShot = false,
) {
  requireBody(response);
  // Check every JavaScript-side precondition before a one-shot begin can
  // release the SAGE graph.
  const hashes = authenticatedChunkHashes(prover);
  if (oneShot) prover.beginOneShotProof(inputJson);
  else prover.beginProof(inputJson);
  const stream = new ExactStreamReader(checkedResponse(hashes, response).body.getReader());
  try {
    const fileHeader = await stream.readExact(12);
    prover.beginZkey(fileHeader);
    const view = new DataView(fileHeader.buffer, fileHeader.byteOffset, fileHeader.byteLength);
    const sectionCount = view.getUint32(8, true);
    for (let section = 0; section < sectionCount; section += 1) {
      const header = await stream.readExact(12);
      const headerView = new DataView(header.buffer, header.byteOffset, header.byteLength);
      const length = Number(headerView.getBigUint64(4, true));
      if (!Number.isSafeInteger(length)) throw new Error("zkey section is too large for JavaScript");
      prover.beginZkeySection(header);
      await stream.pipeExact(length, (chunk) => {
        prover.pushZkeySectionChunk(chunk);
        observe();
      });
      prover.endZkeySection();
    }
    if (!(await stream.atEnd())) throw new Error("trailing bytes after zkey sections");
    return JSON.parse(prover.finishProof());
  } catch (error) {
    abortQuietly(prover);
    await stream.cancel(error);
    throw error;
  } finally {
    stream.release();
  }
}

/**
 * Prove from a cached zkey with the whole-file two-pass protocol. The
 * authentication pass runs only while this prover has not completed one, so
 * repeated proofs on a reusable prover read the zkey once per proof.
 */
export async function proveCachedZkey({
  prover,
  inputJson,
  cache,
  request,
  observe = () => {},
  oneShot = false,
}) {
  if (!authenticatedResponses.has(prover) || !prover.zkeyAuthenticated) {
    const authenticated = await cache.match(request);
    if (!authenticated) throw new Error(`zkey is not cached: ${request}`);
    await authenticateResponse(prover, authenticated, observe);
  }

  // Cache.match returns a fresh Response with a fresh body. The checked
  // adapter validates each second-pass chunk against private hashes from the
  // authenticated pass before exposing it to the Rust parser.
  const proofPass = await cache.match(request);
  if (!proofPass) throw new Error(`zkey disappeared from cache: ${request}`);
  return proveResponse(prover, inputJson, proofPass, observe, oneShot);
}

/**
 * One-pass proof against a pinned chunk manifest. The begin call releases the
 * SAGE graph; any later failure aborts the proof and leaves the prover in that
 * released state (`prover.graphReleased`).
 */
export async function proveManifestResponse(
  prover,
  inputJson,
  manifestBytes,
  expectedManifestSha256,
  response,
  observe = () => {},
) {
  requireBody(response);
  prover.beginOneShotManifestProof(inputJson, manifestBytes, expectedManifestSha256);
  const stream = new ExactStreamReader(response.body.getReader());
  try {
    const { chunkBytes, zkeyBytes } = manifestLayout(manifestBytes);
    let remaining = zkeyBytes;
    while (remaining > 0) {
      const take = Math.min(remaining, chunkBytes);
      // Passing an owned Vec<u8> lets Rust authenticate and parse this complete
      // chunk directly instead of copying it into a second pending buffer.
      prover.pushManifestZkeyChunk(await stream.readExact(take));
      remaining -= take;
      observe();
    }
    if (!(await stream.atEnd())) throw new Error("zkey stream exceeds manifest size");
    return JSON.parse(prover.finishManifestProof());
  } catch (error) {
    abortQuietly(prover);
    await stream.cancel(error);
    throw error;
  } finally {
    stream.release();
  }
}

export async function proveCachedZkeyOnePass({
  prover,
  inputJson,
  manifestBytes,
  expectedManifestSha256,
  cache,
  request,
  observe = () => {},
}) {
  const response = await cache.match(request);
  if (!response) throw new Error(`zkey is not cached: ${request}`);
  return proveManifestResponse(
    prover,
    inputJson,
    manifestBytes,
    expectedManifestSha256,
    response,
    observe,
  );
}

export class ExactStreamReader {
  constructor(reader) {
    this.reader = reader;
    this.pending = null;
    this.offset = 0;
    this.done = false;
  }

  async nextChunk() {
    if (this.pending && this.offset < this.pending.byteLength) {
      return this.pending.subarray(this.offset);
    }
    for (;;) {
      const result = await this.reader.read();
      this.done = result.done;
      this.pending = result.done ? null : result.value;
      this.offset = 0;
      if (this.pending === null || this.pending.byteLength !== 0) return this.pending;
      // A zero-length value with `done: false` is legal. It carries no bytes and
      // is not evidence of either EOF or trailing data, so keep reading.
    }
  }

  consume(count) {
    const chunk = this.pending.subarray(this.offset, this.offset + count);
    this.offset += count;
    return chunk;
  }

  async readExact(count) {
    const result = new Uint8Array(count);
    let written = 0;
    while (written < count) {
      const chunk = await this.nextChunk();
      if (!chunk) throw new Error("zkey stream ended early");
      const take = Math.min(count - written, chunk.byteLength);
      result.set(this.consume(take), written);
      written += take;
    }
    return result;
  }

  async pipeExact(count, consume) {
    let remaining = count;
    while (remaining > 0) {
      const chunk = await this.nextChunk();
      if (!chunk) throw new Error("zkey stream ended early");
      const take = Math.min(remaining, chunk.byteLength);
      consume(this.consume(take));
      remaining -= take;
    }
  }

  async atEnd() {
    const chunk = await this.nextChunk();
    return chunk === null;
  }

  /** Stop reading after a failure; never throws. */
  async cancel(reason) {
    this.pending = null;
    await this.reader.cancel(reason).catch(() => {});
  }

  release() {
    this.reader.releaseLock();
  }
}

// Report the failure that stopped the stream, not a secondary abort error.
function abortQuietly(prover) {
  try {
    prover.abortProof();
  } catch {
    // A freed or foreign prover cannot be aborted; the original error stands.
  }
}

function requireBody(response) {
  if (!response?.body) throw new Error("artifact Response has no readable body");
}

function manifestLayout(bytes) {
  if (bytes.byteLength < 60) throw new Error("zkey manifest header is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const chunkBytes = view.getUint32(12, true);
  const encodedZkeyBytes = view.getBigUint64(16, true);
  const zkeyBytes = Number(encodedZkeyBytes);
  if (
    chunkBytes < 64 * 1024 ||
    chunkBytes > 8 * 1024 * 1024 ||
    (chunkBytes & (chunkBytes - 1)) !== 0 ||
    !Number.isSafeInteger(zkeyBytes) ||
    zkeyBytes <= 0
  ) {
    throw new Error("zkey manifest dimensions are invalid for JavaScript");
  }
  return { chunkBytes, zkeyBytes };
}
