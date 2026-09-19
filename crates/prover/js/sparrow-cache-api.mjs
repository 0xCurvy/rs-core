// Cache API adapter for WasmStreamingProver. The large zkey paths never
// call Response.arrayBuffer(): only framing records or browser-supplied body
// chunks cross the JS/WASM boundary. Small graphs, derived SAGE programs, and
// manifests use byte slices because their Rust parsers currently do the same.

const SAGE_CACHE_LAYOUT_VERSION = 1;
const SAGE_CACHE_PREFIX = "/__curvy_derived/sage/";
const SOURCE_HASH_HEADER = "x-curvy-source-graph-sha256";
const PROGRAM_HASH_HEADER = "x-curvy-sage-program-sha256";
const PROGRAM_BYTES_HEADER = "x-curvy-sage-program-bytes";
const COMPILER_VERSION_HEADER = "x-curvy-sage-compiler-version";
const PROFILE_HEADER = "x-curvy-sage-limits-profile";

export async function cachedArtifactBytes(cache, url) {
  const request = new Request(url);
  let response = await cache.match(request);
  if (!response) {
    response = await fetch(request);
    if (!response.ok) throw new Error(`artifact fetch failed (${response.status}): ${url}`);
    await cache.put(request, response.clone());
  }
  return new Uint8Array(await response.arrayBuffer());
}

/**
 * Load a locally derived SAGE program or compile and cache one from the
 * authenticated source graph on the first use.
 *
 * The cache is deliberately keyed by source digest, compiler-cache version,
 * and limits profile. Its stored digest detects truncation/storage corruption;
 * Warm loads require expectedSageProgramSha256 from trusted deployment metadata
 * or retained trusted process state. Without it, compile the authenticated graph
 * again. The embedded source digest does not prove correct compilation.
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
  onStatus = () => {},
}) {
  const sourceHash = normalizeSha256(expectedSourceGraphSha256, "source graph SHA-256");
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
  let graphBytes = await cachedArtifactBytes(cache, graphUrl);
  let prover = wasm.WasmStreamingProver.fromSignetWithConfig(
    graphBytes,
    sourceHash,
    expectedZkeySha256,
    batchProfile,
    windowBits,
    msmChunkPoints,
  );
  graphBytes = null;

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

  let cacheStored = true;
  let cacheWriteError = null;
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
  } catch (error) {
    cacheStored = false;
    cacheWriteError = errorMessage(error);
    onStatus(`SAGE compiled successfully but could not be cached (${cacheWriteError})`);
  }

  return {
    prover,
    cacheHit: false,
    cacheStored,
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
export async function authenticateResponse(prover, response, observe = () => {}) {
  authenticatedResponses.delete(prover);
  const hashes = [];
  for await (const chunk of fixedChunks(response)) {
    hashes.push(await sha256Hex(chunk));
    prover.authenticateZkeyChunk(chunk);
    observe();
  }
  const bytes = prover.finishZkeyAuthentication();
  authenticatedResponses.set(prover, hashes);
  return bytes;
}
function checkedResponse(prover, response) {
  const hashes = authenticatedResponses.get(prover);
  if (!hashes) throw new Error("authenticate this zkey response before proving");
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

export async function proveResponse(
  prover,
  inputJson,
  response,
  observe = () => {},
  oneShot = false,
) {
  requireBody(response);
  if (oneShot) prover.beginOneShotProof(inputJson);
  else prover.beginProof(inputJson);
  const checked = checkedResponse(prover, response);
  const stream = new ExactStreamReader(checked.body.getReader());
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
  } finally {
    stream.release();
  }
}

export async function proveCachedZkey({
  prover,
  inputJson,
  cache,
  request,
  observe = () => {},
  oneShot = false,
}) {
  const authenticated = await cache.match(request);
  if (!authenticated) throw new Error(`zkey is not cached: ${request}`);
  await authenticateResponse(prover, authenticated, observe);

  // Cache.match returns a fresh Response with a fresh body. Reopening is
  // checked adapter validates each second-pass chunk against private hashes
  // from the authenticated pass before exposing it to the Rust parser.
  const proofPass = await cache.match(request);
  if (!proofPass) throw new Error(`zkey disappeared from cache: ${request}`);
  return proveResponse(prover, inputJson, proofPass, observe, oneShot);
}

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
  const { chunkBytes, zkeyBytes } = manifestLayout(manifestBytes);
  const stream = new ExactStreamReader(response.body.getReader());
  try {
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
  } finally {
    stream.release();
  }
  return JSON.parse(prover.finishManifestProof());
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

  release() {
    this.reader.releaseLock();
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
