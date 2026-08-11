import {
  cachedArtifactBytes,
  loadOrCompileSageProver,
  proveCachedZkeyOnePass,
  sha256Hex,
} from "./sparrow-cache-api.mjs";

const PHASE_TIMEOUTS = {
  moduleImport: 90_000,
  wasmInitialization: 120_000,
  threadPoolInitialization: 45_000,
};

let threadedRuntime = null;
let threadedRuntimeFailure = null;

export async function runProof({
  profile,
  settings,
  cacheName,
  onProgress = () => {},
  shouldStop = () => false,
}) {
  const started = performance.now();
  const { wasm, timings: runtimeTimings, reused } = await loadRuntime(settings, onProgress);
  throwIfStopped(shouldStop);

  onProgress("artifacts", "Reading manifest and input from Cache API");
  const artifactStarted = performance.now();
  const cache = await caches.open(cacheName);
  const zkeyRequest = new Request(profile.artifacts.zkey.url);
  if (!(await cache.match(zkeyRequest))) {
    throw new Error("zkey is not cached; use Cache source artifacts before running a proof");
  }
  const manifestBytes = await cachedArtifactBytes(cache, profile.artifacts.manifest.url);
  const inputBytes = await cachedArtifactBytes(cache, profile.artifacts.input.url);
  const inputSha256 = await sha256Hex(inputBytes);
  if (inputSha256 !== profile.artifacts.input.sha256) {
    throw new Error(
      `input digest mismatch: expected ${profile.artifacts.input.sha256}, got ${inputSha256}`,
    );
  }
  const inputJson = new TextDecoder("utf-8", { fatal: true }).decode(inputBytes);
  const artifactReadMs = performance.now() - artifactStarted;
  throwIfStopped(shouldStop);

  onProgress("prover", "Loading or compiling the derived SAGE evaluator");
  const proverStarted = performance.now();
  const sage = await loadOrCompileSageProver({
    wasm,
    cache,
    graphUrl: profile.artifacts.graph.url,
    expectedSourceGraphSha256: profile.sourceGraphSha256,
    expectedZkeySha256: profile.artifacts.zkey.sha256,
    batchProfile: profile.batchProfile,
    windowBits: settings.windowBits,
    msmChunkPoints: settings.msmChunkPoints,
    onStatus(message) {
      onProgress("sage-cache", message);
    },
  });
  const { prover } = sage;
  const proverInitMs = performance.now() - proverStarted;

  let observedChunks = 0;
  let lastProgress = 0;
  const observe = () => {
    observedChunks += 1;
    throwIfStopped(shouldStop);
    const now = performance.now();
    if (now - lastProgress > 500) {
      lastProgress = now;
      onProgress("proof", `Authenticated and consumed ${observedChunks} zkey chunks`, {
        observedChunks,
      });
    }
  };
  onProgress("proof", "Evaluating witness and streaming the proving key");
  const proofStarted = performance.now();
  const proof = await proveCachedZkeyOnePass({
    prover,
    inputJson,
    manifestBytes,
    expectedManifestSha256: profile.artifacts.manifest.sha256,
    cache,
    request: zkeyRequest,
    observe,
  });
  const proofMs = performance.now() - proofStarted;

  return {
    timestamp: new Date().toISOString(),
    profileId: profile.id,
    profileLabel: profile.label,
    settings,
    runtime: settings.threaded ? "rust-wasm-threads" : "rust-wasm-single-thread",
    environment: {
      executionContext: globalThis.window === globalThis ? "page" : "worker",
      crossOriginIsolated,
      hardwareConcurrency: navigator.hardwareConcurrency,
      userAgent: navigator.userAgent,
    },
    timings: {
      ...runtimeTimings,
      moduleInitMs:
        runtimeTimings.moduleImportMs +
        runtimeTimings.wasmInitializationMs +
        runtimeTimings.threadPoolInitializationMs,
      artifactReadMs,
      proverInitMs,
      proofAndVerifyMs: proofMs,
      totalRunMs: performance.now() - started,
    },
    reusedRuntime: reused,
    sageCacheHit: sage.cacheHit,
    sageCacheStored: sage.cacheStored,
    sageCacheWriteError: sage.cacheWriteError ?? null,
    sageCompilerVersion: sage.compilerVersion,
    sageProgramBytes: sage.programBytes,
    sageProgramSha256: sage.programSha256,
    inputSha256,
    observedChunks,
    assignmentSize: prover.assignmentSize,
    sageSlots: prover.sageSlots,
    proof,
  };
}

async function loadRuntime(settings, onProgress) {
  if (settings.threaded && threadedRuntime) {
    if (threadedRuntime.threads !== settings.threads) {
      throw new Error(
        `the page already initialized ${threadedRuntime.threads} WASM workers; reload before changing to ${settings.threads}`,
      );
    }
    onProgress("wasm-ready", `Reusing the ${settings.threads}-worker WASM runtime`);
    return {
      wasm: threadedRuntime.wasm,
      reused: true,
      timings: emptyRuntimeTimings(),
    };
  }
  if (settings.threaded && threadedRuntimeFailure) throw threadedRuntimeFailure;

  const timings = emptyRuntimeTimings();
  onProgress("wasm-import", "Downloading and compiling the optimized prover module");
  let phaseStarted = performance.now();
  const wasm = await withTimeout(
    import(
      settings.threaded
        ? "../pkg-web-threads/curvy_prover.js"
        : "../pkg-web/curvy_prover.js"
    ),
    PHASE_TIMEOUTS.moduleImport,
    "optimized prover module import",
  );
  timings.moduleImportMs = performance.now() - phaseStarted;

  onProgress("wasm-init", "Instantiating the optimized prover WASM");
  phaseStarted = performance.now();
  await withTimeout(
    wasm.default(),
    PHASE_TIMEOUTS.wasmInitialization,
    "optimized prover WASM initialization",
  );
  timings.wasmInitializationMs = performance.now() - phaseStarted;

  if (settings.threaded) {
    try {
      if (!crossOriginIsolated || typeof SharedArrayBuffer === "undefined") {
        throw new Error(
          "threaded WASM is unavailable because this page is not cross-origin isolated",
        );
      }
      onProgress("rayon", `Starting the ${settings.threads}-worker Rayon pool`);
      phaseStarted = performance.now();
      await withTimeout(
        wasm.initThreadPool(settings.threads),
        PHASE_TIMEOUTS.threadPoolInitialization,
        "Rayon worker-pool initialization",
      );
      timings.threadPoolInitializationMs = performance.now() - phaseStarted;
      threadedRuntime = { wasm, threads: settings.threads };
    } catch (error) {
      threadedRuntimeFailure = new Error(
        `${error?.message || error}. Reload the page and retry with fewer workers, or disable WASM threads.`,
      );
      throw threadedRuntimeFailure;
    }
  }

  return { wasm, timings, reused: false };
}

function emptyRuntimeTimings() {
  return {
    moduleImportMs: 0,
    wasmInitializationMs: 0,
    threadPoolInitializationMs: 0,
  };
}

function withTimeout(promise, milliseconds, label) {
  let timeout;
  const expired = new Promise((_, reject) => {
    timeout = setTimeout(
      () => reject(new Error(`${label} did not complete within ${milliseconds / 1000} seconds`)),
      milliseconds,
    );
  });
  return Promise.race([promise, expired]).finally(() => clearTimeout(timeout));
}

function throwIfStopped(shouldStop) {
  if (shouldStop()) throw new Error("benchmark stopped by user");
}
