import { runProof } from "./mobile-harness-runner.mjs";
import {
  cachedSageProgramMetadata,
  deleteCachedSagePrograms,
} from "./sparrow-cache-api.mjs";

const elements = Object.fromEntries(
  [
    "title", "security-warning", "diagnostics", "profile", "threaded", "threads",
    "window-bits", "chunk-points", "runs", "cache", "cache-all", "run", "run-all",
    "stop", "refresh", "clear", "download", "status", "progress", "progress-detail",
    "summary", "result", "log",
  ].map((id) => [id, document.getElementById(id)]),
);
const launchParameters = new URL(location.href).searchParams;

let config;
let activeWorker = null;
let activeRunReject = null;
let activePageRun = false;
let stopRequested = false;
let latestReport = null;
const logLines = [];

initialize().catch(showFatal);

async function initialize() {
  // The server exchanges the one-time query token for an HttpOnly cookie.
  // Remove the token from browser history and downloaded benchmark metadata.
  if (launchParameters.has("token")) {
    const scrubbed = new URL(location.href);
    scrubbed.searchParams.delete("token");
    history.replaceState(null, "", `${scrubbed.pathname}${scrubbed.search}`);
  }
  const response = await fetch("/__curvy_mobile_config", { cache: "no-store" });
  if (!response.ok) throw new Error(`harness config failed: ${response.status}`);
  config = await response.json();
  elements.title.textContent = config.title;
  for (const profile of config.profiles) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = `${profile.label} (${formatBytes(totalArtifactBytes(profile))})`;
    elements.profile.append(option);
  }
  elements.profile.addEventListener("change", selectProfile);
  elements.threaded.addEventListener("change", updateThreadControls);
  elements.cache.addEventListener("click", () => cacheProfile().catch(showError));
  elements["cache-all"].addEventListener("click", () => cacheAllProfiles().catch(showError));
  elements.run.addEventListener("click", () => runBenchmark().catch(showError));
  elements["run-all"].addEventListener("click", () => runAllBenchmarks().catch(showError));
  elements.stop.addEventListener("click", stopBenchmark);
  elements.refresh.addEventListener("click", () => refreshDiagnostics().catch(showError));
  elements.clear.addEventListener("click", () => clearProfileCache().catch(showError));
  elements.download.addEventListener("click", downloadResults);
  selectProfile();
  applyLaunchOverrides();
  await refreshDiagnostics();
  await refreshCacheStatus();
  setStatus("Ready", "ok");
  if (launchParameters.get("autorun") === "1") {
    await cacheProfile();
    await runBenchmark();
  }
}

function applyLaunchOverrides() {
  const profileId = launchParameters.get("profile");
  if (profileId && config.profiles.some((profile) => profile.id === profileId)) {
    elements.profile.value = profileId;
    selectProfile();
  }
  if (launchParameters.has("threaded")) {
    elements.threaded.checked = launchParameters.get("threaded") === "1" && !elements.threaded.disabled;
  }
  const overrides = [
    ["threads", "threads"],
    ["windowBits", "window-bits"],
    ["msmChunkPoints", "chunk-points"],
    ["runs", "runs"],
  ];
  for (const [parameter, id] of overrides) {
    if (launchParameters.has(parameter)) elements[id].value = launchParameters.get(parameter);
  }
  updateThreadControls();
}

function selectProfile() {
  const profile = selectedProfile();
  const threadedAvailable = crossOriginIsolated && typeof SharedArrayBuffer !== "undefined";
  elements.threaded.checked = threadedAvailable;
  elements.threaded.disabled = !threadedAvailable;
  elements.threads.value = Math.max(1, navigator.hardwareConcurrency || 1);
  elements["window-bits"].value = profile.defaults.windowBits;
  elements["chunk-points"].value = profile.defaults.msmChunkPoints;
  elements.runs.value = profile.defaults.runs;
  updateThreadControls();
  refreshCacheStatus().catch(showError);
}

function updateThreadControls() {
  elements.threads.disabled = !elements.threaded.checked;
  if (!elements.threaded.checked) elements.threads.value = 1;
}

async function refreshDiagnostics() {
  const storage = await storageSnapshot();
  const battery = await batterySnapshot();
  const rows = {
    "Secure context": booleanStatus(isSecureContext),
    "Cross-origin isolated": booleanStatus(crossOriginIsolated),
    "SharedArrayBuffer": booleanStatus(typeof SharedArrayBuffer !== "undefined"),
    "Cache API": booleanStatus(typeof caches !== "undefined"),
    "Logical CPUs exposed": navigator.hardwareConcurrency ?? "unknown",
    "Device memory hint": navigator.deviceMemory ? `${navigator.deviceMemory} GiB` : "not exposed",
    "Storage usage / quota": storage
      ? `${formatBytes(storage.usage)} / ${formatBytes(storage.quota)}`
      : "not exposed",
    "Persistent storage": storage?.persisted == null ? "not exposed" : booleanStatus(storage.persisted),
    "Battery": battery ? `${Math.round(battery.level * 100)}% (${battery.charging ? "charging" : "battery"})` : "not exposed",
    "Screen": `${screen.width}×${screen.height} @ ${devicePixelRatio}x`,
    "User agent": navigator.userAgent,
  };
  elements.diagnostics.replaceChildren();
  for (const [name, value] of Object.entries(rows)) {
    const term = document.createElement("dt");
    term.textContent = name;
    const description = document.createElement("dd");
    description.textContent = String(value);
    elements.diagnostics.append(term, description);
  }
  const secureEnough = isSecureContext && typeof caches !== "undefined";
  elements["security-warning"].hidden = secureEnough;
  elements["security-warning"].textContent = secureEnough
    ? ""
    : "This origin is not a secure context. Cache API and WASM threads require trusted HTTPS, or http://localhost through adb reverse on Android.";
  elements.cache.disabled = !secureEnough;
  elements["cache-all"].disabled = !secureEnough;
  elements.run.disabled = !secureEnough;
  elements["run-all"].disabled = !secureEnough;
  return { storage, battery };
}

async function cacheProfile() {
  return cacheProfiles([selectedProfile()]);
}

async function cacheAllProfiles() {
  return cacheProfiles(config.profiles);
}

async function cacheProfiles(profiles) {
  requireIdle();
  if (typeof caches === "undefined") throw new Error("Cache API is unavailable on this origin");
  setBusy(true);
  try {
    let persistence = null;
    if (navigator.storage?.persist) {
      try { persistence = await navigator.storage.persist(); } catch { persistence = false; }
      log(`Persistent storage request: ${persistence ? "granted" : "not granted"}`);
    }
    const cache = await caches.open(config.cacheName);
    const artifacts = profiles.flatMap((profile) =>
      Object.entries(profile.artifacts).map(([kind, artifact]) => ({ profile, kind, artifact })),
    );
    const total = artifacts.reduce((sum, { artifact }) => sum + artifact.size, 0);
    let completed = 0;
    setProgress(0, total, "Preparing artifact cache");
    for (const { profile, kind, artifact } of artifacts) {
      const label = profiles.length === 1 ? kind : `${profile.id}/${kind}`;
      const request = new Request(artifact.url);
      if (await cache.match(request)) {
        completed += artifact.size;
        setProgress(completed, total, `${label}: already cached`);
        continue;
      }
      setStatus(`Caching ${label}…`);
      const response = await fetch(request, { cache: "no-store" });
      if (!response.ok || !response.body) throw new Error(`${label} fetch failed: ${response.status}`);
      let artifactLoaded = 0;
      const trackedBody = response.body.pipeThrough(new TransformStream({
        transform(chunk, controller) {
          artifactLoaded += chunk.byteLength;
          setProgress(completed + artifactLoaded, total, `${label}: ${formatBytes(artifactLoaded)} / ${formatBytes(artifact.size)}`);
          controller.enqueue(chunk);
        },
      }));
      const trackedResponse = new Response(trackedBody, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
      try {
        await cache.put(request, trackedResponse);
      } catch (error) {
        throw new Error(`${label} could not be stored (likely origin quota): ${error?.message || error}`);
      }
      if (artifactLoaded !== artifact.size) {
        await cache.delete(request);
        throw new Error(`${label} size mismatch: expected ${artifact.size}, received ${artifactLoaded}`);
      }
      completed += artifact.size;
      log(`Cached ${label}: ${formatBytes(artifact.size)}`);
    }
    await refreshDiagnostics();
    await refreshCacheStatus();
    setStatus(`${profiles.length === 1 ? "Profile" : "All profiles"} cached`, "ok");
  } finally {
    setBusy(false);
  }
}

async function runBenchmark() {
  return runProfiles([selectedProfile()], false);
}

async function runAllBenchmarks() {
  return runProfiles(config.profiles, true);
}

async function runProfiles(profiles, matrixMode) {
  requireIdle();
  await requireCachedProfiles(profiles);
  const selectedSettings = readSettings();
  const before = await refreshDiagnostics();
  const report = {
    harnessVersion: 3,
    mode: matrixMode ? "all-circuits" : "single-circuit",
    startedAt: new Date().toISOString(),
    profile: matrixMode
      ? { id: "all-circuits", label: "All configured circuits" }
      : { id: profiles[0].id, label: profiles[0].label },
    profiles: profiles.map(({ id, label }) => ({ id, label })),
    settings: selectedSettings,
    pageEnvironment: pageEnvironment(),
    before,
    runs: [],
  };
  let wakeLock = null;
  let peakJsHeapBytes = performance.memory?.usedJSHeapSize ?? null;
  const memorySampler = setInterval(() => {
    if (performance.memory) {
      peakJsHeapBytes = Math.max(peakJsHeapBytes || 0, performance.memory.usedJSHeapSize);
    }
  }, 100);
  stopRequested = false;
  setBusy(true, true);
  try {
    if (navigator.wakeLock?.request) {
      try { wakeLock = await navigator.wakeLock.request("screen"); } catch { /* optional */ }
    }
    for (const [profileIndex, profile] of profiles.entries()) {
      const settings = matrixMode
        ? {
            ...selectedSettings,
            windowBits: profile.defaults.windowBits,
            msmChunkPoints: profile.defaults.msmChunkPoints,
          }
        : selectedSettings;
      for (let index = 0; index < settings.runs; index += 1) {
        if (stopRequested) throw new Error("benchmark stopped by user");
        const matrixPosition = `${profileIndex + 1}/${profiles.length}`;
        setStatus(
          matrixMode
            ? `Running ${profile.label} (${matrixPosition}), proof ${index + 1}/${settings.runs}…`
            : `Running proof ${index + 1} of ${settings.runs}…`,
        );
        setIndeterminate(
          settings.threaded
            ? `Starting page-level threaded proof ${index + 1}/${settings.runs}`
            : `Starting isolated portable proof worker ${index + 1}/${settings.runs}`,
        );
        const result = await runOnce(profile, settings);
        result.runIndex = index + 1;
        result.matrixIndex = profileIndex + 1;
        report.runs.push(result);
        log(
          `${profile.id} run ${index + 1}: SAGE ` +
          `${result.sageCacheHit ? "warm cache" : "cold compile"} ` +
          `${formatDuration(result.timings.proverInitMs)}, proof + verify ` +
          formatDuration(result.timings.proofAndVerifyMs),
        );
        renderPartialReport(report);
        if (index + 1 < settings.runs || profileIndex + 1 < profiles.length) await delay(1000);
      }
    }
    report.finishedAt = new Date().toISOString();
    report.after = await refreshDiagnostics();
    await refreshCacheStatus();
    report.peakPageJsHeapBytes = peakJsHeapBytes;
    latestReport = report;
    renderReport(report);
    elements.download.disabled = false;
    setStatus("Benchmark complete; every returned proof self-verified", "ok");
    setProgress(1, 1, "Complete");
  } finally {
    clearInterval(memorySampler);
    if (wakeLock) await wakeLock.release().catch(() => {});
    activeWorker?.terminate();
    activeWorker = null;
    activeRunReject = null;
    setBusy(false);
  }
}

async function runOnce(profile, settings) {
  // wasm-bindgen-rayon documents initialization from the page's main thread.
  // Its generated worker startup has no rejection path if a child never sends
  // the ready message. Portable mode remains isolated for eager termination.
  if (settings.threaded) {
    activePageRun = true;
    try {
      // Give the browser a paint opportunity before synchronous WASM work.
      await delay(50);
      return await runProof({
        profile,
        settings,
        cacheName: config.cacheName,
        onProgress(_phase, message) {
          setIndeterminate(message);
        },
        shouldStop() {
          return stopRequested;
        },
      });
    } finally {
      activePageRun = false;
    }
  }
  return runInWorker(profile, settings);
}

function runInWorker(profile, settings) {
  return new Promise((resolve, reject) => {
    const worker = new Worker("./mobile-harness-worker.mjs", { type: "module" });
    activeWorker = worker;
    activeRunReject = reject;
    worker.onmessage = ({ data }) => {
      if (data.type === "progress") {
        setIndeterminate(data.message);
        return;
      }
      worker.terminate();
      if (activeWorker === worker) activeWorker = null;
      activeRunReject = null;
      if (data.type === "result") resolve(data.result);
      else reject(new Error(data.error || "proof worker failed"));
    };
    worker.onerror = (event) => {
      worker.terminate();
      if (activeWorker === worker) activeWorker = null;
      activeRunReject = null;
      reject(new Error(event.message || "proof worker crashed"));
    };
    worker.postMessage({ type: "run", profile, settings, cacheName: config.cacheName });
  });
}

function stopBenchmark() {
  stopRequested = true;
  activeRunReject?.(new Error("benchmark stopped by user"));
  activeRunReject = null;
  activeWorker?.terminate();
  activeWorker = null;
  setStatus(
    activePageRun
      ? "Stop requested; waiting for the current WASM chunk to yield…"
      : "Stopping benchmark…",
    "bad",
  );
}

async function clearProfileCache() {
  requireIdle();
  const profile = selectedProfile();
  const cache = await caches.open(config.cacheName);
  await Promise.all(Object.values(profile.artifacts).map((artifact) => cache.delete(artifact.url)));
  await deleteCachedSagePrograms(cache, profile.sourceGraphSha256, profile.batchProfile);
  await refreshDiagnostics();
  await refreshCacheStatus();
  setStatus(`${profile.label} cache cleared`);
}

async function refreshCacheStatus() {
  if (!config || typeof caches === "undefined") return;
  const profile = selectedProfile();
  const cache = await caches.open(config.cacheName);
  let cachedBytes = 0;
  let cachedCount = 0;
  const artifacts = Object.values(profile.artifacts);
  for (const artifact of artifacts) {
    if (await cache.match(artifact.url)) {
      cachedBytes += artifact.size;
      cachedCount += 1;
    }
  }
  const sage = await cachedSageProgramMetadata(
    cache,
    profile.sourceGraphSha256,
    profile.batchProfile,
  );
  const sageStatus = sage
    ? `derived SAGE cached (${formatBytes(sage.bytes)})`
    : "derived SAGE compiles on first run";
  elements["progress-detail"].textContent =
    `${cachedCount}/${artifacts.length} source artifacts cached ` +
    `(${formatBytes(cachedBytes)} / ${formatBytes(totalArtifactBytes(profile))}); ${sageStatus}`;
}

async function requireCachedProfiles(profiles) {
  const cache = await caches.open(config.cacheName);
  const missing = [];
  for (const profile of profiles) {
    for (const [kind, artifact] of Object.entries(profile.artifacts)) {
      if (!(await cache.match(artifact.url))) missing.push(`${profile.id}/${kind}`);
    }
  }
  if (missing.length) throw new Error(`cache artifacts before proving; missing: ${missing.join(", ")}`);
}

function readSettings() {
  const threaded = elements.threaded.checked;
  return {
    threaded,
    threads: threaded ? boundedInteger(elements.threads.value, "threads", 1, 64) : 1,
    windowBits: boundedInteger(elements["window-bits"].value, "window bits", 4, 16),
    msmChunkPoints: boundedInteger(elements["chunk-points"].value, "MSM chunk points", 1, 1_048_576),
    runs: boundedInteger(elements.runs.value, "runs", 1, 10),
  };
}

function renderPartialReport(report) {
  elements.result.textContent = JSON.stringify(report, null, 2);
  renderSummary(report);
}

function renderReport(report) {
  window.__curvyResult = report;
  elements.result.textContent = JSON.stringify(report, null, 2);
  renderSummary(report);
}

function renderSummary(report) {
  const samples = report.runs.map((run) => run.timings.proofAndVerifyMs).sort((a, b) => a - b);
  if (!samples.length) return;
  const metrics = report.mode === "all-circuits"
    ? {
        "Circuits completed": new Set(report.runs.map((run) => run.profileId)).size,
        "Proof time total": formatDuration(
          report.runs.reduce((sum, run) => sum + run.timings.proofAndVerifyMs, 0),
        ),
        "Cold SAGE compiles": report.runs.filter((run) => !run.sageCacheHit).length,
        "Workers": report.settings.threaded ? report.settings.threads : "single",
      }
    : {
        "Proof median": formatDuration(samples[Math.floor(samples.length / 2)]),
        "First → last": `${formatDuration(report.runs[0].timings.proofAndVerifyMs)} → ${formatDuration(report.runs.at(-1).timings.proofAndVerifyMs)}`,
        "Workers": report.settings.threaded ? report.settings.threads : "single",
        "Completed runs": report.runs.length,
      };
  elements.summary.replaceChildren();
  for (const [label, value] of Object.entries(metrics)) {
    const item = document.createElement("div");
    item.className = "metric";
    const caption = document.createElement("span");
    caption.textContent = label;
    const strong = document.createElement("strong");
    strong.textContent = value;
    item.append(caption, strong);
    elements.summary.append(item);
  }
}

function downloadResults() {
  if (!latestReport) return;
  const blob = new Blob([JSON.stringify(latestReport, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `curvy-${latestReport.profile.id}-${Date.now()}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function selectedProfile() {
  const profile = config?.profiles.find((candidate) => candidate.id === elements.profile.value);
  if (!profile) throw new Error("select a benchmark profile");
  return profile;
}

function totalArtifactBytes(profile) {
  return Object.values(profile.artifacts).reduce((sum, artifact) => sum + artifact.size, 0);
}

async function storageSnapshot() {
  if (!navigator.storage?.estimate) return null;
  const estimate = await navigator.storage.estimate();
  let persisted = null;
  if (navigator.storage.persisted) {
    try { persisted = await navigator.storage.persisted(); } catch { /* optional */ }
  }
  return { usage: estimate.usage ?? 0, quota: estimate.quota ?? 0, persisted };
}

async function batterySnapshot() {
  if (!navigator.getBattery) return null;
  try {
    const battery = await navigator.getBattery();
    return { level: battery.level, charging: battery.charging };
  } catch {
    return null;
  }
}

function pageEnvironment() {
  return {
    url: `${location.origin}${location.pathname}`,
    secureContext: isSecureContext,
    crossOriginIsolated,
    hardwareConcurrency: navigator.hardwareConcurrency,
    deviceMemoryGiB: navigator.deviceMemory ?? null,
    screen: { width: screen.width, height: screen.height, devicePixelRatio },
    userAgent: navigator.userAgent,
  };
}

function setBusy(busy, running = false) {
  elements.cache.disabled = busy || !isSecureContext;
  elements["cache-all"].disabled = busy || !isSecureContext;
  elements.run.disabled = busy || !isSecureContext;
  elements["run-all"].disabled = busy || !isSecureContext;
  elements.clear.disabled = busy;
  elements.stop.disabled = !running;
  elements.profile.disabled = busy;
}

function requireIdle() {
  if (activeWorker || activePageRun) throw new Error("a proof benchmark is already running");
}

function setStatus(message, className = "") {
  elements.status.textContent = message;
  elements.status.className = className;
  log(message);
}

function setProgress(value, maximum, detail) {
  elements.progress.max = maximum;
  elements.progress.value = value;
  elements["progress-detail"].textContent = detail;
}

function setIndeterminate(detail) {
  elements.progress.removeAttribute("value");
  elements["progress-detail"].textContent = detail;
}

function log(message) {
  logLines.push(`${new Date().toLocaleTimeString()}  ${message}`);
  if (logLines.length > 200) logLines.shift();
  elements.log.textContent = logLines.join("\n");
  elements.log.scrollTop = elements.log.scrollHeight;
}

function showError(error) {
  console.error(error);
  window.__curvyError = error?.stack || String(error);
  setStatus(error?.message || String(error), "bad");
  setBusy(false);
}

function showFatal(error) {
  showError(error);
  elements.cache.disabled = true;
  elements["cache-all"].disabled = true;
  elements.run.disabled = true;
  elements["run-all"].disabled = true;
}

function booleanStatus(value) {
  return value ? "yes" : "no";
}

function boundedInteger(value, label, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} must be in ${minimum}..=${maximum}`);
  }
  return parsed;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "unknown";
  const units = ["B", "KiB", "MiB", "GiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit < 2 ? 0 : 2)} ${units[unit]}`;
}

function formatDuration(milliseconds) {
  return milliseconds >= 1000 ? `${(milliseconds / 1000).toFixed(3)} s` : `${milliseconds.toFixed(1)} ms`;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
