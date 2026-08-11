import { runProof } from "./mobile-harness-runner.mjs";

self.onmessage = async ({ data }) => {
  if (data?.type !== "run") return;
  try {
    const { profile, settings, cacheName } = data;
    const result = await runProof({
      profile,
      settings,
      cacheName,
      onProgress: progress,
    });
    self.postMessage({ type: "result", result });
  } catch (error) {
    self.postMessage({ type: "error", error: error?.stack || String(error) });
  }
};

function progress(phase, message, extra = {}) {
  self.postMessage({ type: "progress", phase, message, ...extra });
}
