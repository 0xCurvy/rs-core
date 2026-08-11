import { execFile } from "node:child_process";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const puppeteerPackage = process.env.CURVY_PUPPETEER_MODULE || "puppeteer";
const { default: puppeteer, KnownDevices } = await import(puppeteerPackage);
const [url, mode = "desktop", throttleText = "1"] = process.argv.slice(2);
if (!url) throw new Error("usage: node run-browser-bench.mjs <benchmark-url> [desktop|mobile] [cpu-throttle]");
const throttle = Number(throttleText);
const profile = await mkdtemp(`${tmpdir()}/curvy-chrome-`);
const browser = await puppeteer.launch({
  executablePath: process.env.CURVY_CHROME_PATH || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  headless: true,
  userDataDir: profile,
  args: ["--enable-precise-memory-info", "--disable-background-timer-throttling"],
});
const browserPid = browser.process().pid;
let peakTreeRssKiB = 0;
let baselineTreeRssKiB = 0;
let sampling = true;

async function sampleTree() {
  try {
    const { stdout } = await execFileAsync("ps", ["-axo", "pid=,ppid=,rss="]);
    const rows = stdout.trim().split("\n").map((line) => line.trim().split(/\s+/).map(Number));
    const descendants = new Set([browserPid]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const [pid, ppid] of rows) {
        if (descendants.has(ppid) && !descendants.has(pid)) {
          descendants.add(pid);
          changed = true;
        }
      }
    }
    const rss = rows.reduce((sum, [pid, , value]) => sum + (descendants.has(pid) ? value : 0), 0);
    peakTreeRssKiB = Math.max(peakTreeRssKiB, rss);
    return rss;
  } catch {
    return 0;
  }
}

const sampler = (async () => {
  while (sampling) {
    await sampleTree();
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
})();

try {
  const page = await browser.newPage();
  if (mode === "mobile") await page.emulate(KnownDevices["iPhone 13"]);
  const cdp = await page.createCDPSession();
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: throttle });
  page.on("console", (message) => console.error(`browser: ${message.text()}`));
  baselineTreeRssKiB = await sampleTree();
  await page.goto(url, { waitUntil: "load", timeout: 60_000 });
  await page.waitForFunction(
    () => window.__curvyResult || window.__curvyError,
    { timeout: 15 * 60_000, polling: 100 },
  );
  const outcome = await page.evaluate(() => ({ result: window.__curvyResult, error: window.__curvyError }));
  if (outcome.error) throw new Error(outcome.error);
  console.log(JSON.stringify({
    ...outcome.result,
    emulation: mode,
    cpuThrottle: throttle,
    baselineChromeTreeRssBytes: baselineTreeRssKiB * 1024,
    peakChromeTreeRssBytes: peakTreeRssKiB * 1024,
    incrementalChromeTreeRssBytes: (peakTreeRssKiB - baselineTreeRssKiB) * 1024,
  }, null, 2));
} finally {
  sampling = false;
  await sampler;
  await browser.close();
}
