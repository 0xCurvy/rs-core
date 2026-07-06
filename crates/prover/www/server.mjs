// Static server with COOP/COEP (cross-origin isolation) so SharedArrayBuffer /
// wasm threads work. Serves www/ plus the threaded wasm pkg at /pkg/.
import { createServer } from "node:http";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, extname } from "node:path";
import { fileURLToPath } from "node:url";

const WWW = dirname(fileURLToPath(import.meta.url));
const PKG = join(WWW, "../pkg-web-threads");
const PORT = 8787;

const MIME = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".mjs": "text/javascript",
  ".wasm": "application/wasm",
  ".json": "application/json",
  ".zkey": "application/octet-stream",
  ".wtns": "application/octet-stream",
};

createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  let path = decodeURIComponent(url.pathname);
  if (path === "/") path = "/index.html";
  // wasm-bindgen-rayon's workerHelpers imports the package DIRECTORY ('../../..');
  // answer directory requests with the main module, like a bundler would.
  if (path === "/pkg" || path === "/pkg/") path = "/pkg/prover_poc.js";
  if (path === "/core-pkg" || path === "/core-pkg/") path = "/core-pkg/curvy_wasm.js";
  const CORE_MT = join(WWW, "../../curvy-wasm/pkg-web-threads");
  const CORE_ST = join(WWW, "../../curvy-wasm/pkg-web");
  const file = path.startsWith("/pkg/")
    ? join(PKG, path.slice(5))
    : path.startsWith("/core-pkg-st/")
      ? join(CORE_ST, path.slice(13))
      : path.startsWith("/core-pkg/")
        ? join(CORE_MT, path.slice(10))
        : join(WWW, path);
  try {
    const body = readFileSync(file);
    res.writeHead(200, {
      "Content-Type": MIME[extname(file)] ?? "application/octet-stream",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cache-Control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end("not found: " + path);
  }
}).listen(PORT, () => console.log(`bench server: http://localhost:${PORT}/`));
