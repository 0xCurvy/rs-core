import { randomBytes, timingSafeEqual } from "node:crypto";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, normalize, resolve, sep } from "node:path";

const port = Number(process.argv[2] || 8766);
const root = resolve(process.env.CURVY_BENCH_ROOT || process.cwd());
const accessToken = process.env.CURVY_BENCH_TOKEN || randomBytes(24).toString("base64url");
if (accessToken.length < 24) throw new Error("CURVY_BENCH_TOKEN must contain at least 24 characters");
const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".json", "application/json"],
  [".wasm", "application/wasm"],
  [".zkey", "application/octet-stream"],
  [".bin", "application/octet-stream"],
]);

const server = createServer(async (request, response) => {
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Origin-Agent-Cluster", "?1");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" }).end("method not allowed");
    return;
  }

  try {
    const url = new URL(request.url, `http://${request.headers.host}`);
    if (!authorizeRequest(request, response, url)) {
      response.writeHead(403).end("invalid or missing benchmark access token");
      return;
    }
    let pathname = decodeURIComponent(url.pathname);
    // wasm-bindgen-rayon's generated worker imports ../../.. (its package
    // directory). A bundler resolves that via package.json; this direct-browser
    // server resolves the generated package entry without assuming the checkout
    // directory is named `rs-core`.
    if (pathname.endsWith("/crates/prover/pkg-web-threads/")) {
      pathname += "curvy_prover.js";
    } else if (pathname.endsWith("/crates/wasm/pkg-web-threads/")) {
      pathname += "curvy_wasm.js";
    }
    const path = normalize(resolve(root, `.${pathname}`));
    if (path !== root && !path.startsWith(`${root}${sep}`)) {
      response.writeHead(403).end("forbidden");
      return;
    }
    const metadata = await stat(path);
    if (!metadata.isFile()) throw new Error("not a file");
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Content-Type", types.get(extname(path)) || "application/octet-stream");
    response.setHeader("Content-Length", metadata.size);
    response.writeHead(200);
    if (request.method === "GET") pipeFile(path, response);
    else response.end();
  } catch {
    if (!response.headersSent) response.writeHead(404).end("not found");
    else response.destroy();
  }
});

server.listen(port, "127.0.0.1", () => {
  const token = encodeURIComponent(accessToken);
  console.log(
    `isolated benchmark server: http://127.0.0.1:${port}/crates/prover/js/sparrow-browser-bench.html?token=${token}`,
  );
});

function pipeFile(file, response) {
  const stream = createReadStream(file);
  stream.once("error", () => response.destroy());
  stream.pipe(response);
}

function authorizeRequest(request, response, url) {
  const queryToken = url.searchParams.get("token");
  const cookieToken = parseCookies(request.headers.cookie || "").curvy_bench_token;
  const suppliedToken = queryToken || cookieToken;
  if (!safeTokenEqual(suppliedToken, accessToken)) return false;
  if (queryToken) {
    response.setHeader(
      "Set-Cookie",
      `curvy_bench_token=${encodeURIComponent(accessToken)}; Path=/; HttpOnly; SameSite=Strict`,
    );
  }
  return true;
}

function parseCookies(header) {
  const parsed = {};
  for (const part of header.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    try { parsed[name] = decodeURIComponent(value); } catch { /* ignore malformed cookie */ }
  }
  return parsed;
}

function safeTokenEqual(left, right) {
  if (typeof left !== "string") return false;
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}
