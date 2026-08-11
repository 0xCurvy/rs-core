import { createReadStream } from "node:fs";
import { readFile, realpath, stat } from "node:fs/promises";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { networkInterfaces } from "node:os";
import { dirname, extname, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDirectory, "../../..");
const repositoryRealRoot = normalize(await realpath(repositoryRoot));
const [configArgument, portArgument] = process.argv.slice(2);
if (!configArgument) {
  throw new Error(
    "usage: node crates/prover/js/mobile-harness-server.mjs <config.json> [port|--check]",
  );
}

const configPath = resolve(configArgument);
const configDirectory = dirname(configPath);
const checkOnly = portArgument === "--check";
const port = checkOnly
  ? null
  : parseInteger(portArgument || process.env.CURVY_MOBILE_PORT || "8766", "port", 1, 65535);
const host = process.env.CURVY_MOBILE_HOST || "127.0.0.1";
const certificatePath = process.env.CURVY_TLS_CERT;
const keyPath = process.env.CURVY_TLS_KEY;
const accessToken = process.env.CURVY_MOBILE_TOKEN || randomBytes(24).toString("base64url");
if (accessToken.length < 24) throw new Error("CURVY_MOBILE_TOKEN must contain at least 24 characters");
if (Boolean(certificatePath) !== Boolean(keyPath)) {
  throw new Error("CURVY_TLS_CERT and CURVY_TLS_KEY must be supplied together");
}

const inputConfig = JSON.parse(await readFile(configPath, "utf8"));
const { publicConfig, artifactRoutes } = await prepareConfig(inputConfig);
if (checkOnly) {
  for (const [route, artifact] of artifactRoutes) {
    const actual = await hashFile(artifact.file);
    if (actual !== artifact.sha256) {
      throw new Error(
        `${route} digest mismatch: expected ${artifact.sha256}, got ${actual}`,
      );
    }
  }
  const bytes = publicConfig.profiles.reduce(
    (sum, profile) => sum + Object.values(profile.artifacts).reduce(
      (profileSum, artifact) => profileSum + artifact.size,
      0,
    ),
    0,
  );
  console.log(
    `mobile harness config ok: ${publicConfig.profiles.length} profile(s), ` +
    `${bytes} source bytes, every digest verified`,
  );
  process.exit(0);
}
const types = new Map([
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".mjs", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".wasm", "application/wasm"],
  [".zkey", "application/octet-stream"],
  [".bin", "application/octet-stream"],
  [".zst", "application/octet-stream"],
]);
const allowedStaticFiles = new Set([
  "/crates/prover/js/mobile-harness.html",
  "/crates/prover/js/mobile-harness.mjs",
  "/crates/prover/js/mobile-harness-worker.mjs",
  "/crates/prover/js/mobile-harness-runner.mjs",
  "/crates/prover/js/sparrow-cache-api.mjs",
]);
const allowedStaticPrefixes = [
  "/crates/prover/pkg-web/",
  "/crates/prover/pkg-web-threads/",
];

const requestHandler = async (request, response) => {
  setIsolationHeaders(response);
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { Allow: "GET, HEAD" }).end("method not allowed");
    return;
  }

  try {
    const requestUrl = new URL(request.url, `${certificatePath ? "https" : "http"}://${request.headers.host}`);
    if (!authorizeRequest(request, response, requestUrl)) {
      response.writeHead(403).end("invalid or missing mobile harness access token");
      return;
    }
    const pathname = decodeURIComponent(requestUrl.pathname);
    if (pathname === "/__curvy_mobile_config") {
      const body = Buffer.from(JSON.stringify(publicConfig));
      response.writeHead(200, {
        "Cache-Control": "no-store",
        "Content-Length": body.length,
        "Content-Type": "application/json; charset=utf-8",
      });
      if (request.method === "GET") response.end(body);
      else response.end();
      return;
    }

    const artifact = artifactRoutes.get(pathname);
    if (artifact) {
      response.writeHead(200, {
        "Cache-Control": "public, max-age=31536000, immutable",
        "Content-Length": artifact.size,
        "Content-Type": artifact.contentType,
        ETag: `"${artifact.etag}"`,
      });
      if (request.method === "GET") pipeFile(artifact.file, response);
      else response.end();
      return;
    }

    const staticFile = await resolveStaticFile(pathname);
    const metadata = await stat(staticFile);
    if (!metadata.isFile()) throw new Error("not a file");
    response.writeHead(200, {
      "Cache-Control": pathname.endsWith(".wasm") ? "no-cache" : "no-store",
      "Content-Length": metadata.size,
      "Content-Type": types.get(extname(staticFile)) || "application/octet-stream",
    });
    if (request.method === "GET") pipeFile(staticFile, response);
    else response.end();
  } catch (error) {
    response.writeHead(404).end("not found");
  }
};

const server = certificatePath
  ? createHttpsServer(
      {
        cert: await readFile(resolve(certificatePath)),
        key: await readFile(resolve(keyPath)),
      },
      requestHandler,
    )
  : createHttpServer(requestHandler);

server.listen(port, host, () => {
  const scheme = certificatePath ? "https" : "http";
  const harnessPath = "/crates/prover/js/mobile-harness.html";
  const tokenQuery = `?token=${encodeURIComponent(accessToken)}`;
  console.log(`Curvy mobile harness (${publicConfig.profiles.length} profile(s))`);
  console.log(`Local:   ${scheme}://localhost:${port}${harnessPath}${tokenQuery}`);
  if (!isLoopbackHost(host)) {
    for (const address of networkAddresses()) {
      console.log(`Device:  ${scheme}://${address}:${port}${harnessPath}${tokenQuery}`);
    }
  }
  if (!certificatePath) {
    console.log("WASM threads require a secure context: use HTTPS, or adb reverse and http://localhost on Android.");
  }
});

async function prepareConfig(config) {
  if (!Array.isArray(config.profiles) || config.profiles.length === 0) {
    throw new Error("mobile harness config must contain at least one profile");
  }
  const ids = new Set();
  const routes = new Map();
  const profiles = [];
  for (const profile of config.profiles) {
    if (typeof profile.id !== "string" || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(profile.id)) {
      throw new Error("profile id must contain lowercase letters, digits, or hyphens");
    }
    if (ids.has(profile.id)) throw new Error(`duplicate profile id: ${profile.id}`);
    ids.add(profile.id);
    const publicProfile = {
      id: profile.id,
      label: requiredString(profile.label, `${profile.id}.label`),
      batchProfile: profile.batchProfile !== false,
      defaults: {
        windowBits: parseInteger(profile.defaults?.windowBits ?? 13, "windowBits", 4, 16),
        msmChunkPoints: parseInteger(
          profile.defaults?.msmChunkPoints ?? 262_144,
          "msmChunkPoints",
          1,
          1_048_576,
        ),
        runs: parseInteger(profile.defaults?.runs ?? 1, "runs", 1, 10),
      },
      artifacts: {},
    };
    for (const [kind, contentType] of [
      ["zkey", "application/octet-stream"],
      ["manifest", "application/octet-stream"],
      ["graph", "application/octet-stream"],
      ["input", "application/json; charset=utf-8"],
    ]) {
      const definition = profile[kind];
      if (!definition || typeof definition.file !== "string") {
        throw new Error(`${profile.id}.${kind}.file is required`);
      }
      const file = resolve(configDirectory, definition.file);
      const metadata = await stat(file);
      if (!metadata.isFile()) throw new Error(`${profile.id}.${kind} is not a file: ${file}`);
      const sha256 = definition.sha256
        ? normalizedHash(definition.sha256, `${profile.id}.${kind}.sha256`)
        : null;
      if (!sha256) throw new Error(`${profile.id}.${kind}.sha256 is required`);
      const url = `/__curvy_artifact/${profile.id}/${kind}`;
      const etag = sha256 || `${metadata.size}-${Math.trunc(metadata.mtimeMs)}`;
      routes.set(url, { file, size: metadata.size, contentType, etag, sha256 });
      publicProfile.artifacts[kind] = { url, size: metadata.size, sha256 };
    }
    publicProfile.sourceGraphSha256 = publicProfile.artifacts.graph.sha256;
    if (profile.sourceGraphSha256 !== undefined) {
      const legacySourceHash = normalizedHash(
        profile.sourceGraphSha256,
        `${profile.id}.sourceGraphSha256`,
      );
      if (legacySourceHash !== publicProfile.sourceGraphSha256) {
        throw new Error(`${profile.id}.sourceGraphSha256 does not match ${profile.id}.graph.sha256`);
      }
    }
    profiles.push(publicProfile);
  }
  return {
    publicConfig: {
      title: typeof config.title === "string" ? config.title : "SPARROW mobile benchmark",
      cacheName: typeof config.cacheName === "string" ? config.cacheName : "curvy-sparrow-mobile-v1",
      profiles,
    },
    artifactRoutes: routes,
  };
}

function hashFile(file) {
  return new Promise((resolveHash, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(file);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.once("error", reject);
    stream.once("end", () => resolveHash(hash.digest("hex")));
  });
}

async function resolveStaticFile(pathname) {
  let adjusted = pathname === "/" ? "/crates/prover/js/mobile-harness.html" : pathname;
  if (
    adjusted === "/crates/prover/pkg-web-threads/" ||
    adjusted === "/crates/prover/pkg-web/"
  ) {
    adjusted += "curvy_prover.js";
  }
  const exactFile = allowedStaticFiles.has(adjusted);
  const allowedPrefix = allowedStaticPrefixes.find((prefix) => adjusted.startsWith(prefix));
  if (!exactFile && !allowedPrefix) throw new Error("static path is not allowlisted");
  const file = normalize(resolve(repositoryRoot, `.${adjusted}`));
  if (exactFile) {
    const expected = normalize(resolve(repositoryRoot, `.${adjusted}`));
    if (file !== expected) throw new Error("forbidden static path");
  } else {
    const packageRoot = normalize(resolve(repositoryRoot, `.${allowedPrefix}`));
    if (!file.startsWith(`${packageRoot}${sep}`)) throw new Error("forbidden package path");
  }
  const realFile = normalize(await realpath(file));
  if (!isWithin(repositoryRealRoot, realFile)) {
    throw new Error("static symlink leaves the repository");
  }
  if (allowedPrefix) {
    const packageRoot = normalize(resolve(repositoryRoot, `.${allowedPrefix}`));
    const realPackageRoot = normalize(await realpath(packageRoot));
    if (!isWithin(realPackageRoot, realFile) || realFile === realPackageRoot) {
      throw new Error("static symlink leaves its package directory");
    }
  }
  return realFile;
}

function isWithin(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${sep}`);
}

function setIsolationHeaders(response) {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  );
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  response.setHeader("Origin-Agent-Cluster", "?1");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
}

function pipeFile(file, response) {
  const stream = createReadStream(file);
  // `pipe()` does not forward source errors. A file removed or truncated after
  // `stat()` must terminate this response, not become an uncaught server error.
  stream.once("error", () => response.destroy());
  stream.pipe(response);
}

function authorizeRequest(request, response, requestUrl) {
  const queryToken = requestUrl.searchParams.get("token");
  const cookieToken = parseCookies(request.headers.cookie || "").curvy_mobile_token;
  const suppliedToken = queryToken || cookieToken;
  if (!safeTokenEqual(suppliedToken, accessToken)) return false;
  if (queryToken) {
    const secure = certificatePath ? "; Secure" : "";
    response.setHeader(
      "Set-Cookie",
      `curvy_mobile_token=${encodeURIComponent(accessToken)}; Path=/; HttpOnly; SameSite=Strict${secure}`,
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

function normalizedHash(value, label) {
  const text = requiredString(value, label).toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(text)) throw new Error(`${label} must be a SHA-256 hex digest`);
  return text;
}

function requiredString(value, label) {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${label} is required`);
  return value;
}

function parseInteger(value, label, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} must be an integer in ${minimum}..=${maximum}`);
  }
  return parsed;
}

function networkAddresses() {
  const addresses = new Set();
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family === "IPv4" && !entry.internal) addresses.add(entry.address);
    }
  }
  return [...addresses].sort();
}

function isLoopbackHost(value) {
  return value === "127.0.0.1" || value === "::1" || value === "localhost";
}
