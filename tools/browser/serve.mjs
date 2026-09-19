import http from 'node:http';
import { createReadStream } from 'node:fs';
import { readFile, stat, realpath } from 'node:fs/promises';
import { dirname, extname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const port = Number(process.env.PORT || 8127);
const artifactFile = process.argv[2];
const cases = artifactFile ? JSON.parse(await readFile(artifactFile, 'utf8')) : [];
const artifacts = new Map(cases.flatMap(c => [[c.zkeyUrl, c.zkeyPath], [c.graphUrl, c.graphPath]]));
const types = {'.html':'text/html', '.js':'text/javascript', '.mjs':'text/javascript', '.wasm':'application/wasm', '.json':'application/json'};
export const server = http.createServer(async (request, response) => {
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (!["127.0.0.1", "localhost"].some(host => request.headers.host === `${host}:${port}`) ||
      (request.headers.origin && ![`http://127.0.0.1:${port}`, `http://localhost:${port}`].includes(request.headers.origin))) {
    response.writeHead(403).end(); return;
  }
  if (!["GET", "HEAD"].includes(request.method)) { response.writeHead(405).end(); return; }
  try {
    let pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
    // wasm-bindgen-rayon imports its package directory. Bundlers resolve this
    // through package.json; direct web serving needs the equivalent entry URL.
    if (pathname === '/crates/prover/pkg-web-threads/') pathname += 'curvy_prover.js';
    if (pathname === '/benchmark/config.json') {
      response.setHeader('Content-Type', 'application/json');
      response.end(JSON.stringify(cases.map(({zkeyPath, graphPath, ...config}) => config)));
      return;
    }
    const allowed = ['/tools/browser/', '/crates/prover/pkg-web/', '/crates/prover/pkg-web-threads/', '/crates/prover/testdata/'];
    const path = await realpath(artifacts.get(pathname) || resolve(root, '.' + pathname));
    if (!artifacts.has(pathname) && (!path.startsWith(root + sep) || !allowed.some(prefix => path.startsWith(resolve(root, '.' + prefix) + sep)) || pathname.split('/').some(p => p.startsWith('.')))) {
      response.writeHead(404).end(); return;
    }
    const info = await stat(path);
    if (!info.isFile()) { response.writeHead(404).end(); return; }
    response.setHeader('Content-Type', types[extname(path)] || 'application/octet-stream');
    response.setHeader('Content-Length', info.size);
    if (request.method === 'HEAD') response.end();
    else createReadStream(path).on('error', () => response.destroy()).pipe(response);
  } catch { response.writeHead(404).end(); }
});
server.listen(port, '127.0.0.1', () => console.log(`http://127.0.0.1:${port}/tools/browser/proof-check.html`));
