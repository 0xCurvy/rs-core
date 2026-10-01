// Publish gate for @0xcurvy/rs-core-wasm: prove the packed tarball actually
// loads from a real install before it reaches the registry.
//
// Usage: node scripts/smoke-npm.mjs <dir-with-the-package-installed>
//
// The portable entries are instantiated for real, and the portable prover runs
// a complete self-verified Groth16 proof of the multiplier fixture from this
// checkout's crates/prover/testdata. The threaded entries cannot be imported
// here at all - their Rayon snippet registers a worker message handler on
// `self` at module scope, which exists in browsers and workers but not in Node -
// so they are checked structurally instead. CI proves the identical threaded
// build in browsers (tools/browser/check.mjs threaded).

import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { checkResidentProver } from "../tools/browser/node-proof-check.mjs";

const projectDir = resolve(process.argv[2] ?? ".");
const require = createRequire(join(projectDir, "smoke-npm.mjs"));
const resolvePackage = (specifier) => pathToFileURL(require.resolve(specifier));

for (const [subpath, binary] of [
  ["core", "curvy_wasm_bg.wasm"],
  ["prover", "curvy_prover_bg.wasm"],
]) {
  const entry = await import(resolvePackage(`@0xcurvy/rs-core-wasm/${subpath}`));
  const bytes = await readFile(resolvePackage(`@0xcurvy/rs-core-wasm/${subpath}/${binary}`));
  await entry.default({ module_or_path: bytes });

  if (subpath === "core") {
    // Poseidon over a known pair (the circomlib vector) - a wrong or
    // half-linked binary fails here rather than in a consumer.
    const digest = entry.poseidon(["1", "2"]);
    const expected = "7853200120776062878684798364095072458815029376092732009249414926327459813530";
    if (digest !== expected) throw new Error(`core poseidon returned ${digest}, expected ${expected}`);
    console.log(`${subpath.padEnd(14)} instantiated`);
  } else {
    const proof = checkResidentProver(entry);
    console.log(`${subpath.padEnd(14)} proved publicSignals=${JSON.stringify(proof.publicSignals)} (self-verified)`);
  }
}

for (const [subpath, binary] of [
  ["core-threads", "curvy_wasm_bg.wasm"],
  ["prover-threads", "curvy_prover_bg.wasm"],
]) {
  const glue = await readFile(resolvePackage(`@0xcurvy/rs-core-wasm/${subpath}`), "utf8");
  if (!glue.includes("export function initThreadPool")) {
    throw new Error(`${subpath} is missing initThreadPool`);
  }
  await WebAssembly.compile(await readFile(resolvePackage(`@0xcurvy/rs-core-wasm/${subpath}/${binary}`)));
  console.log(`${subpath.padEnd(14)} compiled`);
}

console.log("npm package smoke test passed");
