// Assemble the browser wasm-bindgen output into a publishable npm package.
//
// The JS side of the protocol consumes this repo through npm, not through a
// sibling checkout: `crates.io` ships Rust source, and the JS glue only exists
// after `wasm-bindgen` runs. This script packages the four browser artifacts
// (`scripts/build.sh wasm-web` + `wasm-web-threads`) so the TypeScript SDK can
// depend on a version, not a working copy.
//
// Usage: node scripts/build-npm.mjs [--out <dir>] [--pack]
//
// The generated package ships the wasm-bindgen output UNMODIFIED. Its
// `new URL('curvy_wasm_bg.wasm', import.meta.url)` and the Rayon helper's
// `new Worker(new URL('./workerHelpers.js', import.meta.url))` are the patterns
// every major bundler resolves natively — consumers must therefore keep this
// package out of their bundler's pre-bundling/optimization step (see README).

import { execFileSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const outIndex = args.indexOf("--out");
const outDir = resolve(repoRoot, outIndex === -1 ? "dist/npm" : (args[outIndex + 1] ?? "dist/npm"));
const shouldPack = args.includes("--pack");

const PACKAGE_NAME = "@0xcurvy/rs-core-wasm";

// One npm package, four entry points. All four artifacts MUST come from the
// same commit — a single tarball makes version skew structurally impossible
// instead of something a manifest has to assert.
const ENTRIES = [
  { subpath: "core", source: "crates/wasm/pkg-web", module: "curvy_wasm", threaded: false },
  { subpath: "core-threads", source: "crates/wasm/pkg-web-threads", module: "curvy_wasm", threaded: true },
  { subpath: "prover", source: "crates/prover/pkg-web", module: "curvy_prover", threaded: false },
  {
    subpath: "prover-threads",
    source: "crates/prover/pkg-web-threads",
    module: "curvy_prover",
    threaded: true,
  },
];

function workspaceVersion() {
  const cargoToml = readFileSync(join(repoRoot, "Cargo.toml"), "utf8");
  const workspacePackage = cargoToml.match(/\[workspace\.package\]([\s\S]*?)(?=\n\[|$)/)?.[1];
  const version = workspacePackage?.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (!version) throw new Error("no [workspace.package] version in Cargo.toml");
  return version;
}

function assertBuilt({ subpath, source, module, threaded }) {
  const sourceDir = join(repoRoot, source);
  let present;
  try {
    present = readdirSync(sourceDir);
  } catch {
    throw new Error(`${source} is missing — run scripts/build.sh wasm-web and wasm-web-threads first`);
  }
  for (const required of [`${module}.js`, `${module}.d.ts`, `${module}_bg.wasm`]) {
    if (!present.includes(required)) throw new Error(`${source}/${required} is missing`);
  }
  if (!threaded) return sourceDir;

  // The Rayon helper self-spawns as a module Worker and re-imports its own
  // package via `../../..`. That relative directory import is why every entry
  // gets its own package.json below.
  const snippets = readdirSync(join(sourceDir, "snippets")).filter((entry) =>
    entry.startsWith("wasm-bindgen-rayon-"),
  );
  if (snippets.length !== 1) {
    throw new Error(`expected exactly one Rayon snippet in ${source}/snippets, found ${snippets.length}`);
  }
  const helper = readFileSync(join(sourceDir, "snippets", snippets[0], "src/workerHelpers.js"), "utf8");
  if (!helper.includes("new Worker(new URL('./workerHelpers.js', import.meta.url)")) {
    throw new Error(`${source} Rayon helper no longer self-spawns via import.meta.url`);
  }
  if (!helper.includes("await import('../../..')")) {
    throw new Error(`${source} Rayon helper no longer re-imports its package via '../../..'`);
  }
  return sourceDir;
}

const version = workspaceVersion();
rmSync(outDir, { force: true, recursive: true });
mkdirSync(outDir, { recursive: true });

const exportsMap = { "./package.json": "./package.json" };

for (const entry of ENTRIES) {
  const sourceDir = assertBuilt(entry);
  const targetDir = join(outDir, entry.subpath);
  cpSync(sourceDir, targetDir, { recursive: true });

  // Per-entry package.json. Two jobs: it makes the Rayon helper's `../../..`
  // resolve to this entry's glue, and it scopes `sideEffects` so a bundler
  // cannot tree-shake the snippet's worker message handlers away (the blanket
  // `"sideEffects": false` wasm-pack emits is exactly the bug the helper's own
  // comments warn about).
  writeFileSync(
    join(targetDir, "package.json"),
    `${JSON.stringify(
      {
        name: `${PACKAGE_NAME}-${entry.subpath}`,
        version,
        type: "module",
        main: `./${entry.module}.js`,
        module: `./${entry.module}.js`,
        types: `./${entry.module}.d.ts`,
        exports: {
          ".": { types: `./${entry.module}.d.ts`, default: `./${entry.module}.js` },
          [`./${entry.module}_bg.wasm`]: `./${entry.module}_bg.wasm`,
          "./package.json": "./package.json",
        },
        sideEffects: entry.threaded ? ["./snippets/**"] : false,
      },
      null,
      2,
    )}\n`,
  );

  exportsMap[`./${entry.subpath}`] = {
    types: `./${entry.subpath}/${entry.module}.d.ts`,
    default: `./${entry.subpath}/${entry.module}.js`,
  };
  // The raw binary is part of the public surface: Node reads its bytes off disk
  // (no fetch of file: URLs) and bundlers may want it via a `?url` import.
  exportsMap[`./${entry.subpath}/${entry.module}_bg.wasm`] =
    `./${entry.subpath}/${entry.module}_bg.wasm`;
}

writeFileSync(
  join(outDir, "package.json"),
  `${JSON.stringify(
    {
      name: PACKAGE_NAME,
      version,
      description: "Browser WebAssembly builds of the Curvy Rust core and Groth16 prover",
      license: "MIT",
      repository: { type: "git", url: "git+https://github.com/0xCurvy/rs-core.git" },
      homepage: "https://github.com/0xCurvy/rs-core",
      bugs: { url: "https://github.com/0xCurvy/rs-core/issues" },
      keywords: ["curvy", "wasm", "webassembly", "zero-knowledge", "groth16", "babyjubjub", "poseidon"],
      type: "module",
      sideEffects: ["./*/snippets/**"],
      publishConfig: { access: "public", provenance: true },
      exports: exportsMap,
      files: ENTRIES.map((entry) => entry.subpath).concat(["README.md", "LICENSE", "THIRD-PARTY-NOTICES.md"]),
      engines: { node: ">=20" },
    },
    null,
    2,
  )}\n`,
);

for (const file of ["LICENSE", "THIRD-PARTY-NOTICES.md"]) {
  cpSync(join(repoRoot, file), join(outDir, file));
}
cpSync(join(repoRoot, "npm/README.md"), join(outDir, "README.md"));

if (shouldPack) {
  execFileSync("npm", ["pack", "--pack-destination", repoRoot], { cwd: outDir, stdio: "inherit" });
}

console.log(`assembled ${PACKAGE_NAME}@${version} in ${outDir}`);
