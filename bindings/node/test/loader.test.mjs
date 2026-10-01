import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
// The loader is exercised as if on Linux, so join POSIX paths on every host.
import { join } from "node:path/posix";
import { runInNewContext } from "node:vm";
import test from "node:test";
const source = readFileSync(new URL("../index.js", import.meta.url), "utf8");
function load({ local = true, packageVersion = "1", binaryVersion = "1", glibc = "2.36" } = {}) {
  const loaded = [];
  const binding = { rsCoreVersion: () => binaryVersion, ResidentProver: class {} };
  const context = {
    __dirname: "/package", module: { exports: {} }, Symbol,
    process: { platform: "linux", arch: "x64", env: { NAPI_RS_NATIVE_LIBRARY_PATH: "/untrusted/evil.node" }, report: { getReport: () => ({ header: { glibcVersionRuntime: glibc } }) } },
    require(name) {
      loaded.push(name);
      if (name === "node:fs") return { existsSync: () => local };
      if (name === "node:path") return { join };
      if (name === "./package.json") return { version: "1" };
      if (name === "@0xcurvy/rs-core-node-linux-x64-gnu/package.json") return { version: packageVersion };
      if (["/package/curvy_rs_core_node.linux-x64-gnu.node", "@0xcurvy/rs-core-node-linux-x64-gnu"].includes(name)) return binding;
      throw new Error(`unexpected library or subprocess access: ${name}`);
    },
  };
  runInNewContext(source, context);
  loaded.exports = context.module.exports;
  return loaded;
}
test("loader ignores environment library overrides and never invokes a subprocess", () => {
  assert.ok(load().includes("/package/curvy_rs_core_node.linux-x64-gnu.node"));
  assert.ok(load({ local: false }).includes("@0xcurvy/rs-core-node-linux-x64-gnu"));
});
test("loader always checks package and compiled binary versions", () => {
  assert.throws(() => load({ binaryVersion: "2" }), /binary version mismatch/);
  assert.throws(() => load({ local: false, packageVersion: "2" }), /package version mismatch/);
  assert.throws(() => load({ local: false, binaryVersion: "2" }), /binary version mismatch/);
});
test("loader explicitly rejects unpublished musl targets", () => {
  assert.throws(() => load({ glibc: "" }), /requires glibc/);
});
test("loader makes ResidentProver disposable through close()", async () => {
  const { ResidentProver } = load().exports;
  const calls = [];
  ResidentProver.prototype.close = function close() {
    calls.push(this);
    return Promise.resolve();
  };
  const prover = new ResidentProver();
  assert.equal(await prover[Symbol.asyncDispose](), undefined);
  assert.equal(prover[Symbol.dispose](), undefined);
  assert.deepEqual(calls, [prover, prover]);
});
