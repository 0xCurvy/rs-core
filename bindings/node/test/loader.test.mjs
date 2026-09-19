import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import test from "node:test";
const source = readFileSync(new URL("../index.js", import.meta.url), "utf8");
function load({ local = true, packageVersion = "1", binaryVersion = "1", glibc = "2.36" } = {}) {
  const loaded = [];
  const binding = { rsCoreVersion: () => binaryVersion };
  const context = {
    __dirname: "/package", module: { exports: {} },
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
