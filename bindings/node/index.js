"use strict";
// Repository-owned loader. Build with `napi --no-js` to preserve this policy.
const { existsSync } = require("node:fs");
const { join } = require("node:path");
const { version } = require("./package.json");
const targets = {
  "darwin-arm64": "darwin-arm64",
  "linux-x64": "linux-x64-gnu",
  "linux-arm64": "linux-arm64-gnu",
  "win32-x64": "win32-x64-msvc",
};
const target = targets[`${process.platform}-${process.arch}`];
if (!target) throw new Error(`Unsupported rs-core Node platform: ${process.platform}-${process.arch}`);
if (process.platform === "linux" && !process.report?.getReport().header.glibcVersionRuntime) {
  throw new Error("rs-core Node requires glibc on Linux; musl builds are not published");
}
const local = join(__dirname, `curvy_rs_core_node.${target}.node`);
let binding;
if (existsSync(local)) {
  binding = require(local);
} else {
  const packageName = `@0xcurvy/rs-core-node-${target}`;
  if (require(`${packageName}/package.json`).version !== version) {
    throw new Error("rs-core native package version mismatch; reinstall dependencies");
  }
  binding = require(packageName);
}
if (binding.rsCoreVersion() !== version) {
  throw new Error("rs-core native binary version mismatch; rebuild or reinstall dependencies");
}
module.exports = binding;
module.exports.ResidentProver = binding.ResidentProver;
module.exports.IndexedMerkleTree = binding.IndexedMerkleTree;
module.exports.rsCoreVersion = binding.rsCoreVersion;
