import { execFileSync } from "node:child_process";

const native = JSON.parse(
  execFileSync("cargo", ["run", "--quiet", "-p", "curvy-ffi", "--bin", "vectors"], {
    encoding: "utf8",
    maxBuffer: 64 << 20,
  }),
);
const wasm = JSON.parse(
  execFileSync(process.execPath, ["scripts/ffi-wasm-vectors.mjs"], {
    encoding: "utf8",
    maxBuffer: 64 << 20,
  }),
);

const keys = [...new Set([...Object.keys(native), ...Object.keys(wasm)])].sort();
const mismatches = keys.filter((key) => JSON.stringify(native[key]) !== JSON.stringify(wasm[key]));

if (mismatches.length > 0) {
  throw new Error(
    `WASM/FFI golden-vector drift:\n${mismatches
      .map((key) => `- ${key}: FFI=${JSON.stringify(native[key])} WASM=${JSON.stringify(wasm[key])}`)
      .join("\n")}`,
  );
}

console.log(`FFI and WASM agree on all ${keys.length} golden vectors`);

