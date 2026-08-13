import { copyFileSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageDir = join(root, "bindings/node");
const cargoToml = readFileSync(join(root, "Cargo.toml"), "utf8");
const workspacePackage = cargoToml.match(/\[workspace\.package\]([\s\S]*?)(?=\n\[|$)/)?.[1];
const workspaceVersion = workspacePackage?.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
const packageJson = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));

if (!workspaceVersion) throw new Error("no [workspace.package] version in Cargo.toml");
if (packageJson.version !== workspaceVersion) {
  throw new Error(
    `Node package version ${packageJson.version} does not match rs-core workspace ${workspaceVersion}`,
  );
}

for (const file of ["LICENSE", "THIRD-PARTY-NOTICES.md"]) {
  copyFileSync(join(root, file), join(packageDir, file));
}

console.log(`prepared ${packageJson.name}@${packageJson.version}`);
