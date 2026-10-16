// Only replace directories created by this packager. Never infer ownership
// from package.json: --out may accidentally name a source or dependency tree.
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
export const marker = ".curvy-npm-output";
export const owner = "@0xcurvy/rs-core-wasm packaging output v1\n";
function within(path, parent) {
  const rel = relative(parent, path);
  return rel === "" || (rel !== ".." && !rel.startsWith(`..${sep}`) && !rel.startsWith(sep));
}
function physicalPath(path) {
  if (existsSync(path)) return realpathSync(path);
  const parent = dirname(path);
  if (parent === path) return path;
  return join(physicalPath(parent), path.slice(parent.length));
}
export function validateOutput(path, repoRoot) {
  path = resolve(path);
  const physical = physicalPath(path);
  const root = realpathSync(repoRoot);
  if (within(root, physical) || [".git", ".agents", ".codex"].some(dir => within(physical, join(root, dir)))) {
    throw new Error("refusing to replace a repository, its ancestor, or its metadata");
  }
  // lstat also sees dangling symlinks that existsSync does not follow.
  let stat;
  try { stat = lstatSync(path); } catch (error) { if (error.code !== "ENOENT") throw error; }
  if (!stat) return;
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("output must be a real directory");
  if (readdirSync(path).length === 0) return;
  const ownership = join(path, marker);
  if (!existsSync(ownership) || !lstatSync(ownership).isFile() || lstatSync(ownership).isSymbolicLink() || readFileSync(ownership, "utf8") !== owner) {
    throw new Error("refusing to delete an existing directory without the Curvy packaging ownership marker; choose a new --out directory");
  }
}
export function publishOutput(stage, output, repoRoot) {
  validateOutput(output, repoRoot);
  const backup = `${stage}.previous`;
  const hadOutput = existsSync(output);
  if (hadOutput) renameSync(output, backup);
  try { renameSync(stage, output); }
  catch (error) { if (hadOutput) renameSync(backup, output); throw error; }
  if (hadOutput) rmSync(backup, { recursive: true, force: true });
}
