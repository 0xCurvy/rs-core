import { createHash } from "node:crypto";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageDir = join(root, "bindings/node");
const dockerfile = join(packageDir, "Dockerfile.release");
const releaseDir = join(packageDir, "release");
const artifactsDir = join(releaseDir, "artifacts");
const temporaryRoot = mkdtempSync(join(tmpdir(), "curvy-node-release-"));

const targets = [
  {
    filename: "curvy_rs_core_node.darwin-arm64.node",
    format: /Mach-O 64-bit.*arm64/i,
    host: true,
    npmDirectory: "darwin-arm64",
    packageName: "@0xcurvy/rs-core-node-darwin-arm64",
  },
  {
    filename: "curvy_rs_core_node.linux-x64-gnu.node",
    format: /ELF 64-bit.*x86-64/i,
    dockerPlatform: "linux/amd64",
    dockerTarget: "linux-x64",
    npmDirectory: "linux-x64-gnu",
    packageName: "@0xcurvy/rs-core-node-linux-x64-gnu",
  },
  {
    filename: "curvy_rs_core_node.linux-arm64-gnu.node",
    format: /ELF 64-bit.*(?:ARM aarch64|aarch64)/i,
    dockerPlatform: "linux/arm64",
    dockerTarget: "linux-arm64",
    npmDirectory: "linux-arm64-gnu",
    packageName: "@0xcurvy/rs-core-node-linux-arm64-gnu",
  },
  {
    filename: "curvy_rs_core_node.win32-x64-msvc.node",
    format: /PE32\+.*x86-64.*Windows/i,
    dockerPlatform: "linux/amd64",
    dockerTarget: "windows-x64",
    npmDirectory: "win32-x64-msvc",
    packageName: "@0xcurvy/rs-core-node-win32-x64-msvc",
  },
];

try {
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    throw new Error(
      `release assembly must run on an Apple Silicon Mac; got ${process.platform}-${process.arch}`,
    );
  }

  run("docker", ["version", "--format", "{{.Server.Version}}"], root, {}, 15_000);
  run("docker", ["buildx", "version"], root, {}, 15_000);
  run("npm", ["ci"], packageDir, {
    npm_config_cache: join(tmpdir(), "curvy-rs-core-node-npm-cache"),
  });

  rmSync(releaseDir, { recursive: true, force: true });
  mkdirSync(artifactsDir, { recursive: true });
  for (const target of targets) rmSync(join(packageDir, target.filename), { force: true });

  console.log("\n==> Building and testing macOS arm64");
  run(
    "npm",
    ["run", "build", "--", "--target", "aarch64-apple-darwin", "--", "--locked"],
    packageDir,
    { MACOSX_DEPLOYMENT_TARGET: "11.0" },
  );
  run("npm", ["test"], packageDir, {
    NAPI_RS_NATIVE_LIBRARY_PATH: join(packageDir, targets[0].filename),
  });
  verifyBinary(targets[0], join(packageDir, targets[0].filename));
  copyFileSync(join(packageDir, targets[0].filename), join(artifactsDir, targets[0].filename));

  for (const target of targets.filter((candidate) => !candidate.host)) {
    console.log(`\n==> Building ${target.dockerTarget} with Docker Buildx`);
    const outputDir = join(temporaryRoot, target.dockerTarget);
    run(
      "docker",
      [
        "buildx",
        "build",
        "--platform",
        target.dockerPlatform,
        "--file",
        dockerfile,
        "--target",
        "artifact",
        "--build-arg",
        `NODE_RELEASE_TARGET=${target.dockerTarget}`,
        "--output",
        `type=local,dest=${outputDir}`,
        root,
      ],
      root,
    );
    const built = findFile(outputDir, target.filename);
    const destination = join(artifactsDir, target.filename);
    copyFileSync(built, destination);
    verifyBinary(target, destination);
  }

  run("npm", ["run", "package:metadata"], packageDir);
  for (const filename of [
    "package.json",
    "index.js",
    "index.d.ts",
    "README.md",
    "LICENSE",
    "THIRD-PARTY-NOTICES.md",
  ]) {
    copyFileSync(join(packageDir, filename), join(releaseDir, filename));
  }

  run(
    "npx",
    ["--no-install", "napi", "create-npm-dirs", "--cwd", releaseDir, "--npm-dir", "npm"],
    packageDir,
  );
  run(
    "npx",
    [
      "--no-install",
      "napi",
      "artifacts",
      "--cwd",
      releaseDir,
      "--output-dir",
      "artifacts",
      "--npm-dir",
      "npm",
    ],
    packageDir,
  );
  run(
    "npx",
    [
      "--no-install",
      "napi",
      "pre-publish",
      "--cwd",
      releaseDir,
      "--npm-dir",
      "npm",
      "--no-gh-release",
      "--skip-optional-publish",
    ],
    packageDir,
  );

  const preview = capture(
    "npm",
    ["pack", "--dry-run", "--ignore-scripts", "--json"],
    releaseDir,
    { npm_config_cache: join(tmpdir(), "curvy-rs-core-node-npm-cache") },
  );
  const packed = JSON.parse(preview)[0];
  const packedFiles = new Set(packed.files.map((file) => file.path));
  for (const target of targets) {
    if (packedFiles.has(target.filename)) {
      throw new Error(`${target.filename} leaked into the root loader package`);
    }
  }

  const releasePackage = JSON.parse(readFileSync(join(releaseDir, "package.json"), "utf8"));
  for (const target of targets) {
    if (releasePackage.optionalDependencies?.[target.packageName] !== releasePackage.version) {
      throw new Error(`${target.packageName} is not pinned to ${releasePackage.version}`);
    }
    const platformPreview = JSON.parse(
      capture(
        "npm",
        ["pack", "--dry-run", "--ignore-scripts", "--json"],
        join(releaseDir, "npm", target.npmDirectory),
        { npm_config_cache: join(tmpdir(), "curvy-rs-core-node-npm-cache") },
      ),
    )[0];
    if (!platformPreview.files.some((file) => file.path === target.filename)) {
      throw new Error(`${target.filename} is missing from ${target.packageName}`);
    }
  }

  console.log("\nRelease packages ready:");
  console.log(`  ${packed.name}@${packed.version}`);
  for (const target of targets) console.log(`  ${target.packageName}@${packed.version}`);
  console.log(`  root packed size: ${formatBytes(packed.size)}`);
  console.log(`  staged at: ${releaseDir}`);
  console.log("  npm packages to publish: 5 (users install only the root package)");
  console.log("\nPublish manually from the staging directory, platform packages first:");
  console.log(`  cd ${releaseDir}`);
  for (const target of targets) {
    console.log(
      `  npm publish ./npm/${target.npmDirectory} --ignore-scripts --access public --tag next --provenance=false`,
    );
  }
  console.log("  npm publish . --ignore-scripts --access public --tag next --provenance=false");
} finally {
  rmSync(temporaryRoot, { recursive: true, force: true });
}

function run(command, args, cwd, extraEnv = {}, timeout) {
  execFileSync(command, args, {
    cwd,
    env: { ...process.env, ...extraEnv },
    stdio: "inherit",
    timeout,
  });
}

function capture(command, args, cwd, extraEnv = {}) {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ...extraEnv },
    stdio: ["ignore", "pipe", "inherit"],
  });
}

function findFile(directory, filename) {
  const found = findFileOrNull(directory, filename);
  if (found) return found;
  throw new Error(`${filename} was not exported below ${directory}`);
}

function findFileOrNull(directory, filename) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      const nested = findFileOrNull(path, filename);
      if (nested) return nested;
    } else if (entry.name === filename) {
      return path;
    }
  }
  return null;
}

function verifyBinary(target, path) {
  const size = statSync(path).size;
  if (size < 1_000_000) throw new Error(`${target.filename} is unexpectedly small (${size} bytes)`);
  const description = capture("file", ["-b", path], root).trim();
  if (!target.format.test(description)) {
    throw new Error(`${target.filename} has unexpected format: ${description}`);
  }
  const sha256 = createHash("sha256").update(readFileSync(path)).digest("hex");
  console.log(`  ${target.filename}`);
  console.log(`    ${description}`);
  console.log(`    sha256=${sha256}`);
}

function formatBytes(bytes) {
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
}
