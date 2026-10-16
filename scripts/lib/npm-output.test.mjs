import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, symlinkSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { marker, owner, validateOutput, publishOutput } from "./npm-output.mjs";
test("packaging protects source trees and only replaces owned outputs", () => {
  const root = mkdtempSync(join(tmpdir(), "curvy-output-test-"));
  try {
    const repo = join(root, "repo"); mkdirSync(repo);
    const source = join(repo, "source"); mkdirSync(source);
    writeFileSync(join(source, "sentinel"), "keep");
    for (const output of [repo, root, join(repo, ".git", "nested"), source]) {
      assert.throws(() => validateOutput(output, repo), /refusing/);
    }
    const link = join(root, "link"); symlinkSync(source, link);
    assert.throws(() => validateOutput(link, repo));
    assert.equal(readFileSync(join(source, "sentinel"), "utf8"), "keep");
    const output = join(repo, "dist", "npm"); mkdirSync(output, { recursive: true });
    writeFileSync(join(output, marker), owner); writeFileSync(join(output, "old"), "old");
    const stage = join(repo, "stage"); mkdirSync(stage);
    writeFileSync(join(stage, marker), owner); writeFileSync(join(stage, "new"), "new");
    publishOutput(stage, output, repo);
    assert.equal(readFileSync(join(output, "new"), "utf8"), "new");
    assert.equal(existsSync(join(output, "old")), false);
    assert.equal(existsSync(`${stage}.previous`), false);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
