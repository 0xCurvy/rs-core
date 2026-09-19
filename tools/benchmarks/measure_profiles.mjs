#!/usr/bin/env node

import { spawnSync } from "node:child_process";

function usage() {
  throw new Error(
    "usage: node measure_profiles.mjs <samples> --profile <name> <command> [args...] [--profile ...]",
  );
}

const argv = process.argv.slice(2);
const samples = Number.parseInt(argv.shift() ?? "", 10);
if (!Number.isSafeInteger(samples) || samples < 1) usage();

const profiles = [];
while (argv.length > 0) {
  if (argv.shift() !== "--profile") usage();
  const name = argv.shift();
  if (!name) usage();
  const command = [];
  while (argv.length > 0 && argv[0] !== "--profile") command.push(argv.shift());
  if (command.length === 0) usage();
  profiles.push({ name, executable: command[0], args: command.slice(1), values: new Map() });
}
if (profiles.length === 0) usage();

function execute(profile) {
  const result = spawnSync(profile.executable, profile.args, {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${profile.name} exited with status ${result.status}`);
  }
  const parsed = new Map();
  for (const line of result.stdout.trim().split("\n")) {
    const match = /^([^=]+)=(-?(?:\d+(?:\.\d*)?|\.\d+))$/.exec(line);
    if (match) parsed.set(match[1], Number(match[2]));
  }
  for (const line of result.stderr.trim().split("\n")) {
    const rss = /^\s*(\d+)\s+maximum resident set size$/.exec(line);
    if (rss) parsed.set("peak_rss_bytes", Number(rss[1]));
  }
  return parsed;
}

// Warm every artifact and code path before the measured alternating sweep.
for (const profile of profiles) execute(profile);

for (let sample = 0; sample < samples; sample += 1) {
  const ordered = sample % 2 === 0 ? profiles : [...profiles].reverse();
  for (const profile of ordered) {
    for (const [key, value] of execute(profile)) {
      if (!profile.values.has(key)) profile.values.set(key, []);
      profile.values.get(key).push(value);
    }
  }
}

function summarize(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  const variance =
    sorted.reduce((sum, value) => sum + (value - mean) ** 2, 0) / sorted.length;
  return {
    min: sorted[0],
    median: sorted[Math.floor(sorted.length / 2)],
    max: sorted[sorted.length - 1],
    mean,
    standard_deviation: Math.sqrt(variance),
  };
}

const output = { samples, profiles: {} };
for (const profile of profiles) {
  output.profiles[profile.name] = Object.fromEntries(
    [...profile.values].map(([key, values]) => [key, summarize(values)]),
  );
}
console.log(JSON.stringify(output, null, 2));
