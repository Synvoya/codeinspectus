#!/usr/bin/env tsx

import { resolve } from "node:path";

import { runOpengrepShadowParity } from "../src/shadow/opengrep-parity.js";

const args = process.argv.slice(2);
const requireHit = args.includes("--require-hit");
const targets = args.filter((argument) => argument !== "--require-hit");

if (!targets.length) {
  process.stderr.write("Usage: npm run shadow:opengrep -- [--require-hit] <target> [target ...]\n");
  process.exit(2);
}

const reports = [];
for (const target of targets) reports.push(await runOpengrepShadowParity(resolve(target)));
const selectedHits = reports.reduce((count, report) => count + report.comparison.reference_count, 0);
const passed = reports.every((report) => report.passed) && (!requireHit || selectedHits > 0);

process.stdout.write(`${JSON.stringify({
  passed,
  require_hit: requireHit,
  selected_hits: selectedHits,
  reports,
}, null, 2)}\n`);
process.exit(passed ? 0 : 1);
