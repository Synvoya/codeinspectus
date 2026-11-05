/**
 * Maintainer-only: rewrite (or --check) the SHA-256 digests in
 * detection-db/synvoya/manifest.json after a data file changes.
 *
 *   node scripts/synvoya-manifest.mjs [--check] [dir]
 *
 * Only the `files` digests are rewritten; version and date are bumped by hand.
 * Exit 0 when current / rewritten, 1 when --check finds drift.
 */

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DATA_FILES = ["advisories.json", "aliases.json", "eol.json", "libraries.json"];
const DEFAULT_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../detection-db/synvoya");

const args = process.argv.slice(2);
const check = args.includes("--check");
const dir = resolve(args.find((arg) => !arg.startsWith("--")) ?? DEFAULT_DIR);
const manifestPath = join(dir, "manifest.json");

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const files = {};
for (const name of DATA_FILES) {
  files[name] = `sha256:${createHash("sha256").update(await readFile(join(dir, name))).digest("hex")}`;
}

const drifted = DATA_FILES.filter((name) => manifest.files?.[name] !== files[name]);
if (check) {
  if (drifted.length > 0) {
    console.error(`[synvoya-manifest] stale digest(s): ${drifted.join(", ")}`);
    process.exit(1);
  }
  console.error("[synvoya-manifest] manifest is current");
} else {
  await writeFile(manifestPath, `${JSON.stringify({ ...manifest, files }, null, 2)}\n`);
  console.error(`[synvoya-manifest] wrote ${manifestPath}`);
}
