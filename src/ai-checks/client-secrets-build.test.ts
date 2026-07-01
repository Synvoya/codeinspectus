/**
 * CG-30 — the §6.1 client-bundle secret check must fire across the FULL build-output dir
 * set (not just dist/.next), because git-aware routing keeps ONLY this check in build dirs
 * and drops commodity-engine findings. If the check didn't fire in .nuxt/.svelte-kit, a
 * bundled secret there would be silently lost. Temp-dir based (no gitignore conflict).
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runClientSecretsCheck } from "./client-secrets.js";

// INTENTIONAL FAKE TEST DATA — not a real credential (same shape as the eval fixture value).
const SECRET = "sk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP1rE5wB9mNqK7";
const BUNDLE = "ci-ai-secret-in-bundle";
const BUILD_DIRS = ["dist", ".next", "out", ".output", ".nuxt", ".svelte-kit"];

describe("§6.1 bundle-secret check across the build-output dir set (CG-30)", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ci-bundle-"));
    for (const d of BUILD_DIRS) {
      await mkdir(join(dir, d), { recursive: true });
      await writeFile(join(dir, d, "bundle.js"), `const k = "${SECRET}";\n`);
    }
    // A server-only file with no hard-coded secret: must NOT be a bundle finding.
    await mkdir(join(dir, "server"), { recursive: true });
    await writeFile(join(dir, "server", "safe.ts"), `const k = process.env.SECRET;\n`);
  }, 60000);
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("a hard-coded secret in EACH build dir fires ci-ai-secret-in-bundle (critical, shipped)", async () => {
    const findings = await runClientSecretsCheck(dir);
    const bundle = findings.filter((f) => f.rule_id === BUNDLE);
    const firedDirs = new Set(bundle.map((f) => f.location.file.split("/")[0]));
    for (const d of BUILD_DIRS) {
      expect(firedDirs.has(d)).toBe(true); // every build dir must surface the bundled secret
    }
    expect(bundle.every((f) => f.severity === "critical")).toBe(true);
    expect(bundle[0]!.title.toLowerCase()).toMatch(/bundle|shipped/);
    // The server file must not produce a bundle finding (no hard-coded value).
    expect(bundle.some((f) => f.location.file.startsWith("server/"))).toBe(false);
  }, 60000);
});
