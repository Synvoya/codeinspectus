import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { inspectPubDatabase } from "./database.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("Pub advisory database inspection", () => {
  it("reports the bundled database inventory and exact matching mode", async () => {
    const inspection = await inspectPubDatabase();
    expect(["current", "stale"]).toContain(inspection.info.state);
    expect(inspection.info.active_advisories).toBeGreaterThan(0);
    expect(inspection.info.matching).toBe("exact-enumerated-versions");
    expect(inspection.info.content_digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(inspection.loaded).toBeDefined();
  });

  it("distinguishes missing and invalid snapshots", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-pub-db-"));
    roots.push(root);
    const missing = await inspectPubDatabase(join(root, "missing.json"));
    expect(missing.info.state).toBe("missing");
    const invalidPath = join(root, "invalid.json");
    await writeFile(invalidPath, "{}", "utf8");
    const invalid = await inspectPubDatabase(invalidPath);
    expect(invalid.info.state).toBe("invalid");
  });

  it("becomes stale at the exact configured age boundary", async () => {
    const baseline = await inspectPubDatabase();
    const checkedMs = Date.parse(baseline.info.checked_at ?? "");
    expect(Number.isFinite(checkedMs)).toBe(true);

    const thresholdMs = baseline.info.stale_after_days * 24 * 60 * 60 * 1000;
    const current = await inspectPubDatabase(undefined, { nowMs: checkedMs + thresholdMs - 1 });
    const stale = await inspectPubDatabase(undefined, { nowMs: checkedMs + thresholdMs });

    expect(current.info.state).toBe("current");
    expect(current.info.age_days).toBe(baseline.info.stale_after_days - 1);
    expect(stale.info.state).toBe("stale");
    expect(stale.info.age_days).toBe(baseline.info.stale_after_days);
  });
});
