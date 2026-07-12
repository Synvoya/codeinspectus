/**
 * CG-75 / Claim 2 — store hardening: path containment + safeParse of loaded JSON.
 * Defense-in-depth behind the schema regex: even if a non-conforming id reaches getScan,
 * the resolved path must stay under MANAGED_SCANS, and loaded JSON must be validated
 * before use (never crash on corrupt data, never return unvalidated data).
 */

import { describe, test, expect } from "vitest";
import { readdir } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { resolve, sep } from "node:path";
import { resolveScanPath, safeParseScanJson, getScan } from "./store.js";
import { MANAGED_SCANS } from "./config.js";

describe("resolveScanPath — containment (Claim 2b)", () => {
  test("a real generated id resolves to a file under MANAGED_SCANS", () => {
    const p = resolveScanPath(`scan-${randomUUID()}`);
    expect(p).not.toBeNull();
    expect(p!.startsWith(resolve(MANAGED_SCANS) + sep)).toBe(true);
    expect(p!.endsWith(".json")).toBe(true);
  });

  for (const bad of ["../../etc/passwd", "../../../../../../../../etc/passwd", "/etc/passwd"]) {
    test(`rejects ${JSON.stringify(bad)} → null (escapes managed dir)`, () => {
      expect(resolveScanPath(bad)).toBeNull();
    });
  }
});

describe("safeParseScanJson — validate loaded JSON (Claim 2c)", () => {
  test("corrupt JSON → { ok:false } with an actionable error, no throw", () => {
    const r = safeParseScanJson("{ this is not valid json");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/json/i);
  });

  test("valid JSON of the wrong shape → { ok:false }", () => {
    const r = safeParseScanJson(JSON.stringify({ hello: "world" }));
    expect(r.ok).toBe(false);
  });

  test("an old stored scan lacking git_safety (CG-41+) still parses (store-tolerant)", () => {
    // Minimal pre-CG-41 shape: every required field EXCEPT git_safety.
    const old = {
      scan_id: "scan-00000000-0000-4000-8000-000000000000",
      target: "/tmp/x",
      started_at: "2026-01-01T00:00:00.000Z",
      duration_ms: 1,
      engines_run: [],
      engine_details: [],
      offline: true,
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
      findings: [],
      truncated: false,
      total_findings_before_limit: 0,
      disclaimer: "d",
      warnings: [],
    };
    const r = safeParseScanJson(JSON.stringify(old));
    expect(r.ok).toBe(true);
  });

  test("CG-76: store schema is SURGICAL — a scan missing a CORE field (findings) is REJECTED", () => {
    // Same shape as the git_safety-less scan above but ALSO missing `findings` (a core field).
    // The store-tolerant schema only makes version-added fields (git_safety, scan_config) optional;
    // core fields stay required, so a blanket .partial() regression would be caught here.
    const missingCore = {
      scan_id: "scan-00000000-0000-4000-8000-000000000000",
      target: "/tmp/x",
      started_at: "2026-01-01T00:00:00.000Z",
      duration_ms: 1,
      engines_run: [],
      engine_details: [],
      offline: true,
      summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
      // findings: MISSING (core field)
      truncated: false,
      total_findings_before_limit: 0,
      disclaimer: "d",
      warnings: [],
    };
    const r = safeParseScanJson(JSON.stringify(missingCore));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/findings/i);
  });
});

describe("getScan — end-to-end against real managed store", () => {
  test("a REAL prior stored scan id still loads and validates", async () => {
    let files: string[] = [];
    try {
      files = (await readdir(MANAGED_SCANS)).filter((f) => f.endsWith(".json"));
    } catch {
      /* no managed dir in this env */
    }
    if (!files.length) {
      // No stored scans here — nothing to assert; the corrupt/containment cases still cover logic.
      return;
    }
    const first = files[0];
    if (!first) return;
    const id = first.replace(/\.json$/, "");
    const scan = await getScan(id);
    expect(scan).toBeDefined();
    expect(scan!.scan_id).toBe(id);
    expect(Array.isArray(scan!.findings)).toBe(true);
  });

  test("a well-formed but nonexistent id → undefined (not a throw)", async () => {
    const scan = await getScan(`scan-${randomUUID()}`);
    expect(scan).toBeUndefined();
  });

  test("a containment-violating id → throws an actionable error", async () => {
    await expect(getScan("../../etc/passwd")).rejects.toThrow(/managed scans/i);
  });
});
