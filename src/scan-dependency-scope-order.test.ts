/**
 * M5 fix round 1, item 6: the dependency-scope pass (and the declared-minimum pass) must run after dedup in
 * the scan orchestrator. Lowering first would tie two copies of one dev advisory at the same severity and let
 * the fingerprint tiebreak pick the other copy, so the stored fingerprint would change between releases.
 *
 * Trivy is replayed with two results for one CVE on one dev package version (two lockfile locations), a
 * medium and a low. Dedup keeps the medium one; the scope pass then lowers it to low. Lines are chosen so the
 * low copy's fingerprint sorts first: had the scope pass run before dedup, the low copy would survive.
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, test, vi } from "vitest";

import { fingerprint as makeFingerprint } from "./util/hash.js";

const RULE = "CVE-2099-0001";
const fp = (line: number) => makeFingerprint(["trivy", "package-lock.json", line, line, "CWE-1395", RULE, undefined]);
/** The first line pair (medium at `a`, low at `b`) whose low copy has the smaller fingerprint. */
const [MEDIUM_LINE, LOW_LINE] = (() => {
  for (let a = 10; a < 200; a += 1) for (let b = a + 1; b < a + 20; b += 1) if (fp(b) < fp(a)) return [a, b];
  throw new Error("no line pair found");
})();

vi.mock("./engines/trivy.js", async () => {
  const result = (level: string, line: number) => ({
    ruleId: RULE, ruleIndex: 0, level,
    message: { text: `Package: handlebars\nInstalled Version: 4.7.9\nVulnerability ${RULE}\nSeverity: MEDIUM\nFixed Version: 4.7.10\nLink: [${RULE}](https://example.invalid)` },
    locations: [{ physicalLocation: { artifactLocation: { uri: "package-lock.json" }, region: { startLine: line, endLine: line } } }],
  });
  return {
    readTrivyDbDate: vi.fn(async () => "2026-11-14T00:00:00Z"),
    runTrivy: vi.fn(async () => ({
      engine: "trivy", version: "0.76.1", available: true, ran: true, durationMs: 1,
      componentSignatures: { "trivy:binary": "sha256:binary" },
      sarif: {
        version: "2.1.0",
        runs: [{
          tool: { driver: { name: "Trivy", rules: [{ id: RULE, name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security"] } }] } },
          results: [result("warning", MEDIUM_LINE), result("note", LOW_LINE)],
        }],
      },
      packages: [
        { ecosystem: "npm", name: "handlebars", version: "4.7.9", file: "package-lock.json", line: MEDIUM_LINE, dev: true },
        { ecosystem: "npm", name: "handlebars", version: "4.7.9", file: "package-lock.json", line: LOW_LINE, dev: true },
      ],
    })),
  };
});
vi.mock("./store.js", async (original) => ({ ...(await original<typeof import("./store.js")>()), saveScan: vi.fn(async () => undefined) }));

// No managed engines: only the replayed Trivy output. Set before scan.js loads (the managed root is read then).
const ORIGINAL_HOME = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
const ISOLATED_HOME = mkdtempSync(join(tmpdir(), "ci-scope-order-home-"));
const TARGET = mkdtempSync(join(tmpdir(), "ci-scope-order-target-"));
writeFileSync(join(TARGET, "package-lock.json"), '{"name":"x","lockfileVersion":3,"packages":{"":{"name":"x","devDependencies":{"handlebars":"4.7.9"}}}}\n');
process.env.HOME = ISOLATED_HOME;
process.env.USERPROFILE = ISOLATED_HOME;
afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL_HOME)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(ISOLATED_HOME, { recursive: true, force: true });
  rmSync(TARGET, { recursive: true, force: true });
});

const { executeScan } = await import("./scan.js");
const { DEDUP_COMPONENT } = await import("./provenance.js");
const { secretContainmentAgainst } = await import("./dedup.js");

describe("scan orchestrator order: dedup, then dependency scope", () => {
  test("the dedup survivor (the medium copy) is the one lowered; the low copy never takes its place", async () => {
    expect(fp(LOW_LINE) < fp(MEDIUM_LINE)).toBe(true);
    const { canonical } = await executeScan({ path: TARGET, scanners: ["vuln"] }, { persist: false });
    const findings = canonical.findings.filter((finding) => finding.rule_id === RULE);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.fingerprint).toBe(fp(MEDIUM_LINE));
    expect(findings[0]!.location.start_line).toBe(MEDIUM_LINE);
    expect(findings[0]!.severity).toBe("low");
    expect(findings[0]!.dependency_scope).toBe("dev");
    expect(findings[0]!.message).toContain("Severity lowered from medium to low: development-only dependency.");
  }, 30_000);

  test("a 4.1 scan records the dedup marker, so later comparisons never use the pre-4.1 containment match", async () => {
    const { canonical } = await executeScan({ path: TARGET, scanners: ["vuln"] }, { persist: false });
    expect(canonical.component_signatures?.[DEDUP_COMPONENT]).toMatch(/^sha256:/);
    expect(secretContainmentAgainst(canonical, canonical)).toEqual({ secretContainment: false });
    expect(secretContainmentAgainst({}, canonical)).toEqual({ secretContainment: true });
  }, 30_000);
});
