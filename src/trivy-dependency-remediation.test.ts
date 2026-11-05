/**
 * Field re-test G5: Trivy-primary vulnerability findings carried the generic CWE-1395 remediation
 * although Trivy's message names the package, the installed version and the fixed version.
 *
 * The fixture is a real Trivy 0.76.1 SARIF and the scan CodeInspectus 3.3.2 stored from that same
 * run (only the scratch target path is replaced). Replaying the SARIF through today's pipeline must
 * keep every finding's id, fingerprint, rule, severity, CWE and location, so baselines, triage notes
 * and rescans made with 3.3.x still match. Only the title and remediation may change.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, describe, expect, test, vi } from "vitest";

const FIXTURE = resolve(process.cwd(), "fixtures/coverage-honesty-corpus/trivy-dependency");

vi.mock("./engines/trivy.js", async () => {
  const { readFile: read } = await import("node:fs/promises");
  const { resolve: resolvePath } = await import("node:path");
  const sarif = JSON.parse(await read(resolvePath(process.cwd(), "fixtures/coverage-honesty-corpus/trivy-dependency/trivy-sarif.json"), "utf8"));
  return {
    readTrivyDbDate: vi.fn(async () => "2026-10-30T10:03:03.087335Z"),
    runTrivy: vi.fn(async () => ({
      engine: "trivy",
      version: "0.76.1",
      available: true,
      ran: true,
      sarif,
      durationMs: 1,
      componentSignatures: { "trivy:binary": "sha256:binary" },
    })),
  };
});
vi.mock("./store.js", async (original) => ({ ...(await original<typeof import("./store.js")>()), saveScan: vi.fn(async () => undefined) }));

// Only Trivy is replayed: an empty managed home keeps a locally installed osv-scanner (and its OSV
// databases) out of the scan, so the result does not depend on the machine. Set before scan.js loads,
// because the managed root is read from the home directory at module load.
const ORIGINAL_HOME = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
const ISOLATED_HOME = mkdtempSync(join(tmpdir(), "ci-trivy-remediation-home-"));
process.env.HOME = ISOLATED_HOME;
process.env.USERPROFILE = ISOLATED_HOME;
afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL_HOME)) {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  }
  rmSync(ISOLATED_HOME, { recursive: true, force: true });
});

const { executeScan } = await import("./scan.js");
const { safeParseScanJson } = await import("./store.js");

async function storedScan() {
  const parsed = safeParseScanJson(await readFile(resolve(FIXTURE, "stored-scan-3.3.2.json"), "utf8"));
  if (!parsed.ok) throw new Error(`stored 3.3.2 scan fixture did not load: ${parsed.error}`);
  return parsed.value;
}

describe("Trivy dependency findings against a stored 3.3.2 scan", () => {
  test("ids, fingerprints, rules, severities, CWEs and locations are unchanged", async () => {
    const stored = await storedScan();
    const { canonical } = await executeScan(
      { path: resolve(FIXTURE, "project"), scanners: ["vuln", "license"] },
      { persist: false },
    );

    const identity = (finding: (typeof canonical.findings)[number]) => ({
      id: finding.id,
      fingerprint: finding.fingerprint,
      rule_id: finding.rule_id,
      severity: finding.severity,
      cwe: finding.cwe,
      location: {
        file: finding.location.file,
        start_line: finding.location.start_line,
        end_line: finding.location.end_line,
      },
    });
    expect(stored.findings).toHaveLength(13);
    expect(canonical.findings.map(identity)).toEqual(stored.findings.map(identity));
  });

  test("titles name the package and remediation names the installed and fixed versions", async () => {
    const { canonical } = await executeScan(
      { path: resolve(FIXTURE, "project"), scanners: ["vuln", "license"] },
      { persist: false },
    );
    const byRule = new Map(canonical.findings.map((finding) => [finding.rule_id, finding]));

    expect(byRule.get("CVE-2019-10744")?.title).toBe(
      "nodejs-lodash: prototype pollution in defaultsDeep function leading to modifying properties (lodash@4.17.4)",
    );
    expect(byRule.get("CVE-2019-10744")?.remediation.summary).toBe(
      "Upgrade lodash from 4.17.4 to 4.17.12, then rebuild the lockfile.",
    );
    expect(byRule.get("CVE-2018-16487")?.remediation.summary).toBe(
      "Upgrade lodash from 4.17.4 to a fixed version (>=4.17.11), then rebuild the lockfile.",
    );
    expect(byRule.get("CVE-2021-44906")?.remediation.summary).toBe(
      "Upgrade minimist from 1.2.0 to a fixed version (1.2.6, 0.2.4; choose the one on your release line), then rebuild the lockfile.",
    );
    // An advisory CWE taken from the description must not replace dependency guidance.
    expect(byRule.get("CVE-2019-1010266")?.cwe).toEqual(["CWE-400"]);
    expect(byRule.get("CVE-2019-1010266")?.remediation.summary).toBe(
      "Upgrade lodash from 4.17.4 to 4.17.11, then rebuild the lockfile.",
    );
    expect(byRule.get("CVE-2026-85393")?.remediation.summary).toBe(
      "No fixed version of node-forge is listed for 1.4.0. Remove or replace the package, or confirm the vulnerable code path is unreachable.",
    );

    for (const finding of canonical.findings) {
      expect(finding.title).toMatch(/ \((?:lodash@4\.17\.4|minimist@1\.2\.0|node-forge@1\.4\.0)\)$/);
      expect(finding.remediation.summary).not.toMatch(/^Upgrade the vulnerable dependency/);
      expect(finding.remediation.steps[0]).toBe(finding.remediation.summary);
      expect(finding.remediation.references).toContain("CWE-1395");
    }
  });
});
