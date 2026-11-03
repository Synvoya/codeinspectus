import { cp, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, test, vi } from "vitest";

import type { Finding } from "../types.js";
import { isSynvoyaFinding, withEngineFamily, SYNVOYA_FAMILY_DISPLAY } from "./family.js";

// The "without the family step" scan swaps withEngineFamily for the identity function.
const family = vi.hoisted(() => ({ enabled: true }));
vi.mock("./family.js", async (importOriginal) => {
  const real = await importOriginal<typeof import("./family.js")>();
  return { ...real, withEngineFamily: (finding: Finding) => (family.enabled ? real.withEngineFamily(finding) : finding) };
});
vi.mock("../store.js", () => ({ saveScan: vi.fn(async () => undefined) }));

function finding(engine: Finding["engine"], ruleId: string): Finding {
  return {
    id: "CI-0001", fingerprint: `fp-${engine}-${ruleId}`, title: "t", severity: "high", engine, engines: [engine],
    rule_id: ruleId, cwe: ["CWE-1"], location: { file: "a.ts", start_line: 1, end_line: 1 }, message: "m",
    remediation: { summary: "s", steps: [], references: [] }, frameworks: [], confidence: "high",
  };
}

describe("Synvoya display family membership", () => {
  const rows: Array<[Finding["engine"], string, boolean]> = [
    ["synvoya", "synvoya-anything", true],
    ["codeinspectus-ai", "ci-ai-client-hardcoded-secret", true],
    ["codeinspectus-pub", "GHSA-xxxx-yyyy-zzzz", true],
    ["opengrep", "ci-baseline-weak-hash", true],
    ["opengrep", "syn-example-rule", true],
    ["gitleaks", "codeinspectus-stripe-live-secret", true],
    ["gitleaks", "codeinspectus-anthropic-key", true],
    ["gitleaks", "aws-access-token", false],
    ["opengrep", "javascript.lang.security.audit.eval", false],
    ["opengrep", "ci-baselinex-not-a-prefix", false],
    ["trivy", "CVE-2024-0001", false],
    ["trivy", "ci-baseline-weak-hash", false],
    ["osv-scanner", "GHSA-aaaa-bbbb-cccc", false],
    ["osv-scanner", "syn-looks-like-ours", false],
  ];

  test.each(rows)("%s / %s -> %s", (engine, ruleId, member) => {
    expect(isSynvoyaFinding({ engine, rule_id: ruleId })).toBe(member);
    const tagged = withEngineFamily(finding(engine, ruleId));
    if (member) expect(tagged.engine_family).toBe("synvoya");
    else expect(tagged).not.toHaveProperty("engine_family");
  });

  test("a non-member is returned unchanged (same object); a member keeps every raw field", () => {
    const upstream = finding("trivy", "CVE-2024-0001");
    expect(withEngineFamily(upstream)).toBe(upstream);
    const native = finding("codeinspectus-ai", "ci-ai-public-env-secret");
    const tagged = withEngineFamily(native);
    expect(tagged).toEqual({ ...native, engine_family: "synvoya" });
    expect(native).not.toHaveProperty("engine_family");
  });

  test("the display name is Synvoya (CodeInspectus)", () => {
    expect(SYNVOYA_FAMILY_DISPLAY).toBe("Synvoya (CodeInspectus)");
  });
});

describe("engine_family is not part of finding identity", () => {
  test("a fixture scan has identical ids, fingerprints, engines and rule ids with and without the family step", async () => {
    const { executeScan } = await import("../scan.js");
    const dir = await mkdtemp(join(tmpdir(), "ci-synvoya-family-"));
    await cp(join(process.cwd(), "fixtures", "prompt-injection-corpus", "tp"), dir, { recursive: true });

    const identity = (findings: Finding[]) => findings.map((f) => ({
      id: f.id, fingerprint: f.fingerprint, engine: f.engine, engines: f.engines, rule_id: f.rule_id,
      severity: f.severity, producer_components: f.producer_components, location: f.location,
    }));

    family.enabled = true;
    const withFamily = (await executeScan({ path: dir, scanners: ["ai"] }, { persist: false })).canonical.findings;
    family.enabled = false;
    const without = (await executeScan({ path: dir, scanners: ["ai"] }, { persist: false })).canonical.findings;
    family.enabled = true;

    expect(withFamily.length).toBeGreaterThan(0);
    expect(withFamily.every((f) => f.engine_family === "synvoya")).toBe(true);
    expect(without.some((f) => "engine_family" in f)).toBe(false);
    expect(identity(withFamily)).toEqual(identity(without));
  });
});
