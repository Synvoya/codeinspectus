import { describe, expect, test } from "vitest";

import { diffRescan } from "./rescan.js";
import { summarizeRescan } from "./summarize.js";
import type { Engine, EngineRunInfo, Finding, ScanResult } from "./types.js";

type TestFinding = Finding & {
  producer_components?: string[];
  finding_kind?: "vulnerability" | "license" | "misconfiguration" | "secret" | "sast" | "ai" | "other";
};

type TestScan = ScanResult & {
  component_signatures?: Record<string, string>;
};

const PIPELINE = "codeinspectus:pipeline";

function engineInfo(engine: Engine): EngineRunInfo {
  return { engine, version: "1", available: true, ran: true, finding_count: 0, duration_ms: 1 };
}

function finding(
  fingerprint: string,
  engine: Engine,
  components: string[] | undefined,
  kind: TestFinding["finding_kind"] = engine === "trivy" ? "vulnerability" : "ai",
): TestFinding {
  return {
    id: "CI-0001",
    fingerprint,
    title: "Test finding",
    severity: "high",
    engine,
    engines: [engine],
    rule_id: "TEST-RULE",
    cwe: ["CWE-000"],
    location: { file: `${fingerprint}.ts`, start_line: 1, end_line: 1 },
    message: "m",
    remediation: { summary: "s", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    ...(components ? { producer_components: components } : {}),
    finding_kind: kind,
  };
}

function scan(
  findings: Finding[],
  components: Record<string, string> | undefined,
  engines: Engine[] = ["codeinspectus-ai"],
): TestScan {
  return {
    scan_id: "scan-00000000-0000-4000-8000-000000000000",
    target: "/repo",
    started_at: "2026-07-18T00:00:00.000Z",
    duration_ms: 1,
    engines_run: [],
    engine_details: engines.map(engineInfo),
    offline: true,
    summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length },
    findings,
    truncated: false,
    total_findings_before_limit: findings.length,
    disclaimer: "d",
    warnings: [],
    git_safety: { state: "clean" },
    scan_config: { max_findings: 200 },
    ...(components ? { component_signatures: components } : {}),
  };
}

describe("diffRescan — component provenance", () => {
  test("same components + absent finding remains provably resolved", () => {
    const components = { [PIPELINE]: "p1", "ai:supabase-rls-policy-state": "r1" };
    const prior = scan([finding("rls", "codeinspectus-ai", Object.keys(components))], components);
    const fresh = scan([], components);
    expect(diffRescan(prior, fresh).summary).toMatchObject({ resolved: 1, not_rechecked: 0 });
  });

  test("changed RLS component + absent finding is not_rechecked", () => {
    const priorComponents = { [PIPELINE]: "p1", "ai:supabase-rls-policy-state": "r1" };
    const freshComponents = { ...priorComponents, "ai:supabase-rls-policy-state": "r2" };
    const prior = scan([finding("rls", "codeinspectus-ai", Object.keys(priorComponents))], priorComponents);
    const result = diffRescan(prior, scan([], freshComponents));
    expect(result.summary).toMatchObject({ resolved: 0, not_rechecked: 1 });
    expect(result.not_rechecked_note).toContain("we can't tell whether you fixed this; the checks changed");
    expect(summarizeRescan(result)).toContain("we can't tell whether you fixed this; the checks changed");
  });

  test("changed RLS component + present finding remains remaining", () => {
    const priorComponents = { [PIPELINE]: "p1", "ai:supabase-rls-policy-state": "r1" };
    const freshComponents = { ...priorComponents, "ai:supabase-rls-policy-state": "r2" };
    const priorFinding = finding("rls", "codeinspectus-ai", Object.keys(priorComponents));
    const result = diffRescan(scan([priorFinding], priorComponents), scan([priorFinding], freshComponents));
    expect(result.summary).toMatchObject({ remaining: 1, resolved: 0, not_rechecked: 0 });
  });

  test("changed RLS component does not block an unchanged metadata-authz finding resolving", () => {
    const priorComponents = {
      [PIPELINE]: "p1",
      "ai:supabase-rls-policy-state": "r1",
      "ai:client-metadata-authz": "m1",
    };
    const freshComponents = { ...priorComponents, "ai:supabase-rls-policy-state": "r2" };
    const metadata = finding("metadata", "codeinspectus-ai", [PIPELINE, "ai:client-metadata-authz"]);
    expect(diffRescan(scan([metadata], priorComponents), scan([], freshComponents)).summary).toMatchObject({
      resolved: 1,
      not_rechecked: 0,
    });
  });

  test.each([
    ["opengrep ruleset", "opengrep:ruleset", "opengrep"],
    ["Gitleaks config", "gitleaks:config", "gitleaks"],
  ] as const)("changed %s + absent finding is not_rechecked", (_label, component, engine) => {
    const priorComponents = { [PIPELINE]: "p1", [component]: "v1" };
    const freshComponents = { ...priorComponents, [component]: "v2" };
    const prior = scan([finding(component, engine, Object.keys(priorComponents), engine === "gitleaks" ? "secret" : "sast")], priorComponents, [engine]);
    expect(diffRescan(prior, scan([], freshComponents, [engine])).summary).toMatchObject({
      resolved: 0,
      not_rechecked: 1,
    });
  });

  test("changed Trivy DB + vanished vulnerability is not_rechecked", () => {
    const priorComponents = { [PIPELINE]: "p1", "trivy:binary": "b1", "trivy:vulnerability-db": "db1" };
    const freshComponents = { ...priorComponents, "trivy:vulnerability-db": "db2" };
    const vuln = finding("vuln", "trivy", Object.keys(priorComponents), "vulnerability");
    expect(diffRescan(scan([vuln], priorComponents, ["trivy"]), scan([], freshComponents, ["trivy"])).summary).toMatchObject({
      resolved: 0,
      not_rechecked: 1,
    });
  });

  test.each(["license", "misconfiguration"] as const)(
    "changed Trivy DB + vanished %s finding resolves when its own components are unchanged",
    (kind) => {
      const priorComponents = { [PIPELINE]: "p1", "trivy:binary": "b1", "trivy:vulnerability-db": "db1" };
      const freshComponents = { ...priorComponents, "trivy:vulnerability-db": "db2" };
      const prior = finding(kind, "trivy", [PIPELINE, "trivy:binary"], kind);
      expect(diffRescan(scan([prior], priorComponents, ["trivy"]), scan([], freshComponents, ["trivy"])).summary).toMatchObject({
        resolved: 1,
        not_rechecked: 0,
      });
    },
  );

  test("merged finding with one changed producer component is not_rechecked", () => {
    const priorComponents = { [PIPELINE]: "p1", "opengrep:ruleset": "o1", "gitleaks:config": "g1" };
    const freshComponents = { ...priorComponents, "gitleaks:config": "g2" };
    const merged = finding("merged", "opengrep", Object.keys(priorComponents), "secret");
    merged.engines = ["opengrep", "gitleaks"];
    expect(diffRescan(scan([merged], priorComponents, ["opengrep", "gitleaks"]), scan([], freshComponents, ["opengrep", "gitleaks"])).summary).toMatchObject({
      resolved: 0,
      not_rechecked: 1,
    });
  });

  test("legacy missing provenance + vanished is not_rechecked; present is remaining", () => {
    const legacy = finding("legacy", "opengrep", undefined, "sast");
    const vanished = diffRescan(scan([legacy], undefined, ["opengrep"]), scan([], { [PIPELINE]: "p1" }, ["opengrep"]));
    expect(vanished.summary).toMatchObject({ resolved: 0, not_rechecked: 1 });

    const present = diffRescan(
      scan([legacy], undefined, ["opengrep"]),
      scan([legacy], { [PIPELINE]: "p1" }, ["opengrep"]),
    );
    expect(present.summary).toMatchObject({ remaining: 1, resolved: 0, not_rechecked: 0 });
  });
});
