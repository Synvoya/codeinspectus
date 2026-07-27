import { beforeAll, describe, expect, test } from "vitest";
import { join } from "node:path";

import { runAiChecks } from "../../ai-checks/index.js";
import {
  AI_INVOCATION_COMPONENT,
  FLUTTER_DART_PARSER_COMPONENT,
  FLUTTER_PACK_DISPATCH_COMPONENT,
  PIPELINE_COMPONENT,
} from "../../provenance.js";
import { detectTechnologies } from "../../technology-detection.js";
import type { Finding, Severity } from "../../types.js";
import { loadFlutterProject } from "./project.js";

const CORPUS = join(process.cwd(), "fixtures", "flutter-corpus");
const REDACTION_SENTINEL = "CI_FLUTTER_REDACTION_SENTINEL";

const EXPECTED = [
  {
    file: "lib/01_tls_verification.dart",
    ruleId: "ci-flutter-tls-verification-disabled",
    severity: "high",
    cwe: ["CWE-295"],
    component: "ai:flutter-tls-verification",
  },
  {
    file: "lib/02_sensitive_preferences.dart",
    ruleId: "ci-flutter-sensitive-shared-preferences",
    severity: "high",
    cwe: ["CWE-312"],
    component: "ai:flutter-sensitive-preferences",
  },
  {
    file: "lib/03_untrusted_webview.dart",
    ruleId: "ci-flutter-webview-untrusted-content",
    severity: "medium",
    cwe: ["CWE-20", "CWE-346"],
    component: "ai:flutter-webview-untrusted-content",
  },
  {
    file: "lib/04_sensitive_log.dart",
    ruleId: "ci-flutter-sensitive-log",
    severity: "medium",
    cwe: ["CWE-532"],
    component: "ai:flutter-sensitive-log",
  },
  {
    file: "lib/05_supabase_privileged_key.dart",
    ruleId: "ci-flutter-supabase-privileged-key-client",
    severity: "critical",
    cwe: ["CWE-798", "CWE-312", "CWE-285"],
    component: "ai:flutter-supabase-privileged-key",
  },
  {
    file: "lib/06_cleartext_network.dart",
    ruleId: "ci-flutter-cleartext-network",
    severity: "medium",
    cwe: ["CWE-319"],
    component: "ai:flutter-cleartext-network",
  },
] as const satisfies readonly {
  file: string;
  ruleId: string;
  severity: Severity;
  cwe: readonly string[];
  component: string;
}[];

type AiResult = Awaited<ReturnType<typeof runAiChecks>>;
type TechnologyResult = Awaited<ReturnType<typeof detectTechnologies>>;

interface ScenarioResult {
  ai: AiResult;
  technology: TechnologyResult;
}

let tp: ScenarioResult;
let fp: ScenarioResult;
let fixed: ScenarioResult;

async function analyze(name: "tp" | "fp" | "fixed"): Promise<ScenarioResult> {
  const target = join(CORPUS, name);
  const [ai, technology] = await Promise.all([
    runAiChecks(target),
    detectTechnologies(target),
  ]);
  return { ai, technology };
}

function expectFlutterDetection(result: TechnologyResult): void {
  expect(result.limitations).toEqual([]);
  expect(result.detected_technologies.map((technology) => technology.id)).toEqual([
    "dart",
    "flutter",
  ]);
  expect(result.detected_technologies.find((technology) => technology.id === "flutter"))
    .toMatchObject({
      kind: "framework",
      confidence: "high",
      evidence: expect.arrayContaining(["pubspec.yaml"]),
    });
}

function expectFlutterRan(result: AiResult): void {
  expect(result.packCoverage.find((pack) => pack.pack_id === "flutter")).toMatchObject({
    state: "ran",
    analyzers: { registered: 6, ran: 6 },
    rules: { registered: 6, ran: 6 },
  });
}

function findingFor(result: AiResult, expected: typeof EXPECTED[number]): Finding {
  const finding = result.findings.find((candidate) => candidate.rule_id === expected.ruleId);
  expect(finding, `missing ${expected.ruleId}`).toBeDefined();
  return finding!;
}

beforeAll(async () => {
  [tp, fp, fixed] = await Promise.all([
    analyze("tp"),
    analyze("fp"),
    analyze("fixed"),
  ]);
});

describe("Flutter frozen corpus", () => {
  test("the TP project emits exactly one finding for every frozen file/rule pair", () => {
    const projection = tp.ai.findings
      .map((finding) => ({ file: finding.location.file, ruleId: finding.rule_id }))
      .sort((left, right) => left.file.localeCompare(right.file));

    expect(projection).toEqual(EXPECTED.map(({ file, ruleId }) => ({ file, ruleId })));
    expect(tp.ai.info).toMatchObject({
      engine: "codeinspectus-ai",
      available: true,
      ran: true,
      finding_count: 6,
    });
    expectFlutterDetection(tp.technology);
    expectFlutterRan(tp.ai);
  });

  test("preserves exact metadata, remediation, provenance, and component signatures", () => {
    for (const expected of EXPECTED) {
      const finding = findingFor(tp.ai, expected);
      const producerComponents = [
        PIPELINE_COMPONENT,
        FLUTTER_PACK_DISPATCH_COMPONENT,
        FLUTTER_DART_PARSER_COMPONENT,
        expected.component,
      ];

      expect(finding).toMatchObject({
        engine: "codeinspectus-ai",
        engines: ["codeinspectus-ai"],
        finding_kind: "ai",
        severity: expected.severity,
        confidence: "high",
      });
      expect(finding.cwe).toEqual([...expected.cwe]);
      expect(finding.producer_components).toEqual(producerComponents);
      expect(finding.producer_components).not.toContain(AI_INVOCATION_COMPONENT);
      expect(finding.location.snippet).toMatch(/REDACTED/);
      expect(finding.remediation.summary.length).toBeGreaterThan(0);
      expect(finding.remediation.steps.length).toBeGreaterThan(0);
      expect(finding.remediation.references.length).toBeGreaterThan(0);
      for (const component of producerComponents) {
        expect(tp.ai.componentSignatures[component]).toMatch(/^sha256:[a-f0-9]{64}$/);
      }
    }
  });

  test("does not expose the planted redaction sentinel anywhere in analyzer output", () => {
    expect(JSON.stringify(tp.ai)).not.toContain(REDACTION_SENTINEL);
    expect(tp.ai.findings.every((finding) =>
      !(finding.location.snippet ?? "").includes(REDACTION_SENTINEL) &&
      !finding.message.includes(REDACTION_SENTINEL)
    )).toBe(true);
  });

  test.each([
    ["FP", () => fp],
    ["fixed", () => fixed],
  ] as const)("the %s project stays silent while all Flutter analyzers run", (_label, resultFor) => {
    const result = resultFor();
    expect(result.ai.findings).toEqual([]);
    expect(result.ai.info).toMatchObject({ available: true, ran: true, finding_count: 0 });
    expectFlutterDetection(result.technology);
    expectFlutterRan(result.ai);
  });

  test("excludes generated, test, and standard example files from a project-root scan", async () => {
    const project = await loadFlutterProject(join(CORPUS, "fp"));
    expect(project.files.map((file) => file.path)).toEqual(
      EXPECTED.map((expected) => expected.file),
    );
    expect(project.files.every((file) =>
      !file.path.includes("generated.g.dart") &&
      !file.path.startsWith("test/") &&
      !file.path.startsWith("example/")
    )).toBe(true);
  });
});
