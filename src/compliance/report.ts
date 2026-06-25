/**
 * Per-framework code-level coverage report + severity-weighted posture score
 * (PRD §10.2).
 *
 * Two DISTINCT views (never conflated):
 *   1. Coverage map: "X of N code-visible controls have findings" — N is the
 *      code-visible subset, shown explicitly as the denominator.
 *   2. Posture score: a severity-weighted 0–100 number, its own view, NEVER
 *      presented as "% compliant".
 *
 * HARD RULE (§10): never emit "you are X% compliant" or "you pass [framework]".
 */

import { z } from "zod";
import { getScan } from "../store.js";
import { STANDING_DISCLAIMER } from "../config.js";
import { SEVERITY_RANK } from "../types.js";
import type { Finding, FrameworkCoverage, ComplianceOverview } from "../types.js";
import type { complianceReportOutput } from "../schemas.js";
import type { ComplianceReportInput } from "../schemas.js";
import { loadComplianceData } from "./mapper.js";

type ComplianceReport = z.infer<typeof complianceReportOutput>;

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 15,
  high: 8,
  medium: 3,
  low: 1,
  info: 0,
};

const FRAMEWORK_DISCLAIMERS: Record<string, string> = {
  "ISO27001:2022":
    "Code-level evidence only. NOT an ISO 27001 audit, certification, or attestation. Most ISO 27001 controls are organizational and cannot be assessed by a code scan.",
  "NIST_CSF_2.0":
    "Code-level evidence only. NOT a NIST CSF assessment. Only a small subset of CSF subcategories are code-visible.",
  SOC2: "Code-level evidence only. NOT a SOC 2 examination. Most Trust Services Criteria are organizational/operational.",
  "CIS_v8.1": "Code-level evidence only. NOT a CIS Controls assessment. Most safeguards require operational evidence.",
  EssentialEight:
    "NOT an Essential Eight assessment. Only 'Patch Applications' is meaningfully evidenced by a code scan (via SCA of outdated vulnerable dependencies); the other seven mitigations are out of scope for code scanning.",
  OWASP_Web_2021: "Coverage of OWASP Top 10 (2021) categories for which CodeInspectus has detectors. Not exhaustive.",
  OWASP_LLM_2025: "Coverage of OWASP LLM Top 10 (2025) categories for which CodeInspectus has detectors. Not exhaustive.",
};

export function computePostureScore(findings: Finding[]): number {
  let penalty = 0;
  for (const f of findings) penalty += SEVERITY_WEIGHT[f.severity] ?? 0;
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

function controlsForFinding(f: Finding, framework: string): string[] {
  if (framework === "OWASP_Web_2021") return f.owasp_web ?? [];
  if (framework === "OWASP_LLM_2025") return f.owasp_llm ?? [];
  return f.frameworks.find((t) => t.framework === framework)?.controls ?? [];
}

async function coverageForFramework(
  framework: string,
  findings: Finding[],
  universe: Array<{ id: string; name: string }>,
): Promise<FrameworkCoverage> {
  const counts = new Map<string, number>();
  for (const f of findings) {
    for (const id of controlsForFinding(f, framework)) {
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }
  const controls = universe.map((c) => {
    const n = counts.get(c.id) ?? 0;
    return { id: c.id, name: c.name, findings: n, status: (n > 0 ? "gap" : "clear") as "gap" | "clear" };
  });
  return {
    framework,
    scope: "code-visible subset only",
    code_visible_controls: universe.length,
    controls_with_findings: controls.filter((c) => c.findings > 0).length,
    controls,
    disclaimer: FRAMEWORK_DISCLAIMERS[framework] ?? STANDING_DISCLAIMER,
  };
}

export async function buildComplianceReport(input: ComplianceReportInput): Promise<ComplianceReport> {
  const scan = await getScan(input.scan_id);
  if (!scan) {
    throw new Error(
      `No scan found with id '${input.scan_id}'. Run codeinspectus_scan first; the scan_id is in its result.`,
    );
  }
  const data = await loadComplianceData();
  const wanted = input.framework ? [input.framework] : Object.keys(data.code_visible_controls);

  const frameworks: FrameworkCoverage[] = [];
  for (const fw of wanted) {
    const universe = data.code_visible_controls[fw];
    if (!universe) continue;
    frameworks.push(await coverageForFramework(fw, scan.findings, universe));
  }

  return {
    scan_id: input.scan_id,
    posture_score: computePostureScore(scan.findings),
    posture_note:
      "Severity-weighted posture score (0–100): 100 minus weighted penalties (critical 15, high 8, medium 3, low 1). This is NOT a percent-compliant figure and must not be presented as one.",
    frameworks,
    disclaimer: STANDING_DISCLAIMER,
  };
}

/** Compact overview embedded in the scan envelope (§5). */
export async function buildComplianceOverview(findings: Finding[]): Promise<ComplianceOverview> {
  const data = await loadComplianceData();
  const frameworks = Object.entries(data.code_visible_controls).map(([framework, universe]) => {
    const withFindings = new Set<string>();
    for (const f of findings) {
      for (const id of controlsForFinding(f, framework)) {
        if (universe.some((c) => c.id === id)) withFindings.add(id);
      }
    }
    return {
      framework,
      code_visible_controls: universe.length,
      controls_with_findings: withFindings.size,
    };
  });
  return {
    posture_score: computePostureScore(findings),
    frameworks,
    disclaimer: STANDING_DISCLAIMER,
  };
}
