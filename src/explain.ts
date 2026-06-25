/**
 * Deep explanation for a single finding (PRD §11). Reads a stored scan result
 * and expands the finding's remediation into a full explanation.
 */

import { getScan } from "./store.js";
import type { ExplainFindingInput } from "./schemas.js";
import type { Finding, Remediation } from "./types.js";

export interface ExplainOutput {
  finding: Finding;
  explanation: string;
  why_it_matters: string;
  remediation: Remediation;
  references: string[];
}

const CWE_BLURB: Record<string, string> = {
  "CWE-798":
    "Hard-coded credentials let anyone with access to the source (or a shipped bundle) authenticate as the application or a privileged service.",
  "CWE-312":
    "Cleartext storage of sensitive information exposes it to anyone who can read the file, log, or built artifact.",
  "CWE-285":
    "Improper authorization allows actions the actor should not be permitted to perform.",
  "CWE-862":
    "Missing authorization means a protected resource can be reached without any access-control check.",
  "CWE-863":
    "Incorrect authorization grants access based on a flawed check (e.g. an always-true policy).",
  "CWE-89": "SQL injection lets attacker-controlled input alter the structure of a SQL query.",
  "CWE-79": "Cross-site scripting injects attacker-controlled script into a page's output.",
  "CWE-77": "Command/argument injection lets untrusted input change the command being executed.",
  "CWE-94": "Code injection lets untrusted input be interpreted as code.",
  "CWE-1426":
    "Improper validation of generative-AI output / unsafe handling of untrusted input flowing into an LLM enables prompt injection.",
};

export async function explainFinding(input: ExplainFindingInput): Promise<ExplainOutput> {
  const scan = await getScan(input.scan_id);
  if (!scan) {
    throw new Error(
      `No scan found with id '${input.scan_id}'. Run codeinspectus_scan first; the scan_id is in its result.`,
    );
  }
  const finding = scan.findings.find((f) => f.id === input.finding_id);
  if (!finding) {
    throw new Error(
      `Finding '${input.finding_id}' not found in scan '${input.scan_id}'. Available ids: ${scan.findings
        .slice(0, 20)
        .map((f) => f.id)
        .join(", ")}${scan.findings.length > 20 ? ", …" : ""}.`,
    );
  }

  const cweBlurbs = finding.cwe
    .map((c) => CWE_BLURB[c])
    .filter((b): b is string => Boolean(b));

  const explanation =
    `${finding.message}\n\n` +
    `Detected by ${finding.engines.join(" + ")} (rule: ${finding.rule_id}). ` +
    `Confidence: ${finding.confidence}.` +
    (cweBlurbs.length ? `\n\n${cweBlurbs.join("\n")}` : "");

  const why_it_matters =
    finding.severity === "critical" || finding.severity === "high"
      ? "This is a high-impact weakness an attacker can plausibly exploit; fix before shipping."
      : "Lower immediate impact, but it weakens the application's security posture and should be remediated.";

  return {
    finding,
    explanation,
    why_it_matters,
    remediation: finding.remediation,
    references: finding.remediation.references,
  };
}
