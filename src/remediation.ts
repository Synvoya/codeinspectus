/**
 * Default remediation guidance keyed by CWE (PRD §5 remediation block).
 * Engine findings get a CWE-based default; AI-code checks supply their own
 * richer remediation. Falls back to a generic template when a CWE is unknown.
 */

import type { Remediation } from "./types.js";

const CWE_REMEDIATION: Record<string, Remediation> = {
  "CWE-798": {
    summary: "Remove the hard-coded credential; load it from a server-side secret store and rotate the exposed value.",
    steps: [
      "Delete the literal credential from source.",
      "Move it to a server-side environment variable or a secrets manager (never a client-exposed env prefix).",
      "Rotate/revoke the exposed credential — assume it is already compromised.",
      "Add the file/path to secret-scanning so it cannot reappear.",
    ],
    code_suggestion: "const key = process.env.SERVICE_SECRET_KEY; // server-side only",
    references: ["CWE-798", "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
  },
  "CWE-312": {
    summary: "Do not store sensitive data in cleartext; encrypt at rest or keep it out of source/build artifacts.",
    steps: [
      "Remove the cleartext sensitive value from the file/bundle.",
      "Store secrets in a server-side secret manager; encrypt sensitive data at rest.",
    ],
    references: ["CWE-312"],
  },
  "CWE-285": {
    summary: "Enforce an explicit, default-deny authorization check on the protected resource.",
    steps: [
      "Add an authorization check that verifies the acting user owns/may access the resource.",
      "Default to deny; grant only on an explicit, correct condition (e.g. auth.uid() = owner).",
    ],
    references: ["CWE-285", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
  },
  "CWE-862": {
    summary: "Add the missing authorization check — the resource is currently reachable without one.",
    steps: [
      "Add an access-control check before the protected operation.",
      "For Supabase: enable RLS and add per-operation policies (SELECT/INSERT/UPDATE/DELETE).",
    ],
    references: ["CWE-862", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
  },
  "CWE-863": {
    summary: "Fix the authorization logic so it tests the correct condition instead of an always-true / wrong predicate.",
    steps: [
      "Replace permissive predicates like USING (true) with a real ownership check.",
      "Verify the policy tests the user identity (auth.uid()), not an unrelated claim.",
    ],
    references: ["CWE-863", "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
  },
  "CWE-89": {
    summary: "Use parameterized queries / prepared statements; never build SQL from untrusted input by concatenation.",
    steps: [
      "Replace string-concatenated SQL with parameterized queries or an ORM binding.",
      "Validate/whitelist any dynamic identifiers (table/column names) separately.",
    ],
    references: ["CWE-89", "https://owasp.org/Top10/A03_2021-Injection/"],
  },
  "CWE-79": {
    summary: "Escape/encode output and avoid injecting untrusted input into HTML; prefer framework auto-escaping.",
    steps: [
      "Render untrusted data through the framework's auto-escaping; avoid raw HTML injection sinks.",
      "Apply a Content Security Policy as defense in depth.",
    ],
    references: ["CWE-79", "https://owasp.org/Top10/A03_2021-Injection/"],
  },
  "CWE-77": {
    summary: "Avoid passing untrusted input to a shell; use argument arrays and validate inputs.",
    steps: [
      "Use a process API with an argument array instead of a shell command string.",
      "Validate and whitelist any user-controlled arguments.",
    ],
    references: ["CWE-77"],
  },
  "CWE-94": {
    summary: "Never interpret untrusted input as code; remove dynamic evaluation of external data.",
    steps: [
      "Remove dynamic code evaluation of untrusted input (e.g. eval-style execution).",
      "Parse data declaratively instead of executing it.",
    ],
    references: ["CWE-94"],
  },
  "CWE-1395": {
    summary: "Upgrade the vulnerable dependency to a fixed version (or remove it); rebuild the lockfile.",
    steps: [
      "Bump the affected package to the patched version Trivy reports as fixed.",
      "Update the lockfile and re-run the scan to confirm the CVE is resolved.",
      "If no fix exists, assess whether the vulnerable code path is reachable and consider an alternative dependency.",
    ],
    references: ["CWE-1395", "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
  },
  "CWE-1426": {
    summary: "Treat untrusted content reaching an LLM as data, not instructions: isolate it behind a message-role boundary, constrain output handling, and gate any tool access.",
    steps: [
      "Do not concatenate untrusted input directly into the prompt/system message.",
      "Pass untrusted content as a separate user-role message and constrain with explicit instructions.",
      "Validate/limit what the model's output can trigger; require human confirmation for sensitive tool actions.",
    ],
    references: ["CWE-1426", "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"],
  },
};

const GENERIC: Remediation = {
  summary: "Review the flagged code and remediate per the linked weakness reference.",
  steps: ["Inspect the finding location.", "Apply the standard fix for the associated CWE."],
  references: [],
};

export function remediationForCwe(cwes: string[]): Remediation {
  for (const c of cwes) {
    const r = CWE_REMEDIATION[c];
    if (r) return r;
  }
  return { ...GENERIC, references: cwes.slice() };
}
