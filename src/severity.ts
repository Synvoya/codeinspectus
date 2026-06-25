/**
 * Severity normalization (PRD §5). Maps each engine's native severity onto the
 * common 5-level scale. Prefer numeric CVSS / security-severity (Trivy, and
 * Opengrep when present) over the coarse SARIF level.
 *
 * Mapping table (documented per PRD §5):
 *   security-severity (0–10):  >=9.0 critical | >=7.0 high | >=4.0 medium | >0 low | 0 info
 *   SARIF level:               error→high | warning→medium | note→low | none→info
 *   Opengrep rule severity:    ERROR→high | WARNING→medium | INFO→low
 *   Gitleaks (secrets):        high by default; critical for live-mode keys
 */

import type { Severity, Engine } from "./types.js";

export function fromSecuritySeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function fromSarifLevel(level?: string): Severity {
  switch ((level ?? "").toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    case "none":
      return "info";
    default:
      return "medium";
  }
}

function fromRuleSeverity(sev?: string): Severity | undefined {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "ERROR":
    case "HIGH":
      return "high";
    case "WARNING":
    case "MEDIUM":
      return "medium";
    case "INFO":
    case "LOW":
      return "low";
    default:
      return undefined;
  }
}

export interface SeverityInputs {
  engine: Engine;
  level?: string;
  securitySeverity?: string | number;
  ruleSeverity?: string;
  isSecret?: boolean;
  /** Live-mode secret (sk_live_, AKIA…) → critical. */
  liveSecret?: boolean;
}

export function normalizeSeverity(i: SeverityInputs): Severity {
  // Secrets first: a real hard-coded secret is always at least high.
  if (i.isSecret) return i.liveSecret ? "critical" : "high";

  // Prefer numeric CVSS / security-severity.
  if (i.securitySeverity !== undefined && i.securitySeverity !== "") {
    const n = typeof i.securitySeverity === "number" ? i.securitySeverity : parseFloat(i.securitySeverity);
    if (!Number.isNaN(n)) return fromSecuritySeverity(n);
  }

  // Then explicit rule severity metadata.
  const rule = fromRuleSeverity(i.ruleSeverity);
  if (rule) return rule;

  // Fall back to SARIF level.
  return fromSarifLevel(i.level);
}
