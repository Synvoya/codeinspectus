import { listNativePacks } from "../packs/registry.js";
import type { StoredScanResult } from "../store.js";

export const ISSUE_TEST_SECRET = "RAW-ISSUE-PAYLOAD-SECRET-4938172645";

export function issueTestScan(target = "/repository"): StoredScanResult {
  return {
    scan_id: "scan-00000000-0000-4000-8000-000000000001", target,
    started_at: "2026-07-30T00:00:00.000Z", duration_ms: 1,
    engines_run: ["opengrep@1", "gitleaks@1", "trivy@1"],
    engine_details: ["opengrep", "gitleaks", "trivy"].map((engine) => ({ engine: engine as "opengrep" | "gitleaks" | "trivy", version: "1", available: true, ran: true, finding_count: engine === "gitleaks" ? 1 : 0, duration_ms: 1 })),
    offline: true, detected_technologies: [], pack_coverage: listNativePacks().map((pack) => ({
      pack_id: pack.id, version: pack.version, scanner_kind: pack.scannerKind, state: "not_applicable" as const,
      languages: [], frameworks: [], platforms: [], analyzers: { registered: 0, ran: 0 }, rules: { registered: 0, ran: 0 }, limitations: [],
    })),
    summary: { critical: 1, high: 0, medium: 0, low: 0, info: 0, total: 1 },
    findings: [{ id: "CI-0001", fingerprint: "fp-issue-1", title: "Unsafe @team [payload]", severity: "critical", engine: "gitleaks", engines: ["gitleaks"], rule_id: "generic-secret", cwe: ["CWE-798"], location: { file: "src/@owner/config.ts", start_line: 7, end_line: 7, snippet: ISSUE_TEST_SECRET }, message: ISSUE_TEST_SECRET, remediation: { summary: "Rotate and remove the credential.", steps: ["Move it to a secret manager."], references: [] }, frameworks: [], confidence: "high", is_secret: true, producer_components: ["engine:gitleaks"] }],
    truncated: false, total_findings_before_limit: 1, disclaimer: "test", warnings: [], secret_coverage: "verified", git_safety: { state: "clean" },
    scan_config: { scanners: ["ai"], max_findings: 200 }, storage_schema_version: "2.0.0", canonical_findings: true,
  };
}
