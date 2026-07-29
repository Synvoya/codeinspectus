import { describe, expect, test } from "vitest";
import type { StoredScanResult } from "../store.js";
import { createJsonExport } from "./model.js";
import { createCsvExport, CSV_COLUMNS } from "./csv.js";

function parseCsv(csv: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;
  for (let index = 0; index < csv.length; index++) {
    const char = csv[index]!;
    if (quoted) {
      if (char === '"' && csv[index + 1] === '"') { cell += '"'; index++; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") { row.push(cell); cell = ""; }
    else if (char === "\r" && csv[index + 1] === "\n") {
      row.push(cell); rows.push(row); row = []; cell = ""; index++;
    } else cell += char;
  }
  expect(quoted).toBe(false);
  expect(row).toEqual([]);
  expect(cell).toBe("");
  return rows;
}

function scan(findings = 2): StoredScanResult {
  const all = [
    { id: "CI-0002", fingerprint: "fp-2", title: "+SUM(1,1)", file: "src/b.ts", message: "line, quote \" and\nnewline" },
    { id: "CI-0001", fingerprint: "fp-1", title: "=HYPERLINK(\"https://example.test\")", file: "src/a.ts", message: "RAW-CSV-SECRET-9081726354" },
  ];
  return {
    scan_id: "scan-00000000-0000-4000-8000-000000000001", target: "@repository", started_at: "2026-07-30T00:00:00.000Z", duration_ms: 5,
    engines_run: ["gitleaks@8.30.1"], engine_details: [{ engine: "gitleaks", version: "8.30.1", available: true, ran: true, finding_count: findings, duration_ms: 1 }],
    offline: true, detected_technologies: [], pack_coverage: [], summary: { critical: 0, high: findings, medium: 0, low: 0, info: 0, total: findings },
    findings: all.slice(0, findings).map((item) => ({
      id: item.id, fingerprint: item.fingerprint, title: item.title, severity: "high" as const, engine: "gitleaks" as const, engines: ["gitleaks" as const],
      rule_id: "generic-secret", cwe: ["CWE-798"], location: { file: item.file, start_line: 2, end_line: 2, snippet: item.message }, message: item.message,
      remediation: { summary: "-replace it", steps: ["rotate, then replace"], references: ["https://example.test"] }, frameworks: [{ framework: "OWASP", controls: ["A02"] }], confidence: "high" as const,
      is_secret: item.id === "CI-0001", producer_components: ["engine:gitleaks"],
    })),
    truncated: false, total_findings_before_limit: findings, disclaimer: "test", warnings: [], secret_coverage: "verified", git_safety: { state: "clean" },
    scan_config: { scanners: ["secret"], max_findings: 200 }, storage_schema_version: "2.0.0", canonical_findings: true,
  };
}

describe("CSV export", () => {
  test("imports as RFC 4180 rows with exact stable columns and deterministic finding order", () => {
    const document = createJsonExport(scan());
    const first = createCsvExport(document);
    expect(createCsvExport(document)).toBe(first);
    const rows = parseCsv(first);
    expect(rows[0]).toEqual(CSV_COLUMNS);
    expect(rows).toHaveLength(4);
    const columns = new Map(CSV_COLUMNS.map((column, index) => [column, index]));
    expect(rows[1]![columns.get("record_type")!]).toBe("scan");
    expect(rows.slice(2).map((row) => row[columns.get("finding_id")!])).toEqual(["CI-0001", "CI-0002"]);
    expect(rows[3]![columns.get("message")!]).toBe("line, quote \" and\nnewline");
    expect(JSON.parse(rows[2]![columns.get("producer_components_json")!]!)).toEqual(["engine:gitleaks"]);
  });

  test("retains explicit partial coverage even with zero findings", () => {
    const document = createJsonExport(scan(0));
    const rows = parseCsv(createCsvExport(document));
    const columns = new Map(CSV_COLUMNS.map((column, index) => [column, index]));
    expect(rows).toHaveLength(2);
    expect(rows[1]![columns.get("aggregate_coverage")!]).toBe("partial");
    const evidence = JSON.parse(rows[1]![columns.get("coverage_evidence_json")!]!) as Array<{ state: string }>;
    expect(evidence.some((item) => item.state === "excluded" || item.state === "unknown")).toBe(true);
  });

  test("redacts secrets and neutralizes spreadsheet formula triggers", () => {
    const rows = parseCsv(createCsvExport(createJsonExport(scan())));
    const columns = new Map(CSV_COLUMNS.map((column, index) => [column, index]));
    expect(JSON.stringify(rows)).not.toContain("RAW-CSV-SECRET-9081726354");
    for (const row of rows.slice(1)) {
      for (const value of row) expect(value).not.toMatch(/^[\t\r\n]|^\s*[=+@-]/);
    }
    expect(rows[2]![columns.get("title")!]).toMatch(/^'/);
    expect(rows[3]![columns.get("title")!]).toMatch(/^'/);
    expect(rows[2]![columns.get("target")!]).toMatch(/^'/);
    expect(rows[2]![columns.get("remediation_summary")!]).toMatch(/^'/);
  });
});
