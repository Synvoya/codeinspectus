/**
 * CodeInspectus eval suite (PRD §13). Drives the BUILT server over real MCP stdio
 * and asserts on structuredContent. ≥10 evals against fixtures/vulnerable-app:
 * each independent, read-only, verifiable, stable.
 *
 * Engine-dependent evals (Opengrep SQLi, Trivy SCA) are SKIPPED (not failed) when
 * the engine binary / Trivy DB is unavailable, so the suite is stable in any
 * environment; the AI-code evals are pure-TS and always run.
 *
 * Run: npm run eval
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { resolve } from "node:path";

const FIXTURE = resolve(process.cwd(), "fixtures/vulnerable-app");
// INTENTIONAL FAKE TEST DATA (planted fixture value; the evals below assert it is
// detected and redacted) -- not a real credential; allowlisted in /.gitleaks.toml.
const RAW_SECRET = "sk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP1rE5wB9mNqK7";

// ── Minimal MCP stdio client ────────────────────────────────────────────────
class McpClient {
  private child: ChildProcessWithoutNullStreams;
  private buf = "";
  private pending = new Map<number, (v: any) => void>();
  private nextId = 1;

  constructor() {
    this.child = spawn("node", ["dist/index.js"], { stdio: ["pipe", "pipe", "pipe"] });
    this.child.stdout.on("data", (d) => this.onData(d.toString()));
    this.child.stderr.on("data", () => {});
  }
  private onData(s: string) {
    this.buf += s;
    let i;
    while ((i = this.buf.indexOf("\n")) >= 0) {
      const line = this.buf.slice(0, i).trim();
      this.buf = this.buf.slice(i + 1);
      if (!line) continue;
      try {
        const msg = JSON.parse(line);
        if (msg.id && this.pending.has(msg.id)) {
          this.pending.get(msg.id)!(msg);
          this.pending.delete(msg.id);
        }
      } catch {
        throw new Error(`STDOUT POLLUTION (not JSON-RPC): ${line}`);
      }
    }
  }
  private send(method: string, params: unknown, id?: number) {
    this.child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...(id ? { id } : {}), method, params }) + "\n");
  }
  private request(method: string, params: unknown, timeoutMs = 120000): Promise<any> {
    const id = this.nextId++;
    return new Promise((res, rej) => {
      const t = setTimeout(() => rej(new Error(`timeout: ${method}`)), timeoutMs);
      this.pending.set(id, (v) => {
        clearTimeout(t);
        res(v);
      });
      this.send(method, params, id);
    });
  }
  async init() {
    await this.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "ci-evals", version: "1.0.0" },
    });
    this.send("notifications/initialized", {});
  }
  async callTool(name: string, args: Record<string, unknown>): Promise<any> {
    const r = await this.request("tools/call", { name, arguments: args });
    if (r.error) throw new Error(`tool ${name} error: ${JSON.stringify(r.error)}`);
    return r.result;
  }
  close() {
    this.child.kill();
  }
}

// ── Eval framework ──────────────────────────────────────────────────────────
type Status = "pass" | "fail" | "skip";
interface EvalResult {
  id: string;
  status: Status;
  detail: string;
}
const results: EvalResult[] = [];
function record(id: string, status: Status, detail: string) {
  results.push({ id, status, detail });
}
function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(msg);
}

async function main() {
  const client = new McpClient();
  await client.init();

  // One full scan, reused across evals.
  const scanRes = await client.callTool("codeinspectus_scan", { path: FIXTURE });
  const scan = scanRes.structuredContent;
  const findings: any[] = scan.findings;
  const engineRan = (e: string) => scan.engine_details.some((d: any) => d.engine === e && d.ran);
  const has = (pred: (f: any) => boolean) => findings.some(pred);
  const find = (pred: (f: any) => boolean) => findings.find(pred);

  type Check = { id: string; engineDep?: string; fn: () => Promise<void> | void };
  const checks: Check[] = [
    {
      id: "E01 scan returns a valid envelope (offline, disclaimer, scan_id)",
      fn: () => {
        assert(typeof scan.scan_id === "string" && scan.scan_id.length > 0, "missing scan_id");
        assert(scan.offline === true, "offline must be true");
        assert(/not an audit or certification/i.test(scan.disclaimer), "missing standing disclaimer");
      },
    },
    {
      id: "E02 hard-coded live secret detected at config.ts (CWE-798)",
      fn: () => {
        const f = find((x) => x.location.file === "src/config.ts" && x.cwe.includes("CWE-798"));
        assert(!!f, "no CWE-798 finding at src/config.ts");
        assert(f.severity === "critical", `expected critical, got ${f.severity}`);
      },
    },
    {
      id: "E03 secret VALUE is redacted everywhere (guardrail §5)",
      fn: () => {
        const leaked = findings.some(
          (f) => JSON.stringify(f).includes(RAW_SECRET),
        );
        assert(!leaked, "raw secret value leaked into output — redaction failed");
      },
    },
    {
      id: "E04 USING (true) RLS policy detected as critical CWE-863",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-rls-using-true");
        assert(!!f, "USING (true) not detected");
        assert(f.severity === "critical" && f.cwe.includes("CWE-863"), "wrong severity/CWE for USING(true)");
        assert(f.owasp_web?.includes("A01:2021"), "USING(true) should map to OWASP A01:2021");
      },
    },
    {
      id: "E05 USING(true) inside a SQL COMMENT is NOT flagged (precision)",
      fn: () => {
        const fps = findings.filter((x) => x.rule_id === "ci-ai-rls-using-true");
        assert(fps.length === 1, `expected exactly 1 USING(true) finding, got ${fps.length} (comment false positive?)`);
        assert(fps[0].location.start_line === 18, `expected the real policy at line 18, got ${fps[0].location.start_line}`);
      },
    },
    {
      id: "E06 public table without RLS detected (CWE-862, payments)",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-rls-missing");
        assert(!!f, "missing-RLS not detected");
        assert(/payments/.test(f.title), "expected payments table");
        assert(f.cwe.includes("CWE-862"), "expected CWE-862");
      },
    },
    {
      id: "E07 correctly-secured table (accounts) NOT flagged (precision)",
      fn: () => {
        const bad = findings.some((x) => /'accounts'/.test(x.title) && x.rule_id.startsWith("ci-ai-rls"));
        assert(!bad, "accounts table (RLS + auth.uid policies) wrongly flagged");
      },
    },
    {
      id: "E08 prompt-injection sink + excessive agency (LLM01+LLM06, CWE-1426)",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-prompt-injection-sink");
        assert(!!f, "prompt-injection sink not detected");
        assert(f.cwe.includes("CWE-1426"), "expected CWE-1426");
        assert(f.owasp_llm?.includes("LLM01:2025") && f.owasp_llm?.includes("LLM06:2025"), "expected LLM01 + LLM06");
        assert(f.confidence === "medium", "prompt-injection must be medium confidence (honest scope)");
      },
    },
    {
      id: "E09 secret behind client-exposed env prefix detected; publishable key NOT",
      fn: () => {
        const f = find((x) => x.rule_id === "ci-ai-public-env-secret");
        assert(!!f, "public-env-secret not detected");
        // publishable() uses NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY — must NOT be flagged
        const fpCount = findings.filter((x) => x.rule_id === "ci-ai-public-env-secret").length;
        assert(fpCount === 1, `expected exactly 1 public-env-secret finding, got ${fpCount}`);
      },
    },
    {
      id: "E10 compliance_report: ISO27001 code-visible denominator shown; no '% compliant'",
      fn: async () => {
        const rep = (await client.callTool("codeinspectus_compliance_report", { scan_id: scan.scan_id, framework: "ISO27001:2022" })).structuredContent;
        const iso = rep.frameworks.find((f: any) => f.framework === "ISO27001:2022");
        assert(!!iso, "no ISO27001 framework in report");
        assert(iso.code_visible_controls === 7, `expected 7 code-visible ISO controls, got ${iso.code_visible_controls}`);
        assert(iso.scope === "code-visible subset only", "scope label missing");
        assert(/not an iso 27001 audit/i.test(iso.disclaimer), "ISO disclaimer missing");
        const blob = JSON.stringify(rep).toLowerCase();
        assert(!/%\s*compliant/.test(blob) && !/you pass/.test(blob), "forbidden '% compliant' / 'you pass' language present");
      },
    },
    {
      id: "E11 posture score is its own 0-100 view, never labeled percent-compliant",
      fn: async () => {
        const rep = (await client.callTool("codeinspectus_compliance_report", { scan_id: scan.scan_id })).structuredContent;
        assert(typeof rep.posture_score === "number" && rep.posture_score >= 0 && rep.posture_score <= 100, "posture_score out of range");
        assert(/not a percent-compliant/i.test(rep.posture_note), "posture_note must disclaim '% compliant'");
      },
    },
    {
      id: "E12 explain_finding returns remediation steps + references for a finding",
      fn: async () => {
        const target = find((x) => x.rule_id === "ci-ai-rls-using-true");
        const ex = (await client.callTool("codeinspectus_explain_finding", { scan_id: scan.scan_id, finding_id: target.id })).structuredContent;
        assert(ex.remediation.steps.length > 0, "no remediation steps");
        assert(ex.remediation.references.length > 0, "no references");
        assert(ex.why_it_matters.length > 0, "no why_it_matters");
      },
    },
    {
      id: "E13 rescan with no changes: all remaining, zero resolved, zero introduced",
      fn: async () => {
        // Use the deterministic pure-TS analyzers as the baseline so the diff
        // logic is tested without engine/DB nondeterminism.
        const base = (await client.callTool("codeinspectus_scan", { path: FIXTURE, scanners: ["ai"] })).structuredContent;
        const re = (await client.callTool("codeinspectus_rescan", { path: FIXTURE, prior_scan_id: base.scan_id, scanners: ["ai"] })).structuredContent;
        assert(re.summary.resolved === 0, `expected 0 resolved, got ${re.summary.resolved}`);
        assert(re.summary.introduced === 0, `expected 0 introduced, got ${re.summary.introduced}`);
        assert(re.summary.remaining > 0, "expected findings to remain");
      },
    },
    {
      id: "E14 list_rules exposes the AI-code moat rules + DB version",
      fn: async () => {
        const lr = (await client.callTool("codeinspectus_list_rules", {})).structuredContent;
        assert(lr.custom_rule_count >= 10, `expected >=10 custom rules, got ${lr.custom_rule_count}`);
        assert(lr.custom_rules.some((r: any) => r.id === "ci-ai-rls-using-true"), "missing ci-ai-rls-using-true in list_rules");
        assert(typeof lr.detection_db_version === "string", "missing detection_db_version");
      },
    },
    {
      id: "E15 severity_threshold filters out lower-severity findings",
      fn: async () => {
        const hi = (await client.callTool("codeinspectus_scan", { path: FIXTURE, severity_threshold: "high", scanners: ["ai"] })).structuredContent;
        assert(hi.findings.every((f: any) => ["critical", "high"].includes(f.severity)), "threshold leaked lower severities");
        assert(hi.summary.medium === 0 && hi.summary.low === 0, "threshold summary should have no medium/low");
      },
    },
    {
      id: "E16 [engine] Opengrep detects SQL injection (CWE-89) and NOT the parameterized query",
      engineDep: "opengrep",
      fn: () => {
        const sqli = find((x) => x.cwe.includes("CWE-89") && x.location.file === "src/db.ts");
        assert(!!sqli, "SQLi not detected by Opengrep");
        assert(sqli.location.start_line === 11, `expected SQLi at the unsafe line 11, got ${sqli.location.start_line}`);
        // safe parameterized query is on line 16 — must not be flagged
        const safe = findings.some((x) => x.cwe.includes("CWE-89") && x.location.start_line >= 15);
        assert(!safe, "parameterized query wrongly flagged as SQLi");
      },
    },
    {
      id: "E17 [engine] Trivy detects the outdated vulnerable dependency (lodash/minimist)",
      engineDep: "trivy-vuln",
      fn: () => {
        const dep = find(
          (x) => x.engine === "trivy" && /^(cve-|ghsa-)/i.test(x.rule_id) && /lodash|minimist/i.test(JSON.stringify(x.location) + x.message + x.title),
        );
        assert(!!dep, "no Trivy SCA finding for lodash/minimist");
        assert(dep.frameworks.some((t: any) => t.framework === "EssentialEight"), "vuln dep should map to Essential Eight Patch Applications");
      },
    },
  ];

  for (const c of checks) {
    try {
      // Engine-dependency gating for stable runs.
      if (c.engineDep === "opengrep" && !engineRan("opengrep")) {
        record(c.id, "skip", "opengrep did not run (install-engines)");
        continue;
      }
      if (c.engineDep === "trivy-vuln") {
        if (!engineRan("trivy")) {
          record(c.id, "skip", "trivy did not run (install-engines)");
          continue;
        }
        if (!scan.trivy_db_date) {
          record(c.id, "skip", "trivy vuln DB not present (install-engines populates it)");
          continue;
        }
      }
      await c.fn();
      record(c.id, "pass", "ok");
    } catch (err) {
      record(c.id, "fail", err instanceof Error ? err.message : String(err));
    }
  }

  client.close();

  // Report.
  const pass = results.filter((r) => r.status === "pass").length;
  const fail = results.filter((r) => r.status === "fail").length;
  const skip = results.filter((r) => r.status === "skip").length;
  process.stdout.write("\nCodeInspectus eval results\n=========================\n");
  for (const r of results) {
    const mark = r.status === "pass" ? "PASS" : r.status === "fail" ? "FAIL" : "SKIP";
    process.stdout.write(`[${mark}] ${r.id}${r.status === "pass" ? "" : " — " + r.detail}\n`);
  }
  process.stdout.write(`\n${pass} passed, ${fail} failed, ${skip} skipped (of ${results.length}).\n`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`eval harness error: ${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(2);
});
