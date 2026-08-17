#!/usr/bin/env node
/**
 * CG-24 end-to-end redaction drive (the check CG-20 missed).
 *
 * Plants both a natively recognized Supabase secret and shapes supplied only by
 * commodity scanners — a SendGrid key, a GitLab PAT, a high-entropy generic key,
 * and a full multi-line PEM private key — then drives the REAL built MCP server and
 * asserts the raw value of each appears NOWHERE in codeinspectus_scan output (full
 * response, structuredContent, every finding snippet + message) NOR in
 * codeinspectus_explain_finding output for a secret finding.
 *
 * Run AFTER `npm run build`. Exit 0 = no leak; non-zero = a raw secret leaked.
 */
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Non-allowlisted, clearly-fake test secrets (not real credentials).
const SECRETS = {
  supabaseNative: "sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS",
  supabaseGitleaks: "sb_secret_Z9y8X7w6V5u4T3s2R1q0P9_aB3cD4eF",
  mixedStripe: "sk_live_51MixedLineA2b3C4d5E6f7G8h9J0k1L2m3N4",
  sendgrid: "SG.aB3dE5gH7jK9lM1nO2pQrS.tU4vW6xY8zA0bC2dE4fG6hI8jK0lM2nO4pP6qR8sT0uV",
  gitlabPat: "glpat-Ab1Cd2Ef3Gh4Ij5Kl6Mn",
  generic: "f3Q8zR1xW9kL2mN7pV4tB6cD0sJ5hG8aQ2wE4rT6yU8iO0p",
  pem: [
    "-----BEGIN RSA PRIVATE KEY-----",
    "MIIEowIBAAKCAQEA1Sf4kQv8ttJqFAKEbodyLine0123456789abcdefghijABCDE",
    "FGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEF==",
    "-----END RSA PRIVATE KEY-----",
  ].join("\n"),
};
const SUPABASE_PUBLISHABLE = "sb_publishable_Q1w2E3r4T5y6U7i8O9p0A1_zX8cV7bN";
const RAW_VALUES = Object.values(SECRETS);

const child = spawn("node", ["dist/index.js"], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, CODEINSPECTUS_INTERNAL_DISABLE_SCAN_PERSISTENCE: "1", CODEINSPECTUS_INTERNAL_DISABLE_TRIAGE_PERSISTENCE: "1" },
});
let stdoutBuf = "";
const responses = [];
let stderrBuf = "";

child.stdout.on("data", (d) => {
  stdoutBuf += d.toString();
  let idx;
  while ((idx = stdoutBuf.indexOf("\n")) >= 0) {
    const line = stdoutBuf.slice(0, idx).trim();
    stdoutBuf = stdoutBuf.slice(idx + 1);
    if (!line) continue;
    try {
      responses.push(JSON.parse(line));
    } catch {
      console.error("STDOUT POLLUTION (not JSON-RPC):", JSON.stringify(line));
      process.exit(2);
    }
  }
});
child.stderr.on("data", (d) => (stderrBuf += d.toString()));

const send = (obj) => child.stdin.write(JSON.stringify(obj) + "\n");
async function waitFor(id, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = responses.find((x) => x.id === id);
    if (r) return r;
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error(`timeout waiting for response id=${id}`);
}

/** Find every planted raw value present in a serialized blob. */
function leaks(blob) {
  return RAW_VALUES.filter((v) => blob.includes(v));
}

let fixture;
(async () => {
  fixture = await mkdtemp(join(tmpdir(), "ci-redaction-e2e-"));
  await mkdir(join(fixture, "src"), { recursive: true });
  await writeFile(
    join(fixture, "src", "config.ts"),
    `export const sg = "${SECRETS.sendgrid}";\n` +
      `export const gl = "${SECRETS.gitlabPat}";\n` +
      `export const apiKey = "${SECRETS.generic}";\n`,
  );
  const supabaseSource = join(fixture, "src", "supabase.ts");
  await writeFile(supabaseSource, `export const supabase = "${SECRETS.supabaseNative}";\n`);
  await writeFile(join(fixture, "src", "key.pem"), SECRETS.pem + "\n");
  await mkdir(join(fixture, "server"), { recursive: true });
  await mkdir(join(fixture, "public"), { recursive: true });
  // Non-code files ensure this pair exercises the pinned Gitleaks engine rather than
  // passing solely through the native JavaScript client analyzer.
  await writeFile(
    join(fixture, "server", "credentials.txt"),
    `supabase_secret = "${SECRETS.supabaseGitleaks}";\n`,
  );
  await writeFile(
    join(fixture, "public", "client-config.txt"),
    `supabaseKey = "${SUPABASE_PUBLISHABLE}";\n`,
  );
  await writeFile(
    join(fixture, "public", "mixed-config.txt"),
    `supabaseKey = "${SUPABASE_PUBLISHABLE}"; stripeKey = "${SECRETS.mixedStripe}";\n`,
  );

  send({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "redaction-e2e", version: "0.0.0" } },
  });
  await waitFor(1);
  send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });

  send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "codeinspectus_scan", arguments: { path: fixture } } });
  const scan = await waitFor(2);
  const blob = JSON.stringify(scan);
  const sc = scan.result?.structuredContent;
  if (!sc || !Array.isArray(sc.findings)) throw new Error("scan returned no structuredContent.findings");

  const secretFindings = sc.findings.filter((f) => f.is_secret);
  console.error(`✓ scan: ${sc.findings.length} findings, ${secretFindings.length} is_secret, engines=${sc.engines_run?.join(",")}`);
  if (secretFindings.length === 0) throw new Error("no is_secret findings produced — redaction path was not exercised");
  const gitleaksSupabase = sc.findings.find(
    (finding) =>
      finding.rule_id === "codeinspectus-supabase-secret-key" &&
      finding.location?.file === "server/credentials.txt" &&
      finding.engines?.includes("gitleaks"),
  );
  if (!gitleaksSupabase) {
    throw new Error("pinned Gitleaks did not surface the exact sb_secret_22_8 rule");
  }
  const dedicatedSupabase = sc.findings.find(
    (finding) =>
      finding.rule_id === "ci-ai-supabase-secret-key-client" &&
      finding.location?.file === "src/supabase.ts" &&
      finding.engines?.includes("codeinspectus-ai") &&
      finding.engines?.includes("gitleaks"),
  );
  if (!dedicatedSupabase) {
    throw new Error("final cross-engine dedup did not preserve the dedicated Supabase client rule");
  }
  if (sc.findings.some((finding) => finding.location?.file === "public/client-config.txt")) {
    throw new Error("public sb_publishable_22_8 key produced a finding");
  }
  const mixedLineSecret = sc.findings.find(
    (finding) =>
      finding.location?.file === "public/mixed-config.txt" &&
      finding.engines?.includes("gitleaks"),
  );
  if (!mixedLineSecret) {
    throw new Error("global publishable-key allowlist suppressed an unrelated same-line secret");
  }
  console.error("✓ Gitleaks: exact sb_secret_22_8 detected; publishable stayed silent without hiding a same-line secret");

  const scanLeaks = leaks(blob);
  if (scanLeaks.length) throw new Error(`RAW SECRET LEAKED in scan output: ${scanLeaks.map((v) => v.slice(0, 12) + "…").join(", ")}`);
  // Per-field assertion (defensive — beyond the whole-blob check).
  for (const f of sc.findings) {
    for (const field of [f.location?.snippet ?? "", f.message ?? ""]) {
      const l = leaks(field);
      if (l.length) throw new Error(`RAW SECRET in finding field (${f.rule_id}): ${l[0].slice(0, 12)}…`);
    }
  }
  console.error("✓ scan: no raw secret value in full response, snippets, or messages");

  // explain_finding on a secret finding must also not leak.
  const target = secretFindings[0];
  send({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "codeinspectus_explain_finding", arguments: { scan_id: sc.scan_id, finding_id: target.id } },
  });
  const explain = await waitFor(3);
  const explainLeaks = leaks(JSON.stringify(explain));
  if (explainLeaks.length) throw new Error(`RAW SECRET LEAKED in explain_finding: ${explainLeaks.map((v) => v.slice(0, 12) + "…").join(", ")}`);
  console.error(`✓ explain_finding(${target.id}): no raw secret value`);

  // Drive the real persisted MCP rescan path at one stable file location. This proves routing,
  // cross-engine dedup, scan_config reuse, producer signatures, and diffRescan together.
  await writeFile(supabaseSource, `export const supabase = "${SUPABASE_PUBLISHABLE}";\n`);
  send({
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: { name: "codeinspectus_rescan", arguments: { path: fixture, prior_scan_id: sc.scan_id } },
  });
  const fixedResponse = await waitFor(4);
  const fixed = fixedResponse.result?.structuredContent;
  if (
    !fixed ||
    fixed.summary?.resolved !== 1 ||
    fixed.summary?.introduced !== 0 ||
    fixed.resolved?.[0]?.rule_id !== "ci-ai-supabase-secret-key-client"
  ) {
    throw new Error(`secret-to-publishable rescan diff was wrong: ${JSON.stringify(fixed?.summary)}`);
  }
  if (leaks(JSON.stringify(fixedResponse)).length) throw new Error("RAW SECRET LEAKED in fixed rescan output");

  await writeFile(supabaseSource, `export const supabase = "${SECRETS.supabaseNative}";\n`);
  send({
    jsonrpc: "2.0",
    id: 5,
    method: "tools/call",
    params: { name: "codeinspectus_rescan", arguments: { path: fixture, prior_scan_id: fixed.scan_id } },
  });
  const reintroducedResponse = await waitFor(5);
  const reintroduced = reintroducedResponse.result?.structuredContent;
  if (
    !reintroduced ||
    reintroduced.summary?.resolved !== 0 ||
    reintroduced.summary?.introduced !== 1 ||
    reintroduced.introduced?.[0]?.rule_id !== "ci-ai-supabase-secret-key-client"
  ) {
    throw new Error(`publishable-to-secret rescan diff was wrong: ${JSON.stringify(reintroduced?.summary)}`);
  }
  if (leaks(JSON.stringify(reintroducedResponse)).length) {
    throw new Error("RAW SECRET LEAKED in reintroduced rescan output");
  }
  console.error("✓ rescan: same-path secret → publishable → secret resolved and reintroduced exactly once");

  console.error("\nALL REDACTION E2E CHECKS PASSED — no raw planted secret leaked.");
  await rm(fixture, { recursive: true, force: true }).catch(() => {});
  child.kill();
  process.exit(0);
})().catch(async (err) => {
  console.error("REDACTION E2E FAILED:", err.message);
  console.error("--- server stderr ---\n" + stderrBuf.slice(-1500));
  if (fixture) await rm(fixture, { recursive: true, force: true }).catch(() => {});
  child.kill();
  process.exit(1);
});
