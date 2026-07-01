#!/usr/bin/env node
/**
 * CG-24 end-to-end redaction drive (the check CG-20 missed).
 *
 * Plants secrets whose shapes are NOT in the 11 known SECRET_PATTERNS — a SendGrid
 * key, a GitLab PAT, a high-entropy generic key, and a full multi-line PEM private
 * key — then drives the REAL built MCP server (node dist/index.js over stdio) and
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
const RAW_VALUES = Object.values(SECRETS);

const child = spawn("node", ["dist/index.js"], { stdio: ["pipe", "pipe", "pipe"] });
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
  await writeFile(join(fixture, "src", "key.pem"), SECRETS.pem + "\n");

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

  console.error("\nALL REDACTION E2E CHECKS PASSED — no raw secret leaked on non-allowlisted fixtures.");
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
