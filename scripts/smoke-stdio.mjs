#!/usr/bin/env node
/**
 * Stdio smoke test: spawn the built server, run the MCP handshake, list tools,
 * and call codeinspectus_scan. Asserts that stdout carries ONLY JSON-RPC lines
 * (the critical stdout-hygiene guardrail, PRD §12) — any non-JSON line on stdout
 * fails the test.
 */
import { spawn } from "node:child_process";

const child = spawn("node", ["dist/index.js"], {
  stdio: ["pipe", "pipe", "pipe"],
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

function send(obj) {
  child.stdin.write(JSON.stringify(obj) + "\n");
}

async function waitFor(id, timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = responses.find((x) => x.id === id);
    if (r) return r;
    await new Promise((res) => setTimeout(res, 50));
  }
  throw new Error(`timeout waiting for response id=${id}`);
}

(async () => {
  send({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "smoke", version: "0.0.0" },
    },
  });
  const init = await waitFor(1);
  if (!init.result?.serverInfo?.name) throw new Error("bad initialize result");
  console.error("✓ initialize:", init.result.serverInfo.name, init.result.serverInfo.version);

  send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });

  send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  const list = await waitFor(2);
  const tools = (list.result?.tools ?? []).map((t) => t.name);
  console.error("✓ tools/list:", tools.join(", "));
  const expected = [
    "codeinspectus_scan",
    "codeinspectus_rescan",
    "codeinspectus_compliance_report",
    "codeinspectus_explain_finding",
    "codeinspectus_generate_sbom",
    "codeinspectus_list_rules",
  ];
  for (const e of expected) {
    if (!tools.includes(e)) throw new Error(`missing tool ${e}`);
  }

  send({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "codeinspectus_scan", arguments: { path: process.cwd() } },
  });
  const scan = await waitFor(3);
  const sc = scan.result?.structuredContent;
  if (!sc || typeof sc.scan_id !== "string") throw new Error("scan returned no structuredContent");
  console.error("✓ codeinspectus_scan structuredContent.scan_id:", sc.scan_id);

  console.error("\nALL STDIO SMOKE CHECKS PASSED. stdout was pure JSON-RPC.");
  child.kill();
  process.exit(0);
})().catch((err) => {
  console.error("SMOKE TEST FAILED:", err.message);
  console.error("--- server stderr ---\n" + stderrBuf);
  child.kill();
  process.exit(1);
});
