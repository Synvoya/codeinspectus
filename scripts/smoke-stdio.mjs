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
  const instructions = init.result?.instructions;
  if (typeof instructions !== "string") throw new Error("initialize returned no server instructions");
  const decisionPrefix = instructions.slice(0, 512);
  for (const expected of [
    "Present findings before editing",
    "granular user approval",
    "codeinspectus_rescan",
    "never claim fixed unless confirmed",
  ]) {
    if (!decisionPrefix.includes(expected)) {
      throw new Error(`first 512 instruction characters missing: ${expected}`);
    }
  }
  console.error("✓ initialize:", init.result.serverInfo.name, init.result.serverInfo.version);
  console.error("✓ server instructions: safe scan → consent → fix → rescan workflow advertised");

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
  // A full-project scan invokes all managed engines and can legitimately take
  // longer than the lightweight initialize/tools-list requests, especially on
  // cold CI runners. Keep the short default for protocol calls, but give the
  // scanner a bounded, engine-appropriate window.
  const scan = await waitFor(3, 30_000);
  const sc = scan.result?.structuredContent;
  if (!sc || typeof sc.scan_id !== "string") throw new Error("scan returned no structuredContent");
  if (!Array.isArray(sc.detected_technologies)) throw new Error("scan returned no detected_technologies array");
  if (!Array.isArray(sc.pack_coverage)) throw new Error("scan returned no pack_coverage array");
  if (sc.pack_coverage.length !== 16) throw new Error(`scan returned ${sc.pack_coverage.length} native packs, expected 16`);
  if (!Array.isArray(sc.dependency_coverage)) throw new Error("scan returned no dependency_coverage array");
  const pubCoverage = sc.dependency_coverage.find((coverage) => coverage.engine === "codeinspectus-pub");
  if (!pubCoverage || pubCoverage.matching !== "exact-enumerated-versions") {
    throw new Error("scan returned no exact-version native Pub dependency coverage");
  }
  const nativePack = sc.pack_coverage.find((pack) => pack.pack_id === "javascript-typescript");
  if (!nativePack || nativePack.analyzers?.registered !== 8 || nativePack.rules?.registered !== 22) {
    throw new Error("scan returned incomplete 8-analyzer/22-rule javascript-typescript pack coverage");
  }
  const reactNativePack = sc.pack_coverage.find((pack) => pack.pack_id === "react-native");
  const expoPack = sc.pack_coverage.find((pack) => pack.pack_id === "expo");
  if (reactNativePack?.rules?.registered !== 4 || expoPack?.rules?.registered !== 2) {
    throw new Error("scan returned incomplete React Native/Expo pack inventory");
  }
  const pythonPack = sc.pack_coverage.find((pack) => pack.pack_id === "python-ai-api");
  if (pythonPack?.analyzers?.registered !== 10 || pythonPack?.rules?.registered !== 10) {
    throw new Error("scan returned incomplete Python AI/API pack inventory");
  }
  const goPack = sc.pack_coverage.find((pack) => pack.pack_id === "go-ai");
  if (goPack?.analyzers?.registered !== 1 || goPack?.rules?.registered !== 1) {
    throw new Error("scan returned incomplete Go AI pack inventory");
  }
  const javaPack = sc.pack_coverage.find((pack) => pack.pack_id === "java-ai");
  if (javaPack?.analyzers?.registered !== 1 || javaPack?.rules?.registered !== 1) {
    throw new Error("scan returned incomplete Java AI pack inventory");
  }
  const csharpPack = sc.pack_coverage.find((pack) => pack.pack_id === "csharp-ai");
  if (csharpPack?.analyzers?.registered !== 1 || csharpPack?.rules?.registered !== 1) {
    throw new Error("scan returned incomplete C# AI pack inventory");
  }
  const phpPack = sc.pack_coverage.find((pack) => pack.pack_id === "php-ai");
  if (phpPack?.analyzers?.registered !== 1 || phpPack?.rules?.registered !== 1) {
    throw new Error("scan returned incomplete PHP AI pack inventory");
  }
  const rustPack = sc.pack_coverage.find((pack) => pack.pack_id === "rust-ai");
  if (rustPack?.analyzers?.registered !== 1 || rustPack?.rules?.registered !== 1) {
    throw new Error("scan returned incomplete Rust AI pack inventory");
  }
  const rubyPack = sc.pack_coverage.find((pack) => pack.pack_id === "ruby-ai");
  if (rubyPack?.analyzers?.registered !== 1 || rubyPack?.rules?.registered !== 1) {
    throw new Error("scan returned incomplete Ruby AI pack inventory");
  }
  const firebasePack = sc.pack_coverage.find((pack) => pack.pack_id === "firebase");
  if (firebasePack?.analyzers?.registered !== 1 || firebasePack?.rules?.registered !== 3) {
    throw new Error("scan returned incomplete Firebase pack inventory");
  }
  const githubActionsPack = sc.pack_coverage.find((pack) => pack.pack_id === "github-actions");
  if (githubActionsPack?.analyzers?.registered !== 1 || githubActionsPack?.rules?.registered !== 2) {
    throw new Error("scan returned incomplete GitHub Actions pack inventory");
  }
  const baselinePack = sc.pack_coverage.find((pack) => pack.pack_id === "javascript-baseline");
  if (baselinePack?.scanner_kind !== "sast" || baselinePack?.analyzers?.registered !== 1 || baselinePack?.rules?.registered !== 2) {
    throw new Error("scan returned incomplete JavaScript baseline SAST pack inventory");
  }
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
