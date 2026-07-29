#!/usr/bin/env node

import { spawn } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PACKAGE = "codeinspectus@1.5.0";
const REPOSITORY = "https://github.com/Textualize/rich.git";
const COMMIT = "6d30ad0f30028210124c149811cbbe2b183711f9";
const WORKFLOW = ".github/workflows/newissue.yml";
const RULE_ID = "ci-github-actions-untrusted-expression-command";
const KEEP = process.argv.includes("--keep");

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function run(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${command} ${args.join(" ")} exited ${code}: ${stderr.trim()}`));
    });
  });
}

class McpSession {
  constructor(cwd) {
    this.child = spawn("npx", ["-y", PACKAGE], {
      cwd,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.buffer = "";
    this.stderr = "";
    this.pending = new Map();
    this.nextId = 1;
    this.child.stdout.on("data", (chunk) => this.onData(chunk.toString()));
    this.child.stderr.on("data", (chunk) => (this.stderr += chunk.toString()));
    this.child.on("error", (error) => this.rejectAll(error));
    this.child.on("close", (code) => {
      if (code !== 0 && this.pending.size > 0) {
        this.rejectAll(new Error(`CodeInspectus exited ${code}: ${this.stderr.trim()}`));
      }
    });
  }

  onData(chunk) {
    this.buffer += chunk;
    let newline;
    while ((newline = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        this.rejectAll(new Error(`CodeInspectus stdout was not JSON-RPC: ${line}`));
        continue;
      }
      if (message.id !== undefined && this.pending.has(message.id)) {
        const pending = this.pending.get(message.id);
        this.pending.delete(message.id);
        clearTimeout(pending.timer);
        pending.resolve(message);
      }
    }
  }

  rejectAll(error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }

  send(method, params, id) {
    this.child.stdin.write(
      `${JSON.stringify({ jsonrpc: "2.0", ...(id === undefined ? {} : { id }), method, params })}\n`,
    );
  }

  request(method, params, timeoutMs = 180_000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for ${method}`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.send(method, params, id);
    });
  }

  async initialize() {
    const response = await this.request("initialize", {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "codeinspectus-v1.5-case-study", version: "1.0.0" },
    });
    if (response.error) throw new Error(`initialize failed: ${JSON.stringify(response.error)}`);
    this.send("notifications/initialized", {});
    return response.result;
  }

  async callTool(name, args) {
    const response = await this.request("tools/call", { name, arguments: args });
    if (response.error) throw new Error(`${name} failed: ${JSON.stringify(response.error)}`);
    if (response.result?.isError) {
      throw new Error(`${name} returned an error: ${JSON.stringify(response.result.content)}`);
    }
    assert(response.result?.structuredContent, `${name} returned no structuredContent`);
    return response.result.structuredContent;
  }

  close() {
    this.child.kill();
  }
}

const canonicalTemp = await realpath(tmpdir());
const workspace = await mkdtemp(join(canonicalTemp, "codeinspectus-v1.5-case-study-"));
const target = join(workspace, "rich");
let client;

try {
  console.error(`Cloning ${REPOSITORY} at ${COMMIT}...`);
  await run("git", ["clone", "--quiet", "--no-checkout", REPOSITORY, target]);
  await run("git", ["checkout", "--quiet", COMMIT], { cwd: target });
  const checkedOut = (await run("git", ["rev-parse", "HEAD"], { cwd: target })).stdout.trim();
  assert(checkedOut === COMMIT, `Expected commit ${COMMIT}, got ${checkedOut}`);

  client = new McpSession(workspace);
  const initialized = await client.initialize();
  assert(
    initialized.serverInfo?.version === "1.5.0",
    `Expected published CodeInspectus 1.5.0, got ${initialized.serverInfo?.version ?? "unknown"}`,
  );

  console.error("Scanning the pinned repository with the published npm package...");
  const baseline = await client.callTool("codeinspectus_scan", {
    path: target,
    scanners: ["ai"],
  });
  const targetFindings = baseline.findings.filter((finding) => finding.rule_id === RULE_ID);
  assert(targetFindings.length === 1, `Expected exactly one ${RULE_ID} finding, got ${targetFindings.length}`);
  const finding = targetFindings[0];
  assert(finding.location.file === WORKFLOW, `Expected ${WORKFLOW}, got ${finding.location.file}`);
  const githubActionsPack = baseline.pack_coverage.find((pack) => pack.pack_id === "github-actions");
  assert(githubActionsPack?.state === "ran", "GitHub Actions pack did not report state=ran");
  assert(
    githubActionsPack.analyzers?.ran === 1 && githubActionsPack.rules?.ran === 2,
    "GitHub Actions pack did not report 1/1 analyzers and 2/2 rules",
  );

  const workflowPath = join(target, WORKFLOW);
  const vulnerable = [
    "      - name: Run Suggest",
    "        run: faqtory suggest \"${{ github.event.issue.title }}\" > suggest.md",
  ].join("\n");
  const fixed = [
    "      - name: Run Suggest",
    "        env:",
    "          ISSUE_TITLE: ${{ github.event.issue.title }}",
    "        run: faqtory suggest \"$ISSUE_TITLE\" > suggest.md",
  ].join("\n");
  const before = await readFile(workflowPath, "utf8");
  assert(before.includes(vulnerable), `Pinned workflow no longer contains the expected vulnerable block`);
  assert(before.indexOf(vulnerable) === before.lastIndexOf(vulnerable), "Expected vulnerable block more than once");
  await writeFile(workflowPath, before.replace(vulnerable, fixed));
  await run("git", ["diff", "--check"], { cwd: target });
  const patch = (await run("git", ["diff", "--", WORKFLOW], { cwd: target })).stdout.trim();

  console.error("Rescanning the same path with the original scan ID...");
  const rescan = await client.callTool("codeinspectus_rescan", {
    path: target,
    prior_scan_id: baseline.scan_id,
    scanners: ["ai"],
  });
  const resolved = rescan.resolved.filter((item) => item.rule_id === RULE_ID);
  const stillPresent = [...rescan.remaining, ...rescan.introduced, ...rescan.not_rechecked].filter(
    (item) => item.rule_id === RULE_ID,
  );
  assert(resolved.length === 1, `Expected one resolved ${RULE_ID} finding, got ${resolved.length}`);
  assert(stillPresent.length === 0, `${RULE_ID} remained in a non-resolved bucket`);
  assert(rescan.partial === false, "Rescan was partial");

  console.log(
    JSON.stringify(
      {
        package: PACKAGE,
        server_version: initialized.serverInfo.version,
        repository: REPOSITORY,
        commit: COMMIT,
        scanner_scope: ["ai"],
        baseline: {
          scan_id: baseline.scan_id,
          total_findings: baseline.summary.total,
          target_finding: {
            rule_id: finding.rule_id,
            severity: finding.severity,
            confidence: finding.confidence,
            cwe: finding.cwe,
            owasp_web: finding.owasp_web,
            location: finding.location,
          },
          github_actions_pack: {
            state: githubActionsPack.state,
            analyzers: githubActionsPack.analyzers,
            rules: githubActionsPack.rules,
          },
        },
        fix_patch: patch,
        rescan: {
          scan_id: rescan.scan_id,
          summary: rescan.summary,
          partial: rescan.partial,
          resolved_rule_ids: rescan.resolved.map((item) => item.rule_id),
        },
      },
      null,
      2,
    ),
  );
} finally {
  client?.close();
  if (KEEP) console.error(`Kept case-study workspace: ${workspace}`);
  else await rm(workspace, { recursive: true, force: true });
}
