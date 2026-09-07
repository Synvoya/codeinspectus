#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repository = process.cwd();
const consumer = mkdtempSync(join(tmpdir(), "codeinspectus-sdk-consumer-"));
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const sourceVersion = JSON.parse(readFileSync(join(repository, "package.json"), "utf8")).version;

try {
  const packed = JSON.parse(execFileSync(npmCommand, ["pack", "--json", "--pack-destination", consumer], {
    cwd: repository, encoding: "utf8",
  }));
  if (!Array.isArray(packed) || typeof packed[0]?.filename !== "string") throw new Error("npm pack did not return a tarball filename.");
  const tarball = join(consumer, packed[0].filename);
  writeFileSync(join(consumer, "package.json"), `${JSON.stringify({ name: "codeinspectus-sdk-independent-consumer", private: true, type: "module" }, null, 2)}\n`);
  execFileSync(npmCommand, ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], { cwd: consumer, stdio: "pipe" });
  if (existsSync(join(consumer, "node_modules/@contentauth/c2pa-node"))) {
    throw new Error("normal package installation unexpectedly installed the optional C2PA peer");
  }

  writeFileSync(join(consumer, "consumer.mjs"), `
    import { CodeInspectusClient, SDK_API_VERSION, SDK_COMPATIBILITY } from "codeinspectus/sdk";
    const client = new CodeInspectusClient();
    const result = await client.run(["--version"]);
    if (result.exitCode !== 0 || result.stdout.trim() !== ${JSON.stringify(sourceVersion)}) throw new Error("installed CLI invocation failed");
    if (SDK_API_VERSION !== ${JSON.stringify(sourceVersion)} || SDK_COMPATIBILITY.export_schema !== "3.0.0" || SDK_COMPATIBILITY.repository_trust_schema !== "1.0.0") throw new Error("SDK compatibility metadata mismatch");
    process.stdout.write(JSON.stringify({ sdk: SDK_API_VERSION, cli: result.stdout.trim(), exit: result.exitCode }));
  `);
  const runtime = execFileSync(process.execPath, [join(consumer, "consumer.mjs")], { cwd: consumer, encoding: "utf8" });
  const proof = JSON.parse(runtime);

  writeFileSync(join(consumer, "consumer.ts"), `
    import {
      CodeInspectusClient, type AggregateCoverageV2, type BaselineComparisonV1,
      type BundleManifestV1, type BulkManifestV1, type RepositoryHistoryManifestV1, type IssuePayloadV1, type FindingV2, type HistoryComparisonV1,
      type HistoryListResultV1, type JsonExportV2, type TriageAnnotationV1,
    } from "codeinspectus/sdk";
    const client = new CodeInspectusClient();
    const operation: Promise<{ data: JsonExportV2 }> = client.scan("/tmp/repository");
    function consume(
      finding: FindingV2, coverage: AggregateCoverageV2, history: HistoryListResultV1,
      comparison: HistoryComparisonV1, baseline: BaselineComparisonV1,
      annotation: TriageAnnotationV1, bundle: BundleManifestV1, bulk: BulkManifestV1, repositoryHistory: RepositoryHistoryManifestV1, issue: IssuePayloadV1,
    ): string { return [finding.id, coverage, history.schema_version, comparison.schema_version, baseline.schema_version, annotation.annotation_id, bundle.bundle_id, bulk.run_id, repositoryHistory.run_id, issue.adapter].join(":"); }
    void operation; void consume;
  `);
  const tsc = resolve(repository, "node_modules/typescript/bin/tsc");
  execFileSync(process.execPath, [tsc, "--noEmit", "--strict", "--target", "ES2022", "--module", "NodeNext", "--moduleResolution", "NodeNext", "--esModuleInterop", "--skipLibCheck", "false", "consumer.ts"], {
    cwd: consumer, stdio: "pipe",
  });

  const installedPackage = JSON.parse(readFileSync(join(consumer, "node_modules/codeinspectus/package.json"), "utf8"));
  if (installedPackage.exports?.["./sdk"]?.types !== "./dist/sdk/index.d.ts") throw new Error("Installed package is missing the SDK type export.");
  console.log(`SDK CONSUMER E2E PASSED: ${JSON.stringify({ ...proof, node: process.version, package: installedPackage.version })}`);
} finally {
  rmSync(consumer, { recursive: true, force: true });
}
