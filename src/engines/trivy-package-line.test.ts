import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { dedupFindings } from "../dedup.js";
import { normalizeSarif } from "../sarif/normalize.js";
import type { SarifLog } from "../sarif/types.js";
import type { Finding } from "../types.js";
import { relocateTrivyPackageFindings } from "./trivy-package-line.js";

const PNPM_FIXTURE = resolve("fixtures/output-quality/pnpm");

function vulnerability(uri: string, name: string, version: string, rule = "CVE-2026-106445", line = 1) {
  return {
    ruleId: rule, ruleIndex: 0, level: "error",
    message: { text: `Package: ${name}\nInstalled Version: ${version}\nVulnerability ${rule}\nSeverity: HIGH\nFixed Version: 9.9.9\nLink: [${rule}](https://example.invalid)` },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: line, endLine: line } } }],
  };
}

function trivy(results: unknown[], extraRules: unknown[] = []): Finding[] {
  const log = {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "Trivy", rules: [
        { id: "CVE-2026-106445", name: "LanguageSpecificPackageVulnerability", properties: { tags: ["vulnerability", "security", "HIGH"] } },
        ...extraRules,
      ] } },
      results,
    }],
  } as SarifLog;
  return normalizeSarif(log, "trivy", "/repo");
}

describe("Trivy lockfile findings at the package entry", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(await realpath(tmpdir()), "ci-trivy-line-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  test("moves a pnpm finding to the package entry and keeps its fingerprint", async () => {
    const [finding] = trivy([vulnerability("pnpm-lock.yaml", "handlebars", "4.7.9")]);
    const fingerprint = finding!.fingerprint;
    const { findings, relocated } = await relocateTrivyPackageFindings([finding!], PNPM_FIXTURE);
    expect(relocated).toBe(1);
    // `  handlebars@4.7.9:` under `packages:` (line 21 of the hand-written lockfile).
    expect(findings[0]!.location.start_line).toBe(21);
    expect(findings[0]!.location.end_line).toBe(21);
    expect(findings[0]!.fingerprint).toBe(fingerprint);
    expect(findings[0]!.id).toBe(finding!.id);
    expect(finding!.location.start_line).toBe(1);
  });

  test("a relocated finding drops its line-1 snippet; one left at line 1 keeps it (M5 fix 7)", async () => {
    const [finding] = trivy([vulnerability("pnpm-lock.yaml", "handlebars", "4.7.9")]);
    const withSnippet: Finding = { ...finding!, location: { ...finding!.location, snippet: "lockfileVersion: '9.0'" } };
    const [moved] = (await relocateTrivyPackageFindings([withSnippet], PNPM_FIXTURE)).findings;
    expect(moved!.location.start_line).toBe(21);
    expect("snippet" in moved!.location).toBe(false);
    const [kept] = (await relocateTrivyPackageFindings([{ ...withSnippet, package: { ...withSnippet.package!, name: "absent" } }], PNPM_FIXTURE)).findings;
    expect(kept!.location.snippet).toBe("lockfileVersion: '9.0'");
  });

  test("picks the entry that resolves the installed version", async () => {
    await writeFile(join(root, "pnpm-lock.yaml"), [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  tar@6.2.1:",
      "    resolution: {integrity: sha512-A}",
      "",
      "  tar@7.5.2:",
      "    resolution: {integrity: sha512-B}",
      "",
    ].join("\n"));
    const findings = trivy([vulnerability("pnpm-lock.yaml", "tar", "7.5.2"), vulnerability("pnpm-lock.yaml", "tar", "6.2.1")]);
    const { findings: moved } = await relocateTrivyPackageFindings(findings, root);
    expect(moved.map((finding) => finding.location.start_line)).toEqual([8, 5]);
  });

  test("leaves Trivy lines other than 1 alone", async () => {
    await writeFile(join(root, "package-lock.json"), '{\n  "packages": {\n    "node_modules/handlebars": {\n      "version": "4.7.9"\n    }\n  }\n}\n');
    const findings = trivy([vulnerability("package-lock.json", "handlebars", "4.7.9", "CVE-2026-106445", 5)]);
    const { findings: kept, relocated } = await relocateTrivyPackageFindings(findings, root);
    expect(relocated).toBe(0);
    expect(kept[0]).toBe(findings[0]);
  });

  test("leaves the finding at line 1 when no entry is found", async () => {
    await writeFile(join(root, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n\npackages:\n\n  other@1.0.0:\n    resolution: {integrity: sha512-A}\n");
    const findings = trivy([vulnerability("pnpm-lock.yaml", "handlebars", "4.7.9")]);
    const { findings: kept, relocated } = await relocateTrivyPackageFindings(findings, root);
    expect(relocated).toBe(0);
    expect(kept[0]!.location.start_line).toBe(1);
  });

  test("leaves the finding at line 1 when the lockfile is a symlink", async () => {
    await mkdir(join(root, "real"));
    await writeFile(join(root, "real", "lock.yaml"), "packages:\n\n  handlebars@4.7.9:\n    resolution: {}\n");
    await symlink(join(root, "real", "lock.yaml"), join(root, "pnpm-lock.yaml"));
    const findings = trivy([vulnerability("pnpm-lock.yaml", "handlebars", "4.7.9")]);
    const { findings: kept, relocated } = await relocateTrivyPackageFindings(findings, root);
    expect(relocated).toBe(0);
    expect(kept[0]!.location.start_line).toBe(1);
  });

  test("leaves the finding at line 1 when the path escapes the target", async () => {
    const inside = join(root, "inside");
    await mkdir(inside);
    await writeFile(join(root, "pnpm-lock.yaml"), "packages:\n\n  handlebars@4.7.9:\n    resolution: {}\n");
    await mkdir(join(root, "outside"));
    await writeFile(join(root, "outside", "pnpm-lock.yaml"), "packages:\n\n  handlebars@4.7.9:\n    resolution: {}\n");
    await symlink(join(root, "outside"), join(inside, "linked"));
    const findings = [
      ...trivy([vulnerability("../pnpm-lock.yaml", "handlebars", "4.7.9")]),
      ...trivy([vulnerability(join(root, "pnpm-lock.yaml"), "handlebars", "4.7.9")]),
      ...trivy([vulnerability("a//pnpm-lock.yaml", "handlebars", "4.7.9")]),
      ...trivy([vulnerability("./pnpm-lock.yaml", "handlebars", "4.7.9")]),
      // A directory symlink that leads out of the target.
      ...trivy([vulnerability("linked/pnpm-lock.yaml", "handlebars", "4.7.9")]),
    ];
    const { findings: kept, relocated } = await relocateTrivyPackageFindings(findings, inside);
    expect(relocated).toBe(0);
    expect(kept.map((finding) => finding.location.start_line)).toEqual([1, 1, 1, 1, 1]);
  });

  test("relocates go.mod and uv.lock findings", async () => {
    await writeFile(join(root, "go.mod"), "module example.test/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.33.0\n)\n");
    await writeFile(join(root, "uv.lock"), 'version = 1\n\n[[package]]\nname = "urllib3"\nversion = "2.2.2"\n');
    const findings = trivy([vulnerability("go.mod", "golang.org/x/net", "v0.33.0"), vulnerability("uv.lock", "urllib3", "2.2.2")]);
    const { findings: moved, relocated } = await relocateTrivyPackageFindings(findings, root);
    expect(relocated).toBe(2);
    expect(moved.map((finding) => finding.location.start_line)).toEqual([6, 4]);
    expect(moved.map((finding) => finding.fingerprint)).toEqual(findings.map((finding) => finding.fingerprint));
  });

  test("relocates when the target is the lockfile itself", async () => {
    const [finding] = trivy([vulnerability("pnpm-lock.yaml", "handlebars", "4.7.9")]);
    const { findings, relocated } = await relocateTrivyPackageFindings([finding!], join(PNPM_FIXTURE, "pnpm-lock.yaml"));
    expect(relocated).toBe(1);
    expect(findings[0]!.location.start_line).toBe(21);
  });

  test("does not touch licence or misconfiguration findings", async () => {
    const findings = trivy([
      {
        ruleId: "handlebars:MIT", ruleIndex: 1, level: "note",
        message: { text: "Artifact: pnpm-lock.yaml\nLicense MIT\nPkgName: handlebars\n Classification: notice\n Path: pnpm-lock.yaml" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "pnpm-lock.yaml" }, region: { startLine: 1, endLine: 1 } } }],
      },
      {
        ruleId: "DS002", ruleIndex: 2, level: "error",
        message: { text: "Package: handlebars\nInstalled Version: 4.7.9\nmisconfiguration" },
        locations: [{ physicalLocation: { artifactLocation: { uri: "pnpm-lock.yaml" }, region: { startLine: 1, endLine: 1 } } }],
      },
    ], [
      { id: "handlebars:MIT", name: "License", properties: { tags: ["license"] } },
      { id: "DS002", name: "Misconfiguration", properties: { tags: ["misconfiguration"] } },
    ]);
    findings[1]!.package = { ecosystem: "npm", name: "handlebars", version: "4.7.9" };
    const { findings: kept, relocated } = await relocateTrivyPackageFindings(findings, PNPM_FIXTURE);
    expect(relocated).toBe(0);
    expect(kept).toEqual(findings);
  });

  test("merged Trivy and osv-scanner findings report the same line whichever survives", async () => {
    const [trivyFinding] = (await relocateTrivyPackageFindings(trivy([vulnerability("pnpm-lock.yaml", "handlebars", "4.7.9")]), PNPM_FIXTURE)).findings;
    // osv-scanner reports the GHSA with the CVE alias at the line packageEntryLine gives (osv-scanner.ts).
    const osv: Finding = {
      ...trivyFinding!,
      fingerprint: "sha256:osv",
      engine: "osv-scanner",
      engines: ["osv-scanner"],
      rule_id: "GHSA-p8wg-vrv2-v86f",
      vulnerability_aliases: ["CVE-2026-106445"],
      location: { file: "pnpm-lock.yaml", start_line: 21, end_line: 21 },
    };
    for (const severity of ["critical", "low"] as const) {
      const [merged] = dedupFindings([trivyFinding!, { ...osv, severity }]).findings;
      expect(merged!.location.start_line).toBe(21);
      expect(merged!.location.end_line).toBe(21);
    }
  });
});
