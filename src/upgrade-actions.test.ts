import { describe, expect, test } from "vitest";

import { dependencyRemediation, remediationForCwe } from "./remediation.js";
import type { Finding, Severity } from "./types.js";
import { fixedVersionsFromRemediation, upgradeActions } from "./upgrade-actions.js";

const base = remediationForCwe(["CWE-1395"]);

function vuln(name: string, version: string, severity: Severity, summary: string, over: Partial<Finding> = {}): Finding {
  return {
    id: `CI-${name}-${summary.length}`,
    fingerprint: `fp-${name}-${version}-${summary}`,
    title: `advisory (${name}@${version})`,
    severity,
    engine: "trivy",
    engines: ["trivy"],
    rule_id: "GHSA-test",
    cwe: ["CWE-1395"],
    location: { file: "package-lock.json", start_line: 1, end_line: 1, snippet: "" },
    message: "m",
    remediation: { ...base, summary },
    frameworks: [],
    confidence: "high",
    finding_kind: "vulnerability",
    package: { ecosystem: "npm", name, version },
    ...over,
  };
}

const trivy = (name: string, installed: string, fixed: string[]) => dependencyRemediation(name, installed, fixed, base).summary;

describe("fixedVersionsFromRemediation", () => {
  test("reads every wording this codebase writes", () => {
    expect(fixedVersionsFromRemediation(trivy("next", "16.3.3", ["16.4.1"]))).toEqual(["16.4.1"]);
    expect(fixedVersionsFromRemediation(trivy("next", "16.3.3", ["15.5.28", "16.4.1"]))).toEqual(["15.5.28", "16.4.1"]);
    expect(fixedVersionsFromRemediation(trivy("x", "1.0.0", []))).toEqual([]);
    expect(fixedVersionsFromRemediation("Upgrade zod to 4.6.6, the fixed release listed upstream, or remove the package.")).toEqual(["4.6.6"]);
    expect(fixedVersionsFromRemediation(
      "Upgrade undici to a fixed release listed upstream (6.24.0, 7.30.1; choose the one on your release line), or remove the package.",
    )).toEqual(["6.24.0", "7.30.1"]);
    expect(fixedVersionsFromRemediation("Upgrade x to a version not listed as affected, or remove the package.")).toEqual([]);
    expect(fixedVersionsFromRemediation("Review the flagged code.")).toEqual([]);
    // Fix round 1: Synvoya package and GitHub Actions wordings.
    expect(fixedVersionsFromRemediation("Upgrade minio to RELEASE.2025-10-15T17-29-55Z or later, or remove the package.")).toEqual(["RELEASE.2025-10-15T17-29-55Z"]);
    expect(fixedVersionsFromRemediation("Upgrade lodash to 4.17.21 or 5.0.1 or later, or remove the package.")).toEqual(["4.17.21", "5.0.1"]);
    expect(fixedVersionsFromRemediation("Update tj-actions/changed-files to 46.0.1 or later, pinned by its full commit SHA.")).toEqual(["46.0.1"]);
    expect(fixedVersionsFromRemediation("Upgrade x to 2.0.0 or later, or remove the package, then rebuild and redeploy.")).toEqual(["2.0.0"]);
  });
});

describe("upgradeActions", () => {
  test("one action per locked package: the lowest version fixing every advisory on the current line", () => {
    const actions = upgradeActions([
      vuln("next", "16.3.3", "critical", trivy("next", "16.3.3", ["16.4.1"])),
      vuln("next", "16.3.3", "high", trivy("next", "16.3.3", ["15.5.28", "16.3.4"])),
      vuln("next", "16.3.3", "medium", "Upgrade next to 16.3.5, the fixed release listed upstream, or remove the package."),
      vuln("dompurify", "3.4.16", "critical", trivy("dompurify", "3.4.16", ["3.4.17"])),
      vuln("nodemailer", "8.0.7", "high", trivy("nodemailer", "8.0.7", ["8.0.9"]), { location: { file: "a/package-lock.json", start_line: 1, end_line: 1, snippet: "" } }),
      vuln("nodemailer", "10.0.9", "medium", trivy("nodemailer", "10.0.9", ["10.1.4"])),
      vuln("left-pad", "1.0.0", "low", trivy("left-pad", "1.0.0", []), { dependency_scope: "dev" }),
    ]);
    expect(actions).toEqual([
      { ecosystem: "npm", name: "next", version: "16.3.3", upgrade_to: "16.4.1", resolves: 3, unresolved: 0, highest_severity: "critical", dev_only: false },
      { ecosystem: "npm", name: "dompurify", version: "3.4.16", upgrade_to: "3.4.17", resolves: 1, unresolved: 0, highest_severity: "critical", dev_only: false },
      { ecosystem: "npm", name: "nodemailer", version: "8.0.7", upgrade_to: "8.0.9", resolves: 1, unresolved: 0, highest_severity: "high", dev_only: false },
      { ecosystem: "npm", name: "nodemailer", version: "10.0.9", upgrade_to: "10.1.4", resolves: 1, unresolved: 0, highest_severity: "medium", dev_only: false },
      { ecosystem: "npm", name: "left-pad", version: "1.0.0", resolves: 0, unresolved: 1, highest_severity: "low", dev_only: true },
    ]);
  });

  test("a fix only on a newer major is used when the current line has none; versions at or below current are ignored", () => {
    const [action] = upgradeActions([
      vuln("undici", "7.25.0", "high", trivy("undici", "7.25.0", ["6.24.0", "8.0.1"])),
      vuln("undici", "7.25.0", "low", trivy("undici", "7.25.0", ["7.20.0"])),
    ]);
    expect(action).toMatchObject({ upgrade_to: "8.0.1", resolves: 1, unresolved: 1 });
  });

  // Fix round 1 (review item 8): an advisory counts as resolved only if the target is at least its fix on the
  // target's own release line; structured fixed versions win over the summary text.
  test("cross-major: an advisory fixed only on the old line is not counted as resolved by a new-major target", () => {
    const [action] = upgradeActions([
      vuln("undici", "7.25.0", "high", trivy("undici", "7.25.0", ["8.0.1"])),
      vuln("undici", "7.25.0", "medium", trivy("undici", "7.25.0", ["7.26.0"])),
      vuln("undici", "7.25.0", "low", trivy("undici", "7.25.0", ["7.26.0", "8.0.0"])),
    ]);
    expect(action).toMatchObject({ upgrade_to: "8.0.1", resolves: 2, unresolved: 1 });
  });

  test("structured fixed_versions are used when the engine reported them", () => {
    const [action] = upgradeActions([
      vuln("next", "16.3.3", "high", "Upgrade next to a version not listed as affected, or remove the package.", { fixed_versions: ["15.5.28", "16.4.1"] }),
    ]);
    expect(action).toMatchObject({ upgrade_to: "16.4.1", resolves: 1, unresolved: 0 });
  });

  test("Synvoya and Actions wordings group into upgrades", () => {
    const actions = upgradeActions([
      vuln("lodash", "4.17.15", "high", "Upgrade lodash to 4.17.21 or later, or remove the package.", { engine: "synvoya", engines: ["synvoya"] }),
      vuln("tj-actions/changed-files", "45.0.0", "critical", "Update tj-actions/changed-files to 46.0.1 or later, pinned by its full commit SHA.", {
        engine: "synvoya", engines: ["synvoya"], package: { ecosystem: "GitHub Actions", name: "tj-actions/changed-files", version: "45.0.0" },
      }),
    ]);
    expect(actions.map((action) => [action.name, action.upgrade_to, action.resolves])).toEqual([
      ["tj-actions/changed-files", "46.0.1", 1],
      ["lodash", "4.17.21", 1],
    ]);
  });

  // Fix round 2 (item 4): GitHub Actions refs compare as semver with `v` stripped on both sides.
  test.each(["v45", "v45.0.0"])("GitHub Actions ref %s upgrades to the listed fix", (ref) => {
    const [action] = upgradeActions([
      vuln("tj-actions/changed-files", ref, "critical", "Update tj-actions/changed-files to v46.0.1 or later, pinned by its full commit SHA.", {
        engine: "synvoya", engines: ["synvoya"], package: { ecosystem: "GitHub Actions", name: "tj-actions/changed-files", version: ref },
        fixed_versions: ["v46.0.1"],
      }),
    ]);
    expect(action).toMatchObject({ upgrade_to: "v46.0.1", resolves: 1, unresolved: 0 });
  });

  test("an advisory fixed only on another line is reported with that line", () => {
    const [action] = upgradeActions([
      vuln("undici", "7.25.0", "high", trivy("undici", "7.25.0", ["8.0.1"])),
      vuln("undici", "7.25.0", "medium", trivy("undici", "7.25.0", ["7.26.0"])),
    ]);
    expect(action).toMatchObject({ upgrade_to: "8.0.1", resolves: 1, unresolved: 1, unresolved_fix_lines: ["7.x"] });
  });

  // Fix round 3 (item 4): the target is raised to the highest fix any advisory needs on the chosen line.
  test("target raised to the highest fix needed on its line; that line is not listed as unresolved", () => {
    const [action] = upgradeActions([
      vuln("lib", "16.0.0", "high", trivy("lib", "16.0.0", ["16.4.1", "17.0.3"])),
      vuln("lib", "16.0.0", "medium", trivy("lib", "16.0.0", ["17.0.0"])),
    ]);
    expect(action).toMatchObject({ upgrade_to: "17.0.3", resolves: 2, unresolved: 0 });
    expect(action?.unresolved_fix_lines).toBeUndefined();
  });

  test("an Action pinned by commit SHA carries the fixed version for a manual comparison", () => {
    const sha = "8e5e7e5ab8b370d6c329ec480221332ada57f0ab";
    const [action] = upgradeActions([
      vuln("tj-actions/changed-files", sha, "critical", "Update tj-actions/changed-files to 46.0.1 or later, pinned by its full commit SHA.", {
        engine: "synvoya", engines: ["synvoya"], package: { ecosystem: "GitHub Actions", name: "tj-actions/changed-files", version: sha },
        fixed_versions: ["46.0.1"],
      }),
    ]);
    expect(action).toMatchObject({ version: sha, upgrade_to: "46.0.1", resolves: 0, unresolved: 1 });
  });

  test("code findings, secrets and findings without a package are not upgrade actions", () => {
    expect(upgradeActions([
      vuln("x", "1.0.0", "high", trivy("x", "1.0.0", ["1.0.1"]), { finding_kind: "sast" }),
      vuln("y", "1.0.0", "high", trivy("y", "1.0.0", ["1.0.1"]), { package: undefined }),
    ])).toEqual([]);
  });
});
