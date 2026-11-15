import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { dedupFindings } from "./dedup.js";
import { markDeclaredMinimums, requirementSpecifier } from "./declared-minimum.js";
import type { Finding } from "./types.js";

function vuln(name: string, version: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id: `fp-${name}`, fingerprint: `sha256:${name}-${version}`, title: `Advisory (${name}@${version})`, severity: "high",
    engine: "osv-scanner", engines: ["osv-scanner"], rule_id: "PYSEC-2026-1", cwe: ["CWE-1395"],
    location: { file: "requirements.txt", start_line: 1, end_line: 1 },
    message: `requirements.txt resolves PyPI package ${name}@${version}.`,
    remediation: { summary: "Upgrade.", steps: [], references: [] }, frameworks: [], confidence: "high",
    finding_kind: "vulnerability", package: { ecosystem: "PyPI", name, version },
    ...overrides,
  };
}

const lower = (text: string) => text.toLowerCase().split(/\r?\n/);

describe("requirements.txt declared minimums (4.1 M5 Ruling 9)", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(join(await realpath(tmpdir()), "ci-declared-min-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  test(">= and ~= are declared minimums; == and === are not", () => {
    const table: Array<[string, { exact: boolean; minimum: boolean } | undefined]> = [
      ["urllib3>=2.2.2", { exact: false, minimum: true }],
      ["urllib3 ~= 2.2", { exact: false, minimum: true }],
      ["urllib3==2.2.2", { exact: true, minimum: false }],
      ["urllib3===2.2.2", { exact: true, minimum: false }],
      ["urllib3>2.2.2", { exact: false, minimum: false }],
      ["urllib3<3", { exact: false, minimum: false }],
      ["urllib3", { exact: false, minimum: false }],
      ["urllib3[socks]>=2.2.2", { exact: false, minimum: true }],
      ["requests==2.31.0", undefined],
      ["# urllib3>=2.2.2", undefined],
      ["urllib3-extra>=1", undefined],
    ];
    for (const [line, expected] of table) {
      const result = requirementSpecifier(lower(line), "urllib3");
      expect(result === undefined ? undefined : { exact: result.exact, minimum: result.minimum }, line).toEqual(expected);
    }
    // Several lines for one name: exact if any is exact.
    expect(requirementSpecifier(lower("urllib3>=2.2.2\nurllib3==2.2.3"), "urllib3")).toMatchObject({ exact: true, minimum: true });
  });

  test("a >= with an upper bound is still a minimum", () => {
    expect(requirementSpecifier(lower("urllib3>=2.2.2,<3"), "urllib3")).toMatchObject({ exact: false, minimum: true, specifier: ">=2.2.2,<3" });
  });

  test("markers and comments are ignored", () => {
    expect(requirementSpecifier(lower('urllib3>=2.2.2 ; python_version >= "3.8"  # pinned'), "urllib3"))
      .toMatchObject({ exact: false, minimum: true, specifier: ">=2.2.2" });
    // A marker that mentions == does not make the requirement exact.
    expect(requirementSpecifier(lower('urllib3>=2.2.2; sys_platform == "linux"'), "urllib3")).toMatchObject({ exact: false, minimum: true });
    expect(requirementSpecifier(lower("urllib3>=2.2.2 # was ==2.0"), "urllib3")).toMatchObject({ exact: false, minimum: true });
  });

  test("normalized names match", () => {
    expect(requirementSpecifier(lower("Typing_Extensions>=4"), "typing-extensions")).toMatchObject({ minimum: true });
    expect(requirementSpecifier(lower("typing.extensions>=4"), "Typing_Extensions")).toMatchObject({ minimum: true });
  });

  test("title, message and confidence; severity and fingerprint unchanged", async () => {
    await writeFile(join(root, "requirements.txt"), "urllib3>=2.2.2\nrequests==2.31.0\nsetuptools~=78.1\n");
    const findings = [vuln("urllib3", "2.2.2"), vuln("requests", "2.31.0"), vuln("setuptools", "78.1", { title: "Advisory", severity: "critical" })];
    const { findings: marked, marked: count } = await markDeclaredMinimums(findings, root);
    expect(count).toBe(2);
    expect(marked[0]).toMatchObject({
      title: "Advisory (urllib3@2.2.2, declared minimum)",
      confidence: "low",
      severity: "high",
      fingerprint: "sha256:urllib3-2.2.2",
      message: "requirements.txt resolves PyPI package urllib3@2.2.2.\nrequirements.txt declares urllib3>=2.2.2, so 2.2.2 is the lowest " +
        "version it allows, not necessarily the one installed. Pin an exact version or scan a lockfile to confirm.",
    });
    expect(marked[1]).toBe(findings[1]);
    expect(marked[2]).toMatchObject({ title: "Advisory (declared minimum)", confidence: "low", severity: "critical" });
    expect(marked[2]!.message).toContain("requirements.txt declares setuptools~=78.1, so 78.1 is the lowest version it allows");
    expect(findings[0]!.confidence).toBe("high");
  });

  test("the dev tag and the declared-minimum tag combine", async () => {
    await writeFile(join(root, "requirements-dev.txt"), "urllib3>=2.2.2\n");
    const finding = vuln("urllib3", "2.2.2", { title: "Advisory (urllib3@2.2.2, dev dependency)", location: { file: "requirements-dev.txt", start_line: 1, end_line: 1 } });
    const [marked] = (await markDeclaredMinimums([finding], root)).findings;
    expect(marked!.title).toBe("Advisory (urllib3@2.2.2, dev dependency, declared minimum)");
  });

  test("only requirements*.txt files", async () => {
    await writeFile(join(root, "poetry.lock"), '[[package]]\nname = "urllib3"\nversion = "2.2.2"\n');
    await writeFile(join(root, "constraints.txt"), "urllib3>=2.2.2\n");
    await mkdir(join(root, "docs"));
    await writeFile(join(root, "docs", "requirements.txt"), "urllib3>=2.2.2\n");
    const poetry = vuln("urllib3", "2.2.2", { location: { file: "poetry.lock", start_line: 2, end_line: 2 } });
    const constraints = vuln("urllib3", "2.2.2", { location: { file: "constraints.txt", start_line: 1, end_line: 1 } });
    const nested = vuln("urllib3", "2.2.2", { location: { file: "docs/requirements.txt", start_line: 1, end_line: 1 } });
    const licence: Finding = { ...vuln("urllib3", "2.2.2"), finding_kind: "license" };
    const { findings, marked } = await markDeclaredMinimums([poetry, constraints, nested, licence], root);
    expect(marked).toBe(1);
    expect(findings[0]).toBe(poetry);
    expect(findings[1]).toBe(constraints);
    expect(findings[2]!.confidence).toBe("low");
    expect(findings[3]).toBe(licence);
  });

  test("never reads outside the target", async () => {
    const inside = join(root, "inside");
    await mkdir(inside);
    await writeFile(join(root, "requirements.txt"), "urllib3>=2.2.2\n");
    const escaped = vuln("urllib3", "2.2.2", { location: { file: "../requirements.txt", start_line: 1, end_line: 1 } });
    const { marked } = await markDeclaredMinimums([escaped], inside);
    expect(marked).toBe(0);
  });

  test("runs after dedup (confidence is not seen by preferred())", async () => {
    await writeFile(join(root, "requirements.txt"), "urllib3>=2.2.2\n");
    // Equal severity: osv-scanner (high confidence) survives the 4.0 merge over Trivy (medium confidence).
    const osv = vuln("urllib3", "2.2.2", { fingerprint: "sha256:b-osv", rule_id: "GHSA-aaaa-bbbb-cccc", vulnerability_aliases: ["CVE-2026-1"] });
    const trivy = vuln("urllib3", "2.2.2", { fingerprint: "sha256:c-trivy", engine: "trivy", engines: ["trivy"], rule_id: "CVE-2026-1", confidence: "medium" });
    const [survivor] = (await markDeclaredMinimums(dedupFindings([osv, trivy]).findings, root)).findings;
    expect(survivor!.fingerprint).toBe("sha256:b-osv");
    expect(survivor!.confidence).toBe("low");
    // Marking first would demote osv-scanner's confidence below Trivy's and flip the survivor.
    const [flipped] = dedupFindings((await markDeclaredMinimums([osv, { ...trivy, location: { ...trivy.location, file: "x.txt" } }], root)).findings
      .map((finding) => ({ ...finding, location: { ...finding.location, file: "requirements.txt" } }))).findings;
    expect(flipped!.fingerprint).toBe("sha256:c-trivy");
  });

  test("the fixture requirements file reads as written", async () => {
    const fixture = resolve("fixtures/output-quality/python");
    const { findings } = await markDeclaredMinimums([vuln("urllib3", "2.2.2"), vuln("requests", "2.31.0"), vuln("setuptools", "78.1")], fixture);
    expect(findings.map((finding) => finding.confidence)).toEqual(["low", "high", "low"]);
  });
});
