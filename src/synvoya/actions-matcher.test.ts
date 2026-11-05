import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { synvoyaActionsDatasetFindingComponents, synvoyaActionsFindingComponents } from "../provenance.js";
import { actionsFixtureRecords, zipEntries } from "./actions-osv-fixture.js";
import { datasetActionAdvisories, loadActionsDb, matchActions, parseActionsRecords, unpinnedActionsNote, withDatasetAdvisories, type ActionsDb } from "./actions-matcher.js";
import { loadSynvoyaDataset } from "./dataset.js";
import { parseUses, type ActionDeclaration } from "./readers/actions.js";
import type { SynvoyaAdvisory } from "./types.js";

const NOW = new Date("2026-11-04T12:00:00Z");
/** Records copied verbatim from the installed OSV "GitHub Actions" all.zip (GHSA, CC-BY-4.0), fetched 2026-11-04. */
const realRecords = actionsFixtureRecords;

/**
 * SYNTHETIC, not from the database: no record in it lists an affected commit (its GIT ranges only name the
 * fixing commit), so the listed-commit path is exercised with this one.
 */
const SYNTHETIC_COMMIT_RECORD = {
  id: "GHSA-test-test-test",
  summary: "Synthetic: one compromised commit",
  aliases: [],
  affected: [{
    package: { ecosystem: "GitHub Actions", name: "example/compromised-action" },
    ranges: [{ type: "GIT", repo: "https://github.com/example/compromised-action", events: [{ introduced: "1111111111111111111111111111111111111111" }, { fixed: "2222222222222222222222222222222222222222" }] }],
    versions: ["3333333333333333333333333333333333333333"],
  }],
  database_specific: { severity: "CRITICAL", cwe_ids: ["CWE-506"] },
};

function decl(uses: string, file = ".github/workflows/ci.yml", line = 10): ActionDeclaration {
  const action = parseUses(uses)!;
  const semver = /^v?(\d+\.\d+\.\d+.*)$/.exec(action.ref)?.[1];
  const floating = /^v?(\d+(?:\.\d+)?)$/.exec(action.ref)?.[1];
  const spec = action.kind === "semver" ? semver! : action.kind === "floating" ? floating! : action.kind === "sha" ? action.ref.toLowerCase() : action.ref;
  return {
    subject: { type: "package", ecosystem: "GitHub Actions", name: action.name },
    spec,
    ...(action.kind === "semver" ? { resolved: semver! } : {}),
    precision: action.kind === "semver" ? "exact" : action.kind === "floating" ? "floating" : "unresolved",
    file,
    line,
    source: "workflow step uses",
    producer: "actions",
    action,
  };
}

let db: ActionsDb;
beforeEach(async () => {
  db = parseActionsRecords([...await realRecords(), { name: "GHSA-test-test-test.json", data: Buffer.from(JSON.stringify(SYNTHETIC_COMMIT_RECORD)) }]);
});

describe("matchActions against real GHSA records", () => {
  it("a tj-actions/changed-files tag in the affected range is a finding naming the fixed version", () => {
    const result = matchActions(db, [decl("tj-actions/changed-files@v45.0.7")], NOW);
    expect(result.findings.map((f) => [f.rule_id, f.severity, f.confidence, f.location.start_line, f.package])).toEqual([
      ["GHSA-mrrh-fwg8-r2c3", "high", "high", 10, { ecosystem: "GitHub Actions", name: "tj-actions/changed-files", version: "v45.0.7" }],
    ]);
    const [finding] = result.findings;
    expect(finding!.remediation.summary).toBe("Update tj-actions/changed-files to 46.0.1 or later, pinned by its full commit SHA.");
    expect(finding!.vulnerability_aliases).toEqual(["CVE-2025-30066"]);
    expect(finding!.cwe).toEqual(["CWE-506"]);
    expect(finding!.engine).toBe("synvoya");
    expect(finding!.producer_components).toEqual(synvoyaActionsFindingComponents());
    expect(finding!.message).toMatch(/^\.github\/workflows\/ci\.yml:10 uses tj-actions\/changed-files@v45\.0\.7 \(workflow step uses\)\. GHSA-mrrh-fwg8-r2c3 lists that release as affected\./);
    expect(finding!.remediation.references).toContain("https://osv.dev/vulnerability/GHSA-mrrh-fwg8-r2c3");
    expect(result.evaluated).toEqual(new Set([".github/workflows/ci.yml\0tj-actions/changed-files@v45.0.7"]));
    expect(result.indefinite).toEqual(new Set());
    // An older tag is affected by both changed-files advisories; the fixed release by neither.
    expect(matchActions(db, [decl("tj-actions/changed-files@v40.0.0")], NOW).findings.map((f) => f.rule_id).sort())
      .toEqual(["GHSA-mcph-m25j-8j63", "GHSA-mrrh-fwg8-r2c3"]);
    const fixed = matchActions(db, [decl("tj-actions/changed-files@v46.0.1")], NOW);
    expect(fixed.findings).toEqual([]);
    expect(fixed.notes).toEqual([]);
  });

  it("a major tag: a wholly affected major is a finding; a v4 major with a fixed release is a note only (pin to ≥ X)", () => {
    const whole = matchActions(db, [decl("tj-actions/changed-files@v35")], NOW);
    expect(whole.findings.map((f) => [f.rule_id, f.confidence])).toEqual([["GHSA-mcph-m25j-8j63", "medium"], ["GHSA-mrrh-fwg8-r2c3", "medium"]]);
    expect(whole.findings[0]!.message).toMatch(/affects every release the moving tag v35 can resolve to today/);
    const partial = matchActions(db, [decl("rlespinasse/github-slug-action@v4")], NOW);
    expect(partial.findings).toEqual([]);
    expect(partial.notes).toEqual([
      ".github/workflows/ci.yml:10: rlespinasse/github-slug-action@v4 is a moving tag that can still resolve to a release affected by GHSA-6q4m-7476-932w; pin rlespinasse/github-slug-action to ≥ 4.4.1 by its full commit SHA.",
    ]);
    // Judged (no gap), but a note is not a definite answer: a rescan cannot confirm a fix from this file.
    expect(partial.evaluated.size).toBe(1);
    expect(partial.indefinite).toEqual(new Set([".github/workflows/ci.yml"]));
  });

  it("a tag the record lists verbatim is a finding (reviewdog/action-setup@v1 was the compromised tag)", () => {
    const result = matchActions(db, [decl("reviewdog/action-setup@v1")], NOW);
    expect(result.findings.map((f) => [f.rule_id, f.confidence])).toEqual([["GHSA-qmg3-hpqr-gqvc", "high"]]);
    expect(result.findings[0]!.message).toMatch(/GHSA-qmg3-hpqr-gqvc lists v1 itself as affected/);
    expect(result.findings[0]!.remediation.summary).toBe("No fixed release of reviewdog/action-setup is listed; remove or replace the action.");
    expect(matchActions(db, [decl("reviewdog/action-setup@v2.0.0")], NOW)).toMatchObject({ findings: [], notes: [] });
  });

  it("a SHA is a finding only when a record lists that commit; the fixing commit is clean; any other commit is a note and unevaluated", () => {
    const listed = matchActions(db, [decl("example/compromised-action@1111111111111111111111111111111111111111"), decl("example/compromised-action@3333333333333333333333333333333333333333", ".github/workflows/b.yml")], NOW);
    expect(listed.findings.map((f) => [f.rule_id, f.location.file, f.severity])).toEqual([
      ["GHSA-test-test-test", ".github/workflows/b.yml", "critical"], ["GHSA-test-test-test", ".github/workflows/ci.yml", "critical"],
    ]);
    expect(listed.findings[1]!.message).toMatch(/lists that commit as affected/);
    expect(matchActions(db, [decl("example/compromised-action@2222222222222222222222222222222222222222")], NOW)).toMatchObject({ findings: [], notes: [] });

    const unknown = matchActions(db, [decl("tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67")], NOW);
    expect(unknown.findings).toEqual([]);
    expect(unknown.notes).toEqual([
      ".github/workflows/ci.yml:10: tj-actions/changed-files@0e58ed8671d6 is pinned to a commit; GHSA-mcph-m25j-8j63 has no commit list in its advisory data, so Synvoya could not tell whether that commit is affected (fixed in 41).",
      ".github/workflows/ci.yml:10: tj-actions/changed-files@0e58ed8671d6 is pinned to a commit; GHSA-mrrh-fwg8-r2c3 has no commit list in its advisory data, so Synvoya could not tell whether that commit is affected (fixed in 46.0.1).",
    ]);
    expect(unknown.evaluated).toEqual(new Set());
    expect(unknown.indefinite).toEqual(new Set([".github/workflows/ci.yml"]));
    // The pypi-publish fixing commit clears GHSA-5xjx, whose GIT range names it; nothing else lists commits.
    const fixing = matchActions(db, [decl("pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086")], NOW);
    expect(fixing).toMatchObject({ findings: [], notes: [] });
    expect(fixing.evaluated.size).toBe(1);
    const other = matchActions(db, [decl("pypa/gh-action-pypi-publish@1234567890123456789012345678901234567890")], NOW);
    expect(other.notes[0]).toMatch(/GHSA-5xjx-3w67-w9x9 lists commits, but not this one/);
  });

  it("a branch ref of an action with advisories is a note and unevaluated; any ref of an action with none is evaluated and clean", () => {
    const branch = matchActions(db, [decl("tj-actions/changed-files@main")], NOW);
    expect(branch.findings).toEqual([]);
    expect(branch.notes[0]).toMatch(/tj-actions\/changed-files@main names a branch or other moving ref, so Synvoya could not check it against GHSA-mcph-m25j-8j63/);
    expect(branch.evaluated).toEqual(new Set());
    const clean = matchActions(db, [decl("actions/checkout@main"), decl("actions/checkout@v4"), decl("actions/checkout@0123456789012345678901234567890123456789")], NOW);
    expect(clean).toMatchObject({ findings: [], notes: [] });
    expect(clean.evaluated.size).toBe(3);
    expect(clean.indefinite).toEqual(new Set());
  });

  it("matches names case-insensitively, through github.com URLs and repository sub-paths, and skips withdrawn records", () => {
    expect(matchActions(db, [decl("TJ-Actions/Changed-Files@v45.0.7")], NOW).findings).toHaveLength(1);
    // A record for owner/repo covers its sub-path actions; one for a sub-path covers only that path.
    expect(matchActions(db, [decl("github/codeql-action/init@v3.27.0")], NOW).findings.map((f) => f.rule_id)).toEqual(["GHSA-vqf5-2xx6-9wfm"]);
    expect(matchActions(db, [decl("super-linter/super-linter/slim@v7.0.0")], NOW).findings.map((f) => f.rule_id)).toEqual(["GHSA-r79c-pqj3-577x"]);
    expect(matchActions(db, [decl("pytorch/pytorch/.github/actions/filter-test-configs@main")], NOW).notes).toHaveLength(1);
    // GHSA-jj69 is withdrawn (a duplicate); its range would otherwise make 0.1.21 a finding.
    expect(matchActions(db, [decl("google-github-actions/run-gemini-cli@v0.1.21")], NOW).findings).toEqual([]);
  });

  // Review C1: GHSA-vqf5's second range is introduced-only; its last_known_affected_version_range "< 3.0.0" bounds it.
  it("bounds an introduced-only range with last_known_affected_version_range: no false finding on codeql-action v3/v4", () => {
    expect(matchActions(db, [decl("github/codeql-action/init@v4")], NOW)).toMatchObject({ findings: [], notes: [] });
    const v3 = matchActions(db, [decl("github/codeql-action/init@v3")], NOW);
    expect(v3.findings).toEqual([]);
    expect(v3.notes).toEqual([".github/workflows/ci.yml:10: github/codeql-action/init@v3 is a moving tag that can still resolve to a release affected by GHSA-vqf5-2xx6-9wfm; pin github/codeql-action/init to ≥ 3.28.3 by its full commit SHA."]);
    expect(matchActions(db, [decl("github/codeql-action/analyze@v3.29.5")], NOW)).toMatchObject({ findings: [], notes: [] });
    // Still affected inside both ranges: 2.26.11 up to 3.0.0, and 3.26.11 up to 3.28.3.
    expect(matchActions(db, [decl("github/codeql-action/init@v2.27.0")], NOW).findings.map((f) => f.rule_id)).toEqual(["GHSA-vqf5-2xx6-9wfm"]);
    expect(matchActions(db, [decl("github/codeql-action/init@v3.0.0")], NOW).findings).toEqual([]);
  });

  it("an introduced-only range with an unreadable last-known bound is unknown, never open-ended; with none it stays open", () => {
    const bound = (range: unknown) => parseActionsRecords([{ name: "GHSA-test-test-tst1.json", data: Buffer.from(JSON.stringify({
      id: "GHSA-test-test-tst1", affected: [{ package: { ecosystem: "GitHub Actions", name: "o/r" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }] }],
        ...(range === undefined ? {} : { database_specific: { last_known_affected_version_range: range } }) }],
    })) }]);
    const unknown = matchActions(bound(">= 1.0.0, < 2.0.0"), [decl("o/r@v5.0.0")], NOW);
    expect(unknown.findings).toEqual([]);
    expect(unknown.evaluated.size).toBe(0);
    expect(unknown.notes[0]).toMatch(/could not compare o\/r@v5\.0\.0 against GHSA-test-test-tst1/);
    expect(matchActions(bound("<= 1.4.0"), [decl("o/r@v1.4.0")], NOW).findings).toHaveLength(1);
    expect(matchActions(bound("<= 1.4.0"), [decl("o/r@v1.4.1")], NOW)).toMatchObject({ findings: [], notes: [] });
    // No bound at all: the advisory names no fix, so every later release is affected.
    expect(matchActions(bound(undefined), [decl("o/r@v5.0.0")], NOW).findings).toHaveLength(1);
  });

  // Review C2 (probes P1, P1b): commit-only data says nothing about tags.
  it("a record whose versions list only commits leaves tag references unevaluated and their file unchecked", () => {
    const sha = "a".repeat(40);
    for (const affected of [
      { package: { ecosystem: "GitHub Actions", name: "evil/act" }, versions: [sha, "b".repeat(40)] },
      { package: { ecosystem: "GitHub Actions", name: "evil/act" }, ranges: [{ type: "GIT", repo: "https://github.com/evil/act", events: [{ introduced: sha }, { fixed: "b".repeat(40) }] }], versions: [sha] },
    ]) {
      const commits = parseActionsRecords([{ name: "GHSA-test-test-tst2.json", data: Buffer.from(JSON.stringify({ id: "GHSA-test-test-tst2", affected: [affected] })) }]);
      const result = matchActions(commits, [decl("evil/act@v1.2.3"), decl("evil/act@v1", ".github/workflows/b.yml")], NOW);
      expect(result.findings).toEqual([]);
      expect(result.evaluated).toEqual(new Set());
      expect(result.indefinite).toEqual(new Set([".github/workflows/ci.yml", ".github/workflows/b.yml"]));
      expect(result.notes[0]).toMatch(/GHSA-test-test-tst2 names evil\/act but lists no affected releases/);
      expect(matchActions(commits, [decl(`evil/act@${sha}`)], NOW).findings).toHaveLength(1);
    }
  });

  // Review C3: a reusable workflow is not the action an owner/repo record names.
  it("a reusable workflow matches only a record naming that exact workflow path; otherwise it is an unevaluated note", () => {
    const reusable = matchActions(db, [decl("tj-actions/changed-files/.github/workflows/x.yml@v45.0.0")], NOW);
    expect(reusable.findings).toEqual([]);
    expect(reusable.evaluated).toEqual(new Set());
    expect(reusable.indefinite).toEqual(new Set([".github/workflows/ci.yml"]));
    expect(reusable.notes).toEqual([
      ".github/workflows/ci.yml:10: tj-actions/changed-files/.github/workflows/x.yml@v45.0.0 is a reusable workflow; the advisories for tj-actions/changed-files name the action, not this workflow, so Synvoya could not check it.",
    ]);
    const exact = parseActionsRecords([{ name: "GHSA-test-test-tst3.json", data: Buffer.from(JSON.stringify({
      id: "GHSA-test-test-tst3", affected: [{ package: { ecosystem: "GitHub Actions", name: "org/shared/.github/workflows/deploy.yml" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }] }],
    })) }]);
    expect(matchActions(exact, [decl("org/shared/.github/workflows/deploy.yml@v1.0.0")], NOW).findings).toHaveLength(1);
    // A workflow with no record anywhere in its repository is clean.
    expect(matchActions(exact, [decl("org/other/.github/workflows/deploy.yml@v1.0.0")], NOW).evaluated.size).toBe(1);
  });

  it("one finding per advisory, file and action: the first by line", () => {
    const result = matchActions(db, [decl("tj-actions/changed-files@v45.0.7", ".github/workflows/ci.yml", 30), decl("tj-actions/changed-files@v45.0.0", ".github/workflows/ci.yml", 12)], NOW);
    expect(result.findings.map((f) => f.location.start_line)).toEqual([12]);
    expect(new Set(result.findings.map((f) => f.fingerprint)).size).toBe(1);
  });

  it("names the third-party references that are not pinned to a full commit SHA in one hygiene note", () => {
    expect(unpinnedActionsNote([decl("actions/checkout@v4"), decl("a/b@main", "x.yml"), decl("c/d@0123456789012345678901234567890123456789")]))
      .toBe("2 third-party GitHub Actions reference(s) are not pinned to a full commit SHA, so the code they run can change without a change here (tag poisoning): .github/workflows/ci.yml:10 actions/checkout@v4, x.yml:10 a/b@main. Pin each to a 40-character commit SHA.");
    expect(unpinnedActionsNote([decl("c/d@0123456789012345678901234567890123456789")])).toBeUndefined();
  });
});

describe("parseActionsRecords and loadActionsDb", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-actions-db-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  it("a malformed record fails the whole database closed, never a silent partial read", () => {
    expect(() => parseActionsRecords([{ name: "x.json", data: Buffer.from("{not json") }])).toThrow(/x\.json/);
    expect(() => parseActionsRecords([{ name: "y.json", data: Buffer.from(JSON.stringify({ id: "../../etc", affected: [] })) }])).toThrow(/y\.json/);
    expect(() => parseActionsRecords([{ name: "z.json", data: Buffer.from(JSON.stringify({ id: "GHSA-1", affected: "nope" })) }])).toThrow(/z\.json/);
    // Review minor: an affected entry with no package name, or an overlong one, is malformed, never skipped.
    for (const pkg of [{ ecosystem: "GitHub Actions" }, { ecosystem: "GitHub Actions", name: `o/${"r".repeat(400)}` }]) {
      expect(() => parseActionsRecords([{ name: "n.json", data: Buffer.from(JSON.stringify({ id: "GHSA-2", affected: [{ package: pkg }] })) }])).toThrow(/n\.json/);
    }
  });

  it("loads the installed archive, signed only when its install record matches it", async () => {
    const records = await realRecords();
    const archive = zipEntries(records);
    const path = join(work, "all.zip");
    await writeFile(path, archive);
    const { createHash } = await import("node:crypto");
    const signature = `sha256:${createHash("sha256").update(archive).digest("hex")}`;
    const record = { component: "osv-scanner:vulnerability-db:GitHub Actions", ecosystem: "GitHub Actions" as const, signature, source_url: "x", bytes: archive.length, recorded_at: "2026-11-04T00:00:00.000Z", last_modified: "2026-10-30T20:33:08.000Z" };
    const ready = await loadActionsDb({ zipPath: path, readRecord: async () => record });
    expect(ready).toMatchObject({ state: "ready", db: { signature, date: "2026-10-30", records: records.length } });
    const unsigned = await loadActionsDb({ zipPath: path, readRecord: async () => ({ ...record, signature: `sha256:${"0".repeat(64)}` }) });
    expect(unsigned.state === "ready" && unsigned.db.signature).toBe(undefined);
    expect(unsigned.state === "ready" && unsigned.warning).toMatch(/no install record that matches it/);
    expect(await loadActionsDb({ zipPath: join(work, "absent.zip"), readRecord: async () => undefined })).toEqual({ state: "missing" });
    await writeFile(join(work, "bad.zip"), Buffer.alloc(100));
    expect(await loadActionsDb({ zipPath: join(work, "bad.zip"), readRecord: async () => undefined }))
      .toMatchObject({ state: "failed", reason: expect.stringMatching(/could not be read/) });
  });
});

describe("the dataset's own GitHub Actions advisories", () => {
  let shipped: SynvoyaAdvisory[];
  let datasetOnly: ActionsDb;
  let both: ActionsDb;
  beforeEach(async () => {
    const loaded = await loadSynvoyaDataset();
    if (!loaded.ok) throw new Error(loaded.reason);
    // What the scanner passes: entries still waiting for a reader (the mutable-tag class) are filtered out first.
    shipped = loaded.dataset.advisories.filter((advisory) => advisory.requires === undefined);
    datasetOnly = withDatasetAdvisories(undefined, datasetActionAdvisories(shipped));
    both = withDatasetAdvisories(db, datasetActionAdvisories(shipped));
  });

  it("covers the six version-bearing advisories by action name and never the mutable-tag class", async () => {
    const all = (await loadSynvoyaDataset()) as { ok: true; dataset: { advisories: SynvoyaAdvisory[] } };
    expect([...datasetActionAdvisories(all.dataset.advisories).values()].flat().map((entry) => entry.id).sort())
      .toEqual(["SYN-2026-068", "SYN-2026-069", "SYN-2026-076", "SYN-2026-07601", "SYN-2026-077", "SYN-2026-326"]);
    expect([...datasetActionAdvisories(all.dataset.advisories).keys()].sort()).toEqual([
      "aquasecurity/setup-trivy", "aquasecurity/trivy-action", "pypa/gh-action-pypi-publish", "shivammathur/setup-php", "tj-actions/changed-files", "wktk/conflibot",
    ]);
  });

  it("without the database: an affected tag is a finding from the dataset, the fixed release and an unrelated action are clean", () => {
    const result = matchActions(datasetOnly, [decl("wktk/conflibot@v1.2.0"), decl("wktk/conflibot@v1.2.1", ".github/workflows/b.yml"), decl("actions/checkout@v4")], NOW);
    expect(result.findings.map((f) => [f.rule_id, f.severity, f.confidence, f.location.file, f.location.start_line])).toEqual([["SYN-2026-069", "critical", "high", ".github/workflows/ci.yml", 10]]);
    const [finding] = result.findings;
    expect(finding!.engine).toBe("synvoya");
    expect(finding!.vulnerability_aliases).toEqual(["CVE-2026-55158", "GHSA-2qvg-qr73-mqxp"]);
    expect(finding!.producer_components).toEqual(synvoyaActionsDatasetFindingComponents());
    expect(finding!.producer_components).not.toContain("osv-scanner:vulnerability-db:GitHub Actions");
    expect(finding!.remediation.summary).toBe("Update wktk/conflibot to 1.2.1 or later, pinned by its full commit SHA.");
    expect(finding!.remediation.steps).toContain("Bump to wktk/conflibot@<sha of v1.2.1>; avoid pull_request_target for bots that read branch names.");
    expect(result.evaluated.size).toBe(3);
  });

  it("an exploited advisory says so; a floating major wholly inside the range is a line finding, one that reaches the fix is a note", () => {
    const line = matchActions(datasetOnly, [decl("tj-actions/changed-files@v45")], NOW);
    expect(line.findings.map((f) => [f.rule_id, f.confidence])).toEqual([["SYN-2026-326", "medium"]]);
    expect(line.findings[0]!.message).toMatch(/affects every release the moving tag v45 can resolve to today\. It is known to be exploited\./);
    const reaches = matchActions(datasetOnly, [decl("tj-actions/changed-files@v46")], NOW);
    expect(reaches.findings).toEqual([]);
    expect(reaches.notes).toEqual([expect.stringMatching(/tj-actions\/changed-files@v46 is a moving tag .* SYN-2026-326; pin tj-actions\/changed-files to ≥ 46\.0\.1/)]);
    expect(reaches.indefinite).toEqual(new Set([".github/workflows/ci.yml"]));
  });

  it("a commit pin is never a guessed finding: the fixing commit is clean, any other commit a note that names the missing commit list", () => {
    const fixing = matchActions(datasetOnly, [decl("pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086")], NOW);
    expect(fixing).toMatchObject({ findings: [], notes: [] });
    expect(fixing.evaluated.size).toBe(1);
    const other = matchActions(datasetOnly, [decl("pypa/gh-action-pypi-publish@1234567890123456789012345678901234567890"), decl("wktk/conflibot@1234567890123456789012345678901234567890")], NOW);
    expect(other.findings).toEqual([]);
    expect(other.notes).toEqual([
      expect.stringMatching(/pypa\/gh-action-pypi-publish@123456789012 is pinned to a commit; SYN-2026-068 lists commits, but not this one/),
      expect.stringMatching(/wktk\/conflibot@123456789012 is pinned to a commit; SYN-2026-069 has no commit list in its advisory data/),
    ]);
    expect(other.evaluated.size).toBe(0);
  });

  it("with the database too: the database's finding for the same advisory stands alone, unchanged but for Synvoya's fix steps", () => {
    const upstream = matchActions(db, [decl("tj-actions/changed-files@v45.0.7")], NOW).findings[0]!;
    const result = matchActions(both, [decl("tj-actions/changed-files@v45.0.7")], NOW);
    expect(result.findings).toHaveLength(1);
    const [kept] = result.findings;
    expect(kept).toMatchObject({ rule_id: "GHSA-mrrh-fwg8-r2c3", fingerprint: upstream.fingerprint, id: upstream.id, severity: upstream.severity, title: upstream.title, message: upstream.message });
    expect(kept!.producer_components).toEqual(synvoyaActionsFindingComponents());
    expect(kept!.remediation.summary).toBe(upstream.remediation.summary);
    expect(kept!.remediation.steps.slice(0, upstream.remediation.steps.length)).toEqual(upstream.remediation.steps);
    expect(kept!.remediation.steps.slice(upstream.remediation.steps.length)).toEqual([
      "Synvoya SYN-2026-326: Update tj-actions/changed-files to 46.0.1 or later, pinned by its full commit SHA.",
      "Pin the action to a fixed release (46.0.1) by full commit SHA.",
      "Rotate every secret available to workflows that ran the compromised version and review their logs.",
    ]);
    // The older advisory of the same action is only the database's: untouched.
    expect(matchActions(both, [decl("tj-actions/changed-files@v40.0.0")], NOW).findings.map((f) => f.rule_id).sort()).toEqual(["GHSA-mcph-m25j-8j63", "GHSA-mrrh-fwg8-r2c3"]);
  });

  it("an entry the database has no record for stands alone beside it, and so does one the database judges differently", () => {
    expect(matchActions(both, [decl("wktk/conflibot@v1.2.0")], NOW).findings.map((f) => f.rule_id)).toEqual(["SYN-2026-069"]);
    // The database says 1.14.5 is clean (fixed 1.14.3); a dataset entry for the same advisory that affects it is not folded away.
    const stricter: SynvoyaAdvisory = { ...shipped.find((advisory) => advisory.id === "SYN-2026-068")!, id: "SYN-TEST-1", affected: [{ events: [{ introduced: "0" }, { fixed: "1.14.9" }] }] };
    const mixed = withDatasetAdvisories(db, datasetActionAdvisories([stricter]));
    expect(matchActions(mixed, [decl("pypa/gh-action-pypi-publish@v1.14.5")], NOW).findings.map((f) => f.rule_id)).toEqual(["SYN-TEST-1"]);
    expect(matchActions(mixed, [decl("pypa/gh-action-pypi-publish@v1.14.2")], NOW).findings.map((f) => f.rule_id)).toEqual(["GHSA-5xjx-3w67-w9x9"]);
  });

  // Review I1: the fold must pick the alias-sharing database record that reports the reference, not the first one.
  it("two database records share the dataset entry's aliases: the one that reports the reference is enriched, whichever sorts first", () => {
    const record = (id: string, fixed: string) => ({ name: `${id}.json`, data: Buffer.from(JSON.stringify({
      id, summary: id, affected: [{ package: { ecosystem: "GitHub Actions", name: "o/act" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed }] }] }],
    })) });
    // GHSA-aaaa-aaaa-aaaa (sorts first) says 2.30.0 is fixed; GHSA-bbbb-bbbb-bbbb says it is affected.
    const records = parseActionsRecords([record("GHSA-aaaa-aaaa-aaaa", "2.20.0"), record("GHSA-bbbb-bbbb-bbbb", "2.40.0")]);
    const entry: SynvoyaAdvisory = { ...shipped.find((advisory) => advisory.id === "SYN-2026-069")!, id: "SYN-TEST-2", aliases: ["GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb"],
      target: { type: "package", ecosystem: "GitHub Actions", name: "o/act" }, affected: [{ events: [{ introduced: "0" }, { fixed: "2.40.0" }] }], fixed: ["2.40.0"] };
    const merged = withDatasetAdvisories(records, datasetActionAdvisories([entry]));
    const result = matchActions(merged, [decl("o/act@v2.30.0")], NOW);
    expect(result.findings.map((f) => f.rule_id)).toEqual(["GHSA-bbbb-bbbb-bbbb"]);
    expect(result.findings[0]!.remediation.steps.some((step) => step.startsWith("Synvoya SYN-TEST-2: "))).toBe(true);
    // The same for the repeated note: both records note a floating tag; the dataset entry adds none of its own.
    const noted = matchActions(merged, [decl("o/act@v2")], NOW);
    expect(noted.notes).toHaveLength(2);
    expect(noted.notes.join("\n")).not.toMatch(/SYN-TEST-2/);
  });

  it("a note both the database and the dataset would give for the same advisory is one note", () => {
    const result = matchActions(both, [decl("tj-actions/changed-files@v46")], NOW);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toMatch(/GHSA-mrrh-fwg8-r2c3/);
    expect(result.indefinite).toEqual(new Set([".github/workflows/ci.yml"]));
  });
});
