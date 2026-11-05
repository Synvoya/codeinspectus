import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { readActionReferences } from "./actions.js";

let work: string;

async function tree(files: Record<string, string>): Promise<string> {
  for (const [rel, text] of Object.entries(files)) {
    await mkdir(dirname(join(work, rel)), { recursive: true });
    await writeFile(join(work, rel), text);
  }
  return work;
}

beforeEach(async () => {
  work = await mkdtemp(join(tmpdir(), "ci-synvoya-actions-"));
});
afterEach(async () => {
  await rm(work, { recursive: true, force: true });
});

const WORKFLOW = [
  "on: pull_request",
  "jobs:",
  "  shared:",
  "    uses: kartverket/github-workflows/.github/workflows/run-terraform.yml@v2.7.4",
  "  test:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  "      - uses: actions/checkout@v4",
  "      - uses: 'tj-actions/changed-files@v45.0.7'",
  "      - uses: ./.github/actions/local",
  "      - uses: docker://alpine:3.20",
  "      - uses: pypa/gh-action-pypi-publish@7245906FB61FA33A13554F9D5FB856FE61758086",
  "      - uses: reviewdog/action-setup@main",
  "      - uses: github/codeql-action/init@v3.28",
  "      - run: echo done",
].join("\n");

describe("readActionReferences", () => {
  it("reads job and step `uses:` references with their ref kind; local and docker steps are never declarations", async () => {
    const result = await readActionReferences(await tree({ ".github/workflows/ci.yml": WORKFLOW }));
    expect(result.parsed).toEqual([".github/workflows/ci.yml"]);
    expect(result.skipped).toEqual([]);
    expect(result.declarations.map((d) => [d.subject, d.spec, d.precision, d.resolved, d.line, d.source, d.action])).toEqual([
      [{ type: "package", ecosystem: "GitHub Actions", name: "kartverket/github-workflows" }, "2.7.4", "exact", "2.7.4", 4, "workflow job uses",
        { name: "kartverket/github-workflows", path: "/.github/workflows/run-terraform.yml", ref: "v2.7.4", kind: "semver", uses: "kartverket/github-workflows/.github/workflows/run-terraform.yml@v2.7.4" }],
      [{ type: "package", ecosystem: "GitHub Actions", name: "actions/checkout" }, "4", "floating", undefined, 8, "workflow step uses",
        { name: "actions/checkout", path: "", ref: "v4", kind: "floating", uses: "actions/checkout@v4" }],
      [{ type: "package", ecosystem: "GitHub Actions", name: "tj-actions/changed-files" }, "45.0.7", "exact", "45.0.7", 9, "workflow step uses",
        { name: "tj-actions/changed-files", path: "", ref: "v45.0.7", kind: "semver", uses: "tj-actions/changed-files@v45.0.7" }],
      [{ type: "package", ecosystem: "GitHub Actions", name: "pypa/gh-action-pypi-publish" }, "7245906fb61fa33a13554f9d5fb856fe61758086", "unresolved", undefined, 12, "workflow step uses",
        { name: "pypa/gh-action-pypi-publish", path: "", ref: "7245906FB61FA33A13554F9D5FB856FE61758086", kind: "sha", uses: "pypa/gh-action-pypi-publish@7245906FB61FA33A13554F9D5FB856FE61758086" }],
      [{ type: "package", ecosystem: "GitHub Actions", name: "reviewdog/action-setup" }, "main", "unresolved", undefined, 13, "workflow step uses",
        { name: "reviewdog/action-setup", path: "", ref: "main", kind: "branch", uses: "reviewdog/action-setup@main" }],
      [{ type: "package", ecosystem: "GitHub Actions", name: "github/codeql-action" }, "3.28", "floating", undefined, 14, "workflow step uses",
        { name: "github/codeql-action", path: "/init", ref: "v3.28", kind: "floating", uses: "github/codeql-action/init@v3.28" }],
    ]);
    // Unresolved declarations carry the matcher's own note, never the generic evaluator's.
    expect(result.declarations.filter((d) => d.precision === "unresolved").every((d) => d.noted === true)).toBe(true);
    // Every third-party reference the reader saw, docker ones included (they stay in the actions-unchecked gap).
    expect(result.references.map((r) => r.uses)).toEqual([
      "kartverket/github-workflows/.github/workflows/run-terraform.yml@v2.7.4", "actions/checkout@v4", "tj-actions/changed-files@v45.0.7",
      "docker://alpine:3.20", "pypa/gh-action-pypi-publish@7245906FB61FA33A13554F9D5FB856FE61758086", "reviewdog/action-setup@main",
      "github/codeql-action/init@v3.28",
    ]);
  });

  it("reads a capital-V tag as a version", async () => {
    const result = await readActionReferences(await tree({ ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - uses: o/r@V45.0.0\n      - uses: o/r@V4\n" }));
    expect(result.declarations.map((d) => [d.spec, d.precision, d.action.kind])).toEqual([["45.0.0", "exact", "semver"], ["4", "floating", "floating"]]);
  });

  it("reads composite action steps in action.yml and action.yaml anywhere, and only top-level workflow files", async () => {
    const result = await readActionReferences(await tree({
      "action.yml": "runs:\n  using: composite\n  steps:\n    - uses: shivammathur/setup-php@2.37.0\n",
      ".github/actions/setup/action.yaml": "runs:\n  using: composite\n  steps:\n    - uses: actions/download-artifact@v4.1.2\n",
      ".github/workflows/nested/not-a-workflow.yml": "jobs:\n  t:\n    steps:\n      - uses: a/b@v1\n",
      "docs/action.yml": "name: docker action\nruns:\n  using: docker\n  image: Dockerfile\n",
      "node_modules/x/action.yml": "runs:\n  steps:\n    - uses: a/b@v1\n",
    }));
    expect(result.parsed).toEqual([".github/actions/setup/action.yaml", "action.yml", "docs/action.yml"]);
    expect(result.declarations.map((d) => [d.file, d.action.uses, d.source])).toEqual([
      [".github/actions/setup/action.yaml", "actions/download-artifact@v4.1.2", "composite action step uses"],
      ["action.yml", "shivammathur/setup-php@2.37.0", "composite action step uses"],
    ]);
  });

  it("a reference it cannot read, an alias or a merge key leaves the file unjudged with a note; malformed YAML is skipped", async () => {
    const result = await readActionReferences(await tree({
      ".github/workflows/a.yml": "jobs:\n  t:\n    steps:\n      - uses: not a reference\n      - uses: owner@v1\n",
      ".github/workflows/b.yml": "x: &step\n  uses: tj-actions/changed-files@v35\njobs:\n  t:\n    steps:\n      - *step\n",
      ".github/workflows/c.yml": "x: &s\n  uses: tj-actions/changed-files@v35\njobs:\n  t:\n    steps:\n      - <<: *s\n        name: merged\n",
      ".github/workflows/d.yml": "jobs: [unclosed\n",
      ".github/workflows/e.yml": "jobs:\n  t:\n    steps:\n      - uses: \"\"\n",
    }));
    expect(result.parsed).toEqual([".github/workflows/a.yml", ".github/workflows/b.yml", ".github/workflows/c.yml", ".github/workflows/e.yml"]);
    expect(result.skipped).toEqual([{ file: ".github/workflows/d.yml", reason: "malformed" }]);
    expect(result.unjudged).toEqual([".github/workflows/a.yml", ".github/workflows/b.yml", ".github/workflows/c.yml"]);
    expect(result.declarations).toEqual([]);
    expect(result.references.map((r) => [r.file, r.uses])).toEqual([
      [".github/workflows/a.yml", "not a reference"], [".github/workflows/a.yml", "owner@v1"],
    ]);
    expect(result.notes.join("\n")).toMatch(/a\.yml:4: `uses: not a reference` is not an action reference Synvoya can read/);
    expect(result.notes.join("\n")).toMatch(/b\.yml:.*YAML alias/);
    expect(result.notes.join("\n")).toMatch(/c\.yml:.*merge key/);
  });

  it("never follows a symlinked workflow and honours a single-file scope and the deadline", async () => {
    await tree({ "real.yml": "jobs:\n  t:\n    steps:\n      - uses: a/b@v1\n", ".github/workflows/ok.yml": "jobs:\n  t:\n    steps:\n      - uses: c/d@v2\n" });
    await symlink(join(work, "real.yml"), join(work, ".github", "workflows", "linked.yml"));
    const result = await readActionReferences(work);
    expect(result.parsed).toEqual([".github/workflows/ok.yml"]);
    expect(result.skipped).toEqual([{ file: ".github/workflows/linked.yml", reason: "symlink" }]);
    const only = await readActionReferences(work, { only: ".github/workflows/ok.yml" });
    expect(only.declarations.map((d) => d.action.uses)).toEqual(["c/d@v2"]);
    const controller = new AbortController();
    controller.abort();
    const late = await readActionReferences(work, { signal: controller.signal });
    expect(late.parsed).toEqual([]);
    expect(late.skipped.some((entry) => entry.reason === "deadline")).toBe(true);
  });
});

describe("readActionReferences: hostile inputs", { timeout: 20_000 }, () => {
  it("caps references per file (the file is then capped, never parsed) and stays linear on a large workflow", async () => {
    const steps = Array.from({ length: 300 }, (_, index) => `      - uses: owner/repo-${index}@v1`).join("\n");
    await tree({ ".github/workflows/big.yml": `jobs:\n  t:\n    steps:\n${steps}\n` });
    const started = performance.now();
    const result = await readActionReferences(work);
    expect(performance.now() - started).toBeLessThan(15_000);
    expect(result.declarations).toHaveLength(256);
    expect(result.parsed).toEqual([]);
    expect(result.skipped).toEqual([{ file: ".github/workflows/big.yml", reason: "capped" }]);
    expect(result.notes.join("\n")).toMatch(/more than 256 action references/);
  });

  it("an alias bomb is never expanded and a 70k-document file costs a bounded number of documents", async () => {
    const bomb = ["a: &a [x, x, x, x, x, x, x, x, x, x]"];
    for (let level = 1; level < 12; level++) bomb.push(`${String.fromCharCode(97 + level)}: &${String.fromCharCode(97 + level)} [*${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}, *${String.fromCharCode(96 + level)}]`);
    bomb.push("jobs: *l");
    await tree({
      ".github/workflows/bomb.yml": `${bomb.join("\n")}\n`,
      ".github/workflows/docs.yml": "jobs: {}\n---\n".repeat(70_000),
    });
    const started = performance.now();
    const result = await readActionReferences(work);
    expect(performance.now() - started).toBeLessThan(15_000);
    expect(result.declarations).toEqual([]);
    expect(result.unjudged).toEqual([".github/workflows/bomb.yml"]);
    expect(result.skipped).toEqual([{ file: ".github/workflows/docs.yml", reason: "capped" }]);
  });

  it("an overlong reference is clipped in notes and never becomes a declaration", async () => {
    await tree({ ".github/workflows/long.yml": `jobs:\n  t:\n    steps:\n      - uses: owner/repo@${"x".repeat(5000)}\n` });
    const result = await readActionReferences(work);
    expect(result.declarations).toEqual([]);
    expect(result.unjudged).toEqual([".github/workflows/long.yml"]);
    expect(Math.max(...result.notes.map((note) => note.length))).toBeLessThan(400);
    expect(result.references[0]!.uses.length).toBeLessThanOrEqual(300);
  });
});
