import { afterEach, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  GITHUB_ACTIONS_EXPRESSION_INJECTION_RULE_ID,
  GITHUB_ACTIONS_PWN_REQUEST_RULE_ID,
  GITHUB_ACTIONS_RULE_IDS,
  runGithubActionsSecurity,
} from "./workflow-security.js";

const roots: string[] = [];
const CORPUS = join(process.cwd(), "fixtures", "github-actions-corpus");

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-github-actions-"));
  roots.push(root);
  return root;
}

async function put(root: string, relativePath: string, content: string): Promise<string> {
  const path = join(root, ...relativePath.split("/"));
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, content, "utf8");
  return path;
}

describe("GitHub Actions frozen corpus", () => {
  test("emits exactly one high-confidence finding per TP rule and keeps FP/fixed silent", async () => {
    const tp = await runGithubActionsSecurity(join(CORPUS, "tp"));
    const fp = await runGithubActionsSecurity(join(CORPUS, "fp"));
    const fixed = await runGithubActionsSecurity(join(CORPUS, "fixed"));

    expect(tp.findings).toHaveLength(2);
    expect(new Set(tp.findings.map((finding) => finding.rule_id))).toEqual(new Set(GITHUB_ACTIONS_RULE_IDS));
    expect(tp.findings.every((finding) => finding.confidence === "high")).toBe(true);
    expect(tp.findings.find((finding) =>
      finding.rule_id === GITHUB_ACTIONS_EXPRESSION_INJECTION_RULE_ID
    )?.severity).toBe("high");
    expect(tp.findings.find((finding) =>
      finding.rule_id === GITHUB_ACTIONS_PWN_REQUEST_RULE_ID
    )?.severity).toBe("critical");
    expect(tp.notes).toBeUndefined();
    expect(fp).toEqual({ findings: [] });
    expect(fixed).toEqual({ findings: [] });
  });

  test("does not mutate workflow files while scanning", async () => {
    const path = join(CORPUS, "tp", ".github", "workflows", "expression.yml");
    const before = await readFile(path, "utf8");
    await runGithubActionsSecurity(join(CORPUS, "tp"));
    await expect(readFile(path, "utf8")).resolves.toBe(before);
  });
});

describe("GitHub Actions expression injection precision", () => {
  test("covers scalar and block run scripts but ignores env, with, and shell-comment usage", async () => {
    const root = await temporaryRoot();
    await put(root, ".github/workflows/injection.yml", `
on: issues
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.event.issue.title }}"
      - run: |
          # echo "\${{ github.event.issue.body }}"
          echo "\${{ github.event.comment.body }}"
      - env:
          TITLE: \${{ github.event.issue.title }}
        run: echo "$TITLE"
      - uses: fake/check@v1
        with:
          title: \${{ github.event.issue.title }}
`);
    const result = await runGithubActionsSecurity(root);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      GITHUB_ACTIONS_EXPRESSION_INJECTION_RULE_ID,
      GITHUB_ACTIONS_EXPRESSION_INJECTION_RULE_ID,
    ]);
  });

  test("fails closed on nearby trusted context properties and unsupported bracket notation", async () => {
    const root = await temporaryRoot();
    await put(root, ".github/workflows/trusted.yml", `
on: push
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo "\${{ github.repository }} \${{ github.event.pull_request.number }}"
      - run: echo "\${{ github.event.issue['title'] }}"
`);
    await expect(runGithubActionsSecurity(root)).resolves.toEqual({ findings: [] });
  });
});

describe("GitHub Actions pwn-request precision", () => {
  test("requires privileged trigger, untrusted checkout, known unprotected checkout, and execution", async () => {
    const root = await temporaryRoot();
    await put(root, ".github/workflows/pwn.yml", `
on: [pull_request_target]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm ci
`);
    const result = await runGithubActionsSecurity(root);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      GITHUB_ACTIONS_PWN_REQUEST_RULE_ID,
    ]);
  });

  test("keeps pull_request, trusted checkout, no-execution, and protected v7 workflows silent", async () => {
    const root = await temporaryRoot();
    await put(root, ".github/workflows/pull-request.yml", `
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test
`);
    await put(root, ".github/workflows/trusted.yml", `
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - run: echo safe
`);
    await put(root, ".github/workflows/no-exec.yml", `
on: pull_request_target
jobs:
  inspect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: echo metadata
`);
    await put(root, ".github/workflows/v7.yml", `
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test
`);
    const result = await runGithubActionsSecurity(root);
    expect(result).toEqual({ findings: [] });
  });

  test("recognizes a documented pre-v7 SHA and local action execution", async () => {
    const root = await temporaryRoot();
    await put(root, ".github/workflows/local-action.yml", `
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.1.6
        with:
          ref: \${{ format('refs/pull/{0}/merge', github.event.number) }}
      - uses: ./.github/actions/build
`);
    const result = await runGithubActionsSecurity(root);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      GITHUB_ACTIONS_PWN_REQUEST_RULE_ID,
    ]);
  });
});

describe("GitHub Actions loader boundaries", () => {
  test("only inspects direct workflow files and fails closed on malformed YAML", async () => {
    const root = await temporaryRoot();
    await put(root, ".github/workflows/nested/ignored.yml", `on: issues\njobs: {x: {steps: [{run: 'echo \${{ github.event.issue.title }}'}]}}\n`);
    await put(root, ".github/workflows/malformed.yml", "on: [issues\njobs:\n");
    const result = await runGithubActionsSecurity(root);
    expect(result.findings).toEqual([]);
    expect(result.notes).toEqual([
      "Skipped malformed or unsupported GitHub Actions workflow .github/workflows/malformed.yml.",
    ]);
  });

  test("does not follow direct or discovered symbolic links", async () => {
    const root = await temporaryRoot();
    const outside = await put(root, "outside.yml", `on: issues\njobs: {x: {steps: [{run: 'echo \${{ github.event.issue.title }}'}]}}\n`);
    const project = join(root, "project");
    await mkdir(join(project, ".github", "workflows"), { recursive: true });
    await symlink(outside, join(project, ".github", "workflows", "linked.yml"));

    const directory = await runGithubActionsSecurity(project);
    expect(directory.findings).toEqual([]);
    expect(directory.notes?.join(" ")).toContain("symbolic-link GitHub Actions workflow");

    const direct = await runGithubActionsSecurity(join(project, ".github", "workflows", "linked.yml"));
    expect(direct.findings).toEqual([]);
    expect(direct.notes?.join(" ")).toContain("symbolic-link GitHub Actions target");
  });

  test("reports and skips oversized workflows", async () => {
    const root = await temporaryRoot();
    await put(root, ".github/workflows/oversized.yml", `# ${"x".repeat(1024 * 1024)}\n`);
    const result = await runGithubActionsSecurity(root);
    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toContain("Skipped oversized GitHub Actions workflow");
  });
});
