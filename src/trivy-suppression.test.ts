import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { detectTrivyInlineIgnores, trivyInlineIgnoreWarning } from "./trivy-suppression.js";

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function tree(files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "ci-trivy-ignores-"));
  roots.push(root);
  for (const [path, content] of Object.entries(files)) {
    await mkdir(dirname(join(root, path)), { recursive: true });
    await writeFile(join(root, path), content, "utf8");
  }
  return root;
}

// Review I-6, re-checked on Trivy 0.76.1: `#trivy:ignore:*` above a Terraform resource hid all eight
// AWS findings, and `# trivy:ignore:DS-0025` above a Dockerfile RUN hid DS-0025. The same run read
// main.tf and Dockerfile under node_modules/, vendor/, .venv/, build/ and hidden folders, not .git/,
// and did not follow symlinks.
describe("Trivy inline ignore comments", () => {
  test("counts comments in every folder Trivy reads and names the files", async () => {
    const root = await tree({
      "infra/main.tf": "#trivy:ignore:*\nresource \"aws_s3_bucket\" \"a\" {}\n# tfsec:ignore:aws-s3-enable-versioning\n",
      "Dockerfile": "FROM alpine:3.19\n# trivy:ignore:DS-0025\nRUN apk add curl\n",
      "k8s/deploy.yaml": "# trivy:ignore:KSV-0001\nkind: Deployment\n",
      "docker/api.Dockerfile": "FROM node:22\n",
      "README.md": "Use #trivy:ignore:AVD-DS-0002 to silence a check.\n",
      "node_modules/pkg/main.tf": "#trivy:ignore:*\n",
      ".git/hooks/main.tf": "#trivy:ignore:*\n",
    });

    const found = await detectTrivyInlineIgnores(root);

    expect(found).toEqual({ comments: 5, paths: ["Dockerfile", "infra/main.tf", "k8s/deploy.yaml", "node_modules/pkg/main.tf"], unchecked: [] });
    expect(trivyInlineIgnoreWarning(found)).toBe(
      "Trivy misconfiguration coverage unverified: 5 trivy:ignore or tfsec:ignore comment(s) in 4 file(s) can hide " +
        "misconfiguration findings, and Trivy cannot be told to disregard them: Dockerfile, infra/main.tf, k8s/deploy.yaml, " +
        "node_modules/pkg/main.tf.",
    );
  });

  test("no comments, no warning", async () => {
    const found = await detectTrivyInlineIgnores(await tree({ "main.tf": "resource \"aws_s3_bucket\" \"a\" {}\n" }));
    expect(found).toEqual({ comments: 0, paths: [], unchecked: [] });
    expect(trivyInlineIgnoreWarning(found)).toBeUndefined();
  });

  test("a large file is read in full, including a comment split across read chunks", async () => {
    const padding = "#".repeat(1024 * 1024 - 5);
    const root = await tree({ "plan.json": `${padding}\ntrivy:ignore:* and more ${"x".repeat(3 * 1024 * 1024)} tfsec:ignore:a\n` });
    expect(await detectTrivyInlineIgnores(root)).toEqual({ comments: 2, paths: ["plan.json"], unchecked: [] });
  });

  // Security review: a candidate the search cannot read must never read as "no inline ignores".
  test("a symlinked or unreadable candidate and an unreadable folder make the result unverified", async () => {
    const root = await tree({ "real/main.tf": "resource \"aws_s3_bucket\" \"a\" {}\n", "locked/main.tf": "\n", "closed/x/main.tf": "\n" });
    await symlink(join(root, "real", "main.tf"), join(root, "linked.tf"));
    await chmod(join(root, "locked", "main.tf"), 0o000);
    await chmod(join(root, "closed"), 0o000);
    try {
      const found = await detectTrivyInlineIgnores(root);
      expect(found).toEqual({ comments: 0, paths: [], unchecked: ["closed", "linked.tf", "locked/main.tf"] });
      expect(trivyInlineIgnoreWarning(found)).toBe(
        "Trivy misconfiguration coverage unverified: 3 infrastructure file(s) or folder(s) could not be checked for such " +
          "comments (not a regular file, or unreadable): closed, linked.tf, locked/main.tf.",
      );
    } finally {
      await chmod(join(root, "closed"), 0o755);
      await chmod(join(root, "locked", "main.tf"), 0o644);
    }
  });

  test("a single-file target is read", async () => {
    const root = await tree({ "main.tf": "#trivy:ignore:*\n" });
    expect(await detectTrivyInlineIgnores(join(root, "main.tf"))).toEqual({ comments: 1, paths: ["main.tf"], unchecked: [] });
  });

  test("control-character paths are counted but not echoed, and a bounded search is unverified", () => {
    expect(trivyInlineIgnoreWarning({ comments: 2, paths: ["a\u001b[2J.tf", "b.tf"], unchecked: [] })).toBe(
      "Trivy misconfiguration coverage unverified: 2 trivy:ignore or tfsec:ignore comment(s) in 2 file(s) can hide " +
        "misconfiguration findings, and Trivy cannot be told to disregard them: b.tf, ….",
    );
    expect(trivyInlineIgnoreWarning({ comments: 0, paths: [], unchecked: [], bounded: "candidates" }))
      .toBe("Trivy misconfiguration coverage unverified: the search for trivy:ignore and tfsec:ignore comments stopped at the 200000-file bound.");
    expect(trivyInlineIgnoreWarning({ comments: 0, paths: [], unchecked: [], bounded: "entries" }))
      .toBe("Trivy misconfiguration coverage unverified: the search for trivy:ignore and tfsec:ignore comments stopped at the 5000000-entry bound.");
  });

  // Final review I-3: an installed checkout has hundreds of thousands of entries but far fewer files
  // Trivy parses for misconfiguration; only those count toward the bound.
  test("only candidate files count toward the bound; entries have a separate safety bound", async () => {
    const files: Record<string, string> = { "infra/main.tf": "#trivy:ignore:*\n", "k8s/a.yaml": "kind: Pod\n" };
    for (let index = 0; index < 60; index++) files[`node_modules/.pnpm/p${index}/index.js`] = "";
    const root = await tree(files);
    expect(await detectTrivyInlineIgnores(root, { candidates: 2 })).toEqual({ comments: 1, paths: ["infra/main.tf"], unchecked: [] });
    expect((await detectTrivyInlineIgnores(root, { candidates: 1 })).bounded).toBe("candidates");
    expect((await detectTrivyInlineIgnores(root, { entries: 50 })).bounded).toBe("entries");
  });

  test("a bidi-override file name is counted but never echoed", async () => {
    const root = await tree({ "infra/evil\u202efT.tf": "#trivy:ignore:*\n", "infra/main.tf": "#trivy:ignore:*\n" });
    const found = await detectTrivyInlineIgnores(root);
    expect(found.comments).toBe(2);
    expect(trivyInlineIgnoreWarning(found)).toBe(
      "Trivy misconfiguration coverage unverified: 2 trivy:ignore or tfsec:ignore comment(s) in 2 file(s) can hide " +
        "misconfiguration findings, and Trivy cannot be told to disregard them: infra/main.tf, ….",
    );
  });
});
