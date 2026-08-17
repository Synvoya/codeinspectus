import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { runAiChecks } from "../../ai-checks/index.js";
import { loadFlutterProject } from "./project.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function flutterProject(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "codeinspectus-flutter-bounds-"));
  roots.push(root);
  await Promise.all([
    mkdir(join(root, "lib"), { recursive: true }),
    mkdir(join(root, ".pub-cache"), { recursive: true }),
    mkdir(join(root, ".gradle"), { recursive: true }),
    mkdir(join(root, "vendor"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(join(root, "pubspec.yaml"), "name: bounded\ndependencies:\n  flutter:\n    sdk: flutter\n"),
    writeFile(join(root, "lib", "main.dart"), "void main() {}\n"),
    writeFile(join(root, "lib", "oversized.dart"), "x".repeat(2 * 1024 * 1024 + 1)),
    writeFile(join(root, ".pub-cache", "dependency.dart"), "print(accessToken);\n"),
    writeFile(join(root, ".gradle", "generated.dart"), "print(accessToken);\n"),
    writeFile(join(root, "vendor", "vendored.dart"), "print(accessToken);\n"),
  ]);
  return root;
}

describe("Flutter project source bounds", () => {
  test("ignores dependency trees and records oversized Dart omissions", async () => {
    const root = await flutterProject();
    const project = await loadFlutterProject(root);

    expect(project.files.map((file) => file.path)).toEqual(["lib/main.dart"]);
    expect(project.limitations).toEqual([
      "Skipped oversized Dart file lib/oversized.dart (limit: 2 MiB).",
    ]);
  });

  test("deduplicates source omissions into the applicable pack coverage note", async () => {
    const root = await flutterProject();
    const result = await runAiChecks(root);
    const coverage = result.packCoverage.find((pack) => pack.pack_id === "flutter");

    expect(coverage).toMatchObject({
      state: "partial",
      analyzers: { registered: 6, ran: 6 },
      rules: { registered: 6, ran: 6 },
    });
    expect(coverage?.note).toBe(
      "Skipped oversized Dart file lib/oversized.dart (limit: 2 MiB).",
    );
  });
});
