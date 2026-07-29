import { afterEach, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  FIREBASE_CONFIG_RULE_IDS,
  FIREBASE_DATABASE_PUBLIC_WRITE_RULE_ID,
  FIREBASE_FIRESTORE_PUBLIC_WRITE_RULE_ID,
  FIREBASE_STORAGE_PUBLIC_WRITE_RULE_ID,
  runFirebaseConfig,
} from "./firebase-config.js";

const roots: string[] = [];
const CORPUS = join(process.cwd(), "fixtures", "firebase-config-corpus");

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(join(await realpath(tmpdir()), "codeinspectus-firebase-config-"));
  roots.push(root);
  return root;
}

async function put(root: string, relativePath: string, content: string): Promise<string> {
  const path = join(root, ...relativePath.split("/"));
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, content, "utf8");
  return path;
}

describe("Firebase configuration frozen corpus", () => {
  test("emits exactly one high-confidence critical finding per TP rule and keeps FP/fixed silent", async () => {
    const tp = await runFirebaseConfig(join(CORPUS, "tp"));
    const fp = await runFirebaseConfig(join(CORPUS, "fp"));
    const fixed = await runFirebaseConfig(join(CORPUS, "fixed"));

    expect(tp.findings).toHaveLength(3);
    expect(new Set(tp.findings.map((finding) => finding.rule_id))).toEqual(new Set(FIREBASE_CONFIG_RULE_IDS));
    expect(tp.findings.every((finding) => finding.severity === "critical")).toBe(true);
    expect(tp.findings.every((finding) => finding.confidence === "high")).toBe(true);
    expect(tp.findings.every((finding) => finding.cwe.join(",") === "CWE-862,CWE-285")).toBe(true);
    expect(tp.notes).toBeUndefined();
    expect(fp).toEqual({ findings: [] });
    expect(fixed).toEqual({ findings: [] });
  });

  test("does not mutate rule files while scanning", async () => {
    const path = join(CORPUS, "tp", "firestore.rules");
    const before = await readFile(path, "utf8");
    await runFirebaseConfig(join(CORPUS, "tp"));
    await expect(readFile(path, "utf8")).resolves.toBe(before);
  });
});

describe("Firebase Rules precision", () => {
  test("flags create/update/delete/write with no condition or exactly true, but not public reads", async () => {
    const root = await temporaryRoot();
    await put(root, "firestore.rules", `
      service cloud.firestore {
        match /databases/{database}/documents {
          match /a/{id} { allow create: if (((true))); }
          match /b/{id} { allow update, delete; }
          match /c/{id} { allow read: if true; }
        }
      }
    `);
    const result = await runFirebaseConfig(root);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      FIREBASE_FIRESTORE_PUBLIC_WRITE_RULE_ID,
      FIREBASE_FIRESTORE_PUBLIC_WRITE_RULE_ID,
    ]);
  });

  test("keeps authentication, authorization, false, and mixed true expressions silent", async () => {
    const root = await temporaryRoot();
    await put(root, "storage.rules", `
      service firebase.storage {
        match /b/{bucket}/o {
          match /a/{path=**} { allow write: if request.auth != null; }
          match /b/{path=**} { allow create: if true && request.auth != null; }
          match /c/{path=**} { allow update: if false; }
          match /d/{path=**} { allow delete: if isOwner(); }
        }
      }
    `);
    await expect(runFirebaseConfig(root)).resolves.toEqual({ findings: [] });
  });

  test("requires an exact Firebase service and masks comment/string decoys", async () => {
    const root = await temporaryRoot();
    await put(root, "unrelated.rules", `
      // service cloud.firestore { allow write: if true; }
      service example.firestore {
        function text() { return "allow write: if true;"; }
        allow write: if true;
      }
    `);
    await expect(runFirebaseConfig(root)).resolves.toEqual({ findings: [] });
  });

  test("accepts a valid trailing line comment at end of file", async () => {
    const root = await temporaryRoot();
    await put(root, "storage.rules", "service firebase.storage { allow write: if true; } // intentional fixture");
    const result = await runFirebaseConfig(root);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      FIREBASE_STORAGE_PUBLIC_WRITE_RULE_ID,
    ]);
    expect(result.notes).toBeUndefined();
  });

  test("strictly identifies Realtime Database .write property values without string decoys", async () => {
    const root = await temporaryRoot();
    await put(root, "database.rules.json", JSON.stringify({
      rules: {
        safe: { ".write": "auth != null" },
        publicBoolean: { ".write": true },
        publicString: { ".write": "true" },
        readOnly: { ".read": true },
        note: "\".write\": true",
      },
    }, null, 2));
    const result = await runFirebaseConfig(root);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      FIREBASE_DATABASE_PUBLIC_WRITE_RULE_ID,
      FIREBASE_DATABASE_PUBLIC_WRITE_RULE_ID,
    ]);
  });

  test("fails closed with coverage notes for malformed Rules and JSON", async () => {
    const root = await temporaryRoot();
    await put(root, "firestore.rules", "service cloud.firestore { allow write: if true;\n");
    await put(root, "database.rules.json", '{"rules": {".write": true}');
    const result = await runFirebaseConfig(root);
    expect(result.findings).toEqual([]);
    expect(result.notes).toEqual([
      "Skipped malformed Firebase rule file database.rules.json.",
      "Skipped malformed Firebase rule file firestore.rules.",
    ]);
  });
});

describe("Firebase configuration loader boundaries", () => {
  test("excludes non-production/dependency trees but does not exclude a target because an ancestor is named tests", async () => {
    const container = await temporaryRoot();
    const project = join(container, "tests", "real-app");
    await put(project, "storage.rules", "service firebase.storage { allow write: if true; }");
    await put(project, "examples/firestore.rules", "service cloud.firestore { allow write: if true; }");
    await put(project, "node_modules/database.rules.json", '{"rules":{".write":true}}');

    const result = await runFirebaseConfig(project);
    expect(result.findings.map((finding) => finding.rule_id)).toEqual([
      FIREBASE_STORAGE_PUBLIC_WRITE_RULE_ID,
    ]);
  });

  test("does not follow direct or discovered symbolic links", async () => {
    const root = await temporaryRoot();
    const outside = await put(root, "outside.rules", "service cloud.firestore { allow write: if true; }");
    const project = join(root, "project");
    await mkdir(project);
    await symlink(outside, join(project, "firestore.rules"));

    const directory = await runFirebaseConfig(project);
    expect(directory.findings).toEqual([]);
    expect(directory.notes?.join(" ")).toContain("symbolic-link Firebase rule file firestore.rules");

    const direct = await runFirebaseConfig(join(project, "firestore.rules"));
    expect(direct.findings).toEqual([]);
    expect(direct.notes?.join(" ")).toContain("symbolic-link Firebase configuration target");
  });

  test("reports and skips oversized rule files", async () => {
    const root = await temporaryRoot();
    await put(root, "firestore.rules", `service cloud.firestore { /* ${"x".repeat(1024 * 1024)} */ allow write: if true; }`);
    const result = await runFirebaseConfig(root);
    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toContain("Skipped oversized Firebase rule file firestore.rules");
  });
});
