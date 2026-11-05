import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { parse as parseYaml } from "yaml";

import { isSynvoyaFinding } from "./family.js";

const PACK_DIR = join(process.cwd(), "detection-db", "opengrep-rules", "synvoya-node");
const FIXTURE_DIR = join(process.cwd(), "fixtures", "synvoya-node-corpus");

interface PackRule {
  id: string;
  severity: string;
  languages: string[];
  metadata: { cwe: string; confidence: string; synvoya_pack: string };
}

async function packRules(): Promise<{ file: string; text: string; rules: PackRule[] }[]> {
  const files = (await readdir(PACK_DIR)).filter((name) => name.endsWith(".yaml")).sort();
  return Promise.all(files.map(async (file) => {
    const text = await readFile(join(PACK_DIR, file), "utf8");
    return { file, text, rules: (parseYaml(text) as { rules: PackRule[] }).rules };
  }));
}

describe("Synvoya Node.js Opengrep pack (M3 stream B)", () => {
  test("rule files are ASCII-only and every rule is a syn-node-* rule with CWE and confidence metadata", async () => {
    const files = await packRules();
    expect(files.length).toBeGreaterThan(0);
    for (const { file, text, rules } of files) {
      expect(/^[\x09\x0a\x0d\x20-\x7e]*$/.test(text), `${file} is not ASCII-only`).toBe(true);
      for (const rule of rules) {
        expect(rule.id).toMatch(/^syn-node-[a-z0-9-]+$/);
        expect(["ERROR", "WARNING", "INFO"]).toContain(rule.severity);
        expect(rule.metadata.cwe).toMatch(/^CWE-\d+: /);
        expect(["HIGH", "MEDIUM", "LOW"]).toContain(rule.metadata.confidence);
        expect(rule.metadata.synvoya_pack).toBe("synvoya-node");
      }
    }
  });

  test("the manifest lists exactly the shipped rules, as Opengrep SAST rules with the rule's CWE", async () => {
    const shipped = (await packRules()).flatMap(({ rules }) => rules);
    const manifest = JSON.parse(await readFile(join(process.cwd(), "detection-db", "manifest.json"), "utf8")) as {
      opengrep_rulesets: { name: string }[];
      custom_rules: { id: string; engine: string; kind: string; cwe: string[]; source: string }[];
    };
    expect(manifest.opengrep_rulesets.map((set) => set.name)).toContain("synvoya-node");
    const listed = manifest.custom_rules.filter((rule) => rule.id.startsWith("syn-node-"));
    expect(listed.map((rule) => rule.id).sort()).toEqual(shipped.map((rule) => rule.id).sort());
    for (const rule of shipped) {
      const entry = listed.find((item) => item.id === rule.id)!;
      expect(entry).toMatchObject({ engine: "opengrep", kind: "sast", source: "codeinspectus-custom" });
      expect(entry.cwe[0]).toBe(rule.metadata.cwe.split(":")[0]);
      expect(isSynvoyaFinding({ engine: "opengrep", rule_id: rule.id })).toBe(true);
    }
  });

  test("every shipped rule has non-empty tp/ and fp/ fixture folders and no fixture folder is orphaned", async () => {
    const ids = (await packRules()).flatMap(({ rules }) => rules.map((rule) => rule.id)).sort();
    expect((await readdir(FIXTURE_DIR)).sort()).toEqual(ids);
    for (const id of ids) {
      expect((await readdir(join(FIXTURE_DIR, id, "tp"))).length, `${id} has no TP fixture`).toBeGreaterThan(0);
      expect((await readdir(join(FIXTURE_DIR, id, "fp"))).length, `${id} has no FP fixture`).toBeGreaterThan(0);
    }
  });

  test("rule paths use file-basename globs only (no folder names, no bare substrings)", async () => {
    // Opengrep 1.33.1 matches rule `paths` against the absolute target path: `vendors/` or `*example*`
    // would also match a parent folder of the scanned project and silently switch the rule off.
    for (const { file, rules } of await packRules()) {
      for (const rule of rules as Array<PackRule & { paths?: { include?: string[]; exclude?: string[] } }>) {
        for (const glob of [...(rule.paths?.include ?? []), ...(rule.paths?.exclude ?? [])]) {
          expect(glob, `${file} ${rule.id}: ${glob}`).not.toMatch(/\//);
        }
        for (const glob of rule.paths?.exclude ?? []) {
          // An exclude must name a file: it ends in a concrete extension, not a wildcard.
          expect(glob, `${file} ${rule.id}: ${glob}`).toMatch(/\.[A-Za-z0-9]+$/);
        }
      }
    }
  });

  test("experimental rules live outside the loaded and shipped rule folders", async () => {
    // Opengrep loads every YAML under detection-db/opengrep-rules, and package.json ships detection-db/.
    const loaded = await readdir(join(process.cwd(), "detection-db", "opengrep-rules"), { recursive: true });
    expect(loaded.filter((path) => /experimental/i.test(path))).toEqual([]);
    const pkg = JSON.parse(await readFile(join(process.cwd(), "package.json"), "utf8")) as { files: string[] };
    expect(pkg.files.some((entry) => /experimental/i.test(entry))).toBe(false);
  });
});
