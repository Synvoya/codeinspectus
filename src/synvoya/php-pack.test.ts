import { existsSync, readdirSync } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { parse as parseYaml } from "yaml";

import { opengrepRuleLanguages, sastRuleLanguagesLine } from "../rules.js";
import { isSynvoyaFinding } from "./family.js";

// Synvoya PHP pack contract (design 4.5): original rules with ids syn-php-*, CWE metadata, TP and FP
// fixtures per rule and a manifest entry each.
const ROOT = process.cwd();
const PACK = join(ROOT, "detection-db", "opengrep-rules", "synvoya-php");
const EXPERIMENTAL = join(ROOT, "experimental", "opengrep-rules", "synvoya-php-experimental");

interface Rule {
  id: string;
  languages: string[];
  severity: string;
  message: string;
  metadata: { cwe: string; confidence: string; synvoya_pack: string };
}

async function rulesIn(directory: string): Promise<Rule[]> {
  const rules: Rule[] = [];
  for (const name of (await readdir(directory)).filter((file) => /\.ya?ml$/.test(file))) {
    const text = await readFile(join(directory, name), "utf8");
    // Opengrep reads rule files as ASCII.
    expect(/^[\x09\x0a\x0d\x20-\x7e]*$/.test(text), `${name} is not ASCII-only`).toBe(true);
    rules.push(...((parseYaml(text, { maxAliasCount: 10_000 }) as { rules: Rule[] }).rules));
  }
  return rules;
}

async function fixtureFolders(folder: string): Promise<string[]> {
  return (await readdir(join(ROOT, "fixtures", folder))).sort();
}

describe("Synvoya PHP pack", () => {
  test("every shipped rule is a syn-php-* rule with CWE, confidence, pack tag and TP/FP fixtures", async () => {
    const rules = await rulesIn(PACK);
    const ids = rules.map((rule) => rule.id).sort();
    expect(ids.length).toBe(19);
    expect(new Set(ids).size).toBe(ids.length);
    expect(await fixtureFolders("synvoya-php")).toEqual(ids);
    for (const rule of rules) {
      expect(rule.id).toMatch(/^syn-php-[a-z0-9-]+$/);
      expect(rule.metadata.cwe).toMatch(/^CWE-\d+: /);
      expect(["HIGH", "MEDIUM", "LOW"]).toContain(rule.metadata.confidence);
      expect(rule.metadata.synvoya_pack).toBe("synvoya-php");
      expect(["ERROR", "WARNING", "INFO"]).toContain(rule.severity);
      expect(rule.languages.every((language) => language === "php" || language === "generic")).toBe(true);
      expect(isSynvoyaFinding({ engine: "opengrep", rule_id: rule.id })).toBe(true);
      for (const kind of ["tp", "fp"]) {
        const folder = join(ROOT, "fixtures", "synvoya-php", rule.id, kind);
        expect((await stat(folder)).isDirectory(), `${rule.id} has no ${kind} fixtures`).toBe(true);
        expect((await readdir(folder)).length, `${rule.id} ${kind} fixtures are empty`).toBeGreaterThan(0);
      }
    }
    await expect(readFile(join(PACK, "LICENSE-PROVENANCE.md"), "utf8")).resolves.toMatch(/Apache-2\.0/);
  });

  test("each shipped rule has exactly one opengrep manifest entry with its CWE", async () => {
    const manifest = JSON.parse(await readFile(join(ROOT, "detection-db", "manifest.json"), "utf8")) as {
      opengrep_rulesets: Array<{ name: string }>;
      custom_rules: Array<{ id: string; engine: string; kind: string; cwe: string[] }>;
    };
    expect(manifest.opengrep_rulesets.map((ruleset) => ruleset.name)).toContain("synvoya-php");
    const entries = manifest.custom_rules.filter((rule) => rule.id.startsWith("syn-php-"));
    const rules = await rulesIn(PACK);
    expect(entries.map((entry) => entry.id).sort()).toEqual(rules.map((rule) => rule.id).sort());
    for (const rule of rules) {
      const entry = entries.find((candidate) => candidate.id === rule.id)!;
      expect(entry).toMatchObject({ engine: "opengrep", kind: "sast" });
      expect(entry.cwe).toEqual([rule.metadata.cwe.split(":")[0]]);
    }
    expect(manifest.custom_rules.find((rule) => rule.id === "codeinspectus-laravel-app-key"))
      .toMatchObject({ engine: "gitleaks", kind: "secret", cwe: ["CWE-798"] });
  });

  // experimental/ is dev-only and never seeded into the public repo (a seed leaves the folder empty on disk),
  // so this check runs only where the experimental rules exist.
  test.skipIf(!existsSync(EXPERIMENTAL) || readdirSync(EXPERIMENTAL).length === 0)("experimental rules stay outside the loaded rules directory and the manifest", async () => {
    const experimental = await rulesIn(EXPERIMENTAL);
    // xss-echo failed the M3 re-triage; the other five failed the 4.0 holdout precision gate (deferred to 4.1).
    expect(experimental.map((rule) => rule.id)).toEqual(expect.arrayContaining([
      "syn-php-xss-echo", "syn-php-path-traversal", "syn-php-preg-replace-eval-modifier",
      "syn-php-laravel-mass-assignment-unguarded", "syn-php-open-redirect", "syn-php-xxe-entity-expansion",
    ]));
    expect(await fixtureFolders("synvoya-php-experimental")).toEqual(experimental.map((rule) => rule.id).sort());
    const manifest = await readFile(join(ROOT, "detection-db", "manifest.json"), "utf8");
    const shipped = new Set((await rulesIn(PACK)).map((rule) => rule.id));
    for (const rule of experimental) {
      expect(shipped.has(rule.id)).toBe(false);
      expect(manifest.includes(`"${rule.id}"`)).toBe(false);
    }
  });

  test("the package ships no experimental folder", async () => {
    const packageJson = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8")) as { files: string[] };
    expect(packageJson.files.some((entry) => entry.startsWith("experimental"))).toBe(false);
  });

  // Opengrep matches rule `paths` excludes against the absolute target path, so a directory-name
  // exclude would disable a rule for any project under a parent folder of that name.
  test("no rule excludes paths by directory name", async () => {
    for (const name of (await readdir(PACK)).filter((file) => /\.ya?ml$/.test(file))) {
      const doc = parseYaml(await readFile(join(PACK, name), "utf8"), { maxAliasCount: 10_000 }) as { rules: Array<{ id: string; paths?: { exclude?: string[] } }> };
      for (const rule of doc.rules) {
        for (const pattern of rule.paths?.exclude ?? []) expect(pattern, `${rule.id} excludes ${pattern}`).not.toMatch(/\//);
      }
    }
  });

  test("list_rules counts bundled Opengrep rules per language from the files Opengrep loads", async () => {
    const languages = await opengrepRuleLanguages();
    const php = languages.find((entry) => entry.language === "php");
    const phpRules = (await rulesIn(PACK)).filter((rule) => rule.languages.includes("php"));
    expect(php).toEqual({ language: "php", rule_count: phpRules.length, rulesets: ["synvoya-php"] });
    expect(languages.find((entry) => entry.language === "python")?.rulesets).toEqual(["security-baseline"]);
    expect(languages.map((entry) => entry.language)).toEqual([...languages.map((entry) => entry.language)].sort());
    expect(sastRuleLanguagesLine(languages)).toMatch(/^Opengrep rules by language: .*php \d+/);
    expect(sastRuleLanguagesLine(undefined)).toBe("Opengrep rules by language: unavailable");
  });
});
