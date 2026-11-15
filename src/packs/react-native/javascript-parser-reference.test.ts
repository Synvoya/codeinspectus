/**
 * Native findings and parser tokens pinned on every corpus file (4.1 M4).
 *
 * `fixtures/contract/native-parser-reference.json` was generated on `@babel/parser` 7.25.0 at 3bd0de3, before
 * any M4 change, with
 * `UPDATE_NATIVE_PARSER_REFERENCE=1 npx vitest run src/packs/react-native/javascript-parser-reference.test.ts`.
 * It records, for every JavaScript/TypeScript file under `fixtures/`, whether it parsed and a hash of the
 * mapped tokens and conditional bodies the analyzers read, and, for every fixture directory that holds such
 * a file, the native findings (`runAiChecks`) as fingerprint, rule, location and a hash of the finding's
 * full JSON. A file that parsed then must parse to the same tokens now, and every finding must come back
 * byte-identical, whatever changes in the parser wrapper or its readings. The only change allowed is a file
 * that failed to parse and now parses (`NEWLY_PARSED`); a finding not in the reference must sit in such a file
 * or in a fixture file added after the reference was generated (4.1 M7 fixtures).
 *
 * The public projection ships a subset of `fixtures/`; a directory or file it leaves out is skipped.
 *
 * Intentional regenerations (4.1 M9, each listed with the task that changed the findings):
 * - Task 3 (api-boundary): new fixture files and their findings under `fixtures/api-boundary-corpus/`
 *   (fp/13-17, fp/billing/18, tp/19-29); `ci-ai-sensitive-log` in tp/07 and tp/18 changes its snippet only
 *   (one named header, `authorization`, is no longer also labelled "request headers").
 * - Addendum A1 (api-boundary parsing): new fixture files and their findings under
 *   `fixtures/api-boundary-corpus/` (fp/19-22: no finding; tp/30-36: seven findings). No existing finding changed.
 * - Addendum A4 (project error classes): new fixture files and their findings under
 *   `fixtures/api-boundary-corpus/` (fp/23-app-error-literal-message: no finding; tp/37-39: three findings).
 * - Fix round 1: new fixture files and their findings only (tp/41-42 item 1, and per later items as listed in
 *   the M9 report); A3 (98a3842) was reverted, so its sha changes are gone.
 * - Fix round 2: the Next.js custom exit guard (Task 5) was reverted; its fixtures under
 *   `fixtures/nextjs-admin-route-corpus/tp/app/api/admin/custom-*` stay and each fires.
 * - Fix round 4: `fp/23-app-error-literal-message` moved to `fixtures/api-boundary-public-errors/` (same files and
 *   tokens, no finding); new fixture files and their findings only (tp/72-73 item 1, tp/74-75 item 2, tp/76 item 3).
 * - Fix round 5: new fixture files and their findings only (tp/77-79 item 1, tp/80 item 2).
 * - Task 10 (fresh-set gate, demotions): sha changes only (severity and confidence `low`) of every
 *   `ci-ai-client-error-leak` (81), `ci-ai-llm-output-dangerous-html` (14), `ci-ai-public-env-secret` (5) and
 *   `ci-ai-security-header-disabled` (5) entry. The same regeneration absorbs the 4.1 M7 fixture changes the merge
 *   brought without a regeneration: new and renamed files under `coverage-honesty-corpus/opengrep-rules/`
 *   (`ci-baseline-dom-xss-innerhtml`, `ci-baseline-nosql-injection`, `ci-baseline-weak-hash`) and
 *   `opengrep-shadow-corpus/`, and their native findings (two `ci-ai-unvalidated-request-write` and one
 *   `ci-ai-llm-output-dangerous-html` in known-gap files, at every enclosing root). No existing finding was removed.
 * - Task 10 (fresh-set gate, experimental rules, Ruling 4): removed findings, each from a rule the registry no longer
 *   reports: `ci-ai-sensitive-api-response` (58 entries) and `ci-ai-sensitive-log` (24) in `api-boundary-corpus`
 *   roots, `ci-ai-client-hardcoded-secret` (1, `vulnerable-app/src/config.ts`). Nothing else changed.
 * - Maintainer decision (2026-11-15): `ci-ai-client-hardcoded-secret` ships as in 4.0, so its one entry
 *   (`vulnerable-app/src/config.ts`) is back, byte-identical to b839a67.
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { describe, expect, test } from "vitest";

import { runAiChecks } from "../../ai-checks/index.js";
import type { Finding } from "../../types.js";
import { parseJavaScriptSource } from "./javascript.js";

const REPO = resolve(import.meta.dirname, "../../..");
const FIXTURES = join(REPO, "fixtures");
const REFERENCE = join(FIXTURES, "contract", "native-parser-reference.json");
const JS_FILE = /\.(?:[cm]?[jt]s|[jt]sx)$/i;

/** Fixture files that did not parse when the reference was generated and parse now. */
const NEWLY_PARSED: readonly string[] = [];

interface FileState {
  parsed: boolean;
  tokens?: string;
}

interface FindingEntry {
  fingerprint: string;
  rule_id: string;
  file: string;
  start_line: number;
  end_line: number;
  sha256: string;
}

interface Reference {
  parser: string;
  files: Record<string, FileState>;
  roots: Record<string, FindingEntry[]>;
}

const posix = (path: string): string => path.split(sep).join("/");
const sha256 = (value: string): string => createHash("sha256").update(value).digest("hex");

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) walk(path, out);
    else if (entry.isFile() && JS_FILE.test(entry.name)) out.push(path);
  }
  return out;
}

function fileState(path: string): FileState {
  const document = parseJavaScriptSource(posix(relative(REPO, path)), readFileSync(path, "utf8"));
  if (!document.balanced) return { parsed: false };
  const tokens = document.tokens.map(({ kind, value, raw, start, end, line, staticValue, jsx }) =>
    [kind, value, raw, start, end, line, staticValue ?? null, jsx ?? false]);
  return { parsed: true, tokens: sha256(JSON.stringify([tokens, document.conditionalBodies ?? []])) };
}

/** Every fixture directory that holds a JavaScript/TypeScript file at any depth, each one a scan root. */
function roots(files: readonly string[]): string[] {
  const set = new Set<string>();
  for (const file of files) {
    for (let dir = resolve(file, ".."); dir !== FIXTURES; dir = resolve(dir, "..")) set.add(posix(relative(REPO, dir)));
  }
  return [...set].sort();
}

function entry(finding: Finding): FindingEntry {
  return {
    fingerprint: finding.fingerprint,
    rule_id: finding.rule_id,
    file: finding.location.file,
    start_line: finding.location.start_line,
    end_line: finding.location.end_line ?? finding.location.start_line,
    sha256: sha256(JSON.stringify(finding)),
  };
}

const byKey = (a: FindingEntry, b: FindingEntry): number => {
  const left = `${a.fingerprint}\0${a.sha256}`;
  const right = `${b.fingerprint}\0${b.sha256}`;
  return left < right ? -1 : left > right ? 1 : 0;
};

async function rootFindings(root: string): Promise<FindingEntry[]> {
  const result = await runAiChecks(join(REPO, root));
  return result.findings.map(entry).sort(byKey);
}

function parserVersion(): string {
  return (JSON.parse(readFileSync(join(REPO, "node_modules", "@babel", "parser", "package.json"), "utf8")) as { version: string }).version;
}

if (process.env.UPDATE_NATIVE_PARSER_REFERENCE === "1") {
  test("writes the native parser reference", async () => {
    const files = walk(FIXTURES);
    const reference: Reference = { parser: parserVersion(), files: {}, roots: {} };
    for (const file of files) reference.files[posix(relative(REPO, file))] = fileState(file);
    for (const root of roots(files)) reference.roots[root] = await rootFindings(root);
    writeFileSync(REFERENCE, `${JSON.stringify(reference, null, 1)}\n`);
  }, 600_000);
} else {
  describe("native parser reference (generated at 3bd0de3 on @babel/parser 7.25.0)", () => {
    const reference = JSON.parse(readFileSync(REFERENCE, "utf8")) as Reference;
    const present = (path: string): boolean => existsSync(join(REPO, path));

    test("was generated on the pinned parser", () => {
      expect(reference.parser).toBe("7.25.0");
    });

    test("every fixture file parses as before, to the same tokens, except the newly parsed ones", () => {
      const changed: string[] = [];
      for (const [path, before] of Object.entries(reference.files)) {
        if (!present(path)) continue;
        const now = fileState(join(REPO, path));
        if (before.parsed) expect(now, path).toEqual(before);
        else if (now.parsed) changed.push(path);
      }
      expect(changed).toEqual(NEWLY_PARSED);
    });

    test("every fixture directory yields byte-identical native findings", async () => {
      const newlyParsed = new Set(NEWLY_PARSED.map((path) => path));
      for (const [root, before] of Object.entries(reference.roots)) {
        if (!present(root)) continue;
        const now = await rootFindings(root);
        const nowKeys = new Set(now.map((item) => `${item.fingerprint}\0${item.sha256}`));
        const beforeKeys = new Set(before.map((item) => `${item.fingerprint}\0${item.sha256}`));
        expect(before.filter((item) => !nowKeys.has(`${item.fingerprint}\0${item.sha256}`)), root).toEqual([]);
        const added = now.filter((item) => !beforeKeys.has(`${item.fingerprint}\0${item.sha256}`));
        // A fixture file added after the reference was generated (absent from reference.files) may add findings.
        expect(added.filter((item) => ![...newlyParsed].some((path) => `${root}/${item.file}` === path) &&
          `${root}/${item.file}` in reference.files), root).toEqual([]);
      }
    }, 600_000);
  });
}
