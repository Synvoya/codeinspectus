/**
 * CG-30 — git-aware file routing. Severity/framing is decided by WHERE a finding
 * lives (node_modules / build output / git-ignored / tracked), not by blunt
 * include/exclude. These tests lock both directions.
 */

import { describe, test, expect, beforeAll, afterAll } from "vitest";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding } from "./types.js";
import { normalizeSarif } from "./sarif/normalize.js";
import type { SarifLog } from "./sarif/types.js";
import {
  bucketFor,
  routeFindings,
  reframeLocalHygiene,
  gitIgnoredSet,
  routeScanFindings,
  BUILD_DIRS,
  contextFor,
  vendoredPath,
  thirdPartyText,
  type FileClass,
} from "./file-routing.js";

const execFileP = promisify(execFile);

function mk(file: string, over: Partial<Finding> = {}): Finding {
  return {
    id: "CI-0001",
    fingerprint: `fp-${file}`,
    title: "Hard-coded secret",
    severity: "high",
    engine: "gitleaks",
    engines: ["gitleaks"],
    rule_id: "generic-api-key",
    cwe: ["CWE-798"],
    location: { file, start_line: 3, end_line: 3, snippet: "REDACTED" },
    message: "A secret was detected.",
    remediation: { summary: "Rotate it.", steps: ["rotate"], references: ["CWE-798"] },
    frameworks: [],
    confidence: "high",
    is_secret: true,
    ...over,
  };
}

describe("bucketFor — classification by path", () => {
  const ignored = new Set<string>([".env.local.bak", ".next/x.js", "node_modules/p/i.js"]);

  test("node_modules anywhere → node_modules (wins over gitignored)", () => {
    expect(bucketFor("node_modules/p/i.js", ignored)).toBe("node_modules");
    expect(bucketFor("packages/a/node_modules/q.js", new Set())).toBe("node_modules");
  });

  test("all known build dirs → build_output (wins over gitignored)", () => {
    for (const d of [".next", "dist", "build", "out", ".nuxt", ".svelte-kit", ".output"]) {
      expect(bucketFor(`${d}/chunk.js`, ignored)).toBe("build_output");
    }
    expect(BUILD_DIRS.has(".svelte-kit")).toBe(true);
    expect(BUILD_DIRS.has(".nuxt")).toBe(true);
    expect(BUILD_DIRS.has("_next")).toBe(true);
  });

  test("git-ignored source/backup → gitignored", () => {
    expect(bucketFor(".env.local.bak", ignored)).toBe("gitignored");
  });

  test("tracked / not-ignored source → tracked", () => {
    expect(bucketFor("src/app.ts", ignored)).toBe("tracked");
    expect(bucketFor("supabase/migrations/0001.sql", ignored)).toBe("tracked");
  });
});

describe("routeFindings — severity/framing per bucket", () => {
  const buckets: Record<string, ReturnType<typeof bucketFor>> = {
    "node_modules/dep/secret.js": "node_modules",
    ".next/static/chunk.js": "build_output",
    "dist/bundle.js": "build_output",
    ".env.local.bak": "gitignored",
    "src/config.ts": "tracked",
    "supabase/migrations/0001.sql": "tracked",
  };
  const bucketOf = (rel: string) => buckets[rel] ?? "tracked";

  test("node_modules findings are dropped entirely", () => {
    const { findings, stats } = routeFindings([mk("node_modules/dep/secret.js")], bucketOf);
    expect(findings.length).toBe(0);
    expect(stats.dropped_node_modules).toBe(1);
  });

  test("build output: only the §6.1 AI bundle check survives; commodity-engine noise dropped", () => {
    const aiBundle = mk(".next/static/chunk.js", {
      engine: "codeinspectus-ai",
      engines: ["codeinspectus-ai"],
      rule_id: "ci-ai-secret-in-bundle",
      severity: "critical",
      title: "Secret compiled into shipped bundle",
    });
    const gitleaksNoise = mk("dist/bundle.js");
    const { findings, stats } = routeFindings([aiBundle, gitleaksNoise], bucketOf);
    const kept = findings.map((f) => f.rule_id);
    expect(kept).toContain("ci-ai-secret-in-bundle");
    expect(kept).not.toContain("generic-api-key");
    expect(stats.dropped_build_noise).toBe(1);
    // The surviving bundle finding stays a real (not downgraded) finding.
    expect(findings[0]!.severity).toBe("critical");
    // …and is clearly labelled as shipped-to-browser build output.
    expect(`${findings[0]!.title} ${findings[0]!.message}`.toLowerCase()).toMatch(/build output|shipped|bundle/);
  });

  test("git-ignored secret → reframed local-hygiene, downgraded, NOT dropped", () => {
    const { findings, stats } = routeFindings([mk(".env.local.bak", { severity: "high" })], bucketOf);
    expect(findings.length).toBe(1); // not silently dropped
    expect(stats.reframed).toBe(1);
    const f = findings[0]!;
    expect(f.severity).toBe("low"); // clearly lower urgency than a committed leak
    expect(f.is_secret).toBe(true); // still a secret → redaction still applies
    expect(f.fingerprint).toBe("fp-.env.local.bak"); // rescan stability preserved
    expect(f.rule_id).toBe("generic-api-key"); // rule identity preserved
    expect(`${f.title} ${f.message}`.toLowerCase()).toMatch(/git-ignored|not committed|local/);
  });

  test("tracked finding is UNCHANGED (committed leak stays high/critical)", () => {
    const orig = mk("src/config.ts", { severity: "critical", message: "committed secret" });
    const { findings } = routeFindings([orig], bucketOf);
    expect(findings.length).toBe(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.message).toBe("committed secret");
  });

  test("the real critical class (RLS WITH CHECK(true) on a tracked table) is untouched", () => {
    const rls = mk("supabase/migrations/0001.sql", {
      engine: "codeinspectus-ai",
      engines: ["codeinspectus-ai"],
      rule_id: "ci-ai-rls-using-true",
      severity: "critical",
      is_secret: false,
      title: "Permissive RLS write policy",
    });
    const { findings } = routeFindings([rls], bucketOf);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.rule_id).toBe("ci-ai-rls-using-true");
  });

  test("same secret in a committed file AND a git-ignored backup → both survive, committed dominates", () => {
    const committed = mk("src/config.ts", { severity: "high", fingerprint: "fp-committed" });
    const backup = mk(".env.local.bak", { severity: "high", fingerprint: "fp-backup" });
    const { findings } = routeFindings([committed, backup], bucketOf);
    const bySev = Object.fromEntries(findings.map((f) => [f.fingerprint, f.severity]));
    expect(bySev["fp-committed"]).toBe("high"); // committed leak preserved
    expect(bySev["fp-backup"]).toBe("low"); // backup reframed, still present
    expect(findings.length).toBe(2); // different files → different dedup keys → no masking
  });
});

describe("reframeLocalHygiene", () => {
  test("downgrades above-low severities to low, keeps low/info", () => {
    expect(reframeLocalHygiene(mk("x", { severity: "critical" })).severity).toBe("low");
    expect(reframeLocalHygiene(mk("x", { severity: "high" })).severity).toBe("low");
    expect(reframeLocalHygiene(mk("x", { severity: "medium" })).severity).toBe("low");
    expect(reframeLocalHygiene(mk("x", { severity: "low" })).severity).toBe("low");
    expect(reframeLocalHygiene(mk("x", { severity: "info" })).severity).toBe("info");
  });
});

// ── Real-git integration: key on git STATUS, not filename ─────────────────────
describe("gitIgnoredSet — git status, not filename (committed .env is NOT downgraded)", () => {
  let repo: string;

  beforeAll(async () => {
    repo = await mkdtemp(join(tmpdir(), "ci-route-git-"));
    await execFileP("git", ["-C", repo, "init", "-q"]);
    await writeFile(join(repo, ".gitignore"), ".env\n.env.*\n*.bak\nnode_modules/\n.next/\n");
    // A TRACKED .env: `git check-ignore` (default) is index-aware, so a file staged in the
    // index is treated as tracked and is NOT reported as ignored — it keeps full severity.
    // Staging (add -f) is enough; we avoid `git commit` (global commit.gpgsign can hang it).
    await writeFile(join(repo, ".env"), "SECRET=committed");
    await writeFile(join(repo, "src-app.ts"), "const x = 1;");
    await execFileP("git", ["-C", repo, "add", "-f", ".env", "src-app.ts", ".gitignore"]);
    // A git-ignored backup — never staged/committed.
    await writeFile(join(repo, ".env.local.bak"), "SECRET=backup");
  }, 60000);

  afterAll(async () => {
    await rm(repo, { recursive: true, force: true }).catch(() => {});
  });

  test("committed .env is NOT in the ignored set; git-ignored .bak IS", async () => {
    const ignored = await gitIgnoredSet(repo, [".env", ".env.local.bak", "src-app.ts"]);
    expect(ignored.has(".env")).toBe(false); // committed → leak preserved
    expect(ignored.has(".env.local.bak")).toBe(true); // ignored → reframe
    expect(ignored.has("src-app.ts")).toBe(false);
  }, 60000);

  test("routeScanFindings: committed .env stays high; git-ignored .bak reframed", async () => {
    const committedEnv = mk(".env", { severity: "high", fingerprint: "fp-env" });
    const backup = mk(".env.local.bak", { severity: "high", fingerprint: "fp-bak" });
    const { findings } = await routeScanFindings([committedEnv, backup], repo);
    const bySev = Object.fromEntries(findings.map((f) => [f.fingerprint, f.severity]));
    expect(bySev["fp-env"]).toBe("high"); // committed .env keyed on git status, NOT filename
    expect(bySev["fp-bak"]).toBe("low");
  }, 60000);
});

describe("gitIgnoredSet — non-repo fallback uses filename heuristics", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ci-route-nogit-"));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("outside a git repo, *.bak / .env* reframe; .env.example does not", async () => {
    const ignored = await gitIgnoredSet(dir, [".env.local.bak", ".env", ".env.example", "src/app.ts"]);
    expect(ignored.has(".env.local.bak")).toBe(true);
    expect(ignored.has(".env")).toBe(true);
    expect(ignored.has(".env.example")).toBe(false); // meant to be committed
    expect(ignored.has("src/app.ts")).toBe(false);
  });
});

// ── Design §10.6 precision routing: third-party scripts (controller ruling, review round 2) ─────
// Drop only in Opengrep's own skip scope (case-sensitive vendor/, *.min.js, minified); lower the
// inferred classes (banner, UMD, vendors-style folder); never route secrets or dependency findings.
describe("third-party code detection", () => {
  test("vendor/ is Opengrep's scope, case-sensitive; vendors-style folders are inferred only", () => {
    expect(vendoredPath("public/vendor/lib/x.js")).toBe("vendor");
    expect(vendoredPath("includes/vendors/fremius/assets/js/pricing/freemius-pricing.js")).toBe("vendors");
    expect(vendoredPath("public/app/themes/clarity/src/vendors/magnific-popup.js")).toBe("vendors");
    expect(vendoredPath("lib/third_party/x.js")).toBe("vendors");
    // Review: Laravel's first-party app/Http/Controllers/Vendor/ and other case variants are not vendor/.
    expect(vendoredPath("app/Http/Controllers/Vendor/VendorController.php")).toBeUndefined();
    expect(vendoredPath("src/Vendors/list.ts")).toBeUndefined();
    expect(vendoredPath("src/vendorship/x.js")).toBeUndefined();
    expect(vendoredPath("vendor.js")).toBeUndefined();
  });

  test("an absolute or escaping path is never classified", () => {
    expect(vendoredPath("/home/me/vendor/project/src/app.js")).toBeUndefined();
    expect(vendoredPath("C:\\work\\vendor\\app.js")).toBeUndefined();
    expect(vendoredPath("../vendor/app.js")).toBeUndefined();
  });

  test("minified bodies, preserved banners and UMD wrappers are third-party evidence", () => {
    expect(thirdPartyText(`!function(e,t){${"a=1;".repeat(6000)}}`)).toBe("minified");
    expect(thirdPartyText(`/* lib */\n${"if(a){b(c);}".repeat(120)}\n`)).toBe("minified");
    expect(thirdPartyText("/*! X-editable - v1.5.1\n* In-place editing */\n(function ($) {})(jQuery);")).toBe("library");
    expect(thirdPartyText("/**\n * @license Copyright (c) 2003-2015, CKSource\n */\nCKEDITOR.plugins.add('autolink', {});")).toBe("library");
    expect(thirdPartyText(
      "(function (global, factory) {\n  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :\n" +
      "  typeof define === 'function' && define.amd ? define(factory) : global.confirmDate = factory();\n}(this, function () {}));",
    )).toBe("library");
  });

  test("a project's own code is not minified, even with one long data line", () => {
    expect(thirdPartyText(
      "/*\n * This file is part of the Kimai time-tracking app.\n *\n * For the full copyright and license information, please view the LICENSE\n */\nexport default class KimaiAlert {}\n",
    )).toBeUndefined();
    const ownFile = `${"const x = 1;\n".repeat(400)}const logo = "data:image/png;base64,${"A".repeat(1500)}";\n`;
    expect(thirdPartyText(ownFile)).toBeUndefined();
    // Review: a short first-party module whose only long line is a base64 constant.
    expect(thirdPartyText(`export const LOGO = "${"QUJD".repeat(6000)}";\nexport const n = 1;\n`)).toBeUndefined();
    expect(thirdPartyText("export function stripTags(html) {\n  const div = document.createElement('div');\n  div.innerHTML = html;\n}\n")).toBeUndefined();
  });

  // Re-triage 2 (B): one appended comment line of 20,000 ";" made a first-party script "minified".
  test("comment lines and a minority of dense bytes never make a script minified", () => {
    const own = "export function show(el, html) {\n  el.innerHTML = html;\n}\n";
    expect(thirdPartyText(`${own}//${";".repeat(20_000)}\n`)).toBeUndefined();
    expect(thirdPartyText(`${own}/*${";".repeat(20_000)}*/\n`)).toBeUndefined();
    // A real dense line that is under 80% of the file's bytes is not enough either.
    expect(thirdPartyText(`${"const value = compute(input);\n".repeat(200)}${"a(b);".repeat(300)}\n`)).toBeUndefined();
  });
});

describe("routeFindings — third-party code (tracked files)", () => {
  const sast = (file: string, over: Partial<Finding> = {}) => mk(file, {
    engine: "opengrep", engines: ["opengrep"], rule_id: "ci-baseline-dom-xss-innerhtml", cwe: ["CWE-79"],
    is_secret: false, finding_kind: "sast", severity: "high", confidence: "medium", ...over,
  });
  const tracked = () => "tracked" as const;

  test("Opengrep's path scope (vendor/, *.min.js) is not reported; inferred classes (minified, banner, vendors) are lowered", () => {
    const vendor = sast("public/vendor/lib/x.js");
    const minName = sast("public/js/app.min.js");
    const minified = sast("public/js/jquery.js");
    const banner = sast("assets/js/ckeditor/plugins/autolink/plugin.js");
    const vendors = sast("includes/vendors/fremius/pricing.js");
    const own = sast("assets/js/themer-loop.js");
    const classes: Record<string, FileClass> = {
      "public/js/jquery.js": { third_party: "minified" },
      "assets/js/ckeditor/plugins/autolink/plugin.js": { third_party: "library" },
    };
    const { findings, stats } = routeFindings([vendor, minName, minified, banner, vendors, own], tracked, (rel) => {
      const path = vendoredPath(rel);
      return classes[rel] ?? (path ? { third_party: path } : rel.endsWith(".min.js") ? { third_party: "min-name" } : {});
    });
    expect(stats.third_party_files).toEqual(["public/js/app.min.js", "public/vendor/lib/x.js"]);
    expect(stats.third_party_code).toBe(2);
    expect(stats.third_party_lowered_files).toEqual([
      "assets/js/ckeditor/plugins/autolink/plugin.js", "includes/vendors/fremius/pricing.js", "public/js/jquery.js",
    ]);
    const byFile = Object.fromEntries(findings.map((f) => [f.location.file, f]));
    expect(byFile["assets/js/themer-loop.js"]!.severity).toBe("high");
    for (const file of stats.third_party_lowered_files) {
      expect(byFile[file]!.severity).toBe("low");
      expect(byFile[file]!.title.startsWith("Third-party code — ")).toBe(true);
      expect(byFile[file]!.fingerprint).toBe(`fp-${file}`);
    }
  });

  test("the default classifier drops only exact vendor/ and *.min.js paths", () => {
    const { findings, stats } = routeFindings(
      [sast("public/vendor/x.js"), sast("public/js/a.min.js"), sast("src/Vendor/x.js"), sast("src/vendors/y.js")], tracked);
    expect(stats.third_party_code).toBe(2);
    expect(findings.map((f) => [f.location.file, f.severity])).toEqual([["src/Vendor/x.js", "high"], ["src/vendors/y.js", "low"]]);
  });

  test("secrets, credential-class native findings and dependency findings are never routed", () => {
    const secret = mk("public/vendor/lib/config.js", { severity: "high" });
    const vuln = mk("public/vendor/jquery.js", {
      engine: "osv-scanner", engines: ["osv-scanner"], rule_id: "GHSA-xxxx", is_secret: false, finding_kind: "vulnerability",
    });
    // Review: native CWE-798 checks report finding_kind "ai" without is_secret.
    const publicEnv = sast("public/vendor/env.js", {
      engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], rule_id: "ci-ai-public-env-secret", cwe: ["CWE-798"], finding_kind: "ai",
    });
    const llmKey = sast("includes/vendors/chat.js", {
      engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], rule_id: "ci-ai-llm-key-browser-exposed", cwe: ["CWE-798", "CWE-200"], finding_kind: "ai",
    });
    const nativeSecret = mk("public/vendor/bundle.js", {
      engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], rule_id: "ci-ai-client-hardcoded-secret", is_secret: true, finding_kind: "secret",
    });
    const unclassified = sast("public/vendor/other.js", { finding_kind: undefined });
    const all = [secret, vuln, publicEnv, llmKey, nativeSecret, unclassified];
    const { findings, stats } = routeFindings(all, tracked);
    expect(findings.map((f) => f.severity)).toEqual(all.map((f) => f.severity));
    expect(stats.third_party_code + stats.third_party_lowered).toBe(0);
  });
});

// ── Design §4.6: test, fixture, example and documentation context ──────────────────────────────
describe("contextFor — target-relative, case-sensitive path segments and basenames", () => {
  test("test, fixture, example and docs folders", () => {
    for (const rel of [
      "test/auth.js", "src/tests/auth.js", "src/__tests__/auth.js", "spec/models/user.rb", "fixtures/users.yaml",
      "examples/basic/app.js", "example/app.js", "docs/guide/setup.txt", "packages/a/test/deep/x.ts",
    ]) expect(contextFor(rel), rel).toBeDefined();
  });

  test("test, spec, example, sample, README and Markdown basenames", () => {
    for (const rel of [
      "src/auth.test.ts", "src/auth.spec.js", "config.example.yml", "settings.sample.json", ".env.example",
      "README", "README.rst", "packages/a/README.txt", "notes.md", "docs-src/guide.md",
    ]) expect(contextFor(rel), rel).toBeDefined();
  });

  test("snapshot folders and files, e2e specs, .env.dist and Xcode-style test targets", () => {
    expect(contextFor("features/__snapshots__/Proposal.js.snap")).toBe("test");
    expect(contextFor("__snapshots__/emails/Campaign.html")).toBe("test");
    expect(contextFor("frontend/User-test.tsx.snap")).toBe("test");
    expect(contextFor("e2e/src/server.e2e-spec.ts")).toBe("test");
    expect(contextFor("app/login.e2e-test.js")).toBe("test");
    expect(contextFor(".env.dist")).toBe("example");
    expect(contextFor("backend/.env.dist")).toBe("example");
    expect(contextFor("vibe/web/ios-app/NostrootsNativeTests/NostrootsNativeTests.swift")).toBe("test");
    expect(contextFor("ios/AppTests/a.swift")).toBe("test");
  });

  test("example and sample basenames are anchored; README only as README or README.<ext>", () => {
    for (const rel of ["a.example", "a.example.ts", "a.sample", "a.sample.json", "src/config.sample.yml", ".env.example"]) {
      expect(contextFor(rel), rel).toBe("example");
    }
    for (const rel of ["audio.sampler.ts", "x.sampleRate.ts", "x.examples.ts", "src/a.exampleUser.js", "READMEBuilder.ts", "src/READMEs.ts", "a.example.tar.gz"]) {
      expect(contextFor(rel), rel).toBeUndefined();
    }
    expect(contextFor("README")).toBe("docs");
    expect(contextFor("pkg/README.txt")).toBe("docs");
  });

  test("docs/, example/ and examples/ count only as the first path segment; test folders count anywhere", () => {
    expect(contextFor("docs/x.md")).toBe("docs");
    expect(contextFor("docs/guide/setup.txt")).toBe("docs");
    expect(contextFor("examples/basic/app.js")).toBe("example");
    expect(contextFor("example/app.js")).toBe("example");
    expect(contextFor("src/spec/a.ts")).toBe("test");
    expect(contextFor("packages/a/fixtures/b.ts")).toBe("test");
    for (const rel of ["app/docs/page.tsx", "src/pages/docs/index.tsx", "web/example/app.js", "packages/a/examples/b.js", "src/docs/a.ts"]) {
      expect(contextFor(rel), rel).toBeUndefined();
    }
    expect(contextFor("app/docs/guide.md")).toBe("docs"); // a Markdown file is documentation wherever it is
    // A Java package named `example` is production code (the Java AI eval corpus keeps its severities)...
    expect(contextFor("src/main/java/example/Agent.java")).toBeUndefined();
    // ...while Maven and Gradle test sources are test context.
    expect(contextFor("src/test/java/example/AgentTest.java")).toBe("test");
  });

  test("real env files and broad suffixes stay unclassified", () => {
    for (const rel of [
      ".env.development", ".env.production", ".env.local", "surveyadmin/.env.development",
      "src/Contests/a.ts", "src/contests/a.ts", "src/Tests/a.ts", "src/MyTESTS/a.ts", "src/Tests2/a.ts", "src/NativeTest/a.swift",
      "src/snapshots/a.js", "src/__snapshots/a.js", "a.snapshot", "src/e2e-spec.ts", "src/dist/.env", "app.dist.js",
    ]) expect(contextFor(rel), rel).toBeUndefined();
  });

  test("application source and look-alike names are not context", () => {
    for (const rel of [
      "src/app.ts", "src/contest/entry.ts", "src/latest.ts", "src/testimonials/list.tsx", "src/Tests/a.ts", "Test/a.ts",
      "src/Docs/a.ts", "src/readme.ts", "src/spec.ts", "src/test.ts", "src/mytest/a.ts", "src/auth.tests.ts", "config/recaptcha.php",
      ".env", "src/Examples/a.js", "src/specs/a.ts", "src/e2e/a.ts", "src/demo/a.ts", "src/sampler.ts",
    ]) expect(contextFor(rel), rel).toBeUndefined();
  });

  test("only target-relative paths are classified, never a parent folder outside the target", () => {
    for (const rel of ["/home/u/tests/app/src/a.ts", "../tests/a.ts", "C:/tests/a.ts", "tests\\a.ts", "src//tests/a.ts", ""]) {
      expect(contextFor(rel), rel).toBeUndefined();
    }
  });
});

describe("routeFindings — test/example context (tracked files, design §4.6)", () => {
  const sast = (file: string, over: Partial<Finding> = {}) => mk(file, {
    engine: "opengrep", engines: ["opengrep"], rule_id: "ci-baseline-dom-xss-innerhtml", cwe: ["CWE-79"],
    is_secret: false, finding_kind: "sast", severity: "high", confidence: "medium", ...over,
  });
  const tracked = () => "tracked" as const;

  test("generic Gitleaks rules and code findings are lowered with the label, never dropped", () => {
    const generic = mk("api/src/utils/get-cache-key.test.ts", { fingerprint: "fp-generic" });
    const header = mk("docs/api.md", { rule_id: "curl-auth-header" });
    const user = mk("README.md", { rule_id: "curl-auth-user" });
    const code = sast("src/promo.spec.js");
    const exampleCode = sast("examples/demo/app.js", { engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], finding_kind: "ai", cwe: ["CWE-94"] });
    const { findings, stats } = routeFindings([generic, header, user, code, exampleCode], tracked);
    expect(findings).toHaveLength(5);
    expect(findings.every((f) => f.severity === "low")).toBe(true);
    expect(findings.every((f) => f.title.startsWith("Test/example context — "))).toBe(true);
    expect(findings[0]!.fingerprint).toBe("fp-generic");
    expect(findings[0]!.rule_id).toBe("generic-api-key");
    expect(findings[0]!.is_secret).toBe(true);
    expect(findings[0]!.message).toContain("Test/example context");
    expect(stats.context_lowered).toBe(5);
    expect(stats.context_lowered_rules).toEqual({ "ci-baseline-dom-xss-innerhtml": 2, "curl-auth-header": 1, "curl-auth-user": 1, "generic-api-key": 1 });
    expect(stats.kept).toBe(0);
  });

  test("info stays info and an already-low finding is not relabelled", () => {
    const info = mk("test/a.js", { severity: "info" });
    const low = mk("test/b.js", { severity: "low" });
    const { findings, stats } = routeFindings([info, low], tracked);
    expect(findings.map((f) => [f.severity, f.title])).toEqual([["info", "Hard-coded secret"], ["low", "Hard-coded secret"]]);
    expect(stats.context_lowered).toBe(0);
  });

  test("deny by default: named-provider secrets keep their severity in every test/example/docs path", () => {
    const rules = [
      "aws-access-token", "gcp-api-key", "codeinspectus-stripe-live-secret", "stripe-access-token", "github-pat", "slack-bot-token",
      "private-key", "jwt", "openai-api-key", "some-future-gitleaks-rule", "generic-api-key-v2", "curl-auth-header-x",
    ];
    const all = rules.map((rule_id, i) => mk(`test/keys-${i}.ts`, { rule_id, severity: "critical" }));
    const { findings, stats } = routeFindings(all, tracked);
    expect(findings.map((f) => f.severity)).toEqual(rules.map(() => "critical"));
    expect(stats.context_lowered).toBe(0);
  });

  test("a generic rule name from another engine is not lowered", () => {
    const trivy = mk("test/a.ts", { engine: "trivy", engines: ["trivy"], rule_id: "generic-api-key" });
    const native = mk("test/b.ts", { engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], rule_id: "generic-api-key", finding_kind: "secret" });
    const { findings } = routeFindings([trivy, native], tracked);
    expect(findings.map((f) => f.severity)).toEqual(["high", "high"]);
  });

  test("vulnerability, malware, credential-class and unclassified findings in test paths are untouched", () => {
    const vuln = mk("test/package-lock.json", {
      engine: "trivy", engines: ["trivy"], rule_id: "CVE-2024-0001", is_secret: false, finding_kind: "vulnerability", severity: "critical",
    });
    const malware = mk("examples/package-lock.json", {
      engine: "osv-scanner", engines: ["osv-scanner"], rule_id: "MAL-2024-1", is_secret: false, finding_kind: "vulnerability", severity: "critical",
    });
    const credential = sast("test/env.js", {
      engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], rule_id: "ci-ai-public-env-secret", cwe: ["CWE-798"], finding_kind: "ai",
    });
    const unclassified = sast("test/other.js", { finding_kind: undefined });
    const all = [vuln, malware, credential, unclassified];
    const { findings, stats } = routeFindings(all, tracked);
    expect(findings.map((f) => f.severity)).toEqual(all.map((f) => f.severity));
    expect(stats.context_lowered).toBe(0);
  });

  test("a finding outside the context paths keeps its severity", () => {
    const { findings } = routeFindings([mk("src/config.ts"), sast("src/app.ts")], tracked);
    expect(findings.map((f) => f.severity)).toEqual(["high", "high"]);
  });

  test("ignored-file routing still wins over context", () => {
    const { findings, stats } = routeFindings([mk("test/.env.local")], () => "gitignored");
    expect(findings[0]!.title.startsWith("Local hygiene — ")).toBe(true);
    expect(stats.context_lowered).toBe(0);
  });

  test("third-party handling takes precedence over test context", () => {
    const { findings, stats } = routeFindings([sast("test/vendor/lib.js")], tracked);
    expect(findings).toHaveLength(0);
    expect(stats.third_party_code).toBe(1);
    expect(stats.context_lowered).toBe(0);
  });
});

describe("routeFindings — a test-file secret reused in application code keeps its severity", () => {
  const tracked = () => "tracked" as const;
  const HASH = "sha256:" + "a".repeat(64);
  const OTHER = "sha256:" + "b".repeat(64);

  test("the same generic secret in src/config.js and a test file: both keep their severity, the test copy says why", () => {
    const app = mk("src/config.js", { fingerprint: "fp-app", secret_value_hash: HASH });
    const test = mk("tests/fixtures/app.test.js", { fingerprint: "fp-test", secret_value_hash: HASH });
    const { findings, stats } = routeFindings([app, test], tracked);
    expect(findings.map((f) => [f.location.file, f.severity])).toEqual([["src/config.js", "high"], ["tests/fixtures/app.test.js", "high"]]);
    expect(findings[0]).toEqual(app);
    expect(findings[1]!.title).toBe("Hard-coded secret");
    expect(findings[1]!.message).toContain("same value also found in 1 non-test file(s): src/config.js");
    expect(stats.context_lowered).toBe(0);
    expect(stats.context_kept_reused).toBe(1);
  });

  test("only in the test file: the test copy is lowered, a different value elsewhere does not matter", () => {
    const test = mk("tests/fixtures/app.test.js", { secret_value_hash: HASH });
    const app = mk("src/config.js", { secret_value_hash: OTHER });
    const { findings, stats } = routeFindings([test, app], tracked);
    expect(findings.map((f) => f.severity)).toEqual(["low", "high"]);
    expect(findings[0]!.title.startsWith("Test/example context — ")).toBe(true);
    expect(stats.context_lowered).toBe(1);
    expect(stats.context_kept_reused).toBe(0);
  });

  test("the same value in two test files only is still lowered", () => {
    const a = mk("tests/a.test.js", { secret_value_hash: HASH });
    const b = mk("docs/guide.md", { secret_value_hash: HASH });
    const { findings, stats } = routeFindings([a, b], tracked);
    expect(findings.map((f) => f.severity)).toEqual(["low", "low"]);
    expect(stats.context_kept_reused).toBe(0);
  });

  test("any engine counts as the outside copy, and the outside copy may be a non-generic secret", () => {
    const test = mk("test/a.js", { secret_value_hash: HASH });
    const trivy = mk("src/b.js", { engine: "trivy", engines: ["trivy"], rule_id: "aws-access-key-id", secret_value_hash: HASH });
    const native = mk("src/c.js", { engine: "codeinspectus-ai", engines: ["codeinspectus-ai"], rule_id: "ci-ai-secret", finding_kind: "secret", secret_value_hash: HASH });
    const { findings, stats } = routeFindings([test, trivy, native], tracked);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.message).toContain("same value also found in 2 non-test file(s): src/b.js, src/c.js");
    expect(stats.context_kept_reused).toBe(1);
  });

  test("a copy in an ignored env file counts as outside; one in node_modules does not", () => {
    const test = mk("test/a.js", { secret_value_hash: HASH });
    const env = mk(".env.local", { secret_value_hash: HASH });
    const nm = mk("node_modules/dep/x.js", { secret_value_hash: HASH });
    const bucketOf = (rel: string) => rel === ".env.local" ? "gitignored" as const : rel.startsWith("node_modules/") ? "node_modules" as const : "tracked" as const;
    expect(routeFindings([test, env], bucketOf).findings[0]!.severity).toBe("high");
    expect(routeFindings([test, nm], bucketOf).findings[0]!.severity).toBe("low");
  });

  test("a test finding without a value hash is lowered as before", () => {
    const app = mk("src/config.js", { secret_value_hash: HASH });
    const test = mk("tests/app.test.js");
    const { findings, stats } = routeFindings([app, test], tracked);
    expect(findings.map((f) => f.severity)).toEqual(["high", "low"]);
    expect(stats.context_kept_reused).toBe(0);
  });

  test("a provider secret in a test file is never lowered, with or without reuse", () => {
    const test = mk("tests/a.test.js", { rule_id: "aws-access-token", severity: "critical", secret_value_hash: HASH });
    const { findings, stats } = routeFindings([test], tracked);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.message).not.toContain("same value");
    expect(stats.context_kept_reused).toBe(0);
  });

  test("a code finding in a test file is lowered even when a secret hash exists elsewhere", () => {
    const code = mk("test/a.js", { engine: "opengrep", engines: ["opengrep"], rule_id: "ci-baseline-dom-xss-innerhtml", cwe: ["CWE-79"], is_secret: false, finding_kind: "sast" });
    const app = mk("src/config.js", { secret_value_hash: HASH });
    expect(routeFindings([code, app], tracked).findings[0]!.severity).toBe("low");
  });

  test("the hash is never printed in the message", () => {
    const { findings } = routeFindings([mk("src/config.js", { secret_value_hash: HASH }), mk("test/a.js", { secret_value_hash: HASH })], tracked);
    expect(JSON.stringify(findings.map((f) => f.message + f.title))).not.toContain("aaaaaaaa");
  });
});

describe("routeScanFindings — context is relative to the target", () => {
  let parent: string;
  beforeAll(async () => {
    parent = await mkdtemp(join(tmpdir(), "ci-route-ctx-"));
    await mkdir(join(parent, "tests", "proj", "src"), { recursive: true });
  });
  afterAll(async () => {
    await rm(parent, { recursive: true, force: true }).catch(() => {});
  });

  test("a target that lives inside a tests/ folder does not make its own source test context", async () => {
    const target = join(parent, "tests", "proj");
    const { findings, stats } = await routeScanFindings([mk("src/config.ts"), mk("test/config.ts")], target);
    expect(findings.map((f) => [f.location.file, f.severity])).toEqual([["src/config.ts", "high"], ["test/config.ts", "low"]]);
    expect(stats.context_lowered).toBe(1);
  }, 60000);
});

describe("routeScanFindings — a redacted Gitleaks secret reused outside test context keeps its severity", () => {
  // Gitleaks runs with --redact=100, so its SARIF never carries the value: the reuse key is read back
  // from the source at the reported location. Values are assembled at run time (no secret-shaped literal).
  const value = ["Qm7ZpX2kL9vR4tY8", "wB3nC6dF1gH5jK0s"].join("");
  const other = ["Zt5YbN8cV2xK7mQ4", "pL1wR9sD3fG6hJ0a"].join("");
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ci-route-reuse-"));
    await mkdir(join(dir, "src"), { recursive: true });
    await mkdir(join(dir, "tests"), { recursive: true });
    await writeFile(join(dir, "src", "keys.ts"), `export const config = { api_key: "${value}" };\n`);
    await writeFile(join(dir, "tests", "keys.test.ts"), `// fixture\nconst apiKey = "${value}";\n`);
    await writeFile(join(dir, "tests", "only.test.ts"), `const apiKey = "${other}";\n`);
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("shared value: both keep severity; test-only value: lowered; no finding carries the key", async () => {
    // End columns as Gitleaks 8.30 reports them for these lines.
    const result = (file: string, line: number, endColumn: number) => ({
      ruleId: "generic-api-key",
      message: { text: `generic-api-key has detected secret for file ${file}.` },
      locations: [{ physicalLocation: { artifactLocation: { uri: join(dir, file) }, region: { startLine: line, startColumn: 1, endLine: line, endColumn, snippet: { text: "REDACTED" } } } }],
    });
    const findings = normalizeSarif({ runs: [{ tool: { driver: { name: "gitleaks", rules: [] } }, results: [
      result("src/keys.ts", 1, 67), result("tests/keys.test.ts", 2, 50), result("tests/only.test.ts", 1, 49),
    ] }] } as unknown as SarifLog, "gitleaks", dir);
    const { findings: routed, stats } = await routeScanFindings(findings, dir);
    expect(routed.map((f) => [f.location.file, f.severity])).toEqual([
      ["src/keys.ts", "high"], ["tests/keys.test.ts", "high"], ["tests/only.test.ts", "low"],
    ]);
    expect(routed[1]!.message).toContain("same value also found in 1 non-test file(s): src/keys.ts");
    expect(stats.context_kept_reused).toBe(1);
    expect(stats.context_lowered).toBe(1);
    expect(routed.every((f) => f.secret_value_hash === undefined)).toBe(true);
    expect(JSON.stringify(routed)).not.toContain(value);
  }, 60000);
});

describe("routeScanFindings — reads only scripts that carry code findings", () => {
  let dir: string;
  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "ci-route-thirdparty-"));
    await mkdir(join(dir, "public", "js"), { recursive: true });
    await writeFile(join(dir, "public", "js", "jquery.js"), `/* jQuery */\n!function(e,t){${"a.innerHTML=b;".repeat(3000)}}(window);\n`);
    await writeFile(join(dir, "public", "js", "widget.js"), "/*! Widget v1.0 | MIT */\n(function () {\n  el.innerHTML = html;\n})();\n");
    await writeFile(join(dir, "public", "js", "app.js"), "export function show(el, html) {\n  el.innerHTML = html;\n}\n");
    await writeFile(join(dir, "public", "js", "padded.js"), `export function show(el, html) {\n  el.innerHTML = html;\n}\n//${";".repeat(20_000)}\n`);
    await mkdir(join(dir, "public", "vendor"), { recursive: true });
    await writeFile(join(dir, "public", "vendor", "lib.js"), "el.innerHTML = html;\n");
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  });

  test("vendor/ is not reported; minified and bannered scripts are lowered; own and padded scripts are kept", async () => {
    const make = (file: string) => mk(file, {
      engine: "opengrep", engines: ["opengrep"], rule_id: "ci-baseline-dom-xss-innerhtml", is_secret: false, finding_kind: "sast",
      cwe: ["CWE-79"], fingerprint: `fp-${file}`,
    });
    const { findings, stats } = await routeScanFindings(
      [make("public/js/jquery.js"), make("public/js/widget.js"), make("public/js/app.js"), make("public/js/padded.js"), make("public/vendor/lib.js")], dir);
    expect(findings.map((f) => [f.location.file, f.severity])).toEqual([
      ["public/js/jquery.js", "low"], ["public/js/widget.js", "low"], ["public/js/app.js", "high"], ["public/js/padded.js", "high"],
    ]);
    expect(stats.third_party_files).toEqual(["public/vendor/lib.js"]);
    expect(stats.third_party_lowered_files).toEqual(["public/js/jquery.js", "public/js/widget.js"]);
  }, 60000);
});
