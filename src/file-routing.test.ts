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
import {
  bucketFor,
  routeFindings,
  reframeLocalHygiene,
  gitIgnoredSet,
  routeScanFindings,
  BUILD_DIRS,
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
