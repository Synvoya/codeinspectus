/**
 * CG-30 — Git-aware file routing (Option B): decide SEVERITY and FRAMING by WHERE a
 * finding lives, not by a blunt include/exclude. The CI-03 dogfood produced ~170 "high"
 * secrets in git-ignored build output and *.bak backups, burying the one real committed
 * critical — the CG-18-class signal-burial problem coming from scanning the wrong FILES.
 *
 * "Git-ignored = safe" is dangerously wrong, so we do NOT just exclude git-ignored files:
 *   - node_modules/                  → DROP (not the user's code, not shipped as theirs).
 *   - build output (.next, dist, …)  → keep STRUCTURED secrets from ANY engine (the §6.1
 *                                       check + a fail-closed allow-list of named-provider
 *                                       secret rules), labelled "shipped to browser"; drop
 *                                       generic-entropy / public-by-design / non-secret noise.
 *   - git-ignored source/backup      → DOWNGRADE + REFRAME as local-hygiene (still visible,
 *                                       clearly lower urgency than a committed leak).
 *   - tracked / committed source     → UNCHANGED (a committed .env is still a real leak —
 *                                       this keys on git STATUS, not the .env filename).
 *
 * Classification is engine-agnostic: it runs over the merged finding list before dedup, so
 * Gitleaks / Trivy / Opengrep / AI findings are all routed by the same rule.
 */

import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { basename, join } from "node:path";
import type { Finding, Severity } from "./types.js";
import { BUILD_DIRS } from "./config.js";
import { runGitRead } from "./util/git.js";
import { log } from "./logger.js";
import { secretMatchKeys } from "./secret-match-key.js";

export { BUILD_DIRS };

export type FileBucket = "node_modules" | "build_output" | "gitignored" | "tracked";

export interface RouteStats {
  /** Findings in node_modules, dropped entirely. */
  dropped_node_modules: number;
  /** Commodity-engine findings in build output, dropped (only §6.1 bundle check kept). */
  dropped_build_noise: number;
  /** Git-ignored findings downgraded + reframed as local-hygiene (still surfaced). */
  reframed: number;
  /** Findings kept as-is (tracked) or kept-with-label (build bundle). */
  kept: number;
  /**
   * Design §10.6: code findings (Opengrep and native code checks only; never secrets, CWE-798-class
   * findings or dependency findings) in the scope Opengrep's own default ignore list already skips by
   * path: a `vendor/` folder (case-sensitive, as Opengrep matches it) or a `*.min.js` name. Not
   * reported; disclosed as an informational coverage note.
   */
  third_party_code: number;
  /** The files behind `third_party_code`. */
  third_party_files: string[];
  /**
   * Code findings in scripts whose third-party evidence is inferred from content or a folder name (a
   * preserved banner, a UMD wrapper, a minified body, a `vendors/`-style folder): reported at low
   * severity with a "Third-party code" label. File content never removes a finding.
   */
  third_party_lowered: number;
  /** The files behind `third_party_lowered`. */
  third_party_lowered_files: string[];
  /**
   * Design §4.6: generic secrets (Gitleaks `generic-api-key`, `curl-auth-header`, `curl-auth-user`) and
   * generic code findings in test, fixture, example or documentation files, reported at low severity
   * with a "Test/example context" label. Never dropped.
   */
  context_lowered: number;
  /** `context_lowered` by rule id, for the coverage note. */
  context_lowered_rules: Record<string, number>;
  /**
   * Test, example or documentation secrets that would have been lowered but kept their severity
   * because the same value (by `secret_value_hash`) is also reported in a file outside that context.
   */
  context_kept_reused: number;
}

export interface FileClass {
  /**
   * `vendor` and `min-name` (`*.min.js`) match Opengrep's own path skip scope (dropped); `minified`,
   * `library` (banner or UMD wrapper) and `vendors` (a third-party-looking folder) are inferred from
   * content or names the repository controls (lowered, never dropped).
   */
  third_party?: "vendor" | "min-name" | "minified" | "library" | "vendors";
  /** Set when the file is in a test, fixture, example or documentation context (design §4.6). */
  context?: FileContext;
}

/** Where a tracked file sits for context routing: tests and fixtures, examples and templates, or docs. */
export type FileContext = "test" | "example" | "docs";

/** Classify a finding's (relative, POSIX) path. Precedence: node_modules → build → ignored → tracked. */
export function bucketFor(rel: string, ignored: ReadonlySet<string>): FileBucket {
  const segs = rel.split("/");
  if (segs.includes("node_modules")) return "node_modules";
  if (segs.some((s) => BUILD_DIRS.has(s))) return "build_output";
  if (ignored.has(rel)) return "gitignored";
  return "tracked";
}

// ── Precision routing: vendored and minified third-party scripts (design §10.6) ────────────────────

/**
 * Folders that usually hold copied libraries (`includes/vendors/`, `src/vendors/`). Only inferred
 * evidence: a project may name its own code this way, so findings there are lowered, not dropped.
 * Case-sensitive: Laravel's `app/Http/Controllers/Vendor/` is first-party code.
 */
const THIRD_PARTY_LIKE_DIRS: ReadonlySet<string> = new Set([
  "vendors", "third_party", "third-party", "thirdparty", "bower_components", "jspm_packages",
]);

/** A target-relative POSIX path the router may classify; an absolute or escaping path is never classified. */
function relativeSegments(rel: string): string[] | undefined {
  if (rel === "" || rel.startsWith("/") || /^[A-Za-z]:[\\/]/.test(rel) || rel.includes("\\")) return undefined;
  const segs = rel.split("/");
  if (segs.some((s) => s === ".." || s === "")) return undefined;
  return segs;
}

// ── Test, fixture, example and documentation context (design §4.6) ────────────────────────────────

/** Test folders, matched exactly and case-sensitively on any target-relative path segment. */
const TEST_DIRS: ReadonlySet<string> = new Set(["test", "tests", "__tests__", "__snapshots__", "spec", "fixtures"]);
/** Xcode-style test targets (`NostrootsNativeTests/`): a lowercase letter, then a capital-T `Tests`; never `Contests/`. */
const TEST_TARGET_DIR = /^[A-Za-z0-9_]*[a-z]Tests$/;
/** `<name>.example`, `<name>.example.<ext>`, `<name>.sample`, `<name>.sample.<ext>`; not `x.sampler.ts` or `x.examples.ts`. */
const EXAMPLE_BASENAME = /\.(?:example|sample)(?:\.[A-Za-z0-9]+)?$/;
/** `README` or `README.<ext>`; not `READMEBuilder.ts`. */
const README_BASENAME = /^README(?:\.[A-Za-z0-9]+)?$/;

/**
 * Classify a finding's file as test, example or documentation context by its target-relative path
 * alone. Folders are exact, case-sensitive segments: `test/`, `tests/`, `__tests__/`, `__snapshots__/`,
 * `spec/`, `fixtures/` and Xcode-style `<Name>Tests/` anywhere; `docs/`, `examples/` and `example/` only as
 * the first segment (repository root), so an application route such as `app/docs/` keeps its severity.
 * Basenames: `*.test.*`, `*.spec.*`, `*.e2e-spec.*`, `*.e2e-test.*`, `*.snap`, `<name>.example[.<ext>]`,
 * `<name>.sample[.<ext>]`, `.env.dist`, `README[.<ext>]` and `*.md`. A real env file such as
 * `.env.development` is never context. A parent folder outside the target is never seen: an absolute
 * or escaping path is not classified.
 */
export function contextFor(rel: string): FileContext | undefined {
  const segs = relativeSegments(rel);
  if (!segs) return undefined;
  const base = segs[segs.length - 1]!;
  const dirs = segs.slice(0, -1);
  if (dirs.some((dir) => TEST_DIRS.has(dir) || TEST_TARGET_DIR.test(dir))) return "test";
  if (/\.(?:test|spec|e2e-spec|e2e-test)\./.test(base) || base.endsWith(".snap")) return "test";
  if (dirs[0] === "docs") return "docs";
  if (dirs[0] === "examples" || dirs[0] === "example") return "example";
  if (EXAMPLE_BASENAME.test(base) || base === ".env.dist") return "example";
  if (README_BASENAME.test(base) || base.endsWith(".md")) return "docs";
  return undefined;
}

/**
 * Third-party evidence from the path alone. `vendor` is exactly Opengrep's own skip (`vendor/`,
 * case-sensitive); `vendors` covers the third-party-looking folders, which are inferred only.
 */
export function vendoredPath(rel: string): "vendor" | "vendors" | undefined {
  const segs = relativeSegments(rel);
  if (!segs) return undefined;
  const dirs = segs.slice(0, -1);
  if (dirs.includes("vendor")) return "vendor";
  if (dirs.some((s) => THIRD_PARTY_LIKE_DIRS.has(s))) return "vendors";
  return undefined;
}

/** `*.min.js`, which Opengrep's default ignore list skips by name. */
function minifiedName(rel: string): boolean {
  return /\.min\.(?:js|mjs|cjs)$/.test(rel) && relativeSegments(rel) !== undefined;
}

const SCRIPT_EXT = /\.(?:js|mjs|cjs)$/i;
/** A line this long is never written by hand. */
const MINIFIED_LINE = 20_000;
/** A long line in a file whose lines average this long is minified output. */
const LONG_LINE = 1_000;
const DENSE_AVERAGE = 200;
/** Minified long lines must carry this share of the file's bytes, so one padded line cannot qualify. */
const DENSE_SHARE = 0.8;
/**
 * Minified code is punctuation-dense; a base64 or data-URI constant is not. A long line counts only
 * when at least one in 100 of its characters is `;`, `{`, `}` or `(`.
 */
function codeDense(line: string): boolean {
  let marks = 0;
  for (const ch of line) if (ch === ";" || ch === "{" || ch === "}" || ch === "(") marks++;
  return marks * 100 >= line.length;
}

/**
 * Third-party evidence in a script's leading text: a minified body, a preserved library banner
 * (`/*!` first, or `@license` in the first comment) or a UMD wrapper. A project's own header
 * ("For the full copyright and license information…") is not a banner: it has no `@license` tag.
 */
export function thirdPartyText(text: string): FileClass["third_party"] {
  const head = text.slice(0, 4096).replace(/^﻿/, "").replace(/^#![^\n]*\n/, "").trimStart();
  if (head.startsWith("/*!")) return "library";
  const firstComment = /^\/\*[\s\S]*?\*\//.exec(head)?.[0] ?? "";
  if (/@license\b/.test(firstComment) || /@preserve\b/.test(firstComment)) return "library";
  if (/typeof\s+define\s*={2,3}\s*["']function["']/.test(head) && /define\.amd/.test(head) &&
    /typeof\s+(?:exports|module)\s*={2,3}\s*["']object["']|["']object["']\s*={2,3}\s*typeof\s+(?:exports|module)/.test(head)) {
    return "library";
  }
  // Comment lines never count (one appended `//;;;;…` line must not make a project file "minified"),
  // and the long, dense code lines must hold most of the file's bytes.
  let longestDense = 0;
  let denseBytes = 0;
  let lines = 0;
  for (const line of text.split("\n")) {
    lines++;
    const code = line.trimStart();
    if (code.startsWith("//") || code.startsWith("/*") || code.startsWith("*")) continue;
    if (line.length >= LONG_LINE && codeDense(line)) {
      denseBytes += line.length;
      if (line.length > longestDense) longestDense = line.length;
    }
  }
  if (longestDense < LONG_LINE || denseBytes < DENSE_SHARE * text.length) return undefined;
  if (longestDense >= MINIFIED_LINE || text.length / Math.max(lines, 1) >= DENSE_AVERAGE) return "minified";
  return undefined;
}

/** Credential-class weaknesses: a native check can report them with `finding_kind: "ai"` and no `is_secret`. */
const CREDENTIAL_CWES: ReadonlySet<string> = new Set(["CWE-798", "CWE-312", "CWE-321", "CWE-522", "CWE-256", "CWE-259"]);

/**
 * Code findings: what SAST precision routing applies to. Deny by default: only an Opengrep or native
 * finding explicitly classified sast/ai, not a secret and not credential-class (e.g. native
 * ci-ai-public-env-secret / ci-ai-llm-key-browser-exposed, CWE-798). Secrets, dependency and
 * unclassified findings are never routed.
 */
function isCodeFinding(f: Finding): boolean {
  if (f.is_secret === true) return false;
  if (f.engine !== "opengrep" && f.engine !== "codeinspectus-ai") return false;
  if (f.finding_kind !== "sast" && f.finding_kind !== "ai") return false;
  return !f.cwe.some((cwe) => CREDENTIAL_CWES.has(cwe));
}

/**
 * §4.6, deny by default: only Gitleaks' generic, provider-less rules are lowered in test/example/docs
 * files. Every named-provider rule (AWS, GCP, Stripe, GitHub, Slack, private keys, JWT, CodeInspectus'
 * own provider rules, and any rule added later) keeps its severity everywhere.
 */
const LOWERABLE_SECRET_RULES: ReadonlySet<string> = new Set(["generic-api-key", "curl-auth-header", "curl-auth-user"]);
function isLowerableSecret(f: Finding): boolean {
  return f.is_secret === true && f.engine === "gitleaks" && LOWERABLE_SECRET_RULES.has(f.rule_id);
}

const CONTEXT_PREFIX = "Test/example context — ";
const CONTEXT_WORDS: Record<FileContext, string> = {
  test: "a test or fixture file",
  example: "an example or template file",
  docs: "a documentation file",
};

const REUSE_FILES_SHOWN = 3;

/** Keep a test/example secret at full severity and say where else the same value was found (paths only, never the value). */
function noteReusedSecret(f: Finding, files: ReadonlySet<string>): Finding {
  const sorted = [...files].sort();
  const shown = sorted.slice(0, REUSE_FILES_SHOWN).join(", ") + (sorted.length > REUSE_FILES_SHOWN ? ` and ${sorted.length - REUSE_FILES_SHOWN} more` : "");
  return {
    ...f,
    message: `${f.message} Test/example context not applied: the same value also found in ${sorted.length} non-test file(s): ${shown}. ` +
      "A secret reused in a test is still a live secret; rotate it at the provider.",
  };
}

/** Lower a finding that sits in a test, example or documentation file. Fingerprint and rule id are kept. */
export function reframeContext(f: Finding, context: FileContext): Finding {
  return {
    ...f,
    severity: f.severity === "info" ? "info" : "low",
    title: f.title.startsWith(CONTEXT_PREFIX) ? f.title : CONTEXT_PREFIX + f.title,
    message: `${f.message} Test/example context: this is in ${CONTEXT_WORDS[context]}, so it is reported at low severity; ` +
      "confirm the value or code is not used by the application before dismissing it.",
  };
}

const THIRD_PARTY_PREFIX = "Third-party code — ";

/** Lower a code finding in a script that looks like a copied library; it stays reported. */
export function reframeThirdParty(f: Finding): Finding {
  return {
    ...f,
    severity: f.severity === "info" ? "info" : "low",
    title: f.title.startsWith(THIRD_PARTY_PREFIX) ? f.title : THIRD_PARTY_PREFIX + f.title,
    message: `${f.message} This file looks like a copied third-party library (a preserved licence banner, a UMD ` +
      "wrapper, a minified body or a vendors-style folder), so the finding is reported at low severity; update or replace the library " +
      "rather than patching it, and confirm it is not the project's own code.",
  };
}

/**
 * CG-31 — high-impact, UNAMBIGUOUS server-secret rule families kept in build output (shipped
 * to the browser). FAIL-CLOSED allow-list: an unknown or public-by-design rule_id (Mapbox
 * `pk.`, Sentry DSN, analytics write keys, Stripe publishable `pk_`, Firebase `AIza`, anon
 * JWT, generic-entropy) is NOT listed → dropped, so a newly-added gitleaks default rule can
 * never silently become a "shipped to browser" false positive (a deny-list would fail open).
 * The collision-prone classes (gcp-api-key/AIza, jwt/jwt-token, the supabase keyword-JWT rule,
 * and gitleaks' default stripe-access-token which also matches publishable `pk_`) are
 * deliberately ABSENT — the value-decoding §6.1 AI check is their authority. Re-audit this
 * list on every gitleaks ruleset bump (the default corpus is not vendored).
 */
const BUILD_KEEP_SECRET_RULES: RegExp[] = [
  /^aws-/i, // aws-access-token, aws-secret-...
  /^github/i, // github-pat / -app-token / -fine-grained-pat / gho_ / ghr_ ...
  /^gitlab/i, // gitlab-pat (glpat-)
  /^sendgrid/i,
  /^twilio/i,
  /^slack/i, // slack bot/user/app/webhook tokens (all sensitive)
  /^openai/i, // openai-api-key (sk-...)
  /^anthropic/i,
  /^mailgun/i,
  /^npm/i, // npm-access-token (npm_...)
  /^private-key$/i, // PEM private-key block
  /^codeinspectus-stripe-live-secret$/i, // sk_/rk_live (precise; default stripe-access-token is NOT kept)
  /^codeinspectus-supabase-secret-key$/i, // sb_secret_ is elevated; sb_publishable_ never matches
  /^codeinspectus-anthropic-key$/i,
];

function isStructuredProviderSecret(ruleId: string): boolean {
  return BUILD_KEEP_SECRET_RULES.some((re) => re.test(ruleId));
}

/** Keep a finding in build output: the §6.1 AI check (FP-managed by its own allowlist), or a
 * structured named-provider secret from ANY engine. Everything else (generic-entropy, public-
 * by-design, collision-prone, non-secret SCA/IaC/SAST) is dropped. */
function keepInBuildOutput(f: Finding): boolean {
  if (f.engine === "codeinspectus-ai") return true;
  return f.is_secret === true && isStructuredProviderSecret(f.rule_id);
}

/** Add a "shipped to browser" label to a kept build-output finding if it doesn't already say so. */
function labelBuildOutput(f: Finding): Finding {
  const blob = `${f.title} ${f.message}`.toLowerCase();
  if (/build output|shipped|bundle/.test(blob)) return f;
  return {
    ...f,
    message: `${f.message} (Detected in build output — this file is shipped to the browser.)`,
  };
}

const REFRAME_PREFIX = "Local hygiene — ";

/**
 * Reframe a git-ignored finding as local-hygiene: it is on local disk but NOT committed to
 * the repo, so it is not leaked/shipped via version control. Downgrade urgency and reword;
 * never silently drop. Preserves fingerprint / rule_id / location / is_secret so rescan and
 * redaction are unaffected.
 */
export function reframeLocalHygiene(f: Finding): Finding {
  const severity: Severity = f.severity === "info" ? "info" : "low";
  const title = f.title.startsWith(REFRAME_PREFIX) ? f.title : REFRAME_PREFIX + f.title;
  if (f.finding_kind === "vulnerability") {
    return {
      ...f,
      severity,
      title,
      message:
        `${f.message} This lockfile is git-ignored, so the dependency state is local and is not ` +
        "committed via this repository; confirm whether the deployed build resolves the same version.",
      remediation: {
        ...f.remediation,
        summary:
          "Local dependency hygiene: upgrade or remove the affected package, regenerate the lockfile, and verify the deployed dependency resolution.",
      },
    };
  }
  return {
    ...f,
    severity,
    title,
    message:
      `${f.message} This file is git-ignored, so it is NOT committed to your repository and is not shipped via version control — ` +
      `lower urgency than a committed leak. Don't commit it; delete stale backups (e.g. *.bak) and rotate the value if it was ever shared.`,
    remediation: {
      ...f.remediation,
      summary:
        "Local hygiene (not a repo leak): keep this file out of git (it already is), delete stale backups, and rotate the value if it was ever shared.",
    },
  };
}

/**
 * Route a merged finding list. Pure: takes a classifier so it is unit-testable without git.
 * Run BEFORE dedup so severity-first dedup (CG-24) operates on the corrected severities.
 */
export function routeFindings(
  findings: Finding[],
  bucketOf: (rel: string) => FileBucket,
  classOf: (rel: string) => FileClass = (rel) => {
    const third = vendoredPath(rel) ?? (minifiedName(rel) ? "min-name" as const : undefined);
    const context = contextFor(rel);
    return { ...(third ? { third_party: third } : {}), ...(context ? { context } : {}) };
  },
  /** The value key a secret is matched on for reuse; routing-only keys for redacted engines come from the caller. */
  reuseKeyOf: (f: Finding) => string | undefined = (f) => f.secret_value_hash,
): { findings: Finding[]; stats: RouteStats } {
  const out: Finding[] = [];
  const stats: RouteStats = {
    dropped_node_modules: 0, dropped_build_noise: 0, reframed: 0, kept: 0,
    third_party_code: 0, third_party_files: [], third_party_lowered: 0, third_party_lowered_files: [],
    context_lowered: 0, context_lowered_rules: {}, context_kept_reused: 0,
  };
  // Secret values (by hash, any engine) that are also reported outside test/example/docs context.
  const outsideContext = new Map<string, Set<string>>();
  for (const f of findings) {
    const key = reuseKeyOf(f);
    if (!key || bucketOf(f.location.file) === "node_modules" || classOf(f.location.file).context) continue;
    const files = outsideContext.get(key) ?? new Set<string>();
    files.add(f.location.file);
    outsideContext.set(key, files);
  }
  const thirdPartyFiles = new Set<string>();
  const loweredFiles = new Set<string>();

  for (const f of findings) {
    switch (bucketOf(f.location.file)) {
      case "node_modules":
        stats.dropped_node_modules++;
        break;
      case "build_output":
        if (keepInBuildOutput(f)) {
          out.push(labelBuildOutput(f)); // §6.1 or a structured provider secret, shipped to browser
          stats.kept++;
        } else {
          stats.dropped_build_noise++; // generic-entropy / public-by-design / non-secret noise
        }
        break;
      case "gitignored":
        out.push(reframeLocalHygiene(f));
        stats.reframed++;
        break;
      case "tracked": {
        const fileClass = classOf(f.location.file);
        const third = fileClass.third_party;
        if ((third === "vendor" || third === "min-name") && isCodeFinding(f)) {
          stats.third_party_code++;
          thirdPartyFiles.add(f.location.file);
        } else if ((third === "minified" || third === "library" || third === "vendors") && isCodeFinding(f)) {
          out.push(reframeThirdParty(f));
          stats.third_party_lowered++;
          loweredFiles.add(f.location.file);
        } else if (fileClass.context && isLowerableSecret(f) && outsideContext.has(reuseKeyOf(f) ?? "")) {
          out.push(noteReusedSecret(f, outsideContext.get(reuseKeyOf(f)!)!));
          stats.context_kept_reused++;
          stats.kept++;
        } else if (fileClass.context && (isCodeFinding(f) || isLowerableSecret(f)) && f.severity !== "low" && f.severity !== "info") {
          out.push(reframeContext(f, fileClass.context));
          stats.context_lowered++;
          stats.context_lowered_rules[f.rule_id] = (stats.context_lowered_rules[f.rule_id] ?? 0) + 1;
        } else {
          out.push(f);
          stats.kept++;
        }
        break;
      }
    }
  }
  stats.third_party_files = [...thirdPartyFiles].sort();
  stats.third_party_lowered_files = [...loweredFiles].sort();
  return { findings: out, stats };
}

// ── git classification (impure) ──────────────────────────────────────────────

const BACKUP_BASENAME_RE = /(\.bak|\.orig|\.swp|~)$/i;
/** .env, .env.local, .env.local.bak … but NOT .env.example / .sample / .template (meant to be committed). */
function looksLikeEnvOrBackup(rel: string): boolean {
  const base = basename(rel);
  if (/\.(example|sample|template|dist)$/i.test(base)) return false;
  if (BACKUP_BASENAME_RE.test(base)) return true;
  return base === ".env" || base.startsWith(".env.");
}

/** Non-repo fallback: derive a git-ignored-equivalent set from filename heuristics. */
function heuristicIgnored(relPaths: string[]): Set<string> {
  return new Set(relPaths.filter(looksLikeEnvOrBackup));
}

/**
 * The subset of relPaths that git treats as ignored, computed in ONE batched subprocess
 * (`git check-ignore --stdin`) — never per-file. Default (index-aware) mode is deliberate:
 * a TRACKED file that also matches a .gitignore pattern (e.g. a committed .env) is NOT
 * reported as ignored, so it keeps full severity. Outside a git repo (or if git is
 * unavailable), falls back to filename heuristics for *.bak / .env*.
 */
export async function gitIgnoredSet(target: string, relPaths: string[]): Promise<Set<string>> {
  if (relPaths.length === 0) return new Set();
  const parse = (stdout: string): Set<string> =>
    new Set(stdout.split("\n").map((s) => s.trim()).filter(Boolean));
  try {
    // Read-only: `git check-ignore --stdin` fed newline-delimited paths (CG-41 shared git layer).
    const { code, stdout } = await runGitRead(target, ["check-ignore", "--stdin"], relPaths.join("\n"));
    // Exit 0 (≥1 ignored) or 1 (none ignored) are both valid repo answers → trust stdout.
    if (code === 0 || code === 1) return parse(stdout);
    // Exit 128 (not a git repo) / anything else → filename-heuristic fallback.
    return heuristicIgnored(relPaths);
  } catch {
    // git not installed / could not spawn → filename-heuristic fallback.
    return heuristicIgnored(relPaths);
  }
}

/**
 * Classify every finding's file via git (batched) and route. The git-aware entry point the
 * scan orchestrator calls. Only paths that actually have findings are classified (bounded by
 * finding count, not repo size).
 */
export async function routeScanFindings(
  findings: Finding[],
  target: string,
): Promise<{ findings: Finding[]; stats: RouteStats }> {
  const uniquePaths = [...new Set(findings.map((f) => f.location.file))];
  const ignored = await gitIgnoredSet(target, uniquePaths);
  const codePaths = [...new Set(findings.filter(isCodeFinding).map((f) => f.location.file))];
  const thirdParty = await thirdPartyScripts(target, codePaths);
  // Gitleaks and Trivy withhold the secret value; read it back (bounded) for the reuse check only.
  const matchKeys = await secretMatchKeys(target, findings);
  const routed = routeFindings(findings, (rel) => bucketFor(rel, ignored), (rel) => {
    // Opengrep's path scope first (vendor/, *.min.js: dropped), then inferred evidence (lowered).
    const path = vendoredPath(rel);
    const third = path === "vendor" ? "vendor" as const
      : minifiedName(rel) ? "min-name" as const
        : thirdParty.get(rel) ?? path;
    const context = contextFor(rel);
    return { ...(third ? { third_party: third } : {}), ...(context ? { context } : {}) };
  }, (f) => f.secret_value_hash ?? matchKeys.get(f));
  log.debug(
    `file-routing: kept ${routed.stats.kept}, reframed ${routed.stats.reframed}, ` +
      `dropped ${routed.stats.dropped_node_modules} node_modules + ${routed.stats.dropped_build_noise} build-noise, ` +
      `third-party code ${routed.stats.third_party_code} not reported, ${routed.stats.third_party_lowered} lowered, ` +
      `context-lowered ${routed.stats.context_lowered}`,
  );
  return routed;
}

/** Bytes read per script for third-party evidence; a minified bundle shows it well before this. */
const THIRD_PARTY_READ_BYTES = 512 * 1024;
/** Scripts with code findings that are inspected per scan (bounded by finding count, not repo size). */
const MAX_THIRD_PARTY_PROBES = 2_000;

/**
 * Read-only, bounded: the leading text of each script that carries a code finding, checked for
 * minified or library evidence. A symbolic link, non-regular or unreadable file is left unclassified,
 * so its findings stay reported.
 */
async function thirdPartyScripts(target: string, relPaths: string[]): Promise<Map<string, NonNullable<FileClass["third_party"]>>> {
  const result = new Map<string, NonNullable<FileClass["third_party"]>>();
  const candidates = relPaths
    .filter((rel) => SCRIPT_EXT.test(rel) && relativeSegments(rel) !== undefined && vendoredPath(rel) !== "vendor" && !minifiedName(rel))
    .slice(0, MAX_THIRD_PARTY_PROBES);
  for (const rel of candidates) {
    const path = join(target, ...rel.split("/"));
    try {
      const info = await lstat(path);
      if (!info.isFile()) continue;
      const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
      try {
        const buffer = Buffer.alloc(Math.min(info.size, THIRD_PARTY_READ_BYTES));
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
        const kind = thirdPartyText(buffer.subarray(0, bytesRead).toString("utf8"));
        if (kind) result.set(rel, kind);
      } finally {
        await handle.close();
      }
    } catch {
      // Unreadable: no evidence, so the file's findings are routed as the project's own code.
    }
  }
  return result;
}
