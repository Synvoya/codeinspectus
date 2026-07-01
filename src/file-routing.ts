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

import { basename } from "node:path";
import type { Finding, Severity } from "./types.js";
import { BUILD_DIRS } from "./config.js";
import { runGitRead } from "./util/git.js";
import { log } from "./logger.js";

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
}

/** Classify a finding's (relative, POSIX) path. Precedence: node_modules → build → ignored → tracked. */
export function bucketFor(rel: string, ignored: ReadonlySet<string>): FileBucket {
  const segs = rel.split("/");
  if (segs.includes("node_modules")) return "node_modules";
  if (segs.some((s) => BUILD_DIRS.has(s))) return "build_output";
  if (ignored.has(rel)) return "gitignored";
  return "tracked";
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
): { findings: Finding[]; stats: RouteStats } {
  const out: Finding[] = [];
  const stats: RouteStats = { dropped_node_modules: 0, dropped_build_noise: 0, reframed: 0, kept: 0 };

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
      case "tracked":
        out.push(f);
        stats.kept++;
        break;
    }
  }
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
  const routed = routeFindings(findings, (rel) => bucketFor(rel, ignored));
  log.debug(
    `file-routing: kept ${routed.stats.kept}, reframed ${routed.stats.reframed}, ` +
      `dropped ${routed.stats.dropped_node_modules} node_modules + ${routed.stats.dropped_build_noise} build-noise`,
  );
  return routed;
}
