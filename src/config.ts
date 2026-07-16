/**
 * Central configuration constants.
 *
 * The MCP spec version is isolated behind a single constant (PRD §0.3) so that
 * re-targeting a future spec is a one-line change.
 *
 * Pinned engine versions feed both the download URLs (install-engines) and the
 * SHA-pin lockfile (engines.lock.json). Bumping a version means re-running
 * install-engines, re-verifying the SHA256, and committing the new lockfile.
 *
 * // VERIFY: engine versions below are the PRD-referenced values; confirm each
 * // against the upstream GitHub Releases page at build time.
 */

import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

// ── MCP ────────────────────────────────────────────────────────────────────
// Build against current stable spec. A 2026-07-28 RC exists but is not final
// (PRD §0.3). Do not target the RC.
export const MCP_SPEC_VERSION = "2025-11-25";

export const SERVER_NAME = "codeinspectus";
export const SERVER_VERSION = "0.3.1";

// ── Bundled engine versions (SHA-pinned in engines.lock.json) ───────────────
export const ENGINE_VERSIONS = {
  // Verified against upstream GitHub Releases API on 2026-06-21.
  opengrep: "1.23.0", // PRD said 1.21.0 (stale); 1.23.0 is latest stable.
  gitleaks: "8.30.1", // matches PRD.
  trivy: "0.71.2", // PRD said 0.71.1; 0.71.2 is latest. NEVER 0.69.4–0.69.6 (compromised).
} as const;

export type EngineName = "opengrep" | "gitleaks" | "trivy";

// CodeInspectus's own analyzer "engine" version (the AI-code checks, §6).
export const CODEINSPECTUS_AI_VERSION = "1.0.0";

// ── Managed directories (per-machine, never per-repo) ───────────────────────
// PRD §12: an MCP server is installed once per machine, not per repo.
export const MANAGED_ROOT = join(homedir(), ".codeinspectus");
export const MANAGED_BIN = join(MANAGED_ROOT, "bin");
export const MANAGED_TRIVY_CACHE = join(MANAGED_ROOT, "trivy-cache");
export const MANAGED_SCANS = join(MANAGED_ROOT, "scans");
export const MANAGED_PROVENANCE = join(MANAGED_ROOT, "provenance");
export const MANAGED_TRIVY_DB_META = join(MANAGED_TRIVY_CACHE, "db", "metadata.json");

// ── Package-root-relative asset resolution ──────────────────────────────────
// At runtime the bundle lives at <pkg>/dist/index.js; data/ and detection-db/
// sit at <pkg>/. Resolve them relative to this module, with a dev fallback.
function packageRoot(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // dist/index.js → dist → <pkg>. In dev (tsx) this is src → <pkg>.
    return join(here, "..");
  } catch {
    return process.cwd();
  }
}

export const PKG_ROOT = packageRoot();
export const DATA_DIR = join(PKG_ROOT, "data");
export const DETECTION_DB_DIR = join(PKG_ROOT, "detection-db");
export const OPENGREP_RULES_DIR = join(DETECTION_DB_DIR, "opengrep-rules");
export const GITLEAKS_CONFIG = join(DETECTION_DB_DIR, "gitleaks", "codeinspectus.toml");
export const ENGINES_LOCKFILE = join(PKG_ROOT, "engines.lock.json");

// ── Subprocess limits ───────────────────────────────────────────────────────
export const ENGINE_TIMEOUT_MS = 1000 * 60 * 5; // 5 min hard cap per engine
export const MAX_BUFFER_BYTES = 1024 * 1024 * 256; // 256 MB stdout cap

// ── Build-output directories ────────────────────────────────────────────────
// Single source of truth (CG-30): walk-skip, the §6.1 bundle-secret check, and git-aware
// file routing all share this set. These dirs are git-ignored but SHIPPED to the browser,
// so the bundle-secret check still fires there. Sensible, NON-exhaustive known list
// (Next/Vite/Nuxt/SvelteKit/Astro/Jekyll/Eleventy/Storybook/Expo output) — extend as needed.
// CG-31: name-based build-dir detection is inherently imperfect — ambiguous names that are
// SOURCE in one framework and OUTPUT in another (notably `public/` — source in Next/CRA,
// build output in Gatsby/Hugo) are deliberately NOT listed; for those, git-status is the
// signal (a git-ignored `public/` is handled by the gitignored bucket).
export const BUILD_DIRS: ReadonlySet<string> = new Set([
  ".next",
  "dist",
  "build",
  "out",
  ".nuxt",
  ".svelte-kit",
  ".output",
  "_site", // Jekyll / Eleventy default output
  "storybook-static", // Storybook static build
  "web-build", // Expo / React Native web export
]);

// ── Output defaults ─────────────────────────────────────────────────────────
export const DEFAULT_MAX_FINDINGS = 200;

export const STANDING_DISCLAIMER =
  "AI-drafted, reviewed by a cybersecurity practitioner (Synvoya) — code-level coverage only, not an audit or certification. Community review welcome.";
