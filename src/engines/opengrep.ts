/**
 * Opengrep wrapper — SAST / OWASP Top 10 (PRD §4.1). Fully offline: self-
 * contained binary + local rule files. Emits SARIF 2.1.0.
 *
 * We point Opengrep at the bundled rules directory (CodeInspectus custom AI-code
 * rules + any vendored security-registry rules). We do NOT use `--config auto`
 * or registry packs, which would require network and break zero-egress.
 */

import { readFile, access, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { BUILD_DIRS, DETECTION_DB_DIR, MANAGED_OPENGREP_CACHE, OPENGREP_RULES_DIR } from "../config.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";
import { invocationSignature, rulesetSignature, signature } from "../provenance.js";
import { opengrepFileCoverage } from "./opengrep-coverage.js";
import { engineWorkingDirectory } from "./target.js";

/**
 * Opengrep 1.33.1 reads `.semgrepignore` from its working directory, and a file there replaces its
 * default ignore list, so a scanned repository could remove `src/` from SAST. Its patterns are anchored
 * at the working directory: running elsewhere would match the defaults (`build/`, `tests/`, `vendor/`…)
 * against the target's absolute path and skip a whole checkout under such a folder. Opengrep therefore
 * runs in the target with this managed copy of its default list, named by the (internal, undocumented)
 * SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE variable; eval E71 fails if a release stops honouring it.
 */
export const OPENGREP_IGNORE_FILE = join(DETECTION_DB_DIR, "opengrep-ignore", "default.semgrepignore");
/** The list Opengrep reads: the managed defaults plus BUILD_DIRS, written into the scan's temp dir. */
export const OPENGREP_EFFECTIVE_IGNORE_NAME = "opengrep.semgrepignore";

/**
 * Review I-4 (fix round 3): build output is skipped exactly where file routing (CG-30) drops Opengrep
 * findings anyway, BUILD_DIRS in src/config.ts, so no folder whose findings routing would keep is
 * skipped. Folders already in Opengrep's defaults (build/, dist/) are not repeated.
 */
export function effectiveOpengrepIgnoreList(defaults: string): string {
  const present = new Set(defaults.split("\n").map((line) => line.trim()));
  const added = [...BUILD_DIRS].map((folder) => `${folder}/`).filter((pattern) => !present.has(pattern));
  return `${defaults.replace(/\n*$/, "\n")}\n# Build output (src/config.ts BUILD_DIRS; file routing drops Opengrep findings there).\n` +
    `${added.join("\n")}\n`;
}

export async function runOpengrep(target: string, tmpDir: string): Promise<EngineOutput> {
  const t0 = Date.now();
  let version = "unknown";
  try {
    const bin = await resolveEngine("opengrep");
    version = bin.version;
    const sarifPath = join(tmpDir, "opengrep.sarif");
    const reportPath = join(tmpDir, "opengrep.json");
    const args = buildOpengrepArgs(target, sarifPath, reportPath);
    const ignoreList = effectiveOpengrepIgnoreList(await readFile(OPENGREP_IGNORE_FILE, "utf8"));
    await writeFile(join(tmpDir, OPENGREP_EFFECTIVE_IGNORE_NAME), ignoreList, { encoding: "utf8", flag: "wx" });
    const componentSignatures = {
      "opengrep:binary": `sha256:${bin.sha256}`,
      "opengrep:ruleset": await rulesetSignature(OPENGREP_RULES_DIR),
      "opengrep:invocation": invocationSignature("opengrep", args.map((arg) =>
        arg === `--sarif-output=${sarifPath}` ? "--sarif-output=<managed-temp>"
          : arg === `--output=${reportPath}` ? "--output=<managed-temp>"
          : arg === OPENGREP_RULES_DIR ? "<bundled-ruleset>"
            : arg === target ? "<target>"
              : arg).concat(`ignore-list:${signature(ignoreList)}`)),
    };

    // VERIFY: confirm flag spelling against opengrep v1.33.1 (`--sarif-output=`
    // per PRD §4.1; some builds use `--sarif --output`). Isolated here for easy fix.
    await mkdir(MANAGED_OPENGREP_CACHE, { recursive: true });
    const res = await execBinary(bin.path, args, {
      cwd: await engineWorkingDirectory(target),
      offline: true,
      env: opengrepExecEnvironment(tmpDir),
    });
    // Opengrep exit code is non-zero when findings exist; we read the SARIF
    // regardless and interpret results, not the exit code.
    let sarif: SarifLog | undefined;
    try {
      await access(sarifPath);
      sarif = JSON.parse(await readFile(sarifPath, "utf8")) as SarifLog;
    } catch {
      if (res.timedOut) {
        return engineNote("opengrep", version, t0, "Opengrep timed out before producing SARIF.");
      }
      return engineNote(
        "opengrep",
        version,
        t0,
        `Opengrep produced no SARIF (exit ${res.code}). stderr: ${stderrTail(res.stderr)}`,
      );
    }

    const fileCoverage = opengrepFileCoverage(await readJson(reportPath), target);
    return {
      engine: "opengrep",
      version,
      available: true,
      ran: true,
      sarif,
      durationMs: Date.now() - t0,
      ...(fileCoverage.warning ? { coverageWarnings: [fileCoverage.warning] } : {}),
      ...(fileCoverage.parseErrors ? { coverageGaps: [fileCoverage.parseErrors] } : {}),
      componentSignatures,
    };
  } catch (err) {
    if (err instanceof EngineUnavailableError) {
      return engineNote("opengrep", version, t0, err.message);
    }
    log.warn("opengrep wrapper error", err);
    return engineNote(
      "opengrep",
      version,
      t0,
      err instanceof Error ? err.message : String(err),
    );
  }
}

export function buildOpengrepArgs(target: string, sarifPath: string, reportPath: string): string[] {
  return [
    "scan",
    `--sarif-output=${sarifPath}`,
    // Structured errors and skipped paths with reasons; `paths.skipped` needs --verbose (not --quiet).
    "--json",
    `--output=${reportPath}`,
    "-f",
    OPENGREP_RULES_DIR,
    "--verbose",
    // Scan the same files as Trivy, Gitleaks and the native packs: by default Opengrep asks git for
    // the file list and silently omits untracked git-ignored files (not even in paths.skipped). File
    // routing (CG-30) frames findings in git-ignored locations. Opengrep then never runs git either.
    "--no-git-ignore",
    "--disable-version-check",
    "--taint-intrafile", // intrafile cross-function taint (PRD §1.4 in-scope)
    target,
  ];
}

/**
 * Keep Opengrep's self-extraction cache under CodeInspectus and transient logs out of the user home.
 * Opengrep's Python front end decodes text with the locale's encoding. Without a UTF-8 locale (a
 * GUI-launched MCP host often has none) one non-ASCII byte in a scanned ignore file ends the run
 * with no SARIF, and non-ASCII snippet text is replaced. `PYTHONUTF8` does not reach the frozen
 * binary, so the locale itself is set.
 */
export function opengrepExecEnvironment(tmpDir: string): Record<string, string> {
  return {
    XDG_CACHE_HOME: MANAGED_OPENGREP_CACHE,
    SEMGREP_LOG_FILE: join(tmpDir, "opengrep.log"),
    SEMGREP_VERSION_CACHE_PATH: join(tmpDir, "opengrep-version-cache"),
    OPENGREP_ENABLE_VERSION_CHECK: "0",
    SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE: join(tmpDir, OPENGREP_EFFECTIVE_IGNORE_NAME),
    LC_ALL: "C.UTF-8",
    LANG: "C.UTF-8",
  };
}

function engineNote(
  engine: "opengrep",
  version: string,
  t0: number,
  note: string,
  componentSignatures?: Record<string, string>,
): EngineOutput {
  return { engine, version, available: false, ran: false, durationMs: Date.now() - t0, note, componentSignatures };
}

async function readJson(path: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as unknown;
  } catch {
    return undefined;
  }
}

/**
 * Review M2: under --verbose, stderr starts with a preamble (rule counts, the ignore file, dotted rule
 * paths under the user's install directory); the error that ended the run comes last.
 */
function stderrTail(s: string, n = 300): string {
  const text = s.trim();
  return text.length > n ? "…" + text.slice(-n) : text;
}
