/**
 * Opengrep wrapper — SAST / OWASP Top 10 (PRD §4.1). Fully offline: self-
 * contained binary + local rule files. Emits SARIF 2.1.0.
 *
 * We point Opengrep at the bundled rules directory (CodeInspectus custom AI-code
 * rules + any vendored security-registry rules). We do NOT use `--config auto`
 * or registry packs, which would require network and break zero-egress.
 */

import { readFile, readdir, access, mkdir, writeFile } from "node:fs/promises";
import { basename, extname, join, relative } from "node:path";
import { BUILD_DIRS, DETECTION_DB_DIR, MANAGED_OPENGREP_CACHE, OPENGREP_RULES_DIR } from "../config.js";
import { resolveEngine, EngineUnavailableError } from "./resolve.js";
import { execBinary } from "./exec.js";
import { log } from "../logger.js";
import type { EngineOutput } from "./types.js";
import type { SarifLog } from "../sarif/types.js";
import {
  invocationSignature,
  OPENGREP_BUNDLE_SKIPPING_RULES_LABEL,
  OPENGREP_PACK_INVOCATION,
  rulesetSignature,
  signature as signatureOf,
} from "../provenance.js";
import type { CoverageGap } from "../coverage-gaps.js";
import { checkPackSkips, mergeOpengrepReports, opengrepFileCoverage } from "./opengrep-coverage.js";
import { isDisplayablePath } from "../display-path.js";
import {
  BUNDLE_CLASSIFIER_REVISION,
  findPackBundles,
  managedIgnorePredicate,
  PACK_RULE_DIR_PREFIX,
  PACK_RULE_FILE_PATTERN,
  PACK_TIMEOUT_SECONDS,
  packIgnoreList,
  thirdPartyBundlesGap,
} from "./opengrep-bundles.js";
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
/** The Synvoya pack pass's list: the effective list plus the bundles it skips (opengrep-bundles.ts). */
export const OPENGREP_PACK_IGNORE_NAME = "opengrep-pack.semgrepignore";

/**
 * Review I-4 (fix round 3): build output is skipped exactly where file routing (CG-30) drops Opengrep
 * findings anyway, BUILD_DIRS in src/config.ts, so no folder whose findings routing would keep is
 * skipped. Folders already in Opengrep's defaults (build/, dist/) are not repeated.
 */
export function effectiveOpengrepIgnoreList(raw: string): string {
  // A Windows git checkout gives the defaults CRLF line endings (public CI); Opengrep gets LF only.
  const defaults = raw.replace(/\r\n?/g, "\n");
  const present = new Set(defaults.split("\n").map((line) => line.trim()));
  const added = [...BUILD_DIRS].map((folder) => `${folder}/`).filter((pattern) => !present.has(pattern));
  return `${defaults.replace(/\n*$/, "\n")}\n# Build output (src/config.ts BUILD_DIRS; file routing drops Opengrep findings there).\n` +
    `${added.join("\n")}\n`;
}

/**
 * Rule configurations of the two passes. The pack pass: Synvoya pack folders (`synvoya-*`) and taint-mode
 * baseline files (`*-taint.yaml`, M4 perf fix). The baseline pass: everything else; a baseline folder holding a
 * taint file is passed as its other rule files, one `-f` each, and any other folder as itself.
 */
export async function opengrepRuleSets(dir: string = OPENGREP_RULES_DIR): Promise<{ baseline: string[]; pack: string[] }> {
  const isRuleFile = (name: string): boolean => [".yaml", ".yml"].includes(extname(name).toLowerCase());
  const entries = (await readdir(dir, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() || (entry.isFile() && isRuleFile(entry.name)))
    .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  const baseline: string[] = [];
  const pack: string[] = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.name.startsWith(PACK_RULE_DIR_PREFIX)) pack.push(path);
    else if (!entry.isDirectory()) (PACK_RULE_FILE_PATTERN.test(entry.name) ? pack : baseline).push(path);
    else {
      const files = (await readdir(path, { recursive: true })).filter(isRuleFile).sort();
      if (!files.some((file) => PACK_RULE_FILE_PATTERN.test(basename(file)))) baseline.push(path);
      else for (const file of files) (PACK_RULE_FILE_PATTERN.test(basename(file)) ? pack : baseline).push(join(path, file));
    }
  }
  return { baseline, pack: pack.sort() };
}

interface PassResult {
  sarif?: SarifLog;
  report?: unknown;
  /** Why the pass produced no SARIF. */
  failure?: string;
  /** The pass's invocation signature; recorded only when it produced SARIF. */
  signature: string;
}

interface PassOptions {
  name: "baseline" | "pack";
  configs: readonly string[];
  ignoreList: string;
  timeoutSeconds?: number;
  /** Extra semantic elements of the invocation signature. */
  signatureExtras?: readonly string[];
}

async function runPass(bin: { path: string }, target: string, tmpDir: string, cwd: string, options: PassOptions): Promise<PassResult> {
  const prefix = options.name === "baseline" ? "opengrep" : "opengrep-pack";
  const sarifPath = join(tmpDir, `${prefix}.sarif`);
  const reportPath = join(tmpDir, `${prefix}.json`);
  const ignoreName = options.name === "baseline" ? OPENGREP_EFFECTIVE_IGNORE_NAME : OPENGREP_PACK_IGNORE_NAME;
  await writeFile(join(tmpDir, ignoreName), options.ignoreList, { encoding: "utf8", flag: "wx" });
  const args = buildOpengrepArgs(target, sarifPath, reportPath, options.configs, { timeoutSeconds: options.timeoutSeconds });
  const configs = new Set(options.configs);
  const signature = invocationSignature("opengrep", args.map((arg) =>
    arg === `--sarif-output=${sarifPath}` ? "--sarif-output=<managed-temp>"
      : arg === `--output=${reportPath}` ? "--output=<managed-temp>"
        : arg === OPENGREP_RULES_DIR ? "<bundled-ruleset>"
          : configs.has(arg) ? `<bundled-ruleset>/${relative(OPENGREP_RULES_DIR, arg).replace(/\\/g, "/")}`
            : arg === target ? "<target>"
              : arg).concat(`ignore-list:${signatureOf(options.ignoreList)}`, ...(options.signatureExtras ?? [])));
  const res = await execBinary(bin.path, args, {
    cwd,
    offline: true,
    env: opengrepExecEnvironment(tmpDir, process.platform, options.name),
  });
  // Opengrep exit code is non-zero when findings exist; we read the SARIF
  // regardless and interpret results, not the exit code.
  try {
    await access(sarifPath);
    const sarif = JSON.parse(await readFile(sarifPath, "utf8")) as SarifLog;
    return { sarif, report: await readJson(reportPath), signature };
  } catch {
    return {
      signature,
      failure: res.timedOut ? "Opengrep timed out before producing SARIF." : `Opengrep produced no SARIF (exit ${res.code}). stderr: ${stderrTail(res.stderr)}`,
    };
  }
}

/**
 * Two Opengrep passes over the same target, working directory and target argument, so paths and lines of
 * findings are those of a single run: the baseline rules over every file (settings unchanged), then the
 * Synvoya pack rules and the taint-mode baseline rules with an explicit per-rule timeout and an ignore list
 * that also names the vendored or minified bundles (opengrep-bundles.ts). Each pass records its own invocation signature; the
 * pack's covers the files it skipped, so a rescan whose bundle set changed cannot resolve a pack finding.
 */
export async function runOpengrep(target: string, tmpDir: string): Promise<EngineOutput> {
  const t0 = Date.now();
  let version = "unknown";
  try {
    const bin = await resolveEngine("opengrep");
    version = bin.version;
    const rules = await opengrepRuleSets();
    // Without `-f`, Opengrep would look for a default configuration; never run it without bundled rules.
    if (!rules.baseline.length) throw new Error("no bundled baseline Opengrep rules were found");
    const ignoreList = effectiveOpengrepIgnoreList(await readFile(OPENGREP_IGNORE_FILE, "utf8"));
    const cwd = await engineWorkingDirectory(target);
    // Classification runs while the baseline pass does; it only reads the target.
    const bundlesTask = rules.pack.length
      ? findPackBundles(target, ignoreList).catch((err: unknown) => {
        log.warn("Synvoya pack routing could not classify bundles; the pack pass scans every file", err);
        return { bundles: [] as string[] };
      })
      : undefined;

    await mkdir(MANAGED_OPENGREP_CACHE, { recursive: true });
    const baseline = await runPass(bin, target, tmpDir, cwd, { name: "baseline", configs: rules.baseline, ignoreList });
    if (!baseline.sarif) {
      await bundlesTask;
      return engineNote("opengrep", version, t0, baseline.failure ?? "Opengrep produced no SARIF.");
    }
    const componentSignatures: Record<string, string> = {
      "opengrep:binary": `sha256:${bin.sha256}`,
      "opengrep:ruleset": await rulesetSignature(OPENGREP_RULES_DIR),
      "opengrep:invocation": baseline.signature,
    };
    const reports = [baseline.report];
    const runs = [...(baseline.sarif.runs ?? [])];
    const warnings: string[] = [];
    let bundles: string[] = [];
    if (bundlesTask) {
      bundles = (await bundlesTask).bundles;
      const pack = await runPass(bin, target, tmpDir, cwd, {
        name: "pack",
        configs: rules.pack,
        ignoreList: packIgnoreList(ignoreList, bundles),
        timeoutSeconds: PACK_TIMEOUT_SECONDS,
        signatureExtras: [`bundle-classifier:${BUNDLE_CLASSIFIER_REVISION}`],
      });
      if (pack.sarif) {
        reports.push(pack.report);
        runs.push(...(pack.sarif.runs ?? []));
        // Fail closed: the pack pass may skip only the chosen bundles, and only those it skipped are the gap.
        const check = checkPackSkips(pack.report, bundles, target, managedIgnorePredicate(ignoreList));
        if (check) bundles = check.skipped;
        const unexpected = check?.unexpected ?? [];
        if (unexpected.length) {
          const shown = unexpected.filter((rel) => !rel.startsWith("\u0000") && isDisplayablePath(rel));
          warnings.push(`Opengrep SAST coverage partial: the bundle-skipping pass (${OPENGREP_BUNDLE_SKIPPING_RULES_LABEL}) also skipped ${unexpected.length} ` +
            `file(s) bundle routing did not choose, so findings of that pass are unknown there${shown.length ? `: ${shown.slice(0, 5).join(", ")}${shown.length > 5 ? ", …" : ""}` : ""}.`);
        }
        // Without a verified skip list (malformed report: its own warning) the pack checked nothing provably.
        if (check && !unexpected.length) componentSignatures[OPENGREP_PACK_INVOCATION] = pack.signature;
      } else {
        bundles = [];
        warnings.push(`Opengrep SAST coverage partial: the bundle-skipping pass (${OPENGREP_BUNDLE_SKIPPING_RULES_LABEL}) ${pack.failure!.replace(/^Opengrep /, "")}`);
      }
    }

    const fileCoverage = opengrepFileCoverage(mergeOpengrepReports(reports), target);
    if (fileCoverage.warning) warnings.push(fileCoverage.warning);
    const notes = fileCoverage.note ? [fileCoverage.note] : [];
    const gaps = [fileCoverage.parseErrors, thirdPartyBundlesGap(bundles)].filter((gap): gap is CoverageGap => gap !== undefined);
    return {
      engine: "opengrep",
      version,
      available: true,
      ran: true,
      sarif: { ...baseline.sarif, runs },
      durationMs: Date.now() - t0,
      ...(warnings.length ? { coverageWarnings: warnings } : {}),
      ...(gaps.length ? { coverageGaps: gaps } : {}),
      ...(notes.length ? { coverageNotes: notes } : {}),
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

export function buildOpengrepArgs(
  target: string,
  sarifPath: string,
  reportPath: string,
  configs: readonly string[] = [OPENGREP_RULES_DIR],
  options: { timeoutSeconds?: number } = {},
): string[] {
  return [
    "scan",
    `--sarif-output=${sarifPath}`,
    // Structured errors and skipped paths with reasons; `paths.skipped` needs --verbose (not --quiet).
    "--json",
    `--output=${reportPath}`,
    ...configs.flatMap((config) => ["-f", config]),
    "--verbose",
    // Scan the same files as Trivy, Gitleaks and the native packs: by default Opengrep asks git for
    // the file list and silently omits untracked git-ignored files (not even in paths.skipped). File
    // routing (CG-30) frames findings in git-ignored locations. Opengrep then never runs git either.
    "--no-git-ignore",
    "--disable-version-check",
    "--taint-intrafile", // intrafile cross-function taint (PRD §1.4 in-scope)
    ...(options.timeoutSeconds !== undefined ? ["--timeout", String(options.timeoutSeconds)] : []),
    target,
  ];
}

/**
 * Keep Opengrep's self-extraction cache under CodeInspectus and transient logs out of the user home.
 * Opengrep's Python front end decodes text with the locale's encoding. Without a UTF-8 locale (a
 * GUI-launched MCP host often has none) one non-ASCII byte in a scanned ignore file ends the run
 * with no SARIF, and non-ASCII snippet text is replaced. `PYTHONUTF8` does not reach the frozen
 * binary, so the locale itself is set. It must exist on the host: macOS before 26 has no C.UTF-8 (the
 * public CI macOS runner fell back to ASCII), while every macOS ships en_US.UTF-8; Linux images have
 * C.UTF-8. A missing locale still fails closed: no SARIF means Opengrep did not run.
 */
export function opengrepExecEnvironment(
  tmpDir: string,
  platform: NodeJS.Platform = process.platform,
  pass: "baseline" | "pack" = "baseline",
): Record<string, string> {
  const locale = platform === "darwin" ? "en_US.UTF-8" : "C.UTF-8";
  return {
    XDG_CACHE_HOME: MANAGED_OPENGREP_CACHE,
    SEMGREP_LOG_FILE: join(tmpDir, pass === "baseline" ? "opengrep.log" : "opengrep-pack.log"),
    SEMGREP_VERSION_CACHE_PATH: join(tmpDir, "opengrep-version-cache"),
    OPENGREP_ENABLE_VERSION_CHECK: "0",
    SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE: join(tmpDir, pass === "baseline" ? OPENGREP_EFFECTIVE_IGNORE_NAME : OPENGREP_PACK_IGNORE_NAME),
    LC_ALL: locale,
    LANG: locale,
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
