/**
 * `requirements*.txt` lower bounds as a declared minimum (4.1 M5, Ruling 9).
 *
 * osv-scanner reads `urllib3>=2.2.2` in a requirements file as version 2.2.2 and matches advisories against it,
 * although `>=` only declares the lowest version allowed: the environment may well hold a fixed release. Such a
 * finding keeps its severity but reads "declared minimum" in its title and message and gets `confidence: "low"`
 * (the confidence enum has no `info`). A requirement is a declared minimum when its line(s) carry no `==`/`===`
 * and do carry `>=` or `~=`. Runs after dedup, because confidence is a `preferred()` tiebreak.
 */

import { targetLockfileReader } from "./engines/trivy-package-line.js";
import { normalizePackageName } from "./osv/ecosystems.js";
import type { Finding } from "./types.js";

const REQUIREMENTS_FILE = /^requirements.*\.txt$/i;
/** A requirement line: name, optional extras, then the specifier (markers and comments already removed). */
const REQUIREMENT = /^([a-z0-9](?:[a-z0-9._-]*[a-z0-9])?)\s*(?:\[[^\]]*\])?\s*(.*)$/i;

export interface RequirementSpecifier {
  exact: boolean;
  minimum: boolean;
  /** The first lower-bound specifier as written (`>=2.2.2,<3`), for the message; the first specifier otherwise. */
  specifier: string;
}

/**
 * How a requirements file constrains `name` (PEP 503 name match), or undefined when no line names it.
 * Comments and environment markers (after `;`) are ignored; with several lines, exact if any is exact.
 */
export function requirementSpecifier(lines: readonly string[], name: string): RequirementSpecifier | undefined {
  const wanted = normalizePackageName(name);
  let result: RequirementSpecifier | undefined;
  for (const raw of lines) {
    const line = raw.replace(/(^|\s)#.*$/, "").split(";")[0]!.trim();
    if (!line || line.startsWith("-")) continue;
    const match = REQUIREMENT.exec(line);
    if (!match || normalizePackageName(match[1]!) !== wanted) continue;
    const specifier = match[2]!.replace(/\s+--?\S.*$/, "").replace(/\s+/g, "");
    const exact = specifier.includes("==");
    const minimum = /(?:>=|~=)/.test(specifier.replace(/===?/g, ""));
    if (!result) result = { exact, minimum, specifier };
    else {
      if (minimum && !result.minimum) result.specifier = specifier;
      result.exact ||= exact;
      result.minimum ||= minimum;
    }
  }
  return result;
}

function minimumTitle(finding: Finding): string {
  const pkg = finding.package!;
  const tag = ` (${pkg.name}@${pkg.version}`;
  for (const ending of [`${tag})`, `${tag}, dev dependency)`]) {
    if (finding.title.endsWith(ending)) return `${finding.title.slice(0, -1)}, declared minimum)`;
  }
  return `${finding.title} (declared minimum)`;
}

export async function markDeclaredMinimums(findings: Finding[], target: string): Promise<{ findings: Finding[]; marked: number }> {
  const eligible = (finding: Finding) => finding.finding_kind === "vulnerability" && Boolean(finding.package?.name) &&
    REQUIREMENTS_FILE.test(finding.location.file.slice(finding.location.file.lastIndexOf("/") + 1));
  if (!findings.some(eligible)) return { findings, marked: 0 };
  const linesFor = targetLockfileReader(target);
  let marked = 0;
  const out: Finding[] = [];
  for (const finding of findings) {
    const lines = eligible(finding) ? await linesFor(finding.location.file) : undefined;
    const declared = lines ? requirementSpecifier(lines.lower, finding.package!.name) : undefined;
    if (!declared || declared.exact || !declared.minimum) {
      out.push(finding);
      continue;
    }
    const { file } = finding.location;
    const { name, version } = finding.package!;
    marked += 1;
    out.push({
      ...finding,
      confidence: "low",
      title: minimumTitle(finding),
      message: `${finding.message}\n${file} declares ${name}${declared.specifier}, so ${version} is the lowest version it allows, ` +
        "not necessarily the one installed. Pin an exact version or scan a lockfile to confirm.",
    });
  }
  return { findings: out, marked };
}
