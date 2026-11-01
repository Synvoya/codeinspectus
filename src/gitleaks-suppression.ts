/**
 * Read-only discovery of target-controlled Gitleaks suppression surfaces.
 * Records channel names, counts, and relative paths only — never config contents,
 * source snippets, or matched secret values.
 */

import { existsSync } from "node:fs";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import { collectFiles } from "./ai-checks/walk.js";
import { escapePathForDisplay } from "./display-path.js";
import type { SecretSuppressionChannel, SecretSuppressionMetadata } from "./types.js";

const INLINE_ALLOW_RE = /gitleaks:allow\b/g;
const MAX_GITLEAKS_IGNORE_BYTES = 1024 * 1024;

/**
 * Whether one `.gitleaksignore` line can hide a finding from CodeInspectus's `gitleaks dir <absolute
 * target>` run. Verified on Gitleaks 8.30.1: it trims each line and looks up the whole
 * `<file>:<rule>:<line>` it reports, where `<file>` is absolute, so the number of `:` in an entry does
 * not matter (an absolute path under `colon:target/` or `sub:dir/` matches). An entry that starts like
 * an absolute path (`/`, `\`, `\\?\`, a drive letter) can match; only a 3-part relative entry and a
 * commit-scoped entry (hex or empty commit) are known inert; any other shape is assumed able to match.
 * Gitleaks trims with Go's `strings.TrimSpace`, which strips U+0085 where JavaScript's `trim()` does
 * not, so only plain printable-ASCII lines are classified by shape.
 */
export function gitleaksIgnoreEntryCanMatch(line: string): boolean {
  const entry = line.replace(/\r$/, "").replace(/^[ \t]+|[ \t]+$/g, "");
  if (!entry || entry.startsWith("#")) return false;
  if (!/^[\t\x20-\x7E]*$/.test(entry)) return true;
  if (/^(?:[/\\]|[A-Za-z]:)/.test(entry)) return true;
  const parts = entry.split(":");
  if (parts.length === 3) return false;
  return !(parts.length === 4 && /^[0-9a-f]{0,64}$/i.test(parts[0]!));
}

async function gitleaksIgnoreCanSuppress(path: string): Promise<boolean> {
  try {
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.size > MAX_GITLEAKS_IGNORE_BYTES) return true;
    return (await readFile(path, "utf8")).split("\n").some(gitleaksIgnoreEntryCanMatch);
  } catch {
    return true;
  }
}

export async function detectGitleaksSuppression(target: string): Promise<SecretSuppressionMetadata> {
  const channels: SecretSuppressionChannel[] = [];

  if (existsSync(join(target, ".gitleaks.toml"))) {
    channels.push({
      channel: "target_config",
      count: 1,
      paths: [".gitleaks.toml"],
      handling: "ignored_by_codeinspectus",
    });
  }

  if (existsSync(join(target, ".gitleaksignore"))) {
    channels.push({
      channel: "gitleaks_ignore",
      count: 1,
      paths: [".gitleaksignore"],
      handling: await gitleaksIgnoreCanSuppress(join(target, ".gitleaksignore"))
        ? "coverage_unverified"
        : "ignored_by_codeinspectus",
    });
  }

  const inlinePaths = new Set<string>();
  let inlineCount = 0;
  const files = await collectFiles(target, { includeBuilt: true });
  for (const file of files) {
    const matches = file.content.match(INLINE_ALLOW_RE);
    if (!matches?.length) continue;
    inlineCount += matches.length;
    inlinePaths.add(file.rel);
  }
  if (inlineCount) {
    channels.push({
      channel: "inline_allow",
      count: inlineCount,
      // Every file stays listed (the warning counts them); unsafe names are shown escaped.
      paths: [...inlinePaths].map(escapePathForDisplay).sort(),
      handling: "ignored_by_codeinspectus",
    });
  }

  return { channels };
}

export function secretSuppressionWarnings(metadata: SecretSuppressionMetadata): string[] {
  const warnings: string[] = [];
  for (const surface of metadata.channels) {
    if (surface.channel === "target_config") {
      warnings.push(
        "This repo has a .gitleaks.toml. CodeInspectus ignores it so its own secret checks always run — your custom rules and allowlists are not applied.",
      );
    } else if (surface.channel === "inline_allow") {
      warnings.push(
        `This repo has ${surface.count} gitleaks:allow comment(s) in ${surface.paths.length} file(s). ` +
          "CodeInspectus ignores them so its own secret checks always run.",
      );
    } else if (surface.handling === "ignored_by_codeinspectus") {
      warnings.push(
        "This repo has a .gitleaksignore file, but none of its entries can match CodeInspectus's " +
          "directory scan, so it hides no secret findings here.",
      );
    } else {
      warnings.push(
        "This repo has a .gitleaksignore file that hides some secret findings from the scanner. " +
          "Secret coverage here is partial and cannot be guaranteed — review .gitleaksignore.",
      );
    }
  }
  return warnings;
}

export function hasUnverifiedSecretCoverage(metadata: SecretSuppressionMetadata): boolean {
  return metadata.channels.some((surface) =>
    surface.channel === "gitleaks_ignore" && surface.handling === "coverage_unverified");
}
