/**
 * Read-only discovery of target-controlled Gitleaks suppression surfaces.
 * Records channel names, counts, and relative paths only — never config contents,
 * source snippets, or matched secret values.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";
import { collectFiles } from "./ai-checks/walk.js";
import type { SecretSuppressionChannel, SecretSuppressionMetadata } from "./types.js";

const INLINE_ALLOW_RE = /gitleaks:allow\b/g;

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
      handling: "coverage_unverified",
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
      paths: [...inlinePaths].sort(),
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
  return metadata.channels.some((surface) => surface.channel === "gitleaks_ignore");
}
