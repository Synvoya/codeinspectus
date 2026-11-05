/**
 * Routing-only match keys for secret findings whose value the engine withholds.
 *
 * Gitleaks runs with `--redact=100` and Trivy masks its match, so their SARIF never carries the secret and
 * the normalizer cannot set `secret_value_hash`. To tell whether a test-file secret is also used outside
 * test context (design 4.6), the value is read back from the source at the reported location and hashed
 * with `hashSecret`. The key lives only in the map this module returns: it is never written to a finding,
 * so `secret_value_hash`, fingerprints, stored scans and exports are unchanged.
 *
 * Reads are read-only and bounded: regular files only (no symbolic links), at most `MAX_FILE_BYTES` per file,
 * lines up to `MAX_LINE_BYTES`, and at most `MAX_KEYED_FINDINGS` findings per scan.
 */
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";

import { findSecret, hashSecret } from "./redact.js";
import type { Finding } from "./types.js";

const MAX_FILE_BYTES = 1024 * 1024;
const MAX_LINE_BYTES = 64 * 1024;
const MAX_KEYED_FINDINGS = 2_000;
/** Shortest value taken as a secret (Gitleaks' generic rule needs 10 characters, its curl rules 8). */
const MIN_VALUE_LENGTH = 8;
/** A secret-shaped token: word characters plus `.~@+/-`, with up to three `=` of base64 padding. */
const VALUE_TOKEN = /[\w.~@+/-]+={0,3}/g;

/** Gitleaks' match end column (1-based, in bytes) per finding, recorded by the normalizer. */
const gitleaksMatchEnds = new WeakMap<Finding, number>();

/** Called by the SARIF normalizer for a Gitleaks secret finding it could not hash. */
export function recordGitleaksMatchEnd(finding: Finding, endColumn: number | undefined): void {
  if (typeof endColumn === "number" && Number.isInteger(endColumn) && endColumn > 0) gitleaksMatchEnds.set(finding, endColumn);
}

/**
 * The secret a Gitleaks match ends with. Gitleaks matches end with the secret plus at most a terminator
 * (quote, space, `;`), and its end column counts bytes from the line start (one byte further on lines
 * after the first), so the value is the last secret-shaped token before that column.
 */
export function secretValueAt(line: Buffer, endColumn: number): string | undefined {
  const head = line.subarray(0, Math.max(0, Math.min(endColumn, line.length))).toString("utf8");
  const tokens = head.match(VALUE_TOKEN)?.filter((token) => token.length >= MIN_VALUE_LENGTH) ?? [];
  return tokens.at(-1);
}

function safeSegments(rel: string): string[] | undefined {
  if (rel === "" || rel.startsWith("/") || /^[A-Za-z]:[\\/]/.test(rel) || rel.includes("\\")) return undefined;
  const segments = rel.split("/");
  return segments.some((segment) => segment === "" || segment === "." || segment === "..") ? undefined : segments;
}

/** The file's lines as bytes, or undefined for a link, non-regular, unreadable file or one past the read cap. */
async function readLines(target: string, rel: string): Promise<Buffer[] | undefined> {
  const segments = safeSegments(rel);
  if (!segments) return undefined;
  const path = join(target, ...segments);
  try {
    const info = await lstat(path);
    if (!info.isFile()) return undefined;
    const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const buffer = Buffer.alloc(Math.min(info.size, MAX_FILE_BYTES));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
      const lines: Buffer[] = [];
      let start = 0;
      for (let index = 0; index < bytesRead; index++) {
        if (buffer[index] !== 0x0a) continue;
        lines.push(buffer.subarray(start, index));
        start = index + 1;
      }
      // A last line cut by the read cap is not read whole, so it is not used.
      if (start < bytesRead && bytesRead === info.size) lines.push(buffer.subarray(start, bytesRead));
      return lines;
    } finally {
      await handle.close();
    }
  } catch {
    return undefined;
  }
}

function lineAt(lines: Buffer[], number: number): Buffer | undefined {
  const line = lines[number - 1];
  return line && line.length <= MAX_LINE_BYTES ? line : undefined;
}

function needsKey(finding: Finding): boolean {
  return finding.is_secret === true && !finding.secret_value_hash && (finding.engine === "gitleaks" || finding.engine === "trivy");
}

/**
 * Routing-only reuse keys (`hashSecret` of the value) for Gitleaks and Trivy secret findings that carry no
 * `secret_value_hash`. A Gitleaks value is the last token before its match end; a Trivy finding (masked, no
 * columns) is keyed only when its line holds a known-pattern secret. Anything unreadable gets no key.
 */
export async function secretMatchKeys(target: string, findings: readonly Finding[]): Promise<Map<Finding, string>> {
  const keys = new Map<Finding, string>();
  const wanted = findings.filter(needsKey).slice(0, MAX_KEYED_FINDINGS);
  const byFile = new Map<string, Finding[]>();
  for (const finding of wanted) {
    const group = byFile.get(finding.location.file);
    if (group) group.push(finding);
    else byFile.set(finding.location.file, [finding]);
  }
  for (const [rel, group] of byFile) {
    const lines = await readLines(target, rel);
    if (!lines) continue;
    for (const finding of group) {
      const line = lineAt(lines, finding.location.end_line);
      if (!line) continue;
      const end = gitleaksMatchEnds.get(finding);
      const value = finding.engine === "gitleaks"
        ? end === undefined ? undefined : secretValueAt(line, end)
        : findSecret(line.toString("utf8"))?.value;
      if (value) keys.set(finding, hashSecret(value));
    }
  }
  return keys;
}
