import { createHash } from "node:crypto";

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Stable finding fingerprint from its identifying parts (PRD §5 dedup/rescan). */
export function fingerprint(parts: Array<string | number | undefined>): string {
  const norm = parts.map((p) => (p === undefined ? "" : String(p))).join("|");
  return `sha256:${sha256Hex(norm)}`;
}
