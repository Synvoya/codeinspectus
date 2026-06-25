/**
 * Lightweight source-file walker for the CodeInspectus AI-code analyzers (§6).
 * Skips dependency/VCS dirs. Built-output dirs (dist/build/.next/out) are skipped
 * by default but INCLUDED when scanning for secrets compiled into shipped bundles
 * (§6.1).
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";

const ALWAYS_IGNORE = new Set([
  "node_modules",
  ".git",
  ".cache",
  "coverage",
  ".turbo",
  ".vercel",
  ".idea",
  ".vscode",
  ".pnpm-store",
]);
const BUILD_DIRS = new Set(["dist", "build", ".next", "out", ".output"]);

export interface SourceFile {
  abs: string;
  rel: string;
  content: string;
  ext: string;
}

export interface WalkOptions {
  /** Only yield files with these extensions (lowercase, no dot). Empty = all. */
  exts?: string[];
  /** Include built-output dirs (dist/build/.next). Default false. */
  includeBuilt?: boolean;
  /** Skip files larger than this (bytes). Default 2 MB. */
  maxBytes?: number;
}

export async function collectFiles(root: string, opts: WalkOptions = {}): Promise<SourceFile[]> {
  const exts = new Set((opts.exts ?? []).map((e) => e.toLowerCase()));
  const maxBytes = opts.maxBytes ?? 2 * 1024 * 1024;
  const out: SourceFile[] = [];

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const ent of entries) {
      const name = ent.name;
      const abs = join(dir, name);
      if (ent.isDirectory()) {
        if (ALWAYS_IGNORE.has(name)) continue;
        if (!opts.includeBuilt && BUILD_DIRS.has(name)) continue;
        await walk(abs);
      } else if (ent.isFile()) {
        const ext = extname(name).slice(1).toLowerCase();
        if (exts.size && !exts.has(ext)) continue;
        try {
          const st = await stat(abs);
          if (st.size > maxBytes) continue;
          const content = await readFile(abs, "utf8");
          out.push({ abs, rel: relative(root, abs).replace(/\\/g, "/"), content, ext });
        } catch {
          /* unreadable/binary — skip */
        }
      }
    }
  }

  await walk(root);
  return out;
}

/** 1-based line number for a character offset. */
export function lineOf(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

/** The source line text at a 1-based line number. */
export function lineText(content: string, line: number): string {
  const lines = content.split(/\r?\n/);
  return lines[line - 1] ?? "";
}
