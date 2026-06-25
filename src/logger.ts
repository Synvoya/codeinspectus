/**
 * stderr-only logger.
 *
 * GUARDRAIL (PRD §12): the stdio MCP transport requires that stdout carry ONLY
 * JSON-RPC. A single stray write to stdout silently corrupts the transport and
 * is the most common MCP server bug. Therefore EVERY diagnostic in this codebase
 * must go through this logger, which writes exclusively to stderr. Never call
 * console.log anywhere in src/.
 */

type Level = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<Level, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

// Default to info; CG_LOG_LEVEL=debug for verbose, CG_LOG_LEVEL=silent to mute.
function activeThreshold(): number {
  const raw = (process.env.CG_LOG_LEVEL ?? "info").toLowerCase();
  if (raw === "silent") return Number.POSITIVE_INFINITY;
  return LEVEL_ORDER[raw as Level] ?? LEVEL_ORDER.info;
}

function emit(level: Level, args: unknown[]): void {
  if (LEVEL_ORDER[level] < activeThreshold()) return;
  const ts = new Date().toISOString();
  const parts = args.map((a) =>
    typeof a === "string" ? a : safeStringify(a),
  );
  // process.stderr.write — never process.stdout.
  process.stderr.write(`[codeinspectus ${ts} ${level}] ${parts.join(" ")}\n`);
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

export const log = {
  debug: (...args: unknown[]) => emit("debug", args),
  info: (...args: unknown[]) => emit("info", args),
  warn: (...args: unknown[]) => emit("warn", args),
  error: (...args: unknown[]) => emit("error", args),
};
