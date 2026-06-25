/**
 * Helpers for building MCP tool results.
 *
 * Tools return BOTH a human-readable text block and structuredContent (PRD §11).
 * Errors return actionable messages with isError:true so the agent can recover
 * (PRD §11: "guide the agent to a fix").
 */

export interface ToolTextContent {
  type: "text";
  text: string;
}

export interface ToolResult {
  // Index signature required for assignability to the SDK's CallToolResult type.
  [key: string]: unknown;
  content: ToolTextContent[];
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

export function ok(text: string, structured: Record<string, unknown>): ToolResult {
  return {
    content: [{ type: "text", text }],
    structuredContent: structured,
  };
}

export function fail(text: string): ToolResult {
  return {
    content: [{ type: "text", text }],
    isError: true,
  };
}

/** Wrap an unknown thrown value into an actionable error message. */
export function describeError(prefix: string, err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  return `${prefix}: ${msg}`;
}
