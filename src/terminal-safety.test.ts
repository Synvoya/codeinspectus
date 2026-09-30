/**
 * Scan output interpolates repository-controlled text (file names, metadata fields, validator
 * messages). Output must never carry raw terminal control sequences; JSON stays valid.
 */
import { describe, expect, test } from "vitest";
import { fail, ok } from "./result.js";
import { forStream, terminalSafe } from "./util/terminal.js";

const HOSTILE = "img\u001b]8;;https://evil.example\u0007click\u001b]8;;\u0007\u009b2J\u0085.png";

describe("terminal-safe human output", () => {
  test("escapes C0/C1 control characters but keeps newlines, tabs, and CRLF", () => {
    const safe = terminalSafe(`a\tb\n${HOSTILE}\r\n`);

    expect(safe).not.toMatch(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/);
    expect(safe).toContain("a\tb\n");
    expect(safe).toContain("\\u001b");
    expect(safe.endsWith("\r\n")).toBe(true);
    expect(terminalSafe("safe\rspoofed")).toBe("safe\\u000dspoofed");
  });

  test("JSON shown on a terminal stays valid JSON with the same data", () => {
    const json = JSON.stringify({ file: HOSTILE });

    expect(JSON.parse(forStream(json))).toEqual({ file: HOSTILE });
  });

  test("CLI output is always escaped because pipes can still reach a terminal (tee, less -R)", () => {
    expect(forStream(`name: ${HOSTILE}\n`)).not.toMatch(/[\u001b\u0007\u009b]/);
    expect(JSON.parse(forStream(JSON.stringify({ file: HOSTILE })))).toEqual({ file: HOSTILE });
  });

  test("MCP text content is terminal-safe while structuredContent is untouched", () => {
    const result = ok(`finding in ${HOSTILE}`, { file: HOSTILE });

    expect(result.content[0]!.text).not.toMatch(/[\u001b\u0007\u009b\u0085]/);
    expect(result.structuredContent).toEqual({ file: HOSTILE });
    expect(fail(`error in ${HOSTILE}`).content[0]!.text).not.toMatch(/[\u001b\u0007\u009b]/);
  });
});
