import { describe, expect, test } from "vitest";

import { jsCalls, parseJavaScriptSource } from "./javascript.js";

/**
 * KNOWN LIMITATIONS of the native JavaScript/TypeScript lexer (pre-release review C-1, Ruling 30).
 *
 * The native packs use a lightweight lexer, not a JavaScript parser. Each input below runs an `eval`
 * in Node, yet the lexer can read the file as parsed with no `eval` call, so a native check never sees
 * it. Ruling 28/30 stopped further keyword-context heuristics; the fix is a real JS/TS parser in 4.0.
 *
 * The property every input should meet: the file is refused (not balanced, so it lands in
 * `native-parse-errors`) or the `eval` call is visible to the analyzers.
 * - `closed`: met today by a fail-closed language fact (line terminators, `.mts`/`.cts`, HTML-like
 *   comments, numeric literal syntax). These are ordinary regression tests.
 * - `open`: NOT met today. They use `test.fails`, so they pass while the limitation stands and start
 *   failing when a parser change closes one; then move that input to `closed`.
 */
function refusedOrVisible(path: string, source: string): boolean {
  const document = parseJavaScriptSource(path, source);
  return !document.balanced || jsCalls(document).some((call) => call.callee === "eval");
}

const closed: Array<[string, string, string]> = [
  ["cr-comment", "a.js", "// note\reval(payload)\n"],
  ["u2028-comment", "a.js", "// note\u2028eval(payload)\n"],
  ["hashbang-cr", "a.js", "#!/usr/bin/env node\reval(payload)\n"],
  ["html-open-comment", "a.cjs", "<!-- `\neval(payload)\n<!-- `\n"],
  ["mts-nonnull", "a.mts", "declare const x: any;\nconst r = x! /2; eval(payload); const z = 1/ 1;\n"],
  ["cts-nonnull", "a.cts", "declare const x: any;\nconst r = x! /2; eval(payload); const z = 1/ 1;\n"],
  // Re-review N-3: the number lexer swallowed `+e` of an unspaced `eval`.
  ["number-swallows-identifier", "a.js", "const r = 1+eval(payload);\n"],
];

const open: Array<[string, string, string]> = [
  // `of`, and `await`/`yield` as script identifiers, are read as regex-start keywords.
  ["of-identifier", "a.js", "const of = 4;\nconst r = of /2; eval(payload); const z = 1/ 1;\n"],
  ["await-identifier-script", "a.cjs", "var await = 4;\nvar r = await /2; eval(payload); var z = 1/ 1;\n"],
  // After extends/new/default, break + ASI and ++ + ASI, JavaScript reads a regex but the lexer divides.
  ["extends-regex-comment", "a.js", "function unused() { return class extends /`/ {} }\neval(payload)\n// ` {} }\n"],
  ["new-regex", "a.js", "function unused() { return new /`/ }\neval(payload)\n// ` }\n"],
  ["export-default-regex", "a.mjs", "export default /`/;\neval(payload)\n// `\n"],
  ["break-asi-regex", "a.js", "for(;;){ break\n/`/ }\neval(payload)\n// ` }\n"],
  ["plusplus-asi-regex", "a.js", "let a = 1\n++/`/.lastIndex\neval(payload)\n// `\n"],
  // Identifier escapes and non-ASCII identifiers are not lexed.
  ["unicode-escape-ident", "a.js", "\\u0065val(payload)\n"],
  // The TypeScript non-null rule accepts only identifier, number, `]` or `)` before `!`.
  ["ts-nonnull-string", "a.ts", "const r = \"a\"! /2; eval(payload); const z = 1/ 1;\n"],
  ["ts-nonnull-template", "a.ts", "const r = `a`! /2; eval(payload); const z = 1/ 1;\n"],
  ["ts-nonnull-double", "a.ts", "declare const x: any;\nconst r = x!! /2; eval(payload); const z = 1/ 1;\n"],
  ["ts-nonnull-brace", "a.ts", "const r = {}! /2; eval(payload); const z = 1/ 1;\n"],
];

describe("native lexer known limitations (review C-1; parser replacement planned for 4.0)", () => {
  test.each(closed)("closed: %s is refused or shows the eval", (_name, path, source) => {
    expect(refusedOrVisible(path, source)).toBe(true);
  });

  test.fails.each(open)("KNOWN LIMITATION (open until 4.0): %s hides the eval", (_name, path, source) => {
    expect(refusedOrVisible(path, source)).toBe(true);
  });

  test("control: a plain eval is visible", () => {
    expect(refusedOrVisible("a.js", "eval(payload)\n")).toBe(true);
    const document = parseJavaScriptSource("a.js", "eval(payload)\n");
    expect(document.balanced && jsCalls(document).some((call) => call.callee === "eval")).toBe(true);
  });
});
