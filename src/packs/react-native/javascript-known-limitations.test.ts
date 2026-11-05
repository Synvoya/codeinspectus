import { describe, expect, test } from "vitest";

import { jsCalls, parseJavaScriptSource } from "./javascript.js";

/**
 * Former KNOWN LIMITATIONS of the native JavaScript/TypeScript lexer (pre-release review C-1, Ruling 30),
 * closed in 4.0 by the parser (design §10.9).
 *
 * Each input below runs an `eval` in Node, yet the 3.x lexer could read the file as parsed with no
 * `eval` call, so a native check never saw it. The native packs now read files with `@babel/parser`:
 * every input is valid JavaScript/TypeScript, so each must parse and show the `eval` to the analyzers.
 * - `lexer-closed`: already met by the 3.x lexer through a fail-closed language fact.
 * - `parser-closed`: the twelve inputs that were `test.fails` until the parser replaced the lexer.
 */
function parsedAndVisible(path: string, source: string): boolean {
  const document = parseJavaScriptSource(path, source);
  return document.balanced && jsCalls(document).some((call) => call.callee === "eval");
}

const lexerClosed: Array<[string, string, string]> = [
  ["cr-comment", "a.js", "// note\reval(payload)\n"],
  ["u2028-comment", "a.js", "// note\u2028eval(payload)\n"],
  ["hashbang-cr", "a.js", "#!/usr/bin/env node\reval(payload)\n"],
  ["html-open-comment", "a.cjs", "<!-- `\neval(payload)\n<!-- `\n"],
  ["mts-nonnull", "a.mts", "declare const x: any;\nconst r = x! /2; eval(payload); const z = 1/ 1;\n"],
  ["cts-nonnull", "a.cts", "declare const x: any;\nconst r = x! /2; eval(payload); const z = 1/ 1;\n"],
  // Re-review N-3: the number lexer swallowed `+e` of an unspaced `eval`.
  ["number-swallows-identifier", "a.js", "const r = 1+eval(payload);\n"],
];

const parserClosed: Array<[string, string, string]> = [
  // `of`, and `await`/`yield` as script identifiers, were read as regex-start keywords.
  ["of-identifier", "a.js", "const of = 4;\nconst r = of /2; eval(payload); const z = 1/ 1;\n"],
  ["await-identifier-script", "a.cjs", "var await = 4;\nvar r = await /2; eval(payload); var z = 1/ 1;\n"],
  // After extends/new/default, break + ASI and ++ + ASI, JavaScript reads a regex but the lexer divided.
  ["extends-regex-comment", "a.js", "function unused() { return class extends /`/ {} }\neval(payload)\n// ` {} }\n"],
  ["new-regex", "a.js", "function unused() { return new /`/ }\neval(payload)\n// ` }\n"],
  ["export-default-regex", "a.mjs", "export default /`/;\neval(payload)\n// `\n"],
  ["break-asi-regex", "a.js", "for(;;){ break\n/`/ }\neval(payload)\n// ` }\n"],
  ["plusplus-asi-regex", "a.js", "let a = 1\n++/`/.lastIndex\neval(payload)\n// `\n"],
  // Identifier escapes and non-ASCII identifiers were not lexed.
  ["unicode-escape-ident", "a.js", "\\u0065val(payload)\n"],
  // The TypeScript non-null rule accepted only identifier, number, `]` or `)` before `!`.
  ["ts-nonnull-string", "a.ts", "const r = \"a\"! /2; eval(payload); const z = 1/ 1;\n"],
  ["ts-nonnull-template", "a.ts", "const r = `a`! /2; eval(payload); const z = 1/ 1;\n"],
  ["ts-nonnull-double", "a.ts", "declare const x: any;\nconst r = x!! /2; eval(payload); const z = 1/ 1;\n"],
  ["ts-nonnull-brace", "a.ts", "const r = {}! /2; eval(payload); const z = 1/ 1;\n"],
];

describe("native lexer limitations closed by the parser (review C-1; design §10.9)", () => {
  test.each(lexerClosed)("lexer-closed: %s parses and shows the eval", (_name, path, source) => {
    expect(parsedAndVisible(path, source)).toBe(true);
  });

  test.each(parserClosed)("parser-closed: %s parses and shows the eval", (_name, path, source) => {
    expect(parsedAndVisible(path, source)).toBe(true);
  });

  test("control: a plain eval is visible", () => {
    expect(parsedAndVisible("a.js", "eval(payload)\n")).toBe(true);
  });
});
