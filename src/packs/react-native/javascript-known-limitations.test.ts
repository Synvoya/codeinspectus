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

/**
 * Under `decorators-legacy`, a decorator followed by a computed class key on the next line
 * (`@ApiProperty({...})` then `[UploadFieldName.PROFILE_DATA]!: string`, one immich DTO) reads as the member
 * access `@ApiProperty({...})[UploadFieldName.PROFILE_DATA]`, so the file was `native-parse-errors` on every
 * 7.x release (7.29.13 too). TypeScript reads it as a decorator and a computed key. A TypeScript file the
 * legacy reading rejects is read once more with standard decorators (4.1 M4). A file both readings reject
 * stays unparsed, never clean.
 */
describe("standard-decorators fallback: a decorator before a computed class key (4.1 M4)", () => {
  const immich = [
    "enum UploadFieldName { PROFILE_DATA = 'file' }",
    "export class CreateProfileImageDto {",
    "  @ApiProperty({ type: 'string', format: 'binary' })",
    "  [UploadFieldName.PROFILE_DATA]!: string;",
    "}",
    "eval(payload);",
    "",
  ].join("\n");

  test.each(["a.ts", "a.tsx", "a.mts"])("the immich pattern parses in %s", (path) => {
    expect(parsedAndVisible(path, immich)).toBe(true);
  });

  // A `.cts` file is a script, where `export` is a parse error under any reading (unchanged by M4).
  test("the immich pattern without `export` parses in a.cts", () => {
    expect(parsedAndVisible("a.cts", immich.replace("export class", "class"))).toBe(true);
  });

  test("the fallback reads the decorator and the computed key token for token", () => {
    const document = parseJavaScriptSource("a.ts", immich);
    expect(document.tokens.filter((token) => token.line === 3 || token.line === 4).map((token) => token.value)).toEqual([
      "@", "ApiProperty", "(", "{", "type", ":", "'string'", ",", "format", ":", "'binary'", "}", ")",
      "[", "UploadFieldName", ".", "PROFILE_DATA", "]", "!", ":", "string", ";",
    ]);
  });

  test.each([
    // A syntax error no decorator reading fixes.
    ["syntax error", "a.ts", "export class A {\n  [K]!: string = \n}\neval(payload);\n"],
    // The legacy reading rejects the computed key; standard decorators reject the parameter decorator.
    ["computed key and parameter decorator", "a.ts",
      "class A {\n  @Dec()\n  [K]!: string;\n  constructor(@Inject(X) x: X) {}\n}\neval(payload);\n"],
    // The legacy reading rejects the computed key; standard decorators reject a call before a member access.
    ["computed key and legacy decorator expression", "a.tsx",
      "class A {\n  @Dec()\n  [K]!: string;\n  @a.b().c m() {}\n}\neval(payload);\n"],
  ])("a file both readings reject stays unparsed: %s", (_name, path, source) => {
    const document = parseJavaScriptSource(path, source);
    expect(document.balanced).toBe(false);
    expect(document.tokens).toEqual([]);
    expect(document.lexicalIssues.join("\n")).toMatch(/parse error/);
  });

  // Review nit (M4 cleanup 4): when both readings fail, the error further into the file is the useful one.
  test("both readings fail: the standard reading's error is reported when it is further into the file", () => {
    const source = "class A {\n  @Dec()\n  [K]!: string;\n  m() { const = 1; }\n}\n";
    const document = parseJavaScriptSource("a.ts", source);
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues.join("\n")).toMatch(/\(4:\d+\)/);
  });

  test("both readings fail: the legacy reading's error is reported when it is further into the file", () => {
    const source = "class A {\n  constructor(@Inject(X) x: X) {}\n}\nconst = 1;\n";
    const document = parseJavaScriptSource("a.ts", source);
    expect(document.balanced).toBe(false);
    expect(document.lexicalIssues.join("\n")).toMatch(/\(4:\d+\)/);
  });

  test("JavaScript gets no decorator fallback", () => {
    expect(parseJavaScriptSource("a.js", "class A {\n  @dec\n  [k] = 1;\n}\n").balanced).toBe(false);
  });
});
