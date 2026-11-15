import { describe, expect, test } from "vitest";

import { maskCommentsFromParser, withJavaScriptParseCache, activeJavaScriptParseCache } from "./javascript-parse.js";
import { REACT_NATIVE_MAX_JS_TOKENS } from "./javascript.js";

/** Spaces for every code unit of `text` except line terminators, as the mask must produce. */
const blank = (text: string): string => text.replace(/[^\n\r\u2028\u2029]/g, " ");

describe("maskCommentsFromParser (4.1 M4)", () => {
  test("blanks line and block comments in place, keeping length, newlines and code", () => {
    const source = "const a = 1; // note\n/* one\n   two */ eval(x);\n";
    const masked = maskCommentsFromParser(source, "a.ts");
    expect(masked).toBe(`const a = 1; ${blank("// note")}\n${blank("/* one\n   two */")} eval(x);\n`);
    expect(masked).toHaveLength(source.length);
  });

  test("a block comment across lines keeps every line number", () => {
    const source = "/*\n * a\n * b\n */\nexec(cmd);\n";
    const masked = maskCommentsFromParser(source, "a.js")!;
    expect(masked.split("\n")).toHaveLength(source.split("\n").length);
    expect(masked.split("\n")[4]).toBe("exec(cmd);");
  });

  test("a regex literal that holds /* or // is code, not a comment", () => {
    const source = "const re = /\\/*/;\nconst slashes = /\\/\\//g;\neval(payload);\n";
    expect(maskCommentsFromParser(source, "a.ts")).toBe(source);
  });

  test('"//" and "/*" in strings and templates stay', () => {
    const source = "const u = \"https://x\";\nconst t = `a // b ${'/*'} c`;\nconst s = '/* not */';\neval(u);\n";
    expect(maskCommentsFromParser(source, "a.mjs")).toBe(source);
  });

  test("JSX text is not a comment; a JSX comment is", () => {
    const source = "export const A = () => <p>see http://x /* y */ {/* hidden */}</p>;\n";
    expect(maskCommentsFromParser(source, "a.jsx")).toBe(
      `export const A = () => <p>see http://x /* y */ {${blank("/* hidden */")}}</p>;\n`,
    );
  });

  test("a code point outside the BMP in a comment keeps every later offset", () => {
    const source = `// ${String.fromCodePoint(0x1f389)} party\neval(x);\n`;
    const masked = maskCommentsFromParser(source, "a.ts")!;
    expect(masked).toHaveLength(source.length);
    expect(masked.indexOf("eval")).toBe(source.indexOf("eval"));
  });

  test("an HTML-like comment in a script is a comment", () => {
    const source = "<!-- hidden\neval(x);\n";
    expect(maskCommentsFromParser(source, "a.cjs")).toBe(`${blank("<!-- hidden")}\neval(x);\n`);
  });

  test("a file the parser cannot read, or a non-JavaScript file, is undefined (callers fall back)", () => {
    expect(maskCommentsFromParser("const = ;\n// c\n", "a.ts")).toBeUndefined();
    expect(maskCommentsFromParser("# comment\nx = 1\n", "a.py")).toBeUndefined();
    expect(maskCommentsFromParser('{"a": "//"}\n', "a.json")).toBeUndefined();
    expect(maskCommentsFromParser("server { } # //\n", "nginx.conf")).toBeUndefined();
  });

  test("a TypeScript file only the standard-decorators fallback reads is masked too", () => {
    const source = "class A {\n  @Field() // note\n  [Key]!: string;\n}\n";
    expect(maskCommentsFromParser(source, "a.ts")).toBe(`class A {\n  @Field() ${blank("// note")}\n  [Key]!: string;\n}\n`);
  });

  test("shares the scan's parse cache with the native packs (same token bound)", async () => {
    await withJavaScriptParseCache(async () => {
      maskCommentsFromParser("// c\neval(x);\n", "a.ts");
      expect(activeJavaScriptParseCache()?.get("01100:" + REACT_NATIVE_MAX_JS_TOKENS, "// c\neval(x);\n")).toBeDefined();
    });
  });
});
