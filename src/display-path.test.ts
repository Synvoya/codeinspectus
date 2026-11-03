import { describe, expect, test } from "vitest";

import { escapePathForDisplay, isDisplayablePath } from "./display-path.js";

// Security review: repository paths reach warnings, notes and gap examples. A bidi override (U+202E)
// can make "evil\u202egnp.js" render as "evilsj.png"; separators and escapes can forge lines.
describe("repository path display", () => {
  test.each([
    ["a bidi override", "src/evil\u202egnp.js"],
    ["a bidi isolate", "src/a\u2066b.js"],
    ["a zero-width space", "src/a\u200bb.js"],
    ["a byte-order mark", "\ufeffsrc/a.js"],
    ["a line separator", "src/a\u2028b.js"],
    ["a paragraph separator", "src/a\u2029b.js"],
    ["NEL", "src/a\u0085b.js"],
    ["an escape", "src/a\u001b[2Jb.js"],
    ["a newline", "src/a\nb.js"],
  ])("a path with %s is not displayable", (_label, path) => {
    expect(isDisplayablePath(path)).toBe(false);
  });

  test("ordinary and non-Latin paths are displayable", () => {
    expect(isDisplayablePath("src/app.ts")).toBe(true);
    expect(isDisplayablePath("docs/naïve-文件 (copy).md")).toBe(true);
  });

  test("escaping keeps the entry but shows unsafe characters as code points", () => {
    expect(escapePathForDisplay("src/evil\u202egnp.js")).toBe("src/evil\\u{202e}gnp.js");
    expect(escapePathForDisplay("src/app.ts")).toBe("src/app.ts");
  });
});
