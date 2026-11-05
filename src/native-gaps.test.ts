import { describe, expect, test } from "vitest";

import { nativeGaps } from "./native-gaps.js";

describe("native-pack gap records", () => {
  test("files are counted once per id, sorted by code point, and unsafe names are counted but not shown", () => {
    expect(nativeGaps([
      { id: "native-parse-errors", path: "b.ts" },
      { id: "native-parse-errors", path: "B.ts" },
      { id: "native-parse-errors", path: "b.ts" },
      { id: "native-parse-errors", path: `evil${String.fromCodePoint(0x202e)}.ts` },
      { id: "symlinked-paths", path: ".claude/skills/x" },
    ])).toEqual([
      { id: "native-parse-errors", files: 3, examples: ["B.ts", "b.ts"] },
      { id: "symlinked-paths", files: 1, examples: [".claude/skills/x"] },
    ]);
  });
});
