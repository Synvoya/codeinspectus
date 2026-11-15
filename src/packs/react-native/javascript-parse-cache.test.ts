import { describe, expect, test } from "vitest";

import { parseJavaScriptSource } from "./javascript.js";
import {
  COMMENT_CACHE_MAX_OFFSETS,
  maskCommentsFromParser,
  parseJavaScriptTokens,
  PARSE_CACHE_MAX_CHARS,
  PARSE_CACHE_MAX_TOKENS,
  activeJavaScriptParseCache,
  JavaScriptParseCache,
  withJavaScriptParseCache,
} from "./javascript-parse.js";

/** A small distinct source file of roughly 300 tokens. */
function smallFile(index: number): string {
  return Array.from({ length: 20 }, (_, line) => `export const v${index}_${line} = obj${index}.key(${line}, "s") + 1;`).join("\n");
}

// Review (stream D, Critical 2): the parse cache held ~170 bytes per token far past its character bound
// and lived for the whole server. It is now one cache per scan, bounded by tokens and source size, and
// cleared when the scan ends.
describe("JavaScript/TypeScript parse cache", () => {
  test("there is no cache outside a scan, so nothing is retained", () => {
    expect(activeJavaScriptParseCache()).toBeUndefined();
    const first = parseJavaScriptSource("a.ts", smallFile(1));
    const second = parseJavaScriptSource("a.ts", smallFile(1));
    expect(first.tokens).not.toBe(second.tokens);
  });

  test("4,000 small files stay under the token and size bound and nothing survives the scan", async () => {
    const cache = new JavaScriptParseCache();
    let peakTokens = 0;
    let peakChars = 0;
    let totalTokens = 0;
    await withJavaScriptParseCache(async () => {
      expect(activeJavaScriptParseCache()).toBe(cache);
      for (let index = 0; index < 4_000; index++) {
        const document = parseJavaScriptSource(`src/f${index}.ts`, smallFile(index));
        expect(document.balanced).toBe(true);
        totalTokens += document.tokens.length;
        peakTokens = Math.max(peakTokens, cache.tokens);
        peakChars = Math.max(peakChars, cache.chars);
        // A second analyzer reading the same file shares the parse.
        if (index % 997 === 0) expect(parseJavaScriptSource(`src/f${index}.ts`, smallFile(index)).tokens).toBe(document.tokens);
        await Promise.resolve();
      }
    }, cache);
    expect(totalTokens).toBeGreaterThan(4 * PARSE_CACHE_MAX_TOKENS);
    expect(peakTokens).toBeGreaterThan(0);
    expect(peakTokens).toBeLessThanOrEqual(PARSE_CACHE_MAX_TOKENS);
    expect(peakChars).toBeLessThanOrEqual(PARSE_CACHE_MAX_CHARS);
    expect(cache.size).toBe(0);
    expect(cache.tokens).toBe(0);
    expect(cache.chars).toBe(0);
    expect(activeJavaScriptParseCache()).toBeUndefined();
  }, 60000);

  test("the cache is cleared when a scan fails, and concurrent scans do not share one", async () => {
    const failing = new JavaScriptParseCache();
    await expect(withJavaScriptParseCache(async () => {
      parseJavaScriptSource("a.ts", smallFile(2));
      throw new Error("analyzer crashed");
    }, failing)).rejects.toThrow("analyzer crashed");
    expect(failing.size).toBe(0);
    const seen: Array<JavaScriptParseCache | undefined> = [];
    await Promise.all([
      withJavaScriptParseCache(async () => { await Promise.resolve(); seen.push(activeJavaScriptParseCache()); }),
      withJavaScriptParseCache(async () => { await Promise.resolve(); seen.push(activeJavaScriptParseCache()); }),
    ]);
    expect(seen[0]).toBeDefined();
    expect(seen[0]).not.toBe(seen[1]);
  });

  test("the path's reading class is part of the key", async () => {
    await withJavaScriptParseCache(async () => {
      const source = "x <!--y; `\neval(payload)\n// `\n";
      expect(parseJavaScriptSource("a.cjs", source).balanced).toBe(true);
      expect(parseJavaScriptSource("a.js", source).balanced).toBe(false);
    });
  });
});

// 4.1 M4 field timing: the four regex analyzers each sweep every file for its comment ranges. With only the
// token-bounded cache, a large repository's parses were evicted before the next analyzer reached them, and
// each analyzer parsed every file again (directus native scan 6.9 s -> 12.0 s).
describe("comment-range cache (4.1 M4)", () => {
  test("a file parsed once in a scan is comment-masked without a second parse after eviction", async () => {
    await withJavaScriptParseCache(async () => {
      const cache = activeJavaScriptParseCache()!;
      const files = Array.from({ length: 2000 }, (_, index) => `// file ${index}\n${smallFile(index)}`);
      for (const file of files) expect(parseJavaScriptSource("a.ts", file).balanced).toBe(true);
      expect(cache.get("01100:200000", files.at(-1)!)).toBeDefined();
      expect(cache.get("01100:200000", files[0]!)).toBeUndefined(); // evicted by the token bound
      expect(maskCommentsFromParser(files[0]!, "b.ts")).toBe(`${" ".repeat("// file 0".length)}\n${smallFile(0)}`);
      expect(cache.get("01100:200000", files[0]!)).toBeUndefined(); // served from comment ranges, not re-parsed
    });
    // 2,000 parses: the 5 s default timed out once under a parallel field run (4.1 M8).
  }, 30_000);

  // Review nit (M4 cleanup 5): comments read under another token bound are never reused by the mask, whose
  // own bound could refuse the file.
  test("the mask never reuses comment ranges read under another token bound", async () => {
    await withJavaScriptParseCache(async () => {
      const cache = activeJavaScriptParseCache()!;
      const file = `// note\n${smallFile(1)}`;
      parseJavaScriptTokens("a.ts", file, 1_000_000);
      expect(cache.get("01100:200000", file)).toBeUndefined();
      expect(maskCommentsFromParser(file, "a.ts")).toBe(`${" ".repeat("// note".length)}\n${smallFile(1)}`);
      expect(cache.get("01100:200000", file)).toBeDefined(); // parsed at the mask's own bound
    });
  });

  test("comment ranges are bounded and cleared with the scan", () => {
    const cache = new JavaScriptParseCache();
    const ranges = Array.from({ length: 1000 }, (_, index) => index);
    for (let index = 0; index < 3 * COMMENT_CACHE_MAX_OFFSETS / ranges.length; index++) cache.setComments(`k${index}`, ranges);
    expect(cache.commentOffsets).toBeLessThanOrEqual(COMMENT_CACHE_MAX_OFFSETS);
    expect(cache.getComments("k0")).toBeUndefined();
    cache.clear();
    expect(cache.commentOffsets).toBe(0);
  });
});
