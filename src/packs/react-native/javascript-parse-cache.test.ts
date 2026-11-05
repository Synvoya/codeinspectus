import { describe, expect, test } from "vitest";

import { parseJavaScriptSource } from "./javascript.js";
import {
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
  });

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
