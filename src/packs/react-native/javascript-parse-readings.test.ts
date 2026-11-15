/**
 * Review nit (M4 cleanup 1): a TypeScript file is read with legacy decorators first. Standard decorators are
 * only a fallback, so a file both readings accept is always the legacy reading; swapping the order in
 * `pluginSets` fails this test. The parser is spied on to see which plugin sets it was called with.
 */
import { beforeEach, describe, expect, test, vi } from "vitest";

const calls = vi.hoisted(() => [] as unknown[][]);

vi.mock("@babel/parser", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@babel/parser")>();
  return {
    ...actual,
    parse: (input: string, options?: { plugins?: unknown[] }) => {
      calls.push(options?.plugins ?? []);
      return actual.parse(input, options as never);
    },
  };
});

const { parseJavaScriptTokens } = await import("./javascript-parse.js");

const legacy = (plugins: unknown[]) => plugins.includes("decorators-legacy");
const standard = (plugins: unknown[]) => plugins.some((plugin) => Array.isArray(plugin) && plugin[0] === "decorators");

beforeEach(() => {
  calls.length = 0;
});

describe("TypeScript decorator readings (4.1 M4)", () => {
  test("a file both readings accept is read with legacy decorators only", () => {
    const source = "export class A {\n  @Injectable()\n  m() {}\n}\n";
    expect(parseJavaScriptTokens("a.ts", source, 200_000).issues).toEqual([]);
    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every(legacy)).toBe(true);
    expect(calls.some(standard)).toBe(false);
  });

  test("standard decorators are read only after the legacy reading fails", () => {
    const source = "export class A {\n  @Field()\n  [Key]!: string;\n}\n";
    expect(parseJavaScriptTokens("a.ts", source, 200_000).issues).toEqual([]);
    const firstStandard = calls.findIndex(standard);
    expect(firstStandard).toBeGreaterThan(0);
    expect(calls.slice(0, firstStandard).every(legacy)).toBe(true);
  });
});
