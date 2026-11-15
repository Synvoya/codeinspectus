import { describe, expect, test } from "vitest";

import {
  assignDisplayIds,
  baseDisplayId,
  DISPLAY_ID_PATTERN,
  displayIdBasis,
  displayIdHint,
  LEGACY_DISPLAY_ID_PATTERN,
} from "./display-id.js";
import type { Finding } from "./types.js";

function finding(fingerprint: string, overrides: Partial<Finding> = {}): Finding {
  return {
    id: fingerprint,
    fingerprint,
    title: "Finding",
    severity: "high",
    engine: "trivy",
    engines: ["trivy"],
    rule_id: "CVE-2026-0001",
    cwe: ["CWE-1395"],
    location: { file: "pnpm-lock.yaml", start_line: 1, end_line: 1 },
    message: "message",
    remediation: { summary: "", steps: [], references: [] },
    frameworks: [],
    confidence: "high",
    ...overrides,
  };
}

/** Deterministic Fisher-Yates with a small LCG, so a failure reproduces. */
function shuffled<T>(items: readonly T[], seed: number): T[] {
  const out = [...items];
  let state = seed;
  for (let index = out.length - 1; index > 0; index -= 1) {
    state = (state * 1103515245 + 12345) % 2147483648;
    const swap = state % (index + 1);
    [out[index], out[swap]] = [out[swap]!, out[index]!];
  }
  return out;
}

const pkg = (name: string) => ({ ecosystem: "npm", name, version: "1.0.0" });

describe("display ids", () => {
  test("matches the pinned test vectors", () => {
    expect(baseDisplayId(finding("sha256:89941b59ddb4cce706fd92c357bb1f7c8937e55b7004d48ece417796075d85bc"))).toBe("CI-4b53368c3f");
    expect(baseDisplayId(finding("fp-a"))).toBe("CI-94ec2858d9");
    expect(baseDisplayId(finding("fp-a", { package: pkg("@intlify/core") }))).toBe("CI-e8431c0363");
    expect(baseDisplayId(finding("fp-a", { package: pkg("@intlify/core-base") }))).toBe("CI-87e6e56a12");
    expect(displayIdBasis(finding("fp-a", { package: pkg("Typing_Extensions") }))).toBe("fp-a\0typing-extensions");
  });

  test("is independent of input order", () => {
    const base = Array.from({ length: 50 }, (_, index) => finding(`fp-${index}`));
    const reference = base.map((item) => ({ ...item }));
    assignDisplayIds(reference);
    const expected = new Map(reference.map((item) => [item.fingerprint, item.id]));
    for (let seed = 1; seed <= 10; seed += 1) {
      const copy = shuffled(base.map((item) => ({ ...item })), seed);
      assignDisplayIds(copy);
      for (const item of copy) expect(item.id).toBe(expected.get(item.fingerprint));
    }
  });

  test("an added or removed finding changes no other id", () => {
    const before = Array.from({ length: 20 }, (_, index) => finding(`fp-${index}`));
    assignDisplayIds(before);
    const after = [...before.slice(1).map((item) => ({ ...item })), finding("fp-new-1"), finding("fp-new-2")];
    assignDisplayIds(after);
    const ids = new Map(before.map((item) => [item.fingerprint, item.id]));
    for (const item of after) if (ids.has(item.fingerprint)) expect(item.id).toBe(ids.get(item.fingerprint));
  });

  test("findings that share a fingerprint get different ids when their packages differ", () => {
    const sink = [
      finding("sha256:shared-line-1", { package: pkg("@intlify/core") }),
      finding("sha256:shared-line-1", { package: pkg("@intlify/core-base") }),
    ];
    assignDisplayIds(sink);
    expect(sink[0]!.id).not.toBe(sink[1]!.id);
    for (const item of sink) expect(item.id).toMatch(/^CI-[0-9a-f]{10}$/);
  });

  test("collisions get -2, -3 by the documented order", () => {
    const constant = () => "abcdef0123456789";
    const make = () => [
      finding("fp-b", { package: pkg("zeta") }),
      finding("fp-a", { package: pkg("beta") }),
      finding("fp-a", { package: pkg("alpha") }),
    ];
    const forward = make();
    assignDisplayIds(forward, { hash: constant });
    const reversed = make().reverse();
    assignDisplayIds(reversed, { hash: constant });
    const mapping = (items: Finding[]) => Object.fromEntries(items.map((item) => [`${item.fingerprint}/${item.package?.name}`, item.id]));
    expect(mapping(forward)).toEqual({
      "fp-a/alpha": "CI-abcdef0123",
      "fp-a/beta": "CI-abcdef0123-2",
      "fp-b/zeta": "CI-abcdef0123-3",
    });
    expect(mapping(reversed)).toEqual(mapping(forward));
  });

  test("an identical basis is ordered by the remaining fields", () => {
    const make = () => [
      finding("fp-same", { location: { file: "b.ts", start_line: 1, end_line: 1 }, engine: "gitleaks", engines: ["gitleaks"], is_secret: true }),
      finding("fp-same", { location: { file: "a.ts", start_line: 1, end_line: 1 }, engine: "gitleaks", engines: ["gitleaks"], is_secret: true }),
    ];
    const forward = make();
    assignDisplayIds(forward);
    const reversed = make().reverse();
    assignDisplayIds(reversed);
    const byFile = (items: Finding[]) => Object.fromEntries(items.map((item) => [item.location.file, item.id]));
    expect(byFile(forward)).toEqual(byFile(reversed));
    expect(byFile(forward)["a.ts"]).toMatch(/^CI-[0-9a-f]{10}$/);
    expect(byFile(forward)["b.ts"]).toBe(`${byFile(forward)["a.ts"]}-2`);
  });

  test("two versions sharing a fingerprint are ordered by version, so removing one keeps the other's id (M5 fix round 2)", () => {
    // Trivy pnpm findings keep their legacy line-1 fingerprint after relocation: two versions of one package share it.
    const at = (version: string, line: number) => finding("sha256:pnpm-line-1", {
      package: { ecosystem: "npm", name: "semver", version }, location: { file: "pnpm-lock.yaml", start_line: line, end_line: line },
    });
    const both = [at("7.5.1", 12), at("5.7.1", 40)];
    assignDisplayIds(both);
    const ids = Object.fromEntries(both.map((item) => [item.package!.version, item.id]));
    expect(ids["7.5.1"]).toBe(`${ids["5.7.1"]}-2`);
    // The lower version keeps its id when the other disappears, and moving lines changes nothing.
    const alone = [at("5.7.1", 40)];
    assignDisplayIds(alone);
    expect(alone[0]!.id).toBe(ids["5.7.1"]);
    const moved = [at("5.7.1", 3), at("7.5.1", 90)];
    assignDisplayIds(moved);
    expect(Object.fromEntries(moved.map((item) => [item.package!.version, item.id]))).toEqual(ids);
    // A leading v is the same version.
    const prefixed = [at("v5.7.1", 40), at("7.5.1", 12)];
    assignDisplayIds(prefixed);
    expect(prefixed.map((item) => item.id)).toEqual([ids["5.7.1"], ids["7.5.1"]]);
  });

  test("every id is unique and matches DISPLAY_ID_PATTERN", () => {
    const many = Array.from({ length: 5000 }, (_, index) =>
      finding(`sha256:${index % 4000}`, index % 3 === 0 ? { package: pkg(`pkg-${index % 7}`) } : {}));
    assignDisplayIds(many);
    const ids = many.map((item) => item.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(DISPLAY_ID_PATTERN);
      expect(id).not.toMatch(LEGACY_DISPLAY_ID_PATTERN);
    }
  });

  test("displayIdHint", () => {
    const fresh = { findings: [finding("fp-a", { id: "CI-94ec2858d9" })] };
    const legacy = { findings: [finding("fp-a", { id: "CI-0001" })] };
    expect(displayIdHint("CI-0007", fresh)).toBe(
      "Ids like CI-0007 come from scans stored before CodeInspectus 4.1; this scan's ids are derived from each finding's fingerprint. ",
    );
    expect(displayIdHint("CI-4b53368c3f", legacy)).toBe(
      "This scan was stored before CodeInspectus 4.1 and uses positional ids such as CI-0001. ",
    );
    expect(displayIdHint("CI-0007", legacy)).toBe("");
    expect(displayIdHint("CI-4b53368c3f", fresh)).toBe("");
    expect(displayIdHint("nonsense", fresh)).toBe("");
    expect(displayIdHint("CI-0007", { findings: [] })).toBe("");
  });
});
