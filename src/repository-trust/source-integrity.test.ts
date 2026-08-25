import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv } from "ajv";
import { afterEach, describe, expect, test } from "vitest";
import { repositoryTrustDocumentSchema } from "./schemas.js";
import {
  SOURCE_INTEGRITY_VALIDATOR,
  scanSourceIntegrity,
} from "./source-integrity.js";

const cleanup: string[] = [];

async function fixture(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-source-integrity-"));
  cleanup.push(directory);
  return directory;
}

afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("V3.1 deterministic source-integrity scanner", () => {
  test("detects high-signal bidi, zero-width, tag, variation-selector, and confusable evidence", async () => {
    const root = await fixture();
    await writeFile(join(root, "dangerous.ts"), [
      `const allowed = true; // \u202E } dangerous bidi override`,
      `const admin\u200BRole = "owner";`,
      `const tagged = "A\u{E0061}\u{E0062}";`,
      `const encoded = "X\uFE00\uFE01\uFE02\uFE03";`,
      `const p\u0430ypalToken = "value";`,
      `const isolate = "\u2067unterminated";`,
    ].join("\n"), "utf8");

    const document = await scanSourceIntegrity(root);
    expect(repositoryTrustDocumentSchema.parse(document)).toEqual(document);
    const packagedSchema = JSON.parse(
      await readFile("schemas/codeinspectus-repository-trust-1.0.0.schema.json", "utf8"),
    );
    const validate = new Ajv({ strict: false, validateSchema: false }).compile(packagedSchema);
    expect(validate(document), JSON.stringify(validate.errors)).toBe(true);
    expect(document.coverage.state).toBe("partial");
    expect(document.coverage.capabilities.find((item) => item.capability === "source_integrity"))
      .toMatchObject({ state: "ran", validators: [SOURCE_INTEGRITY_VALIDATOR] });
    expect(document.artifacts.map((artifact) => artifact.marker_class)).toEqual(expect.arrayContaining([
      "unicode_bidi_override",
      "unicode_bidi_unbalanced",
      "unicode_zero_width_token",
      "unicode_tag_payload",
      "unicode_variation_selector_payload",
      "unicode_mixed_script_identifier",
    ]));
    expect(document.artifacts.filter((artifact) => artifact.state === "verified").length).toBeGreaterThanOrEqual(5);
    expect(document.artifacts.find((artifact) => artifact.marker_class === "unicode_mixed_script_identifier"))
      .toMatchObject({ state: "probable", confidence: "medium", remediation: { eligible: false } });
    for (const artifact of document.artifacts.filter((item) => item.state === "verified")) {
      expect(artifact.location).toMatchObject({ file: "dangerous.ts" });
      expect(artifact.location.start_line).toBeGreaterThan(0);
      expect(artifact.location.start_column).toBeGreaterThan(0);
      expect(artifact.evidence.attributes).toEqual(expect.arrayContaining([
        expect.objectContaining({ name: "code_points" }),
        expect.objectContaining({ name: "escaped_sequence" }),
        expect.objectContaining({ name: "utf8_byte_offset" }),
        expect.objectContaining({ name: "proposed_action" }),
      ]));
      expect(artifact.remediation).toMatchObject({ requires_approval: true, reversible: true });
    }
    expect(JSON.stringify(document)).not.toMatch(/claude|anthropic|ai.generated|vendor.watermark/i);
  });

  test("suppresses or keeps legitimate RTL, emoji, joiners, BOM, and international identifiers non-destructive", async () => {
    const root = await fixture();
    await writeFile(join(root, "legitimate.ts"), [
      `\uFEFFconst greeting = "hello";`,
      `// \u2067مرحبا بالعالم\u2069`,
      `const heart = "❤️";`,
      `const family = "👩‍👩‍👧‍👦";`,
      `const subdivisionFlag = "🏴\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";`,
      `const देवनागरी = "क्‍ष";`,
      `const полностью = true;`,
      `const quoted = "p\u0430ypal";`,
      `// p\u0430ypal is prose, not an identifier`,
      `const ideograph = "葛\u{E0100}";`,
    ].join("\n"), "utf8");

    const document = await scanSourceIntegrity(root);
    expect(document.artifacts.every((artifact) => artifact.remediation.eligible === false)).toBe(true);
    expect(document.artifacts.some((artifact) => artifact.state === "verified")).toBe(false);
    expect(document.artifacts.some((artifact) => artifact.marker_class === "unicode_mixed_script_identifier")).toBe(false);
  });

  test("is deterministic, scans a direct file, and never mutates the target", async () => {
    const root = await fixture();
    const path = join(root, "single.py");
    const source = `admin\u200BRole = True\n`;
    await writeFile(path, source, "utf8");
    const before = await readFile(path);
    const first = await scanSourceIntegrity(path);
    const second = await scanSourceIntegrity(path);
    expect(first).toEqual(second);
    expect(first.artifacts).toHaveLength(1);
    expect(first.artifacts[0]).toMatchObject({
      marker_class: "unicode_zero_width_token",
      location: { file: "single.py", start_line: 1 },
    });
    expect(await readFile(path)).toEqual(before);
  });

  test("fails coverage partial for skipped symlinks, invalid UTF-8, oversized files, and artifact bounds", async () => {
    const root = await fixture();
    const outside = join(await fixture(), "outside.ts");
    await writeFile(outside, `const outside\u200BToken = true;`, "utf8");
    await symlink(outside, join(root, "linked.ts"));
    await writeFile(join(root, "invalid.ts"), Buffer.from([0xff, 0xfe, 0xfd]));
    await writeFile(join(root, "oversized.ts"), Buffer.alloc(2 * 1024 * 1024 + 1, 0x61));
    await mkdir(join(root, "nested"));
    await writeFile(join(root, "nested", "safe.ts"), `const one\u200BToken = true;\nconst two\u200BToken = true;`, "utf8");

    const document = await scanSourceIntegrity(root, { maxArtifacts: 1 });
    const sourceCoverage = document.coverage.capabilities.find((item) => item.capability === "source_integrity")!;
    expect(sourceCoverage.state).toBe("partial");
    expect(sourceCoverage.limitations.join(" ")).toMatch(/symbolic/i);
    expect(sourceCoverage.limitations.join(" ")).toMatch(/UTF-8/i);
    expect(sourceCoverage.limitations.join(" ")).toMatch(/2 MiB/i);
    expect(sourceCoverage.limitations.join(" ")).toMatch(/1-artifact bound/i);
    expect(document.artifacts).toHaveLength(1);
    expect(document.artifacts.every((artifact) => artifact.location.file !== "linked.ts")).toBe(true);
  });

  test("bounds dense marker candidates and long sequence evidence before artifact materialization", async () => {
    const root = await fixture();
    await writeFile(join(root, "dense.ts"), `const value = "${"\u200B".repeat(50_000)}";`, "utf8");
    await writeFile(join(root, "sequence.ts"), `const value = "X${"\uFE00".repeat(5_000)}";`, "utf8");
    await writeFile(join(root, "identifier.ts"), `const ${"a".repeat(50_000)}\u0430 = true;`, "utf8");

    const bounded = await scanSourceIntegrity(root, { maxArtifacts: 5 });
    const boundedCoverage = bounded.coverage.capabilities.find((item) => item.capability === "source_integrity")!;
    expect(bounded.artifacts).toHaveLength(5);
    expect(boundedCoverage.state).toBe("partial");
    expect(boundedCoverage.limitations.join(" ")).toMatch(/5-artifact bound/i);

    const sequenceOnly = await scanSourceIntegrity(join(root, "sequence.ts"));
    const sequence = sequenceOnly.artifacts[0]!;
    expect(sequence).toMatchObject({
      marker_class: "unicode_variation_selector_payload",
      location: { start_column: 17, end_column: 5016 },
    });
    expect(sequence.evidence.attributes).toEqual(expect.arrayContaining([
      { name: "sequence_length", value: 5_000 },
      { name: "evidence_truncated", value: true },
    ]));
    const escapedEvidence = sequence.evidence.attributes.find((item) => item.name === "escaped_sequence")?.value;
    expect(String(escapedEvidence).length).toBeLessThan(1_000);
    expect(sequence.limitations.join(" ")).toMatch(/64 code points/i);

    const identifierOnly = await scanSourceIntegrity(join(root, "identifier.ts"));
    const identifier = identifierOnly.artifacts[0]!;
    const proposedAction = identifier.evidence.attributes.find((item) => item.name === "proposed_action")?.value;
    expect(String(proposedAction).length).toBeLessThan(1_000);
    expect(identifier.limitations.join(" ")).toMatch(/128 code points/i);
  });

  test("reports not_applicable when a directory has no supported source or text files", async () => {
    const root = await fixture();
    await writeFile(join(root, "image.bin"), Buffer.from([0, 1, 2, 3]));
    const document = await scanSourceIntegrity(root);
    expect(document.artifacts).toEqual([]);
    expect(document.coverage.capabilities.find((item) => item.capability === "source_integrity"))
      .toMatchObject({ state: "not_applicable" });
  });
});
