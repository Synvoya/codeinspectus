/**
 * Modern Supabase API-key contract.
 *
 * `sb_secret_` is elevated and must surface in client source and bundles. The public
 * `sb_publishable_` counterpart and docs placeholders stay silent. A server-only literal is
 * outside this client-exposure analyzer (commodity secret scanning remains authoritative).
 * All values are synthetic test data.
 */

import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { runClientSecretsAnalysis, runClientSecretsCheck } from "./client-secrets.js";
import { dedupFindings } from "../dedup.js";
import type { Finding } from "../types.js";

const SECRET = "sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS";
const PUBLISHABLE = "sb_publishable_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS";
const STRIPE_SECRET = "sk_live_51Mz9KQb2eRxW7vYpL3nHsD8tA6cF0gJ4uXiZ2oP";
const DEDICATED_RULE = "ci-ai-supabase-secret-key-client";

let directory: string;
let findings: Finding[];

const at = (file: string): Finding[] =>
  findings.filter((finding) => finding.location.file === file);

describe("modern Supabase secret API keys", () => {
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), "ci-supabase-opaque-key-"));
    await mkdir(join(directory, "src", "components"), { recursive: true });
    await mkdir(join(directory, "app", "api", "admin"), { recursive: true });
    await mkdir(join(directory, "dist"), { recursive: true });

    await writeFile(
      join(directory, "src", "components", "admin.tsx"),
      `export const key = "${SECRET}";\n`,
    );
    await writeFile(
      join(directory, "src", "components", "public.tsx"),
      `export const key = "${PUBLISHABLE}";\n`,
    );
    await writeFile(
      join(directory, "src", "components", "docs.tsx"),
      'export const example = "sb_secret_...";\nexport const short = "sb_secret_testvalue123";\n',
    );
    await writeFile(
      join(directory, "src", "components", "multiple.tsx"),
      `export const keys = ["${SECRET}", "${STRIPE_SECRET}"];\n`,
    );
    await writeFile(
      join(directory, "app", "api", "admin", "route.ts"),
      `export const backendOnly = "${SECRET}";\n`,
    );
    await writeFile(join(directory, "dist", "secret.js"), `const key="${SECRET}";\n`);
    await writeFile(
      join(directory, "dist", "publishable.js"),
      `const key="${PUBLISHABLE}";\n`,
    );

    findings = await runClientSecretsCheck(directory);
  });

  afterAll(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  test("client source emits only the dedicated critical Supabase rule", () => {
    const client = at("src/components/admin.tsx");
    expect(client.map((finding) => finding.rule_id)).toEqual([DEDICATED_RULE]);
    expect(client.every((finding) => finding.severity === "critical")).toBe(true);
    expect(client.find((finding) => finding.rule_id === DEDICATED_RULE)?.cwe).toEqual(
      expect.arrayContaining(["CWE-285", "CWE-798"]),
    );
  });

  test("built output emits only the dedicated Supabase rule", () => {
    const bundle = at("dist/secret.js");
    expect(bundle.map((finding) => finding.rule_id)).toEqual([DEDICATED_RULE]);
    expect(bundle.every((finding) => finding.severity === "critical")).toBe(true);
  });

  test("normal-size source finds every provider secret on the same line", () => {
    const multiple = at("src/components/multiple.tsx");
    expect(
      multiple.filter((finding) => finding.rule_id === "ci-ai-client-hardcoded-secret"),
    ).toHaveLength(1);
    expect(multiple.filter((finding) => finding.rule_id === DEDICATED_RULE)).toHaveLength(1);
  });

  test("publishable keys, placeholders, short examples, and server-only use stay silent", () => {
    for (const file of [
      "src/components/public.tsx",
      "src/components/docs.tsx",
      "dist/publishable.js",
      "app/api/admin/route.ts",
    ]) {
      expect(at(file)).toHaveLength(0);
    }
  });

  test("the raw secret never survives in any finding field", () => {
    expect(JSON.stringify(findings)).not.toContain(SECRET);
    const dedicated = findings.filter((finding) => finding.rule_id === DEDICATED_RULE);
    expect(dedicated).toHaveLength(3);
    expect(dedicated.every((finding) => finding.is_secret === true)).toBe(true);
  });

  test("the final deduplicator preserves the dedicated rule", () => {
    const final = dedupFindings(findings).findings.filter((finding) =>
      finding.location.file === "src/components/admin.tsx",
    );
    expect(final).toHaveLength(1);
    expect(final[0]?.rule_id).toBe(DEDICATED_RULE);
  });
});

describe("client-secret candidate bounds", () => {
  test("same client path transitions from secret to publishable and back without stale state", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-supabase-key-transition-"));
    try {
      const file = join(root, "src", "components", "supabase.ts");
      await mkdir(join(root, "src", "components"), { recursive: true });

      await writeFile(file, `export const key = "${SECRET}";\n`);
      const introduced = await runClientSecretsCheck(root);
      expect(introduced.map((finding) => finding.rule_id)).toEqual([DEDICATED_RULE]);

      await writeFile(file, `export const key = "${PUBLISHABLE}";\n`);
      expect(await runClientSecretsCheck(root)).toEqual([]);

      await writeFile(file, `export const key = "${SECRET}";\n`);
      const reintroduced = await runClientSecretsCheck(root);
      expect(reintroduced.map((finding) => finding.rule_id)).toEqual([DEDICATED_RULE]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("collapses same-line floods, retains distinct lines, and reports the location limit", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-supabase-key-bound-"));
    try {
      await mkdir(join(root, "src", "components"), { recursive: true });
      const repeated = "sb_secret_R1e2P3e4A5t6E7d8K9e0Y1_aB3cD4eF";
      const distinct = Array.from({ length: 1_030 }, (_, index) => {
        const body = index.toString(36).padStart(22, "A");
        const checksum = index.toString(36).padStart(8, "B");
        return `sb_secret_${body}_${checksum}`;
      });
      await writeFile(
        join(root, "src", "components", "repeated.ts"),
        Array.from({ length: 10_000 }, () => repeated).join(","),
      );
      await writeFile(
        join(root, "src", "components", "repeated-lines.ts"),
        Array.from({ length: 3 }, (_, index) => `export const k${index} = "${repeated}";`).join("\n"),
      );
      await writeFile(
        join(root, "src", "components", "distinct.ts"),
        distinct.map((value) => `export const k${value.slice(-8)} = "${value}";`).join("\n"),
      );

      const result = await runClientSecretsAnalysis(root);
      expect(
        result.findings.filter((finding) =>
          finding.location.file === "src/components/repeated.ts",
        ),
      ).toHaveLength(1);
      expect(
        result.findings.filter((finding) =>
          finding.location.file === "src/components/distinct.ts",
        ),
      ).toHaveLength(1_024);
      expect(
        result.findings
          .filter((finding) => finding.location.file === "src/components/repeated-lines.ts")
          .map((finding) => finding.location.start_line),
      ).toEqual([1, 2, 3]);
      expect(result.notes).toEqual([
        expect.stringMatching(/distinct\.ts.*1024-location.*not evaluated/),
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("bounds per-file coverage notes with an omitted-count summary", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-supabase-key-notes-"));
    try {
      await mkdir(join(root, "src", "components"), { recursive: true });
      const values = Array.from({ length: 1_025 }, (_, index) => {
        const body = index.toString(36).padStart(22, "C");
        const checksum = index.toString(36).padStart(8, "D");
        return `sb_secret_${body}_${checksum}`;
      }).join(",");
      for (let index = 0; index < 26; index++) {
        await writeFile(join(root, "src", "components", `limited-${index}.ts`), values);
      }

      const result = await runClientSecretsAnalysis(root);
      expect(result.notes).toHaveLength(24);
      expect(result.notes.at(-1)).toMatch(/3 additional client-secret limitations omitted/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
