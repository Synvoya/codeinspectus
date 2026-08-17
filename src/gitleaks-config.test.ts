import { readFile } from "node:fs/promises";
import { describe, expect, test } from "vitest";
import { parse as parseToml } from "smol-toml";

interface GitleaksRule {
  id: string;
  regex: string;
  secretGroup?: number;
  keywords?: string[];
}

interface GitleaksAllowlist {
  description?: string;
  regexTarget?: string;
  regexes?: string[];
}

describe("CodeInspectus Gitleaks extension", () => {
  test("owns an exact modern Supabase secret rule without matching publishable keys or placeholders", async () => {
    const config = parseToml(
      await readFile("detection-db/gitleaks/codeinspectus.toml", "utf8"),
    ) as {
      extend?: { useDefault?: boolean };
      rules?: GitleaksRule[];
      allowlists?: GitleaksAllowlist[];
    };
    const rules = config.rules ?? [];
    const ids = rules.map((rule) => rule.id);
    const supabase = rules.find(
      (rule) => rule.id === "codeinspectus-supabase-secret-key",
    );

    expect(config.extend?.useDefault).toBe(true);
    expect(new Set(ids).size).toBe(ids.length);
    expect(rules).toHaveLength(4);
    expect(supabase).toMatchObject({
      secretGroup: 1,
      keywords: ["sb_secret_"],
    });

    const expression = new RegExp(supabase!.regex);
    expect(expression.test("sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS")).toBe(true);
    expect(expression.test("sb_publishable_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS")).toBe(false);
    expect(expression.test("sb_secret_...")).toBe(false);
    expect(expression.test("sb_secret_testvalue123")).toBe(false);
    expect(expression.test("sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS4")).toBe(false);

    const publishableAllowlist = (config.allowlists ?? []).find((allowlist) =>
      allowlist.description?.includes("publishable API key"),
    );
    expect(publishableAllowlist?.regexTarget).toBe("match");
    const publishableExpression = new RegExp(publishableAllowlist!.regexes![0]!);
    expect(
      publishableExpression.test(
        'const supabaseKey = "sb_publishable_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS";',
      ),
    ).toBe(true);
    expect(
      publishableExpression.test(
        'const supabaseKey = "sb_secret_A1b2C3d4E5f6G7h8I9j0K1_mN2pQ3rS";',
      ),
    ).toBe(false);
  });
});
