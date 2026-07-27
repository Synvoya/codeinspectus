import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { expoPack } from "../expo-pack.js";
import {
  createExpoAnalyzers,
  loadExpoConfig,
  runExpoSecretInPublicConfig,
  runExpoUnsignedCleartextUpdates,
} from "./index.js";

const projects: string[] = [];

async function project(filename: string, source: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
  projects.push(directory);
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ private: true, dependencies: { expo: "55.0.0" } }),
    "utf8",
  );
  await writeFile(join(directory, filename), source, "utf8");
  return directory;
}

async function put(directory: string, path: string, source: string): Promise<void> {
  const absolute = join(directory, path);
  await mkdir(join(absolute, ".."), { recursive: true });
  await writeFile(absolute, source, "utf8");
}

afterEach(async () => {
  await Promise.all(projects.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("Expo static configuration parser", () => {
  test("accepts JSON comments and trailing commas without treating strings as code", async () => {
    const directory = await project("app.json", `{
      // process.env.COMMENT_SECRET must remain inert
      "expo": {
        "description": "process.env.STRING_SECRET",
        "updates": {
          "url": "http://updates.acme.dev/bundle",
        },
      },
    }`);
    const loaded = await loadExpoConfig(directory);
    expect(loaded.document?.path).toBe("app.json");
    await expect(runExpoSecretInPublicConfig(loaded)).resolves.toMatchObject({ findings: [] });
    const updates = await runExpoUnsignedCleartextUpdates(loaded);
    expect(updates.findings).toHaveLength(1);
    expect(updates.findings[0]).toMatchObject({
      rule_id: "ci-expo-unsigned-cleartext-updates",
      severity: "high",
      confidence: "high",
      cwe: ["CWE-494", "CWE-319"],
    });
  });

  test("does not treat JavaScript syntax in a JSON-named config as executable configuration", async () => {
    for (const source of [
      `{ expo: { extra: { token: process.env.SERVER_TOKEN } } }`,
      `{ 'expo': { 'updates': { 'url': 'http://updates.acme.dev' } } }`,
    ]) {
      const directory = await project("app.json", source);
      const secret = await runExpoSecretInPublicConfig(directory);
      const updates = await runExpoUnsignedCleartextUpdates(directory);
      expect(secret.findings).toHaveLength(0);
      expect(updates.findings).toHaveLength(0);
      expect(secret.notes?.join(" ")).toMatch(/unresolved Expo config/i);
    }
  });

  test("fails closed rather than interpreting regular-expression contents as configuration code", async () => {
    const directory = await project("app.config.js", `
      // export default { extra: { token: process.env.COMMENT_SECRET } };
      const pattern = /process\\.env\\.REGEX_SECRET/;
      export default {
        extra: {
          prose: "process.env.STRING_SECRET",
          template: \`process.env.TEMPLATE_SECRET\`,
        },
        updates: { url: "http://updates.acme.dev" },
      };
    `);
    const secret = await runExpoSecretInPublicConfig(directory);
    const updates = await runExpoUnsignedCleartextUpdates(directory);
    expect(secret.findings).toHaveLength(0);
    expect(updates.findings).toHaveLength(0);
    expect(secret.notes?.join(" ")).toMatch(/Unsupported regular-expression or division syntax/i);
  });

  test("never treats a regular-expression body as a top-level environment alias", async () => {
    const directory = await project("app.config.js", [
      'import { token } from "./safe.js";',
      "const pattern = /const token = process.env.SERVER_SECRET;/;",
      "export default { expo: { name: 'App', slug: 'app', extra: { token } } };",
      "",
    ].join("\n"));
    await put(directory, "safe.js", "export const token = 'public-client-id';\n");

    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toMatch(/Unsupported regular-expression or division syntax/i);
  });

  test("never treats legacy JavaScript HTML-comment text as an environment alias", async () => {
    const directory = await project("app.config.js", [
      "var token = 'public-client-id';",
      "<!-- const token = process.env.SERVER_SECRET;",
      "module.exports = { expo: { name: 'App', slug: 'app', extra: { token } } };",
      "",
    ].join("\n"));

    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toMatch(/Unsupported HTML-comment syntax/i);
  });

  test("treats delimiter-shaped string tokens atomically in aliases, arrays, and object values", async () => {
    const directory = await project("app.config.js", `
      const openCurly = "{";
      const openSquare = "[";
      const openRound = "(";
      const closeCurly = "}";
      const closeSquare = "]";
      const closeRound = ")";
      const comma = ",";
      const greater = ">";
      export default {
        extra: {
          symbols: ["{", "[", "(", "}", "]", ")", ",", ">"],
          token: process.env.SERVER_TOKEN,
        },
      };
    `);
    const result = await runExpoSecretInPublicConfig(directory);
    expect(result.findings).toHaveLength(1);
    expect(result.notes).toBeUndefined();
  });

  test("resolves direct environment reads and one-hop const aliases independent of property order", async () => {
    const directory = await project("app.config.ts", `
      const stripeSecret = process.env.STRIPE_SECRET_KEY;
      export default {
        updates: {
          codeSigningCertificate: './cert.pem',
          enabled: true,
          url: 'http://updates.acme.dev/bundle',
        },
        extra: {
          direct: process.env['DATABASE_URL'],
          stripeSecret,
          publicValue: process.env.EXPO_PUBLIC_SECRET_TOKEN,
        },
      } satisfies ExpoConfig;
    `);
    const secret = await runExpoSecretInPublicConfig(directory);
    expect(secret.findings).toHaveLength(2);
    expect(secret.findings.every((finding) =>
      finding.rule_id === "ci-expo-secret-in-public-config" &&
      finding.severity === "high" && finding.confidence === "high" &&
      finding.cwe.join(",") === "CWE-798,CWE-312"
    )).toBe(true);
    expect(JSON.stringify(secret)).not.toContain("STRIPE_SECRET_KEY");
    expect(JSON.stringify(secret)).not.toContain("DATABASE_URL");
    await expect(runExpoUnsignedCleartextUpdates(directory)).resolves.toMatchObject({ findings: [] });
  });

  test("resolves a semicolonless top-level environment alias before an export", async () => {
    const directory = await project("app.config.ts", [
      "const secret = process.env.SERVER_SECRET",
      "export default { extra: { secret } }",
      "",
    ].join("\n"));

    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toHaveLength(1);
    expect(result.notes).toBeUndefined();
  });

  test("resolves typed and asserted TypeScript environment references", async () => {
    const directory = await project(
      "app.config.ts",
      [
        "const typed: string = process.env.TYPED_SECRET;",
        "const asserted = process.env.ASSERTED_SECRET as string;",
        "export default { expo: { extra: { typed, asserted, direct: process.env.DIRECT_SECRET as string } } };",
      ].join("\n"),
    );
    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toHaveLength(3);
    expect(result.findings.every((finding) =>
      finding.rule_id === "ci-expo-secret-in-public-config" &&
      finding.confidence === "high"
    )).toBe(true);
    expect(result.notes).toBeUndefined();
  });

  test("ends a semicolonless environment alias before function and class declarations", async () => {
    const directory = await project(
      "app.config.ts",
      [
        "const secret = process.env.SERVER_SECRET",
        "function helper() { return true; }",
        "class Marker {}",
        "export default { expo: { extra: { secret } } };",
      ].join("\n"),
    );
    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toHaveLength(1);
    expect(result.notes).toBeUndefined();
  });

  test("supports direct config-file targets, nested arrays, and TypeScript non-null env reads", async () => {
    const directory = await project("app.config.ts", `
      const pluginSecret = process.env.PLUGIN_SECRET!;
      export default {
        plugins: [["acme-plugin", { token: pluginSecret }]],
      };
    `);
    const result = await runExpoSecretInPublicConfig(join(directory, "app.config.ts"));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.location.file).toBe("app.config.ts");
  });

  test("respects lexical alias scope and explicit property values", async () => {
    const explicitValue = await project("app.config.js", `
      const token = process.env.SERVER_TOKEN;
      export default { extra: { token: "safe literal" } };
    `);
    await expect(runExpoSecretInPublicConfig(explicitValue)).resolves.toMatchObject({ findings: [] });

    const blockScoped = await project("app.config.js", `
      { const token = process.env.SERVER_TOKEN; }
      export default { extra: { token } };
    `);
    const result = await runExpoSecretInPublicConfig(blockScoped);
    expect(result.findings).toHaveLength(0);
    expect(result.notes?.join(" ")).toMatch(/unresolved Expo config/i);
  });

  test.each([
    "app.config.js",
    "app.config.ts",
    "app.config.mjs",
    "app.config.mts",
  ])("accepts a direct ESM object export in %s", async (filename) => {
    const directory = await project(filename, `export default {
      extra: { serverToken: process.env.SERVER_TOKEN },
    };`);
    const result = await runExpoSecretInPublicConfig(directory);
    expect(result.findings).toHaveLength(1);
  });

  test.each(["app.config.cjs", "app.config.cts"])(
    "accepts a direct CommonJS object export in %s",
    async (filename) => {
      const directory = await project(filename, `module.exports = {
        extra: { serverToken: process.env.SERVER_TOKEN },
      };`);
      const result = await runExpoSecretInPublicConfig(directory);
      expect(result.findings).toHaveLength(1);
    },
  );

  test.each(["app.config.jsx", "app.config.tsx"])(
    "does not parse unsupported Expo config filename %s",
    async (filename) => {
      const directory = await project(
        filename,
        "export default { expo: { extra: { token: process.env.SERVER_SECRET } } };",
      );

      const loaded = await loadExpoConfig(directory);
      const result = await runExpoSecretInPublicConfig(loaded);

      expect(loaded.documents).toBeUndefined();
      expect(result.findings).toEqual([]);
    },
  );

  test.each([
    ["object assertion", "export default { expo: { extra: { token: process.env.SERVER_SECRET }, updates: { url: 'http://updates.acme.dev' } } } as const;"],
    ["non-null assertion", "export default { expo: { extra: { token: process.env.SERVER_SECRET! }, updates: { url: 'http://updates.acme.dev' } } };"],
    ["typed declaration", "const token: string = process.env.SERVER_SECRET; export default { expo: { extra: { token }, updates: { url: 'http://updates.acme.dev' } } };"],
  ])("rejects TypeScript-only %s syntax in JavaScript config", async (_label, source) => {
    const directory = await project("app.config.mjs", source);

    const secret = await runExpoSecretInPublicConfig(directory);
    const updates = await runExpoUnsignedCleartextUpdates(directory);

    expect(secret.findings).toEqual([]);
    expect(updates.findings).toEqual([]);
    expect(secret.notes?.join(" ")).toMatch(/Skipped unresolved Expo config/i);
  });

  test("excludes only documented private paths and EXPO_PUBLIC variables", async () => {
    const directory = await project("app.config.js", `export default {
      hooks: { postPublish: process.env.HOOK_SECRET },
      ios: { config: { privateKey: process.env.IOS_PRIVATE_KEY } },
      android: { config: { apiKey: process.env.ANDROID_API_KEY } },
      updates: {
        codeSigningCertificate: process.env.SIGNING_CERTIFICATE,
        codeSigningMetadata: { keyid: process.env.SIGNING_KEY },
        codeSigningCertificateBackup: process.env.BACKUP_SECRET,
      },
      extra: {
        publicSecret: process.env.EXPO_PUBLIC_SECRET_TOKEN,
        apiUrl: process.env.API_URL,
        tokenizer: process.env.TOKENIZER_MODEL,
        passwordPolicy: process.env.PASSWORD_POLICY,
        nonExpoPublic: process.env.PUBLIC_API_KEY,
      },
      webhooks: { token: process.env.WEBHOOK_TOKEN },
      iosLookalike: { configuration: process.env.LOOKALIKE_SECRET },
    };`);
    const result = await runExpoSecretInPublicConfig(directory);
    expect(result.findings).toHaveLength(3);
    expect(result.findings.map((finding) => finding.location.start_line).sort((a, b) => a - b))
      .toEqual([8, 17, 18]);
  });

  test("does not classify public client identifiers as high-confidence secrets", async () => {
    const directory = await project("app.config.ts", `export default { expo: {
      name: 'App',
      slug: 'app',
      extra: {
        firebaseApiKey: process.env.FIREBASE_API_KEY,
        mixpanelToken: process.env.MIXPANEL_TOKEN,
        amplitudeApiKey: process.env.AMPLITUDE_API_KEY,
        posthogApiKey: process.env.POSTHOG_API_KEY,
        awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID,
        mapboxAccessToken: process.env.MAPBOX_ACCESS_TOKEN,
      },
    } };`);

    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toEqual([]);
    expect(result.notes).toBeUndefined();
  });

  test("classifies explicit server credential names as high-confidence secrets", async () => {
    const directory = await project("app.config.ts", `export default { expo: { extra: {
      expoToken: process.env.EXPO_TOKEN,
      easToken: process.env.EAS_TOKEN,
      vercelToken: process.env.VERCEL_TOKEN,
      slackBotToken: process.env.SLACK_BOT_TOKEN,
      openAiKey: process.env.OPENAI_API_KEY,
      anthropicKey: process.env.ANTHROPIC_API_KEY,
      sendgridKey: process.env.SENDGRID_API_KEY,
    } } };`);

    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toHaveLength(7);
    expect(result.findings.every((finding) => finding.confidence === "high")).toBe(true);
  });

  test("a root code config overrides a static app.json instead of combining conclusions", async () => {
    const directory = await project("app.json", `{
      "expo": { "updates": { "url": "http://updates.acme.dev/bundle" } }
    }`);
    await writeFile(join(directory, "app.config.js"), `export default {
      updates: { url: 'https://updates.acme.dev/bundle' },
    };`, "utf8");
    const loaded = await loadExpoConfig(directory);
    expect(loaded.document?.path).toBe("app.config.js");
    await expect(runExpoUnsignedCleartextUpdates(loaded)).resolves.toMatchObject({ findings: [] });
  });

  test("analyzes every eligible nested monorepo package root and ignores orphan/corpus configs", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    projects.push(directory);
    await put(directory, "apps/mobile/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(directory, "apps/mobile/app.config.ts", `
      const billingSecret = process.env.BILLING_API_SECRET;
      export default { expo: {
        extra: { billingSecret },
        updates: { url: "http://updates.realproduct.dev" },
      } };
    `);
    await put(directory, "apps/safe/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(directory, "apps/safe/app.config.ts", `
      const nativeKey = process.env.IOS_MAPS_API_KEY;
      export default { expo: {
        ios: { config: { googleMapsApiKey: nativeKey } },
        extra: { clientId: process.env.EXPO_PUBLIC_CLIENT_ID },
        updates: {
          url: "https://updates.realproduct.dev",
          codeSigningCertificate: "./update.pem",
        },
      } };
    `);
    await put(directory, "docs/orphan/app.config.js", `export default {
      extra: { token: process.env.ORPHAN_SECRET },
      updates: { url: "http://orphan.realproduct.dev" },
    };`);
    await put(directory, "examples/demo/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(directory, "examples/demo/app.config.js", `export default {
      extra: { token: process.env.EXAMPLE_SECRET },
    };`);

    const loaded = await loadExpoConfig(directory);
    expect(loaded.documents?.map((document) => document.path)).toEqual([
      "apps/mobile/app.config.ts",
      "apps/safe/app.config.ts",
    ]);
    const secret = await runExpoSecretInPublicConfig(loaded);
    const updates = await runExpoUnsignedCleartextUpdates(loaded);
    expect(secret.findings).toHaveLength(1);
    expect(secret.findings[0]?.location.file).toBe("apps/mobile/app.config.ts");
    expect(updates.findings).toHaveLength(1);
    expect(updates.findings[0]?.location.file).toBe("apps/mobile/app.config.ts");
  });

  test("does not treat an unrelated package app.config file as Expo configuration", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    projects.push(directory);
    await put(directory, "apps/mobile/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(directory, "apps/mobile/app.json", JSON.stringify({
      expo: { name: "Mobile", slug: "mobile", updates: { url: "https://updates.product.dev" } },
    }));
    await put(directory, "apps/web/package.json", JSON.stringify({ dependencies: { vite: "7.0.0" } }));
    await put(directory, "apps/web/app.config.js", [
      "export default {",
      "  name: 'Web Build',",
      "  slug: 'web-build',",
      "  extra: { apiSecret: process.env.API_SECRET },",
      "  updates: { url: 'http://updates.realproduct.dev' },",
      "};",
      "",
    ].join("\n"));

    const loaded = await loadExpoConfig(directory);
    const result = await runExpoSecretInPublicConfig(loaded);

    expect(loaded.documents?.map((document) => document.path)).toEqual(["apps/mobile/app.json"]);
    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toMatch(/Skipped non-Expo app config at apps\/web\/app\.config\.js/i);
  });

  test("never follows a nested config symlink and continues with independent package roots", async () => {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    const outside = await project("app.config.js", `export default {
      extra: { token: process.env.OUTSIDE_SECRET },
    };`);
    projects.push(directory);
    await put(directory, "apps/mobile/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(directory, "apps/mobile/app.json", JSON.stringify({
      expo: { updates: { url: "http://should-not-fire.realproduct.dev" } },
    }));
    await symlink(join(outside, "app.config.js"), join(directory, "apps/mobile/app.config.js"));
    await put(directory, "apps/healthy/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(directory, "apps/healthy/app.config.js", `export default {
      extra: { token: process.env.HEALTHY_SECRET },
    };`);

    const secret = await runExpoSecretInPublicConfig(directory);
    const updates = await runExpoUnsignedCleartextUpdates(directory);
    expect(secret.findings).toHaveLength(1);
    expect(secret.findings[0]?.location.file).toBe("apps/healthy/app.config.js");
    expect(updates.findings).toHaveLength(0);
    expect(secret.notes?.join(" ")).toMatch(/symlinked Expo discovery path apps\/mobile\/app\.config\.js/i);
    expect(secret.notes?.join(" ")).toMatch(/Skipped Expo conclusions for apps\/mobile/i);
  });

  test("reports nested discovery entry, root-count, and depth omissions before parsing", async () => {
    const entryBound = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    const rootBound = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    const depthBound = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    projects.push(entryBound, rootBound, depthBound);

    await put(entryBound, "00.txt", "safe");
    await put(entryBound, "01.txt", "safe");
    await put(entryBound, "zz-app/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(entryBound, "zz-app/app.config.js", `export default {
      extra: { token: process.env.OMITTED_SECRET },
    };`);

    await put(rootBound, "apps/a/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(rootBound, "apps/a/app.config.js", "export default { updates: { url: 'https://safe.dev' } };");
    await put(rootBound, "apps/b/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(rootBound, "apps/b/app.config.js", `export default {
      extra: { token: process.env.OMITTED_SECRET },
    };`);

    await put(depthBound, "apps/mobile/package.json", JSON.stringify({ dependencies: { expo: "55.0.0" } }));
    await put(depthBound, "apps/mobile/app.config.js", `export default {
      extra: { token: process.env.OMITTED_SECRET },
    };`);

    const entry = await loadExpoConfig(entryBound, {
      maxEntries: 2,
      maxProjectRoots: 10,
      maxDepth: 10,
      maxReadFiles: 100,
      maxReadBytes: 1024 * 1024,
      maxTokens: 100_000,
      maxProperties: 20_000,
    });
    const roots = await loadExpoConfig(rootBound, {
      maxEntries: 100,
      maxProjectRoots: 1,
      maxDepth: 10,
      maxReadFiles: 100,
      maxReadBytes: 1024 * 1024,
      maxTokens: 100_000,
      maxProperties: 20_000,
    });
    const depth = await loadExpoConfig(depthBound, {
      maxEntries: 100,
      maxProjectRoots: 10,
      maxDepth: 1,
      maxReadFiles: 100,
      maxReadBytes: 1024 * 1024,
      maxTokens: 100_000,
      maxProperties: 20_000,
    });
    for (const loaded of [entry, roots, depth]) {
      await expect(runExpoSecretInPublicConfig(loaded)).resolves.toMatchObject({ findings: [] });
    }
    expect(entry.notes?.join(" ")).toMatch(/2-entry bound/i);
    expect(roots.notes?.join(" ")).toMatch(/1-root bound/i);
    expect(depth.notes?.join(" ")).toMatch(/depth limit: 1/i);
  });

  test("enforces aggregate Expo config file and byte read bounds", async () => {
    const fileBound = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    const byteBound = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    projects.push(fileBound, byteBound);

    for (const name of ["a", "b"]) {
      await put(
        fileBound,
        `apps/${name}/package.json`,
        JSON.stringify({ dependencies: { expo: "55.0.0" } }),
      );
      await put(
        fileBound,
        `apps/${name}/app.json`,
        JSON.stringify({ expo: { name, slug: name } }),
      );
    }
    await put(
      byteBound,
      "app.json",
      JSON.stringify({ expo: { name: "Mobile", slug: "mobile" } }),
    );

    const files = await loadExpoConfig(fileBound, {
      maxEntries: 100,
      maxProjectRoots: 10,
      maxDepth: 10,
      maxReadFiles: 1,
      maxReadBytes: 1024 * 1024,
      maxTokens: 100_000,
      maxProperties: 20_000,
    });
    const bytes = await loadExpoConfig(byteBound, {
      maxEntries: 100,
      maxProjectRoots: 10,
      maxDepth: 10,
      maxReadFiles: 10,
      maxReadBytes: 16,
      maxTokens: 100_000,
      maxProperties: 20_000,
    });

    expect(files.documents).toHaveLength(1);
    expect(files.documents?.[0]).not.toHaveProperty("source");
    expect(files.notes?.join(" ")).toMatch(/aggregate 1-file/i);
    expect(bytes.documents).toBeUndefined();
    expect(bytes.notes?.join(" ")).toMatch(/aggregate 10-file\/16-byte/i);
  });

  test("enforces aggregate Expo token and property parse bounds", async () => {
    const tokenBound = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    const propertyBound = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    projects.push(tokenBound, propertyBound);
    await put(tokenBound, "app.json", JSON.stringify({ expo: { name: "Mobile", slug: "mobile" } }));
    await put(propertyBound, "app.json", JSON.stringify({ expo: {}, name: "Mobile" }));

    const tokens = await loadExpoConfig(tokenBound, {
      maxTokens: 2,
      maxProperties: 100,
    });
    const properties = await loadExpoConfig(propertyBound, {
      maxTokens: 100,
      maxProperties: 1,
    });

    expect(tokens.documents).toBeUndefined();
    expect(tokens.notes?.join(" ")).toMatch(/aggregate 2-token bound/i);
    expect(properties.documents).toBeUndefined();
    expect(properties.notes?.join(" ")).toMatch(/aggregate 1-property bound/i);
  });

  test.each([
    ["spread", "const base = {}; export default { ...base, extra: { token: process.env.SERVER_TOKEN } };"],
    ["function export", "export default () => ({ extra: { token: process.env.SERVER_TOKEN } });"],
    ["dynamic branch", "export default prod ? { extra: { token: process.env.SERVER_TOKEN } } : {};"],
    ["computed key", "export default { [field]: process.env.SERVER_TOKEN };"],
    ["unresolved alias", "const token = getToken(); export default { extra: { token } };"],
    ["alias declared after export", "export default { extra: { token } }; const token = process.env.SERVER_TOKEN;"],
    ["method", "export default { value() { return process.env.SERVER_TOKEN; } };"],
    ["interpolated template", "export default { extra: { token: `${process.env.SERVER_TOKEN}` } };"],
  ])("suppresses findings and reports coverage for %s", async (_label, source) => {
    const directory = await project("app.config.js", source);
    const secret = await runExpoSecretInPublicConfig(directory);
    const updates = await runExpoUnsignedCleartextUpdates(directory);
    expect(secret.findings).toHaveLength(0);
    expect(updates.findings).toHaveLength(0);
    expect(secret.notes?.join(" ")).toMatch(/Skipped unresolved Expo config/i);
  });

  test.each([
    ["invalid numeric separator", "export default { version: 1__0, extra: { token: process.env.SERVER_TOKEN } };"],
    ["separator after hex prefix", "export default { version: 0x_FF, extra: { token: process.env.SERVER_TOKEN } };"],
    ["separator before decimal point", "export default { version: 1_.0, extra: { token: process.env.SERVER_TOKEN } };"],
    ["separator after decimal point", "export default { version: 1._0, extra: { token: process.env.SERVER_TOKEN } };"],
    ["separator after exponent", "export default { version: 1e_2, extra: { token: process.env.SERVER_TOKEN } };"],
    ["separator after exponent sign", "export default { version: 1e+_2, extra: { token: process.env.SERVER_TOKEN } };"],
    ["invalid hexadecimal escape", "export default { description: \"\\xZZ\", extra: { token: process.env.SERVER_TOKEN } };"],
    ["invalid Unicode escape", "export default { description: \"\\uZZZZ\", extra: { token: process.env.SERVER_TOKEN } };"],
    ["template-literal property key", "export default { `expo`: { extra: { token: process.env.SERVER_SECRET }, updates: { url: 'http://updates.acme.dev/bundle' } } };"],
    ["legacy numeric escape", "export default { expo: { name: '\\8', extra: { token: process.env.SERVER_SECRET }, updates: { url: 'http://updates.acme.dev/bundle' } } };"],
  ])("fails closed for %s in an otherwise finding-bearing config", async (_label, source) => {
    const directory = await project("app.config.js", source);

    const result = await runExpoSecretInPublicConfig(directory);
    const updates = await runExpoUnsignedCleartextUpdates(directory);

    expect(result.findings).toEqual([]);
    expect(updates.findings).toEqual([]);
    expect(result.notes?.join(" ")).toMatch(/Skipped unresolved Expo config/i);
  });

  test.each([
    ["adjacent assertion identifiers", "export default { extra: { token: process.env.SERVER_SECRET } } as Not Valid;"],
    ["assertion followed by a string", "export default { extra: { token: process.env.SERVER_SECRET } } as Foo 'not-a-type';"],
    ["invalid readonly assertion", "export default { extra: { token: process.env.SERVER_SECRET } } as readonly Foo;"],
    ["duplicate top-level const declarations", "const token = process.env.SERVER_SECRET; const token = 'safe'; export default { extra: { token } };"],
  ])("fails closed for malformed TypeScript %s", async (_label, source) => {
    const directory = await project("app.config.ts", source);

    const result = await runExpoSecretInPublicConfig(directory);

    expect(result.findings).toEqual([]);
    expect(result.notes?.join(" ")).toMatch(/Skipped unresolved Expo config/i);
  });

  test.each(["import", "infer", "keyof", "new", "readonly", "typeof", "unique"])(
    "fails closed for an incomplete TypeScript %s assertion",
    async (keyword) => {
      const directory = await project(
        "app.config.ts",
        `export default { expo: { extra: { token: process.env.SERVER_SECRET }, updates: { url: 'http://updates.acme.dev' } } } as ${keyword};`,
      );

      const secret = await runExpoSecretInPublicConfig(directory);
      const updates = await runExpoUnsignedCleartextUpdates(directory);

      expect(secret.findings).toEqual([]);
      expect(updates.findings).toEqual([]);
      expect(secret.notes?.join(" ")).toMatch(/Skipped unresolved Expo config/i);
    },
  );

  test.each(["?", "Foo.", "Foo<,>", "Foo &", "()", "Foo ? Bar", "[Foo,,Bar]", "<Foo>", "Foo..Bar"])(
    "fails closed for malformed TypeScript assertion %s",
    async (assertion) => {
      const directory = await project(
        "app.config.ts",
        `export default { expo: { extra: { token: process.env.SERVER_SECRET }, updates: { url: 'http://updates.acme.dev' } } } as ${assertion};`,
      );

      const secret = await runExpoSecretInPublicConfig(directory);
      const updates = await runExpoUnsignedCleartextUpdates(directory);

      expect(secret.findings).toEqual([]);
      expect(updates.findings).toEqual([]);
      expect(secret.notes?.join(" ")).toMatch(/Skipped unresolved Expo config/i);
    },
  );

  test.each(["false", "function", "null", "this", "true", "void"])(
    "fails closed for a qualified TypeScript %s assertion root",
    async (keyword) => {
      const directory = await project(
        "app.config.ts",
        `export default { expo: { extra: { token: process.env.SERVER_SECRET }, updates: { url: 'http://updates.acme.dev' } } } as ${keyword}.default;`,
      );

      const secret = await runExpoSecretInPublicConfig(directory);
      const updates = await runExpoUnsignedCleartextUpdates(directory);

      expect(secret.findings).toEqual([]);
      expect(updates.findings).toEqual([]);
      expect(secret.notes?.join(" ")).toMatch(/Skipped unresolved Expo config/i);
    },
  );

  test("suppresses malformed, duplicate, ambiguous, oversized, and symlinked configs", async () => {
    const malformed = await project("app.json", `{ "expo": { "name": "broken" `);
    const duplicate = await project("app.json", `{
      "expo": { "extra": {}, "extra": { "token": "safe" } }
    }`);
    const ambiguous = await project("app.config.js", "export default { name: 'one' };");
    await writeFile(join(ambiguous, "app.config.ts"), "export default { name: 'two' };", "utf8");
    const oversized = await project("app.config.js", `export default {
      extra: { token: process.env.SERVER_TOKEN },
      padding: "${"x".repeat(1024 * 1024)}",
    };`);
    const symlinked = await mkdtemp(join(tmpdir(), "codeinspectus-expo-"));
    projects.push(symlinked);
    await symlink(join(ambiguous, "app.config.js"), join(symlinked, "app.config.js"));
    await writeFile(join(symlinked, "app.json"), JSON.stringify({
      expo: { updates: { url: "http://updates.acme.dev/bundle" } },
    }), "utf8");

    for (const directory of [malformed, duplicate, ambiguous, oversized, symlinked]) {
      const result = await runExpoSecretInPublicConfig(directory);
      expect(result.findings).toHaveLength(0);
      expect(result.notes?.length).toBeGreaterThan(0);
    }
    expect((await runExpoSecretInPublicConfig(oversized)).notes?.join(" ")).toMatch(/oversized/i);
    await expect(runExpoUnsignedCleartextUpdates(symlinked)).resolves.toMatchObject({ findings: [] });
  });

  test("enforces token, property-count, and structural-depth bounds before conclusions", async () => {
    const tokenBound = await project(
      "app.config.js",
      `${";".repeat(100_001)}export default { extra: { token: process.env.SERVER_TOKEN } };`,
    );
    const properties = Array.from({ length: 20_001 }, (_, index) => `p${index}: ${index}`).join(",");
    const propertyBound = await project(
      "app.config.js",
      `export default { extra: { token: process.env.SERVER_TOKEN }, ${properties} };`,
    );
    const depthBound = await project(
      "app.config.js",
      `export default { ${"nested: {".repeat(65)} token: process.env.SERVER_TOKEN ${"}".repeat(65)} };`,
    );

    const tokenResult = await runExpoSecretInPublicConfig(tokenBound);
    const propertyResult = await runExpoSecretInPublicConfig(propertyBound);
    const depthResult = await runExpoSecretInPublicConfig(depthBound);
    expect(tokenResult.findings).toHaveLength(0);
    expect(propertyResult.findings).toHaveLength(0);
    expect(depthResult.findings).toHaveLength(0);
    expect(tokenResult.notes?.join(" ")).toMatch(/token bound/i);
    expect(propertyResult.notes?.join(" ")).toMatch(/property bound/i);
    expect(depthResult.notes?.join(" ")).toMatch(/depth bound/i);
  });
});

describe("Expo unsigned cleartext update rule", () => {
  test.each([
    "https://updates.acme.com/bundle",
    "http://localhost:8081/bundle",
    "http://10.0.0.5/bundle",
    "http://172.31.2.3/bundle",
    "http://192.168.1.4/bundle",
    "http://127.0.0.1/bundle",
    "http://169.254.4.2/bundle",
    "http://100.64.4.2/bundle",
    "http://192.0.2.5/bundle",
    "http://198.51.100.8/bundle",
    "http://203.0.113.9/bundle",
    "http://[::1]/bundle",
    "http://[fd00::1]/bundle",
    "http://[2001:db8::1]/bundle",
    "http://[2001:2::1]/bundle",
    "http://[2001:10::1]/bundle",
    "http://[2002::1]/bundle",
    "http://[3fff::1]/bundle",
    "http://[::ffff:10.0.0.1]/bundle",
    "http://updates.example.com/bundle",
    "http://updates.internal/bundle",
    "http://updates.test/bundle",
  ])("keeps HTTPS/local/private/reserved/example URL %s silent", async (url) => {
    const directory = await project("app.json", JSON.stringify({ expo: { updates: { url } } }));
    const result = await runExpoUnsignedCleartextUpdates(directory);
    expect(result.findings).toHaveLength(0);
  });

  test("flags default-enabled and explicitly enabled public HTTP endpoints", async () => {
    const implicit = await project("app.json", JSON.stringify({
      expo: { updates: { url: "http://updates.realproduct.dev/bundle" } },
    }));
    const explicit = await project("app.config.ts", `export default {
      updates: { enabled: true, url: 'http://203.1.1.1/bundle' },
    };`);
    const ipv6 = await project("app.json", JSON.stringify({
      expo: { updates: { url: "http://[2001:4860:4860::8888]/bundle" } },
    }));
    const specialGlobalIpv6 = await project("app.json", JSON.stringify({
      expo: { updates: { url: "http://[2001:20::1]/bundle" } },
    }));
    await expect(runExpoUnsignedCleartextUpdates(implicit)).resolves.toMatchObject({
      findings: [{ rule_id: "ci-expo-unsigned-cleartext-updates" }],
    });
    await expect(runExpoUnsignedCleartextUpdates(explicit)).resolves.toMatchObject({
      findings: [{ rule_id: "ci-expo-unsigned-cleartext-updates" }],
    });
    await expect(runExpoUnsignedCleartextUpdates(ipv6)).resolves.toMatchObject({
      findings: [{ rule_id: "ci-expo-unsigned-cleartext-updates" }],
    });
    await expect(runExpoUnsignedCleartextUpdates(specialGlobalIpv6)).resolves.toMatchObject({
      findings: [{ rule_id: "ci-expo-unsigned-cleartext-updates" }],
    });
  });

  test("keeps disabled and literally signed update configurations silent", async () => {
    const disabled = await project("app.json", JSON.stringify({
      expo: { updates: { enabled: false, url: "http://updates.acme.dev/bundle" } },
    }));
    const signed = await project("app.json", JSON.stringify({
      expo: { updates: {
        enabled: true,
        url: "http://updates.acme.dev/bundle",
        codeSigningCertificate: "./certs/update.pem",
      } },
    }));
    await expect(runExpoUnsignedCleartextUpdates(disabled)).resolves.toMatchObject({ findings: [] });
    await expect(runExpoUnsignedCleartextUpdates(signed)).resolves.toMatchObject({ findings: [] });
  });

  test("does not infer unsigned updates from dynamic relevant fields", async () => {
    for (const source of [
      "export default { updates: { url: process.env.UPDATE_URL } };",
      "export default { updates: { enabled: process.env.UPDATES_ENABLED, url: 'http://updates.acme.dev' } };",
      "export default { updates: { url: 'http://updates.acme.dev', codeSigningCertificate: process.env.UPDATE_CERT } };",
    ]) {
      const directory = await project("app.config.js", source);
      const result = await runExpoUnsignedCleartextUpdates(directory);
      expect(result.findings).toHaveLength(0);
      expect(result.notes?.join(" ")).toMatch(/relevant updates field is dynamic/i);
    }
  });
});

describe("Expo pack contract", () => {
  test("owns exactly two independent analyzers and the agreed static components", async () => {
    const directory = await project("app.json", `{
      "expo": { "updates": { "url": "http://updates.acme.dev/bundle" } }
    }`);
    expect(expoPack).toMatchObject({
      id: "expo",
      version: "1.0.0",
      languages: ["javascript", "typescript", "json"],
      frameworks: ["expo"],
      platforms: [],
    });
    expect(expoPack.isApplicable?.([{
      id: "expo",
      kind: "framework",
      confidence: "high",
      evidence: ["app.json"],
    }])).toBe(true);
    const analyzers = createExpoAnalyzers(directory);
    expect(analyzers.map((analyzer) => ({
      id: analyzer.id,
      components: analyzer.components,
      ruleIds: analyzer.ruleIds,
    }))).toEqual([
      {
        id: "expo-secret-in-public-config",
        components: [
          "pack:expo:dispatch",
          "expo:static-config-parser",
          "ai:expo-secret-in-public-config",
        ],
        ruleIds: ["ci-expo-secret-in-public-config"],
      },
      {
        id: "expo-unsigned-cleartext-updates",
        components: [
          "pack:expo:dispatch",
          "expo:static-config-parser",
          "ai:expo-unsigned-cleartext-updates",
        ],
        ruleIds: ["ci-expo-unsigned-cleartext-updates"],
      },
    ]);
    const results = await Promise.all(analyzers.map((analyzer) => analyzer.run()));
    expect(results[0]?.findings).toHaveLength(0);
    expect(results[1]?.findings).toHaveLength(1);
  });
});
