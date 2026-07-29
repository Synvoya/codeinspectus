import { afterEach, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { detectTechnologies } from "./technology-detection.js";

const temporaryDirectories: string[] = [];

async function temporaryProject(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-technologies-"));
  temporaryDirectories.push(directory);
  return directory;
}

async function put(root: string, relativePath: string, content = ""): Promise<string> {
  const path = join(root, ...relativePath.split("/"));
  await mkdir(join(path, ".."), { recursive: true });
  await writeFile(path, content, "utf8");
  return path;
}

function ids(result: Awaited<ReturnType<typeof detectTechnologies>>): string[] {
  return result.detected_technologies.map((technology) => technology.id);
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe("detectTechnologies", () => {
  test("detects Firebase from deployable rule/config paths and exact package dependencies", async () => {
    const configured = await temporaryProject();
    await put(configured, "firebase.json", '{"firestore":{"rules":"firestore.rules"}}\n');
    await put(configured, "firestore.rules", "service cloud.firestore {}\n");
    const packaged = await temporaryProject();
    await put(packaged, "package.json", JSON.stringify({ dependencies: { firebase: "12.0.0" } }));

    const configuredResult = await detectTechnologies(configured);
    const packagedResult = await detectTechnologies(packaged);

    expect(configuredResult.detected_technologies).toEqual([{
      id: "firebase",
      kind: "platform",
      confidence: "high",
      evidence: ["firebase.json", "firestore.rules"],
    }]);
    expect(packagedResult.detected_technologies).toEqual([{
      id: "firebase",
      kind: "platform",
      confidence: "high",
      evidence: ["package.json"],
    }]);
  });

  test("rejects Firebase filename/package lookalikes and non-production rule paths", async () => {
    const project = await temporaryProject();
    await put(project, "firebase.json.bak", "{}\n");
    await put(project, "custom-firestore.rules", "service cloud.firestore {}\n");
    await put(project, "tests/firestore.rules", "service cloud.firestore {}\n");
    await put(project, "package.json", JSON.stringify({ dependencies: { firebaseish: "1.0.0" } }));

    expect(ids(await detectTechnologies(project))).toEqual([]);
  });

  test("detects JavaScript, TypeScript, SQL, React, Next.js, and Supabase from repository evidence", async () => {
    const project = await temporaryProject();
    await put(project, "src/worker.js", "export const worker = true;\n");
    await put(project, "src/page.tsx", "export const Page = () => null;\n");
    await put(project, "supabase/migrations/0001_init.sql", "select 1;\n");
    await put(
      project,
      "package.json",
      JSON.stringify({ dependencies: { next: "15.0.0", react: "19.0.0", "@supabase/supabase-js": "2.0.0" } }),
    );

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["javascript", "typescript", "sql", "react", "nextjs", "supabase"]);
    expect(result.limitations).toEqual([]);
    expect(result.detected_technologies.find((technology) => technology.id === "supabase")?.evidence).toEqual([
      "package.json",
      "supabase/migrations/0001_init.sql",
    ]);
  });

  test("detects exact React Native and Expo package dependencies with explicit confidence", async () => {
    const project = await temporaryProject();
    await put(
      project,
      "package.json",
      JSON.stringify({
        dependencies: { "react-native": "0.81.0" },
        optionalDependencies: { expo: "56.0.0" },
      }),
    );

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([
      {
        id: "react-native",
        kind: "framework",
        confidence: "high",
        evidence: ["package.json"],
      },
      {
        id: "expo",
        kind: "framework",
        confidence: "high",
        evidence: ["package.json"],
      },
    ]);
    expect(result.limitations).toEqual([]);
  });

  test("recognizes root Expo JSON configs with comments and trailing commas", async () => {
    const project = await temporaryProject();
    await put(
      project,
      "app.json",
      [
        "{",
        "  // Expo permits JSONC app configuration.",
        '  "expo": {',
        '    "name": "Mobile",',
        '    "slug": "mobile",',
        "  },",
        "}",
        "",
      ].join("\n"),
    );

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([
      {
        id: "react-native",
        kind: "framework",
        confidence: "medium",
        evidence: ["app.json"],
      },
      {
        id: "expo",
        kind: "framework",
        confidence: "high",
        evidence: ["app.json"],
      },
    ]);
    expect(result.limitations).toEqual([]);
  });

  test("recognizes only statically proven objects in dynamic Expo configs", async () => {
    const objectProject = await temporaryProject();
    await put(
      objectProject,
      "app.config.js",
      "module.exports = { expo: { name: 'Mobile', slug: 'mobile' } };\n",
    );
    const functionProject = await temporaryProject();
    await put(
      functionProject,
      "app.config.ts",
      "export default ({ config }) => ({ ...config, expo: { name: 'Mobile', slug: 'mobile' } });\n",
    );
    const namedObjectProject = await temporaryProject();
    await put(
      namedObjectProject,
      "app.config.ts",
      [
        "const appConfig = { expo: { name: 'Mobile', slug: 'mobile' } };",
        "export default appConfig;",
        "",
      ].join("\n"),
    );
    const returnedObjectProject = await temporaryProject();
    await put(
      returnedObjectProject,
      "app.config.js",
      "module.exports = function config({ base }) { return { ...base, expo: {} }; };\n",
    );

    expect(ids(await detectTechnologies(objectProject))).toEqual([
      "javascript",
      "react-native",
      "expo",
    ]);
    expect(ids(await detectTechnologies(functionProject))).toEqual([
      "typescript",
      "react-native",
      "expo",
    ]);
    expect(ids(await detectTechnologies(namedObjectProject))).toEqual([
      "typescript",
      "react-native",
      "expo",
    ]);
    expect(ids(await detectTechnologies(returnedObjectProject))).toEqual([
      "javascript",
      "react-native",
      "expo",
    ]);
  });

  test("treats delimiter-shaped strings as data while proving static Expo config", async () => {
    const project = await temporaryProject();
    await put(project, "app.config.js", [
      "export default {",
      "  description: '{',",
      "  symbols: ['[', '(', '}', ']', ')', ',', '>'],",
      "  expo: { name: 'Mobile', slug: 'mobile' },",
      "};",
      "",
    ].join("\n"));

    expect(ids(await detectTechnologies(project))).toEqual([
      "javascript",
      "react-native",
      "expo",
    ]);
  });

  test("does not discover an Expo export embedded in a regular-expression literal", async () => {
    const project = await temporaryProject();
    await put(project, "app.config.js", [
      "const pattern = /export default { expo: {} }/;",
      "export default buildConfig(pattern);",
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["javascript"]);
    expect(result.limitations).toEqual([
      { path: "app.config.js", reason: "manifest_inconclusive" },
    ]);
  });

  test("does not discover Expo syntax embedded in a legacy JavaScript HTML comment", async () => {
    const project = await temporaryProject();
    await put(project, "package.json", JSON.stringify({ dependencies: { vite: "7.0.0" } }));
    await put(project, "app.config.js", [
      "<!-- export default { expo: { name: 'Fake' } };",
      "module.exports = buildWebConfig();",
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["javascript"]);
    expect(result.limitations).toEqual([
      { path: "app.config.js", reason: "manifest_inconclusive" },
    ]);
  });

  test("does not infer React Native or Expo from near-name packages, filenames, or native skeletons", async () => {
    const project = await temporaryProject();
    await put(
      project,
      "package.json",
      JSON.stringify({
        dependencies: {
          "@types/react-native": "1.0.0",
          "react-native-web": "1.0.0",
          "expo-router": "1.0.0",
          "@expo/config": "1.0.0",
          "vite": "7.0.0",
        },
      }),
    );
    await put(
      project,
      "app.config.js",
      [
        "export default {",
        "  name: 'Web Build',",
        "  slug: 'web-build',",
        "};",
        "",
      ].join("\n"),
    );
    await put(project, "android/app/src/main/AndroidManifest.xml", "<manifest />\n");
    await put(project, "ios/Runner/Info.plist", "<plist />\n");

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["javascript", "android", "ios"]);
    expect(ids(result)).not.toContain("react-native");
    expect(ids(result)).not.toContain("expo");
  });

  test("never follows an Expo config symbolic link", async () => {
    const project = await temporaryProject();
    const outside = await temporaryProject();
    const real = await put(outside, "app.json", '{ "expo": { "name": "Outside" } }\n');
    await symlink(real, join(project, "app.json"));

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([]);
    expect(result.limitations).toEqual([{ path: "app.json", reason: "symlink_skipped" }]);

    const direct = await detectTechnologies(join(project, "app.json"));
    expect(direct.detected_technologies).toEqual([]);
    expect(direct.limitations).toEqual([{ path: ".", reason: "symlink_skipped" }]);
  });

  test("reports malformed root Expo JSON without activating Expo", async () => {
    const project = await temporaryProject();
    await put(project, "app.config.json", '{ "expo": { "name": "Broken", },\n');

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([]);
    expect(result.limitations).toEqual([{ path: "app.config.json", reason: "manifest_invalid" }]);
  });

  test("recognizes monorepo package roots but ignores orphan and corpus configs", async () => {
    const project = await temporaryProject();
    await put(project, "apps/mobile/package.json", JSON.stringify({ private: true, dependencies: { expo: "55.0.0" } }));
    await put(
      project,
      "apps/mobile/app.config.json",
      '{ "name": "Mobile", "slug": "mobile", }\n',
    );
    await put(project, "docs/mobile/app.json", '{ "expo": {} }\n');
    await put(project, "examples/mobile/package.json", JSON.stringify({ private: true }));
    await put(project, "examples/mobile/app.json", '{ "expo": {} }\n');

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([
      {
        id: "react-native",
        kind: "framework",
        confidence: "medium",
        evidence: ["apps/mobile/package.json"],
      },
      {
        id: "expo",
        kind: "framework",
        confidence: "high",
        evidence: ["apps/mobile/package.json"],
      },
    ]);
    expect(result.limitations).toEqual([]);
  });

  test("supports direct Expo config and React Native package-manifest targets", async () => {
    const configProject = await temporaryProject();
    const config = await put(
      configProject,
      "nested/app.config.ts",
      "export default () => ({ expo: { name: 'Direct' } });\n",
    );
    const manifestProject = await temporaryProject();
    const manifest = await put(
      manifestProject,
      "nested/package.json",
      JSON.stringify({ peerDependencies: { "react-native": "0.81.0" } }),
    );

    expect(ids(await detectTechnologies(config))).toEqual([
      "typescript",
      "react-native",
      "expo",
    ]);
    expect((await detectTechnologies(manifest)).detected_technologies).toEqual([
      {
        id: "react-native",
        kind: "framework",
        confidence: "high",
        evidence: ["package.json"],
      },
    ]);
  });

  test("recognizes every supported static Expo JavaScript/TypeScript module variant", async () => {
    for (const extension of ["mjs", "cjs", "mts", "cts"]) {
      const project = await temporaryProject();
      const source = extension === "cjs" || extension === "cts"
        ? "module.exports = { expo: { name: 'Mobile' } };\n"
        : "export default { expo: { name: 'Mobile' } };\n";
      await put(project, `app.config.${extension}`, source);
      expect(ids(await detectTechnologies(project))).toEqual(expect.arrayContaining([
        "react-native",
        "expo",
      ]));
    }
  });

  test("does not treat unsupported JSX/TSX app config names as Expo evidence", async () => {
    for (const extension of ["jsx", "tsx"]) {
      const project = await temporaryProject();
      await put(project, `app.config.${extension}`, "export default { expo: {} };\n");

      const result = await detectTechnologies(project);

      expect(ids(result)).toEqual([extension === "tsx" ? "typescript" : "javascript"]);
      expect(result.limitations).toEqual([]);
    }
  });

  test("a Dart package or random Dart source is Dart, not Flutter", async () => {
    const project = await temporaryProject();
    await put(project, "lib/tool.dart", "void main() {}\n");
    await put(
      project,
      "pubspec.yaml",
      "name: dart_tool\ndependencies:\n  http: ^1.0.0\n",
    );

    const result = await detectTechnologies(project);

    expect(ids(result)).toContain("dart");
    expect(ids(result)).not.toContain("flutter");
  });

  test("a symbolic-link pubspec.lock is a Dart path signal but is never followed", async () => {
    const project = await temporaryProject();
    const outside = await temporaryProject();
    const real = await put(outside, "pubspec.lock", "packages: {}\n");
    await symlink(real, join(project, "pubspec.lock"));

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([
      { id: "dart", kind: "language", confidence: "high", evidence: ["pubspec.lock"] },
    ]);
    expect(result.limitations).toEqual([{ path: "pubspec.lock", reason: "symlink_skipped" }]);

    const direct = await detectTechnologies(join(project, "pubspec.lock"));
    expect(direct.detected_technologies).toEqual([
      { id: "dart", kind: "language", confidence: "high", evidence: ["pubspec.lock"] },
    ]);
    expect(direct.limitations).toEqual([{ path: ".", reason: "symlink_skipped" }]);
  });

  test("detects Supabase signals nested inside a monorepo", async () => {
    const project = await temporaryProject();
    await put(project, "apps/api/supabase/functions/hello/index.ts", "export default {}\n");

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["typescript", "supabase"]);
    expect(result.detected_technologies.find((technology) => technology.id === "supabase")?.evidence)
      .toEqual(["apps/api/supabase/functions/hello/index.ts"]);
  });

  test("detects Flutter only from a Flutter SDK pubspec dependency or strong metadata", async () => {
    const sdkProject = await temporaryProject();
    await put(
      sdkProject,
      "pubspec.yaml",
      [
        "name: flutter_app",
        "dependencies:",
        "  flutter:",
        "    sdk: flutter",
        "",
      ].join("\n"),
    );

    const metadataProject = await temporaryProject();
    await put(
      metadataProject,
      ".metadata",
      [
        "# This file tracks properties of this Flutter project.",
        "version:",
        "  revision: abc",
        "project_type: app",
        "",
      ].join("\n"),
    );

    for (const project of [sdkProject, metadataProject]) {
      const result = await detectTechnologies(project);
      expect(ids(result)).toEqual(["dart", "flutter"]);
      expect(result.limitations).toEqual([]);
    }
  });

  test("detects Android and iOS only from platform project signals", async () => {
    const project = await temporaryProject();
    await put(project, "android/app/src/main/AndroidManifest.xml", "<manifest />\n");
    await put(project, "ios/Runner/Info.plist", "<plist />\n");

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["android", "ios"]);
    expect(result.detected_technologies.every((technology) => technology.kind === "platform")).toBe(true);
  });

  test("distinguishes generic iOS and macOS Xcode projects by literal platform settings", async () => {
    const iosProject = await temporaryProject();
    await put(
      iosProject,
      "Runner.xcodeproj/project.pbxproj",
      "{ objects = { RELEASE = { buildSettings = { SDKROOT = iphoneos; }; }; }; }\n",
    );
    const macProject = await temporaryProject();
    await put(
      macProject,
      "Runner.xcodeproj/project.pbxproj",
      "{ objects = { RELEASE = { buildSettings = { SDKROOT = macosx; }; }; }; }\n",
    );

    expect(ids(await detectTechnologies(iosProject))).toEqual(["ios"]);
    expect(ids(await detectTechnologies(macProject))).toEqual([]);
  });

  test("recognizes scalar and quoted iPhone supported-platform settings", async () => {
    for (const setting of [
      "SUPPORTED_PLATFORMS = iphoneos;",
      'SUPPORTED_PLATFORMS = "iphoneos iphonesimulator";',
    ]) {
      const project = await temporaryProject();
      await put(
        project,
        "Runner.xcodeproj/project.pbxproj",
        `{ objects = { RELEASE = { buildSettings = { ${setting} }; }; }; }\n`,
      );
      expect(ids(await detectTechnologies(project))).toEqual(["ios"]);
    }
  });

  test("detects a root AndroidManifest.xml in a directly scanned Android project", async () => {
    const project = await temporaryProject();
    await put(project, "AndroidManifest.xml", "<manifest />\n");

    expect(ids(await detectTechnologies(project))).toEqual(["android"]);
  });

  test("direct mobile configuration targets activate their platform packs", async () => {
    const project = await temporaryProject();
    const androidManifest = await put(project, "nested/AndroidManifest.xml", "<manifest />\n");
    const androidNetworkConfig = await put(
      project,
      "nested/network_security_config.xml",
      "<network-security-config />\n",
    );
    const iosPlist = await put(project, "nested/Info.plist", "<plist />\n");
    const iosEntitlements = await put(project, "nested/Runner.entitlements", "<plist />\n");

    expect(ids(await detectTechnologies(androidManifest))).toEqual(["android"]);
    expect(ids(await detectTechnologies(androidNetworkConfig))).toEqual(["android"]);
    const plistDetection = await detectTechnologies(iosPlist);
    const entitlementDetection = await detectTechnologies(iosEntitlements);
    expect(ids(plistDetection)).toEqual(["ios"]);
    expect(ids(entitlementDetection)).toEqual(["ios"]);
    expect(plistDetection.detected_technologies[0]?.confidence).toBe("medium");
    expect(entitlementDetection.detected_technologies[0]?.confidence).toBe("medium");
  });

  test("debug, test, demo, example, and sample platform skeletons do not activate mobile packs", async () => {
    const project = await temporaryProject();
    await put(project, "android/app/src/debug/AndroidManifest.xml", "<manifest />\n");
    await put(project, "example/ios/Runner/Info.plist", "<plist />\n");
    await put(project, "samples/app/android/app/src/main/AndroidManifest.xml", "<manifest />\n");
    await put(project, "tests/ios/Runner/Runner.entitlements", "<plist />\n");
    await put(project, "demo/android/app/src/main/AndroidManifest.xml", "<manifest />\n");
    await put(project, "demos/ios/Runner/Info.plist", "<plist />\n");

    expect(await detectTechnologies(project)).toEqual({
      detected_technologies: [],
      limitations: [],
    });
  });

  test("ignores dependency, generated, VCS, build, coverage, and cache trees", async () => {
    const project = await temporaryProject();
    const ignoredFiles = [
      ".git/hooks/check.ts",
      ".cache/generated.astro",
      ".dart_tool/generated.dart",
      "build/generated.ts",
      "coverage/report.js",
      "dist/app.vue",
      "node_modules/pkg/index.js",
      "Pods/Runner/Info.plist",
      "target/generated.sql",
      "vendor/pkg/widget.svelte",
    ];
    for (const file of ignoredFiles) await put(project, file, "ignored\n");

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([]);
    expect(result.limitations).toEqual([]);
  });

  test("supports a single-file target with basename-only, forward-slash evidence", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/component.tsx", "export const Component = () => null;\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([
      {
        id: "typescript",
        kind: "language",
        confidence: "high",
        evidence: ["component.tsx"],
      },
    ]);
    expect(result.detected_technologies[0]?.evidence[0]).not.toContain("\\");
  });

  test("orders technologies and their evidence deterministically", async () => {
    const project = await temporaryProject();
    await put(project, "z/widget.svelte", "");
    await put(project, "z/query.sql", "");
    await put(project, "z/main.js", "");
    await put(project, "a/widget.vue", "");
    await put(project, "a/page.astro", "");
    await put(project, "a/main.dart", "");
    await put(project, "a/main.ts", "");

    const first = await detectTechnologies(project);
    const second = await detectTechnologies(project);

    expect(first).toEqual(second);
    expect(ids(first)).toEqual([
      "javascript",
      "typescript",
      "sql",
      "dart",
      "vue",
      "svelte",
      "astro",
    ]);
  });

  test("bounds and sorts evidence for each technology", async () => {
    const project = await temporaryProject();
    for (const name of ["k", "j", "i", "h", "g", "f", "e", "d", "c", "b", "a"]) {
      await put(project, `src/${name}.js`, "export {};\n");
    }

    const result = await detectTechnologies(project);
    const javascript = result.detected_technologies.find((technology) => technology.id === "javascript");

    expect(javascript?.evidence).toEqual([
      "src/a.js",
      "src/b.js",
      "src/c.js",
      "src/d.js",
      "src/e.js",
    ]);
  });

  test("stops before processing an over-budget directory entry set", async () => {
    const project = await temporaryProject();
    await put(project, "a.ts", "export {};\n");
    await put(project, "b.ts", "export {};\n");

    const result = await detectTechnologies(project, { maxEntries: 1 });

    expect(result.detected_technologies).toEqual([]);
    expect(result.limitations).toEqual([
      { path: ".", reason: "discovery_entry_limit_reached" },
    ]);
  });

  test("reports and skips repository evidence beyond the directory-depth bound", async () => {
    const project = await temporaryProject();
    await put(project, "one/two/package.json", JSON.stringify({ private: true }));
    await put(project, "one/two/app.json", '{ "expo": { "name": "Too deep" } }\n');

    const result = await detectTechnologies(project, { maxDepth: 1 });

    expect(result.detected_technologies).toEqual([]);
    expect(result.limitations).toEqual([
      { path: "one/two", reason: "directory_depth_limit_reached" },
    ]);
  });

  test("caps the number of repository manifests read", async () => {
    const project = await temporaryProject();
    await put(project, "app.json", '{ "expo": { "name": "Bounded" } }\n');
    await put(project, "package.json", JSON.stringify({ dependencies: { "react-native": "0.81.0" } }));

    const result = await detectTechnologies(project, { maxManifestFiles: 1 });

    expect(ids(result)).toEqual(["react-native", "expo"]);
    expect(result.limitations).toEqual([
      { path: "package.json", reason: "manifest_count_limit_reached" },
    ]);
  });

  test("caps cumulative manifest bytes before reading the over-budget file", async () => {
    const project = await temporaryProject();
    await put(project, "app.json", '{ "expo": { "name": "Over byte budget" } }\n');

    const result = await detectTechnologies(project, { maxManifestBytes: 8 });

    expect(result.detected_technologies).toEqual([]);
    expect(result.limitations).toEqual([
      { path: "app.json", reason: "manifest_bytes_limit_reached" },
    ]);
  });

  test("detects Python and exact AI/API framework dependencies from requirements", async () => {
    const project = await temporaryProject();
    await put(project, "src/app.py", "print('app')\n");
    await put(project, "requirements-prod.txt", [
      "fastapi[standard]>=0.110",
      "starlette==0.47.0",
      "Flask-Cors==6.0.0",
      "django-cors-headers==4.9.0",
      "Jinja2>=3.1",
      "openai>=1.0",
      "anthropic>=0.40",
      "langchain-community>=0.3",
      "not-fastapi==1.0",
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual([
      "python", "fastapi", "starlette", "flask", "django", "jinja2", "openai", "anthropic", "langchain",
    ]);
    expect(result.detected_technologies.find((technology) => technology.id === "flask")?.confidence)
      .toBe("medium");
    expect(result.limitations).toEqual([]);
  });

  test("detects Go and the exact official OpenAI Go module", async () => {
    const project = await temporaryProject();
    await put(project, "cmd/agent/main.go", "package main\n");
    await put(project, "go.mod", [
      "module example.com/agent",
      "",
      "go 1.24",
      "",
      "require (",
      "  github.com/openai/openai-go/v3 v3.16.0",
      "  github.com/example/openai-go-helper v1.0.0",
      ")",
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["go", "openai"]);
    expect(result.detected_technologies.find((technology) => technology.id === "openai")?.evidence)
      .toEqual(["go.mod"]);
    expect(result.limitations).toEqual([]);
  });

  test("does not infer OpenAI from a near-name Go module", async () => {
    const project = await temporaryProject();
    await put(project, "go.mod", [
      "module example.com/agent",
      "go 1.24",
      "require github.com/example/openai-go v1.0.0",
      "",
    ].join("\n"));

    expect(ids(await detectTechnologies(project))).toEqual(["go"]);
  });

  test("supports a direct Go source target without requiring a manifest", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/main.go", "package main\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([{
      id: "go",
      kind: "language",
      confidence: "high",
      evidence: ["main.go"],
    }]);
  });

  test("detects Java and the exact official OpenAI Java Maven artifact", async () => {
    const project = await temporaryProject();
    await put(project, "src/main/java/example/Agent.java", "package example;\n");
    await put(project, "pom.xml", [
      "<project>",
      "  <dependencies>",
      "    <dependency>",
      "      <groupId>com.openai</groupId>",
      "      <artifactId>openai-java</artifactId>",
      "      <version>4.43.0</version>",
      "    </dependency>",
      "  </dependencies>",
      "</project>",
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["java", "openai"]);
    expect(result.detected_technologies.find((technology) => technology.id === "openai")?.evidence)
      .toEqual(["pom.xml"]);
    expect(result.limitations).toEqual([]);
  });

  test("does not infer OpenAI from near-name or wrong-group Maven artifacts", async () => {
    const project = await temporaryProject();
    await put(project, "pom.xml", [
      "<project><dependencies>",
      "<dependency><groupId>com.example</groupId><artifactId>openai-java</artifactId></dependency>",
      "<dependency><groupId>com.openai</groupId><artifactId>openai-java-helper</artifactId></dependency>",
      "</dependencies></project>",
      "",
    ].join("\n"));

    expect(ids(await detectTechnologies(project))).toEqual(["java"]);
  });

  test("detects the exact official OpenAI Java Gradle coordinate", async () => {
    const project = await temporaryProject();
    await put(project, "build.gradle.kts", [
      "plugins { java }",
      "dependencies { implementation(\"com.openai:openai-java-core:4.43.0\") }",
      "",
    ].join("\n"));

    expect(ids(await detectTechnologies(project))).toEqual(["java", "openai"]);
  });

  test("supports a direct Java source target without requiring a manifest", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/Agent.java", "package nested;\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([{
      id: "java",
      kind: "language",
      confidence: "high",
      evidence: ["Agent.java"],
    }]);
  });

  test("detects C# and the exact official OpenAI NuGet package", async () => {
    const project = await temporaryProject();
    await put(project, "src/Agent.cs", "namespace Agent;\n");
    await put(project, "Agent.csproj", [
      '<Project Sdk="Microsoft.NET.Sdk">',
      "  <ItemGroup>",
      '    <PackageReference Include="OpenAI" Version="2.9.1" />',
      "  </ItemGroup>",
      "</Project>",
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["csharp", "openai"]);
    expect(result.detected_technologies.find((technology) => technology.id === "openai")?.evidence)
      .toEqual(["Agent.csproj"]);
    expect(result.limitations).toEqual([]);
  });

  test("does not infer OpenAI from near-name or commented C# package references", async () => {
    const project = await temporaryProject();
    await put(project, "Agent.csproj", [
      '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>',
      '  <PackageReference Include="OpenAI.Extensions" Version="1.0.0" />',
      '  <!-- <PackageReference Include="OpenAI" Version="2.9.1" /> -->',
      "</ItemGroup></Project>",
      "",
    ].join("\n"));

    expect(ids(await detectTechnologies(project))).toEqual(["csharp"]);
  });

  test("supports a direct C# source target without requiring a project file", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/Agent.cs", "namespace Nested;\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([{
      id: "csharp",
      kind: "language",
      confidence: "high",
      evidence: ["Agent.cs"],
    }]);
  });

  test("detects PHP and the exact OpenAI PHP ecosystem Composer package", async () => {
    const project = await temporaryProject();
    await put(project, "src/Agent.php", "<?php class Agent {}\n");
    await put(project, "composer.json", JSON.stringify({
      require: { php: "^8.2", "openai-php/client": "^0.20" },
    }));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["php", "openai"]);
    expect(result.detected_technologies.find((technology) => technology.id === "openai")?.evidence)
      .toEqual(["composer.json"]);
    expect(result.limitations).toEqual([]);
  });

  test("does not infer OpenAI from near-name PHP packages or unrelated manifest text", async () => {
    const project = await temporaryProject();
    await put(project, "src/Agent.php", "<?php // openai-php/client\n");
    await put(project, "composer.json", JSON.stringify({
      require: { "example/openai-php-client": "1.0.0" },
      description: "openai-php/client",
    }));

    expect(ids(await detectTechnologies(project))).toEqual(["php"]);
  });

  test("supports a direct PHP source target without requiring Composer", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/Agent.php", "<?php class Agent {}\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([{
      id: "php",
      kind: "language",
      confidence: "high",
      evidence: ["Agent.php"],
    }]);
  });

  test("detects Rust and the exact async-openai Cargo dependency", async () => {
    const project = await temporaryProject();
    await put(project, "src/main.rs", "fn main() {}\n");
    await put(project, "Cargo.toml", [
      "[package]",
      'name = "agent"',
      "[dependencies]",
      'async-openai = { version = "0.29", features = ["byot"] }',
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["rust", "openai"]);
    expect(result.detected_technologies.find((technology) => technology.id === "openai")?.evidence)
      .toEqual(["Cargo.toml"]);
    expect(result.limitations).toEqual([]);
  });

  test("does not infer OpenAI from near-name, dev-only, or commented Rust dependencies", async () => {
    const project = await temporaryProject();
    await put(project, "src/main.rs", "// async-openai\nfn main() {}\n");
    await put(project, "Cargo.toml", [
      "[package]",
      'name = "async-openai-example"',
      "[dependencies]",
      'async-openai-extra = "1"',
      '# async-openai = "0.29"',
      "[dev-dependencies]",
      'async-openai = "0.29"',
      "",
    ].join("\n"));

    expect(ids(await detectTechnologies(project))).toEqual(["rust"]);
  });

  test("supports a direct Rust source target without requiring Cargo", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/main.rs", "fn main() {}\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([{
      id: "rust",
      kind: "language",
      confidence: "high",
      evidence: ["main.rs"],
    }]);
  });

  test("detects Ruby and the exact official OpenAI gem", async () => {
    const project = await temporaryProject();
    await put(project, "lib/agent.rb", "class Agent; end\n");
    await put(project, "Gemfile", [
      'source "https://rubygems.org"',
      'gem "openai", "~> 0.72"',
      'gem "openai-helper"',
      "",
    ].join("\n"));

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["ruby", "openai"]);
    expect(result.detected_technologies.find((technology) => technology.id === "openai")?.evidence)
      .toEqual(["Gemfile"]);
    expect(result.limitations).toEqual([]);
  });

  test("does not infer runtime OpenAI from a group-less lockfile but detects a runtime gemspec dependency", async () => {
    const locked = await temporaryProject();
    await put(locked, "Gemfile.lock", [
      "GEM", "  specs:", "    openai (0.72.0)", "DEPENDENCIES", "  openai (~> 0.72)", "",
    ].join("\n"));
    expect(ids(await detectTechnologies(locked))).toEqual(["ruby"]);

    const gemspec = await temporaryProject();
    await put(gemspec, "agent.gemspec", 'spec.add_runtime_dependency "openai", "~> 0.72"\n');
    expect(ids(await detectTechnologies(gemspec))).toEqual(["ruby", "openai"]);
  });

  test("does not infer OpenAI from near-name, commented, or development-only Ruby gems", async () => {
    const project = await temporaryProject();
    await put(project, "Gemfile", [
      '# gem "openai"',
      'gem "ruby-openai"',
      'gem "openai-helper"',
      'group :development, :test do',
      '  gem "openai"',
      "end",
      "",
    ].join("\n"));
    await put(project, "agent.gemspec", 'spec.add_development_dependency "openai"\n');

    expect(ids(await detectTechnologies(project))).toEqual(["ruby"]);
  });

  test("supports a direct Ruby source target without requiring Bundler", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/agent.rb", "class Agent; end\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([{
      id: "ruby",
      kind: "language",
      confidence: "high",
      evidence: ["agent.rb"],
    }]);
  });

  test("detects GitHub Actions only from direct workflow files", async () => {
    const project = await temporaryProject();
    await put(project, ".github/workflows/ci.yml", "on: push\njobs: {}\n");
    await put(project, ".github/workflows/nested/ignored.yaml", "on: push\njobs: {}\n");
    await put(project, "docs/.github/workflows/example.yml", "on: push\njobs: {}\n");

    const result = await detectTechnologies(project);
    expect(result.detected_technologies).toContainEqual({
      id: "github-actions",
      kind: "platform",
      confidence: "high",
      evidence: [".github/workflows/ci.yml"],
    });
  });

  test("supports a direct GitHub Actions workflow target and rejects lookalike YAML", async () => {
    const project = await temporaryProject();
    const workflow = await put(project, ".github/workflows/ci.yaml", "on: push\njobs: {}\n");
    const lookalike = await put(project, "workflows/ci.yaml", "on: push\njobs: {}\n");

    expect(ids(await detectTechnologies(workflow))).toEqual(["github-actions"]);
    expect(ids(await detectTechnologies(lookalike))).toEqual([]);
  });

  test("reads PEP 621 and Poetry dependencies without matching unrelated TOML text", async () => {
    const project = await temporaryProject();
    await put(project, "pyproject.toml", `
[project]
name = "fastapi-lookalike"
dependencies = ["FastAPI>=0.110", "OpenAI>=1"]
[tool.poetry.dependencies]
python = "^3.11"
Django = "^5"
[tool.unrelated]
flask = "not dependency evidence"
`);

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["python", "fastapi", "django", "openai"]);
    expect(result.limitations).toEqual([]);
  });

  test("reports malformed Python dependency metadata without guessing frameworks", async () => {
    const project = await temporaryProject();
    await put(project, "pyproject.toml", `[project]\ndependencies = ["fastapi"\n`);

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["python"]);
    expect(result.limitations).toEqual([{ path: "pyproject.toml", reason: "manifest_invalid" }]);
  });

  test.each([
    [
      "a valid dependency followed by malformed TOML",
      `[project]\ndependencies = ["fastapi"]\n[broken\n`,
    ],
    [
      "an empty Poetry dependency value",
      `[tool.poetry.dependencies]\nopenai =\n`,
    ],
    ["an empty unrelated TOML value", `[project]\ndependencies=["fastapi"]\nbroken =\n`],
    ["trailing dependency-array tokens", `[project]\ndependencies=["fastapi"] trailing\n`],
    ["a non-string dependency-array item", `[project]\ndependencies=["fastapi", nonsense]\n`],
    ["a malformed Poetry inline table", `[tool.poetry.dependencies]\nFastAPI={ broken }\n`],
    ["duplicate dependency keys", `[tool.poetry.dependencies]\nFastAPI="*"\nFastAPI="^1"\n`],
    ["a PEP 621 table dependency item", `[project]\ndependencies=[{note="fastapi"}]\n`],
  ])("does not infer frameworks from %s", async (_label, content) => {
    const project = await temporaryProject();
    await put(project, "pyproject.toml", content);

    const result = await detectTechnologies(project);

    expect(ids(result)).toEqual(["python"]);
    expect(result.limitations).toEqual([{ path: "pyproject.toml", reason: "manifest_invalid" }]);
  });

  test("ignores virtual-environment framework evidence", async () => {
    const project = await temporaryProject();
    await put(project, ".venv/lib/site-packages/fastapi/app.py", "from fastapi import FastAPI\n");
    await put(project, "README.md", "not a Python project\n");

    const result = await detectTechnologies(project);

    expect(result.detected_technologies).toEqual([]);
  });

  test("supports a direct Python source target without requiring a manifest", async () => {
    const project = await temporaryProject();
    const file = await put(project, "nested/app.py", "print('direct')\n");

    const result = await detectTechnologies(file);

    expect(result.detected_technologies).toEqual([{
      id: "python",
      kind: "language",
      confidence: "high",
      evidence: ["app.py"],
    }]);
  });

  test("reports target inspection failures separately from detections", async () => {
    const project = await temporaryProject();
    const result = await detectTechnologies(join(project, "missing"));

    expect(result.detected_technologies).toEqual([]);
    expect(result.limitations).toEqual([{ path: ".", reason: "target_unreadable" }]);
  });
});
