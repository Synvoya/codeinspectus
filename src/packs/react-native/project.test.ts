import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import {
  loadReactNativeProject,
  REACT_NATIVE_MAX_SOURCE_BYTES,
} from "./project.js";
import { createReactNativeAnalyzers } from "./index.js";

const temporary: string[] = [];

afterEach(async () => {
  await Promise.all(temporary.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("React Native project loader bounds", () => {
  test("skips oversized, test, generated, dependency, and symbolic-link sources with bounded notes", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-rn-"));
    temporary.push(root);
    await mkdir(join(root, "src"), { recursive: true });
    await mkdir(join(root, "generated"), { recursive: true });
    await mkdir(join(root, "__tests__"), { recursive: true });
    await mkdir(join(root, "node_modules", "package"), { recursive: true });
    const outside = await mkdtemp(join(tmpdir(), "codeinspectus-rn-outside-"));
    temporary.push(outside);
    await writeFile(join(root, "src", "App.tsx"), "export const App = () => null;\n");
    await writeFile(join(root, "src", "large.ts"), "x".repeat(REACT_NATIVE_MAX_SOURCE_BYTES + 1));
    await writeFile(join(root, "src", "api.generated.ts"), "export const secret = true;\n");
    await writeFile(join(root, "generated", "planted-webview.tsx"), "throw new Error('not production');\n");
    await writeFile(join(root, "__tests__", "App.test.tsx"), "throw new Error('not production');\n");
    await writeFile(join(root, "node_modules", "package", "index.js"), "module.exports = {};\n");
    await writeFile(join(outside, "outside.tsx"), "throw new Error('must not scan outside target');\n");
    await symlink(join(root, "src", "App.tsx"), join(root, "src", "linked.tsx"));
    await symlink(outside, join(root, "src", "linked-directory"));

    const project = await loadReactNativeProject(root);
    expect(project.files.map((file) => file.path)).toEqual(["src/App.tsx"]);
    expect(project.limitations?.join(" ")).toContain("oversized React Native source src/large.ts");
    expect(project.limitations?.join(" ")).toContain("symbolic-link React Native source path src/linked.tsx");
    expect(project.limitations?.join(" ")).toContain("symbolic-link React Native source path src/linked-directory");
  });

  test("stops before reading/parsing candidates beyond injected file and byte bounds", async () => {
    const fileRoot = await mkdtemp(join(tmpdir(), "codeinspectus-rn-file-bound-"));
    const byteRoot = await mkdtemp(join(tmpdir(), "codeinspectus-rn-byte-bound-"));
    temporary.push(fileRoot, byteRoot);
    await Promise.all(["01.ts", "02.ts", "03.ts"].map((name) =>
      writeFile(join(fileRoot, name), `export const ${name.replace(".", "_")} = true;\n`)
    ));
    await writeFile(join(byteRoot, "01.ts"), "export const first = true;\n");
    await writeFile(join(byteRoot, "02.ts"), "export const second = true;\n");

    const fileBounded = await loadReactNativeProject(fileRoot, {
      maxSourceFiles: 2,
      maxDiscoveryEntries: 10,
    });
    expect(fileBounded.files.map((file) => file.path)).toEqual(["01.ts", "02.ts"]);
    expect(fileBounded.limitations?.join(" ")).toContain("2-file project bound");

    const byteBounded = await loadReactNativeProject(byteRoot, {
      maxTotalBytes: 30,
      maxDiscoveryEntries: 10,
    });
    expect(byteBounded.files.map((file) => file.path)).toEqual(["01.ts"]);
    expect(byteBounded.limitations?.join(" ")).toContain("30-byte total-source project bound");
  });

  test("drops the first document that would exceed the injected project token bound", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-rn-token-bound-"));
    temporary.push(root);
    await writeFile(join(root, "01.ts"), "const first = true;\n");
    await writeFile(join(root, "02.ts"), "const second = true;\n");

    const project = await loadReactNativeProject(root, {
      maxTotalTokens: 6,
      maxDiscoveryEntries: 10,
    });
    expect(project.files.map((file) => file.path)).toEqual(["01.ts"]);
    expect(project.limitations?.join(" ")).toContain("6-token project bound");
  });

  test("discards an over-budget single directory instead of sorting or scanning a partial prefix", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-rn-entry-bound-"));
    temporary.push(root);
    await Promise.all(["01.ts", "02.ts", "03.ts"].map((name) =>
      writeFile(join(root, name), "export const value = true;\n")
    ));
    const project = await loadReactNativeProject(root, { maxDiscoveryEntries: 2 });
    expect(project.files).toEqual([]);
    expect(project.limitations?.join(" ")).toContain("2-entry project bound");
  });

  test("surfaces malformed and dynamic-spread limitations through every analyzer", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-rn-notes-"));
    temporary.push(root);
    await writeFile(join(root, "App.tsx"), `
      import WebView from 'react-native-webview';
      const App = (props) => <WebView {...props} source={{ uri: 'https://mobile.production.tld' }} />;
    `);
    await writeFile(join(root, "Broken.ts"), "export const broken = ({;\n");
    const analyzers = createReactNativeAnalyzers(root);
    const results = await Promise.all(analyzers.map((analyzer) => analyzer.run()));
    expect(results).toHaveLength(4);
    expect(results.every((result) => result.notes?.some((note) => note.includes("Dynamic JSX spread props")))).toBe(true);
    expect(results.every((result) => result.notes?.some((note) => note.includes("structurally malformed")))).toBe(true);
  });
});
