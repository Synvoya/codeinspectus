import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import {
  dartAssignments,
  dartCalls,
  dartDefinitions,
  lexDart,
  lexicalScopePath,
  nearestReachingDefinition,
  parseDartSource,
} from "./dart.js";
import {
  createCachedFlutterProjectLoader,
  loadFlutterProject,
} from "./project.js";

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("Dart lexical and structural parser", () => {
  test("keeps comments and string bodies out of executable tokens while preserving lines", () => {
    const source = [
      "// badCertificateCallback = (_) => true;",
      "final example = 'debugPrint(accessToken) { ]';",
      "/* outer { /* nested badCertificateCallback */ } */",
      "client.badCertificateCallback = (_) => true;",
    ].join("\n");
    const tokens = lexDart(source);

    expect(tokens.filter((token) => token.value === "badCertificateCallback")).toHaveLength(1);
    expect(tokens.filter((token) => token.value === "debugPrint")).toHaveLength(0);
    expect(tokens.find((token) => token.value === "badCertificateCallback")?.line).toBe(4);
    expect(tokens.filter((token) => token.kind === "string")).toHaveLength(1);
  });

  test("balances calls and collections without treating quoted delimiters as structure", () => {
    const document = parseDartSource(
      "lib/main.dart",
      "logger.info({'value': fn(') } ]', [1, 2]), 'other': r'''{ raw }''' });",
    );
    const calls = dartCalls(document);

    expect(document.balanced).toBe(true);
    expect(calls.map((call) => call.name)).toEqual(expect.arrayContaining(["info", "fn"]));
    expect(calls.find((call) => call.name === "info")?.arguments).toHaveLength(1);
  });

  test("extracts nested named arguments and assignment expressions structurally", () => {
    const document = parseDartSource(
      "lib/main.dart",
      "final client = Dio(BaseOptions(baseUrl: 'http://api.real.tld/v1')); client.get('/health');",
    );
    const assignments = dartAssignments(document);
    const calls = dartCalls(document);

    expect(assignments.map((assignment) => assignment.name)).toEqual(["client"]);
    expect(calls.find((call) => call.name === "BaseOptions")?.arguments[0]?.name).toBe("baseUrl");
    expect(calls.find((call) => call.name === "get")?.receiver).toBe("client");
  });

  test("caches scope and reaching-definition indexes per immutable document", () => {
    const document = parseDartSource(
      "lib/main.dart",
      "final global = source; void use() { final local = global; print(local); }",
    );
    const printCall = dartCalls(document).find((call) => call.name === "print")!;

    expect(dartDefinitions(document)).toBe(dartDefinitions(document));
    expect(lexicalScopePath(document, printCall.tokenIndex)).toBe(
      lexicalScopePath(document, printCall.tokenIndex),
    );
    expect(nearestReachingDefinition(document, "local", printCall.tokenIndex)?.name).toBe("local");
  });
});

describe("Flutter project loader", () => {
  test("shares one promise per loader and excludes generated/corpus Dart files", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-flutter-loader-"));
    tempRoots.push(root);
    await Promise.all([
      mkdir(join(root, "lib"), { recursive: true }),
      mkdir(join(root, "test"), { recursive: true }),
      mkdir(join(root, "integration_test"), { recursive: true }),
      mkdir(join(root, "example"), { recursive: true }),
      mkdir(join(root, "examples"), { recursive: true }),
    ]);
    await Promise.all([
      writeFile(join(root, "lib", "main.dart"), "void main() {}"),
      writeFile(join(root, "lib", "model.g.dart"), "void generated() {}"),
      writeFile(join(root, "lib", "model.freezed.dart"), "void generated() {}"),
      writeFile(join(root, "test", "main_test.dart"), "void testMain() {}"),
      writeFile(join(root, "integration_test", "app_test.dart"), "void appTest() {}"),
      writeFile(join(root, "example", "demo.dart"), "void demo() {}"),
      writeFile(join(root, "examples", "demo.dart"), "void demo() {}"),
    ]);

    const load = createCachedFlutterProjectLoader(root);
    const first = load();
    expect(load()).toBe(first);
    await expect(first.then((project) => project.files.map((file) => file.path))).resolves.toEqual([
      "lib/main.dart",
    ]);
  });

  test("supports a Dart file target and a directly scanned test root", async () => {
    const root = await mkdtemp(join(tmpdir(), "codeinspectus-flutter-file-"));
    tempRoots.push(root);
    const testRoot = join(root, "test");
    await mkdir(testRoot, { recursive: true });
    const file = join(testRoot, "security_test.dart");
    await writeFile(file, "void main() {};");

    await expect(loadFlutterProject(file).then((project) => project.files.map((item) => item.path)))
      .resolves.toEqual(["security_test.dart"]);
    await expect(loadFlutterProject(testRoot).then((project) => project.files.map((item) => item.path)))
      .resolves.toEqual(["security_test.dart"]);
  });
});
