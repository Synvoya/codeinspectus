import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { Declaration, RuntimeId } from "../types.js";

import { readRuntimePins } from "./runtime.js";
import { matchesCandidate, walkCandidates } from "./walk.js";

const FIXTURES = join(process.cwd(), "fixtures", "synvoya", "runtime");

function decl(
  runtime: RuntimeId,
  spec: string,
  precision: Declaration["precision"],
  file: string,
  line: number,
  source: string,
  resolved?: string,
): Declaration {
  return {
    subject: { type: "runtime", runtime },
    spec,
    ...(resolved === undefined ? {} : { resolved }),
    precision,
    file,
    line,
    source,
  };
}

async function read(name: string) {
  return readRuntimePins(join(FIXTURES, name));
}

describe("readRuntimePins: fixtures", () => {
  it(".nvmrc", async () => {
    const result = await read("nvm");
    expect(result.declarations).toEqual([decl("node", "20.11.0", "exact", ".nvmrc", 1, ".nvmrc", "20.11.0")]);
    expect(result.parsed).toEqual([".nvmrc"]);
    expect(result.skipped).toEqual([]);
  });

  it(".node-version major only is floating", async () => {
    expect((await read("node-version")).declarations).toEqual([
      decl("node", "22", "floating", ".node-version", 1, ".node-version"),
    ]);
  });

  it("lts/* is unresolved and noted", async () => {
    const result = await read("nvm-lts");
    expect(result.declarations).toEqual([decl("node", "lts/*", "unresolved", ".nvmrc", 1, ".nvmrc")]);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain(".nvmrc:1");
  });

  it(".tool-versions maps asdf names and ignores unrelated tools", async () => {
    expect((await read("tool-versions")).declarations).toEqual([
      decl("node", "18.19.0", "exact", ".tool-versions", 2, ".tool-versions", "18.19.0"),
      decl("python", "3.12", "floating", ".tool-versions", 3, ".tool-versions"),
      decl("ruby", "3.2.2", "exact", ".tool-versions", 4, ".tool-versions", "3.2.2"),
      decl("go", "1.21", "floating", ".tool-versions", 5, ".tool-versions"),
      decl("java", "17.0.2", "exact", ".tool-versions", 6, ".tool-versions", "17.0.2"),
      decl("php", "8.3", "floating", ".tool-versions", 7, ".tool-versions"),
    ]);
  });

  it("mise.toml reads only [tools]", async () => {
    expect((await read("mise")).declarations).toEqual([
      decl("node", "20", "floating", "mise.toml", 5, "mise.toml [tools]"),
      decl("python", "3.11.4", "exact", "mise.toml", 6, "mise.toml [tools]", "3.11.4"),
      decl("python", "3.10", "floating", "mise.toml", 6, "mise.toml [tools]"),
      decl("ruby", "3.3", "floating", "mise.toml", 7, "mise.toml [tools]"),
      decl("go", "1.22.1", "exact", "mise.toml", 8, "mise.toml [tools]", "1.22.1"),
    ]);
  });

  it("package.json engines.node and volta.node", async () => {
    expect((await read("package-json")).declarations).toEqual([
      decl("node", ">=20 <23", "range", "package.json", 4, "package.json engines.node"),
      decl("node", "20.11.0", "exact", "package.json", 8, "package.json volta.node", "20.11.0"),
    ]);
  });

  it("composer.json require.php and composer.lock platform are declarations; config.platform.php and platform-overrides only a note", async () => {
    const result = await read("composer");
    expect(result.declarations).toEqual([
      decl("php", "^8.1", "range", "composer.json", 4, "composer.json require.php"),
      decl("php", ">=7.4", "range", "composer.lock", 4, "composer.lock platform"),
    ]);
    // A platform setting is a dependency-resolution hint, not the PHP that is deployed (field run 2026-11-05: 12 FPs).
    expect(result.notes).toEqual([
      'composer.json:9: composer.json config.platform.php "8.1.*" is a dependency-resolution hint, not the deployed PHP version; ' +
        "no runtime finding is made from it (require.php, Dockerfiles, CI and .tool-versions are read for that).",
      'composer.lock:7: composer.lock platform-overrides "8.0.30" is a dependency-resolution hint, not the deployed PHP version; ' +
        "no runtime finding is made from it (require.php, Dockerfiles, CI and .tool-versions are read for that).",
    ]);
    expect(result.parsed).toEqual(["composer.json", "composer.lock"]);
  });

  it(".python-version and runtime.txt", async () => {
    expect((await read("python")).declarations).toEqual([
      decl("python", "3.12", "floating", ".python-version", 1, ".python-version"),
      decl("python", "3.11.4", "exact", "runtime.txt", 1, "runtime.txt", "3.11.4"),
    ]);
  });

  it(".ruby-version, Gemfile and Gemfile.lock", async () => {
    expect((await read("ruby")).declarations).toEqual([
      decl("ruby", "3.2.2", "exact", ".ruby-version", 1, ".ruby-version", "3.2.2"),
      decl("ruby", "~> 3.2.0", "range", "Gemfile", 3, "Gemfile ruby"),
      decl("ruby", "3.2.2", "exact", "Gemfile.lock", 9, "Gemfile.lock RUBY VERSION", "3.2.2"),
    ]);
  });

  it("global.json and csproj target frameworks", async () => {
    const result = await read("dotnet");
    expect(result.declarations).toEqual([
      decl("dotnet", "8.0.100", "exact", "global.json", 3, "global.json sdk.version", "8.0.100"),
      decl("dotnet", "3.1", "floating", "lib/Lib.csproj", 3, "csproj TargetFramework"),
      decl("dotnet", "6.0", "floating", "src/App.csproj", 3, "csproj TargetFrameworks"),
      decl("dotnet", "8.0", "floating", "src/App.csproj", 3, "csproj TargetFrameworks"),
    ]);
    expect(result.notes.some((note) => note.includes("netstandard2.0"))).toBe(true);
  });

  it("Java pins: major-only pom values are ranges", async () => {
    expect((await read("java")).declarations).toEqual([
      decl("java", "17", "floating", ".java-version", 1, ".java-version"),
      decl("java", "21.0.2", "exact", ".sdkmanrc", 2, ".sdkmanrc", "21.0.2"),
      decl("java", "11", "range", "pom.xml", 3, "pom.xml java.version"),
      decl("java", "17", "range", "pom.xml", 4, "pom.xml maven.compiler.release"),
    ]);
  });

  it("go.mod go and toolchain", async () => {
    expect((await read("go")).declarations).toEqual([
      // Since Go 1.21 the go line is a minimum: the toolchain in use is that release or any later one.
      decl("go", ">=1.21", "range", "go.mod", 3, "go.mod go"),
      decl("go", "1.22.1", "exact", "go.mod", 5, "go.mod toolchain", "1.22.1"),
    ]);
  });
});

describe("readRuntimePins: GitHub Actions", () => {
  it("expands matrix values and reads every setup action", async () => {
    const result = await read("workflows");
    const file = ".github/workflows/ci.yml";
    expect(result.declarations).toEqual([
      decl("node", "18", "floating", file, 15, "actions/setup-node node-version"),
      decl("node", "20", "floating", file, 15, "actions/setup-node node-version"),
      decl("node", "22.1.0", "exact", file, 15, "actions/setup-node node-version", "22.1.0"),
      decl("php", "8.1", "floating", file, 21, "shivammathur/setup-php php-version"),
      decl("python", "3.10", "floating", file, 24, "actions/setup-python python-version"),
      decl("go", "stable", "unresolved", file, 27, "actions/setup-go go-version"),
      decl("java", "17", "floating", file, 30, "actions/setup-java java-version"),
      decl("dotnet", "6.0.x", "floating", file, 33, "actions/setup-dotnet dotnet-version"),
      decl("dotnet", "8.0.100", "exact", file, 33, "actions/setup-dotnet dotnet-version", "8.0.100"),
      decl("ruby", "3.1", "floating", file, 38, "ruby/setup-ruby ruby-version"),
      decl("node", "${{ inputs.v }}", "unresolved", file, 44, "actions/setup-node node-version"),
    ]);
    expect(result.notes.some((note) => note.includes("${{ inputs.v }}"))).toBe(true);
  });
});

describe("readRuntimePins: hostile and edge inputs", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-rt-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  it("a matrix value that is an expression leaves the workflow not fully judged; the literal values are kept", async () => {
    await mkdir(join(work, ".github", "workflows"), { recursive: true });
    await writeFile(
      join(work, ".github", "workflows", "ci.yml"),
      "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        node: [20.1.0, \"${{ inputs.extra }}\"]\n" +
        "    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.node }}\n",
    );
    const result = await readRuntimePins(work);
    expect(result.declarations.map((declaration) => declaration.spec)).toEqual(["20.1.0"]);
    expect(result.unjudged).toEqual([".github/workflows/ci.yml"]);
  });

  it("a pom.xml version that refers to another property leaves the file not fully judged", async () => {
    await writeFile(join(work, "pom.xml"), "<project>\n  <properties>\n    <java.version>${jdk}</java.version>\n  </properties>\n</project>\n");
    const result = await readRuntimePins(work);
    expect(result.declarations).toEqual([]);
    expect(result.unjudged).toEqual(["pom.xml"]);
  });

  it("skips a symlinked .nvmrc with reason symlink", async (ctx) => {
    await writeFile(join(work, "real"), "20.11.0\n");
    try {
      await symlink(join(work, "real"), join(work, ".nvmrc"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return ctx.skip();
      throw error;
    }
    const result = await readRuntimePins(work);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: ".nvmrc", reason: "symlink" }]);
  });

  it("skips a 2 MiB package.json as oversized", async () => {
    await writeFile(join(work, "package.json"), JSON.stringify({ engines: { node: "20" }, pad: "x".repeat(2 * 1024 * 1024) }));
    const result = await readRuntimePins(work);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: "package.json", reason: "oversized" }]);
  });

  it("ignores node_modules, vendor and build output", async () => {
    for (const dir of ["node_modules/x", "vendor/y", "dist/z", ".git/w"]) {
      await mkdir(join(work, ...dir.split("/")), { recursive: true });
      await writeFile(join(work, ...dir.split("/"), ".nvmrc"), "14\n");
    }
    await writeFile(join(work, ".nvmrc"), "22\n");
    const result = await readRuntimePins(work);
    expect(result.declarations.map((entry) => entry.file)).toEqual([".nvmrc"]);
    expect(result.skipped).toEqual([]);
  });

  it("reports nested files with forward slashes", async () => {
    await mkdir(join(work, "apps", "web"), { recursive: true });
    await writeFile(join(work, "apps", "web", ".nvmrc"), "20\n");
    expect((await readRuntimePins(work)).declarations.map((entry) => entry.file)).toEqual(["apps/web/.nvmrc"]);
  });

  it("never throws on malformed files", async () => {
    await writeFile(join(work, "package.json"), "{ not json");
    await writeFile(join(work, "composer.json"), "[1,");
    await writeFile(join(work, "mise.toml"), "[tools\nnode = ");
    await mkdir(join(work, ".github", "workflows"), { recursive: true });
    await writeFile(join(work, ".github", "workflows", "bad.yml"), "jobs: [unclosed\n  - : :\n");
    const result = await readRuntimePins(work);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([
      { file: ".github/workflows/bad.yml", reason: "malformed" },
      { file: "composer.json", reason: "malformed" },
      { file: "mise.toml", reason: "malformed" },
      { file: "package.json", reason: "malformed" },
    ]);
  });

  it("a matrix key the job does not define stays unresolved", async () => {
    await mkdir(join(work, ".github", "workflows"), { recursive: true });
    await writeFile(
      join(work, ".github", "workflows", "ci.yaml"),
      "jobs:\n  a:\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: ${{ matrix.missing }}\n",
    );
    const result = await readRuntimePins(work);
    expect(result.declarations).toEqual([
      decl("node", "${{ matrix.missing }}", "unresolved", ".github/workflows/ci.yaml", 6, "actions/setup-node node-version"),
    ]);
  });

  it("an empty target yields an empty result", async () => {
    expect(await readRuntimePins(work)).toEqual({ declarations: [], parsed: [], skipped: [], notes: [] });
  });
});

describe("readRuntimePins: hostile inputs", { timeout: 20_000 }, () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-hostile-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  async function timed(): Promise<{ result: Awaited<ReturnType<typeof readRuntimePins>>; ms: number }> {
    const started = Date.now();
    const result = await readRuntimePins(work);
    return { result, ms: Date.now() - started };
  }

  it.each([30_000, 100_000])("a %d-deep package.json is malformed, quickly", async (depth) => {
    await writeFile(join(work, "package.json"), `${'{"a":'.repeat(depth)}1${"}".repeat(depth)}`);
    const { result, ms } = await timed();
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([{ file: "package.json", reason: "malformed" }]);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("a 1 MiB .python-version reads only the first line", async () => {
    await writeFile(join(work, ".python-version"), "3.12\n".repeat(200_000));
    const { result } = await timed();
    expect(result.declarations).toEqual([decl("python", "3.12", "floating", ".python-version", 1, ".python-version")]);
  });

  it("a short .python-version keeps every pyenv line", async () => {
    await writeFile(join(work, ".python-version"), "3.12.1\n3.11.4\n3.10\n");
    const { result } = await timed();
    expect(result.declarations.map((entry) => entry.spec)).toEqual(["3.12.1", "3.11.4", "3.10"]);
  });

  it("caps declarations per file at 64 with one note", async () => {
    await writeFile(join(work, ".tool-versions"), "nodejs 18.19.0\n".repeat(60_000));
    const { result } = await timed();
    expect(result.declarations).toHaveLength(64);
    expect(result.notes).toEqual([".tool-versions: more than 64 runtime declarations; extra ignored"]);
    // Read only in part: skipped as capped, never parsed (rescan must not treat it as re-checked).
    expect(result.parsed).toEqual([]);
    expect(result.skipped).toEqual([{ file: ".tool-versions", reason: "capped" }]);
  });

  it("caps declarations per scan at 2000 and stops", async () => {
    for (let index = 0; index < 40; index++) {
      await mkdir(join(work, `d${String(index).padStart(2, "0")}`));
      await writeFile(join(work, `d${String(index).padStart(2, "0")}`, ".tool-versions"), "nodejs 18.19.0\n".repeat(70));
    }
    const { result } = await timed();
    expect(result.declarations).toHaveLength(2000);
    expect(result.notes.some((note) => note.includes("more than 2000 runtime declarations; extra ignored"))).toBe(true);
    // The per-scan cap note is the one note the scan's note caps must never drop.
    expect(result.priorityNotes).toEqual([expect.stringContaining("more than 2000 runtime declarations; extra ignored")]);
    expect(result.skipped.some((entry) => entry.reason === "capped")).toBe(true);
    expect(result.parsed).toEqual([]);
  });

  it("an expired deadline starts no file and reports the walk as skipped by deadline", async () => {
    await writeFile(join(work, ".nvmrc"), "20.11.0\n");
    const controller = new AbortController();
    controller.abort();
    const result = await readRuntimePins(work, { signal: controller.signal });
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toEqual([]);
    expect(result.skipped).toEqual([{ file: ".", reason: "deadline" }]);
  });

  it("a deadline reached between files keeps what was read and skips the rest by deadline", async () => {
    await writeFile(join(work, ".node-version"), "20.11.0\n");
    await writeFile(join(work, ".nvmrc"), "18.19.0\n");
    // Count every deadline check of a full run; the last two are the per-file checks, in file order.
    let checks = 0;
    const counting = { get aborted() { checks++; return false; } } as AbortSignal;
    expect((await readRuntimePins(work, { signal: counting })).parsed).toEqual([".node-version", ".nvmrc"]);
    let seen = 0;
    const expiring = { get aborted() { return ++seen >= checks; } } as AbortSignal;
    const result = await readRuntimePins(work, { signal: expiring });
    expect(result.parsed).toEqual([".node-version"]);
    expect(result.declarations.map((declaration) => declaration.file)).toEqual([".node-version"]);
    expect(result.skipped).toEqual([{ file: ".nvmrc", reason: "deadline" }]);
  });

  it("bounds notes from a csproj full of non-runtime targets", async () => {
    await writeFile(join(work, "App.csproj"), `<TargetFrameworks>${"netstandard2.0;".repeat(60_000)}</TargetFrameworks>`);
    const { result } = await timed();
    expect(result.notes.length).toBeLessThanOrEqual(65);
  });

  async function workflow(matrixCount: number, references: number): Promise<void> {
    await mkdir(join(work, ".github", "workflows"), { recursive: true });
    const values = Array.from({ length: matrixCount }, (_, index) => index).join(", ");
    const lines = Array.from({ length: references }, () => "            ${{ matrix.n }}").join("\n");
    await writeFile(
      join(work, ".github", "workflows", "ci.yml"),
      `jobs:\n  a:\n    strategy:\n      matrix:\n        n: [${values}]\n    steps:\n      - uses: actions/setup-node@v4\n        with:\n          node-version: |\n${lines}\n`,
    );
  }

  it("bounds matrix amplification (1000 values x 100 references)", async () => {
    await workflow(1000, 100);
    const { result, ms } = await timed();
    expect(result.declarations.length).toBeLessThanOrEqual(64);
    expect(result.declarations.length).toBeGreaterThan(0);
    expect(result.notes.some((note) => note.includes("more than 64 runtime declarations; extra ignored"))).toBe(true);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("bounds a 40k-value matrix with 1000 references", async () => {
    await workflow(40_000, 1000);
    const { result, ms } = await timed();
    expect(result.declarations.length).toBeLessThanOrEqual(64);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("caps distinct matrix values per key at 32", async () => {
    await workflow(1000, 1);
    const { result } = await timed();
    expect(result.declarations).toHaveLength(32);
    expect(result.notes.some((note) => note.includes("32 distinct"))).toBe(true);
  });
});

describe("walkCandidates", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-walk-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  it("matches by basename, wildcard, suffix and prefix", () => {
    expect(matchesCandidate({ basename: ".nvmrc" }, "a/.nvmrc")).toBe(true);
    expect(matchesCandidate({ basename: ".nvmrc" }, "a/x.nvmrc")).toBe(false);
    expect(matchesCandidate({ basename: "*.csproj" }, "src/App.csproj")).toBe(true);
    expect(matchesCandidate({ basename: "Dockerfile.*" }, "Dockerfile.dev")).toBe(true);
    expect(matchesCandidate({ basename: ["a", "b"] }, "x/b")).toBe(true);
    expect(matchesCandidate({ prefix: ".github/workflows/", suffix: ".yml" }, ".github/workflows/ci.yml")).toBe(true);
    expect(matchesCandidate({ prefix: ".github/workflows/", suffix: ".yml" }, "sub/.github/workflows/ci.yml")).toBe(false);
    expect(matchesCandidate({}, "anything")).toBe(false);
  });

  it("stops descending past the depth limit and says so", async () => {
    let dir = work;
    for (let depth = 0; depth < 14; depth++) dir = join(dir, `d${depth}`);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, ".nvmrc"), "20\n");
    const result = await walkCandidates(work, [{ basename: ".nvmrc" }]);
    expect(result.files).toEqual([]);
    expect(result.skipped).toEqual([{ file: Array.from({ length: 13 }, (_, i) => `d${i}`).join("/"), reason: "depth-limit" }]);
  });

  it("stops after the entry limit and says so", async () => {
    for (let index = 0; index < 10; index++) await writeFile(join(work, `f${index}.txt`), "x");
    const result = await walkCandidates(work, [{ basename: "f9.txt" }], { maxEntries: 5 });
    expect(result.files).toEqual([]);
    expect(result.skipped).toEqual([{ file: ".", reason: "entry-limit" }]);
  });
});
