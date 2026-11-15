import { lstat, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

import type { SetupComponentId, SetupComponentPlan, SetupPlan, installSetupComponents } from "../setup.js";
import type { EngineSetupStatus } from "../types.js";
import { planEngineRepair } from "../install.js";
import { runDatabaseUpdate, type DatabaseUpdateOptions, type DatabaseUpdateResult } from "../update.js";
import { CLAUDE_CODE_ARGV, type InitEnv } from "./clients.js";
import { runInitCli, type InitCliIo, type InitCliOptions } from "./index.js";

const directories: string[] = [];
async function tempDir(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-init-cli-"));
  directories.push(directory);
  return directory;
}
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

const exists = async (path: string): Promise<boolean> => lstat(path).then(() => true, () => false);

function fakeIo(options: { tty?: boolean; answers?: string[] } = {}): InitCliIo & { out: string; err: string; questions: string[] } {
  const answers = [...(options.answers ?? [])];
  const io = {
    stdinIsTTY: options.tty ?? false,
    out: "",
    err: "",
    questions: [] as string[],
    stdout: (text: string) => { io.out += text; },
    stderr: (text: string) => { io.err += text; },
    question: async (prompt: string) => {
      io.questions.push(prompt);
      return answers.shift() ?? "";
    },
  };
  return io;
}

function fakeEnv(home: string, options: { onPath?: string[]; failing?: string[] } = {}): InitEnv & { runs: Array<readonly string[]> } {
  const runs: Array<readonly string[]> = [];
  return {
    home,
    platform: "linux",
    which: async (command) => (options.onPath ?? []).includes(command) ? `/fake/bin/${command}` : undefined,
    run: async (argv) => {
      runs.push(argv);
      return (options.failing ?? []).includes(argv[0]!) ? { code: 1, stderr: "boom" } : { code: 0, stderr: "" };
    },
    runs,
  };
}

const SETUP_IDS: SetupComponentId[] = ["opengrep", "gitleaks", "trivy", "osv-scanner"];

const METADATA: Record<SetupComponentId, { name: string; license: string; size: number }> = {
  opengrep: { name: "Opengrep", license: "GNU LGPL 2.1", size: 40 * 1024 * 1024 },
  gitleaks: { name: "Gitleaks", license: "MIT", size: 8 * 1024 * 1024 },
  trivy: { name: "Trivy", license: "Apache-2.0", size: 50 * 1024 * 1024 },
  "osv-scanner": { name: "OSV-Scanner", license: "Apache-2.0", size: 12 * 1024 * 1024 },
};

/** A setup plan: every component needs a download unless named in `ready`; `blocked` ones cannot run here. */
function setupPlan(options: {
  selection?: readonly SetupComponentId[];
  ready?: readonly SetupComponentId[];
  blocked?: readonly SetupComponentId[];
  osv?: Array<{ ecosystem: "npm" | "PyPI"; state: "installed" | "missing" | "stale" }>;
} = {}): SetupPlan {
  const selection = options.selection ?? ["opengrep", "gitleaks", "trivy", "osv-scanner"];
  const components = (["opengrep", "gitleaks", "trivy", "osv-scanner"] as const).map((id): SetupComponentPlan => {
    const blocked = options.blocked?.includes(id);
    const ready = options.ready?.includes(id);
    return {
      id,
      name: METADATA[id].name,
      version: "1.0.0",
      state: blocked ? "unsupported_platform" : ready ? "ready" : "missing",
      action: blocked ? "blocked" : ready ? "none" : "download",
      selected: selection.includes(id),
      download_size_bytes: METADATA[id].size,
      coverage: [`${id} coverage`],
      license: METADATA[id].license,
      ...(blocked ? { note: "Not available on this platform." } : {}),
      ...(id === "trivy" ? { estimated_database_disk_bytes: 1_181_116_006 } : {}),
    };
  });
  const osvSelected = selection.includes("osv-scanner");
  const osv = (options.osv ?? []).map((database) => ({
    ecosystem: database.ecosystem,
    state: database.state,
    selected: osvSelected,
    estimated_download_bytes: database.ecosystem === "npm" ? 219_600_000 : 37_500_000,
  }));
  const actionable = components.filter((item) => item.selected && item.action !== "none" && item.action !== "blocked");
  return {
    schema_version: "1.0.0",
    platform: "linux-x64",
    native: { rule_count: 100, download_required: false, coverage: "native" },
    components,
    verifier: { name: "Cosign", version: "2.0.0", required: false, available: true, license: "Apache-2.0", purpose: "verify" },
    preference_state: "unconfigured",
    network_required: actionable.length > 0 || osv.some((database) => database.selected && database.state !== "installed"),
    confirmation_required: actionable.length > 0,
    exact_download_bytes: actionable.reduce((sum, item) => sum + (item.download_size_bytes ?? 0), 0),
    osv_databases: osv,
    estimated_osv_download_bytes: osv.filter((database) => database.selected && database.state !== "installed")
      .reduce((sum, database) => sum + database.estimated_download_bytes, 0),
    estimated_database_disk_bytes: actionable.some((item) => item.id === "trivy") ? 1_181_116_006 : 0,
    warnings: [],
  };
}

type PlanArgs = Parameters<NonNullable<InitCliOptions["buildPlan"]>>[0];

/** Engine status for plain `init` tests: binaries missing, the Trivy DB present unless `trivyDb` says otherwise. */
function initStatus(options: { trivyDb?: "ready" | "missing" } = {}): EngineSetupStatus {
  return {
    state: "repair_required",
    platform: "linux-x64",
    engines: SETUP_IDS.map((engine) => ({ engine, version: "1.0.0", state: "missing" as const })),
    trivy_db: options.trivyDb === "missing" ? { state: "missing" } : { state: "ready", downloaded_at: new Date().toISOString() },
    osv_databases: [],
    network_required: true,
  };
}

async function setup(options: {
  status?: EngineSetupStatus;
  onPath?: string[];
  failing?: string[];
  cursor?: boolean;
  plan?: (args: PlanArgs) => SetupPlan;
  install?: typeof installSetupComponents;
} = {}) {
  const home = await tempDir();
  const project = join(home, "project");
  await mkdir(project);
  if (options.cursor ?? true) await mkdir(join(home, ".cursor"));
  const env = fakeEnv(home, { onPath: options.onPath ?? ["claude"], ...(options.failing ? { failing: options.failing } : {}) });
  const buildPlan = vi.fn(async (args: PlanArgs = {}) =>
    (options.plan ?? ((input: PlanArgs) => setupPlan({ ...(input?.selection ? { selection: input.selection } : {}), osv: [{ ecosystem: "PyPI", state: "missing" }] })))(args));
  const install = vi.fn(options.install ?? (async (_selection, _confirm, opts) => ({
    outcome: "installed" as const, message: "Selected components installed and verified.", plan: opts?.plan ?? setupPlan(),
  })));
  const inspect = vi.fn(async () => options.status ?? initStatus());
  const run = (args: string[], io: ReturnType<typeof fakeIo>) =>
    runInitCli(args, { io, env, cwd: project, buildPlan: buildPlan as never, install: install as never, inspect });
  return { home, project, env, buildPlan, install, inspect, run, cursorConfig: join(home, ".cursor", "mcp.json") };
}

describe("codeinspectus init", () => {
  test("--dry-run shows every client, engine and database with sizes and licences, and changes nothing", async () => {
    const ctx = await setup();
    const io = fakeIo({ tty: true });
    expect(await ctx.run(["--dry-run"], io)).toBe(0);
    expect(io.out).toContain(`Claude Code (\`claude\` on PATH): run: claude mcp add-json --scope user codeinspectus '{"command":"npx","args":["-y","codeinspectus"]}'`);
    expect(io.out).toContain(`create ${ctx.cursorConfig}: "mcpServers"."codeinspectus"`);
    expect(io.out).toMatch(/Opengrep 1\.0\.0: download 40\.0 MiB; licence GNU LGPL 2\.1/);
    expect(io.out).toMatch(/Trivy 1\.0\.0: download 50\.0 MiB; licence Apache-2\.0/);
    expect(io.out).toMatch(/PyPI: missing; ~35\.8 MiB download/);
    expect(io.out).not.toMatch(/over 100 MB/);
    expect(io.out).toMatch(/Total download: about \d+\.\d MiB/);
    expect(io.out).toContain('"mcpServers"'); // the manual route for other assistants
    expect(io.out).toMatch(/Dry run: nothing was changed/);
    expect(io.questions).toEqual([]);
    expect(ctx.env.runs).toEqual([]);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(await exists(ctx.cursorConfig)).toBe(false);
    expect(ctx.buildPlan).toHaveBeenCalledWith(expect.objectContaining({ selection: ["opengrep", "gitleaks", "trivy", "osv-scanner"], target: ctx.project }));
  });

  test("--dry-run --json prints one JSON document with the planned steps", async () => {
    const ctx = await setup();
    const io = fakeIo();
    expect(await ctx.run(["--dry-run", "--json"], io)).toBe(0);
    const document = JSON.parse(io.out);
    expect(document.dry_run).toBe(true);
    expect(document.plan.clients.map((step: { client: string; status: string }) => [step.client, step.status])).toEqual([["claude", "add"], ["cursor", "add"]]);
    expect(document.plan.clients[0].argv).toEqual(CLAUDE_CODE_ARGV);
    expect(document.plan.engines.components).toHaveLength(4);
    expect(document.plan.target).toBe(ctx.project);
    expect(document.result).toBeUndefined();
    expect(await exists(ctx.cursorConfig)).toBe(false);
  });

  test("declining at the confirmation writes nothing, runs no client CLI and downloads nothing", async () => {
    const ctx = await setup();
    const io = fakeIo({ tty: true, answers: ["n"] });
    expect(await ctx.run([], io)).toBe(0);
    expect(io.questions).toEqual(["Set all of this up? [y/N] "]);
    expect(io.out).toMatch(/--clients claude,codex.*--skip-engines/);
    expect(io.out).toMatch(/Nothing was changed/);
    expect(ctx.env.runs).toEqual([]);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(await exists(ctx.cursorConfig)).toBe(false);
  });

  test("without a terminal it needs --yes and changes nothing", async () => {
    const ctx = await setup();
    const io = fakeIo();
    expect(await ctx.run([], io)).toBe(2);
    expect(io.err).toMatch(/--yes/);
    expect(ctx.env.runs).toEqual([]);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(await exists(ctx.cursorConfig)).toBe(false);
  });

  test("--yes registers every client, then installs all four engines once, after the registrations", async () => {
    const order: string[] = [];
    const ctx = await setup({
      install: async (_selection, _confirm, opts) => {
        order.push("install");
        return { outcome: "installed", message: "Selected components installed and verified.", plan: opts!.plan! };
      },
    });
    const io = fakeIo();
    const run = ctx.env.run;
    ctx.env.run = async (argv) => { order.push("run"); return run(argv); };
    expect(await ctx.run(["--yes"], io)).toBe(0);
    expect(ctx.env.runs).toEqual([CLAUDE_CODE_ARGV]);
    expect(JSON.parse(await readFile(ctx.cursorConfig, "utf8")).mcpServers.codeinspectus).toEqual({ command: "npx", args: ["-y", "codeinspectus"] });
    expect(ctx.install).toHaveBeenCalledTimes(1);
    const [selection, confirm, opts] = ctx.install.mock.calls[0]!;
    expect(selection).toEqual(["opengrep", "gitleaks", "trivy", "osv-scanner"]);
    expect(confirm).toBe(true);
    expect(opts).toMatchObject({ target: ctx.project });
    expect(opts?.plan?.osv_databases.map((database: { ecosystem: string }) => database.ecosystem)).toEqual(["PyPI"]);
    expect(order).toEqual(["run", "install"]);
    expect(io.out).toMatch(/Claude Code: registered/);
    expect(io.out).toMatch(/Cursor: registered/);
    expect(io.out).toMatch(/restart your assistant and ask it to run a security scan/i);
  });

  test("a TTY yes does the same", async () => {
    const ctx = await setup();
    const io = fakeIo({ tty: true, answers: ["y"] });
    expect(await ctx.run([], io)).toBe(0);
    expect(ctx.env.runs).toEqual([CLAUDE_CODE_ARGV]);
    expect(ctx.install).toHaveBeenCalledTimes(1);
  });

  test("--skip-engines registers clients and never plans or installs engines", async () => {
    const ctx = await setup();
    const io = fakeIo();
    expect(await ctx.run(["--yes", "--skip-engines"], io)).toBe(0);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(ctx.buildPlan).not.toHaveBeenCalled();
    expect(await exists(ctx.cursorConfig)).toBe(true);
    expect(io.out).toMatch(/Engines: skipped \(--skip-engines\)/);
  });

  test("--clients limits registration to the named assistants", async () => {
    const ctx = await setup();
    const io = fakeIo();
    expect(await ctx.run(["--yes", "--clients", "cursor", "--skip-engines"], io)).toBe(0);
    expect(ctx.env.runs).toEqual([]);
    expect(await exists(ctx.cursorConfig)).toBe(true);
  });

  test("a client named in --clients but not found is reported, not an error", async () => {
    const ctx = await setup();
    const io = fakeIo();
    expect(await ctx.run(["--dry-run", "--clients", "windsurf"], io)).toBe(0);
    expect(io.out).toMatch(/Windsurf: not found on this machine/);
  });

  test("a failing client CLI is reported, the rest continue, engines still install once: exit 1", async () => {
    const ctx = await setup({ failing: ["claude"] });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(1);
    expect(io.out).toMatch(/Claude Code: failed — `claude` exited with code 1: boom/);
    expect(await exists(ctx.cursorConfig)).toBe(true);
    expect(ctx.install).toHaveBeenCalledTimes(1);
  });

  test("an engine install failure is named: exit 1", async () => {
    const ctx = await setup({ install: async () => { throw new Error("Trivy download failed (503)"); } });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(1);
    expect(io.out + io.err).toMatch(/Engine setup failed: Trivy download failed \(503\)/);
    expect(await exists(ctx.cursorConfig)).toBe(true);
  });

  test("a component that cannot run on this platform is shown and left out of the install", async () => {
    const ctx = await setup({ plan: (args) => setupPlan({ ...(args?.selection ? { selection: args.selection } : {}), blocked: ["opengrep"] }) });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(0);
    expect(io.out).toMatch(/Opengrep 1\.0\.0: not available here \(Not available on this platform\.\)/);
    expect(ctx.install.mock.calls[0]![0]).toEqual(["gitleaks", "trivy", "osv-scanner"]);
  });

  test("a second run reports already registered everywhere and downloads nothing", async () => {
    const ready = (args: PlanArgs) => setupPlan({
      ...(args?.selection ? { selection: args.selection } : {}),
      ready: ["opengrep", "gitleaks", "trivy", "osv-scanner"],
      osv: [{ ecosystem: "npm", state: "installed" }],
    });
    const ctx = await setup({ onPath: [], plan: ready });
    expect(await ctx.run(["--yes"], fakeIo())).toBe(0);
    const before = await readFile(ctx.cursorConfig, "utf8");
    const io = fakeIo({ tty: true });
    expect(await ctx.run([], io)).toBe(0);
    expect(io.questions).toEqual([]);
    expect(io.out).toMatch(/Cursor \(.*\): already registered/);
    expect(io.out).toMatch(/Everything is already set up/);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(await readFile(ctx.cursorConfig, "utf8")).toBe(before);
  });

  test("nothing to do but a file needs a manual step: never claims everything is set up", async () => {
    const ready = (args: PlanArgs) => setupPlan({ ...(args?.selection ? { selection: args.selection } : {}), ready: SETUP_IDS });
    const ctx = await setup({ onPath: [], plan: ready });
    const { writeFile } = await import("node:fs/promises");
    await writeFile(ctx.cursorConfig, "{ // mine\n}", "utf8");
    const io = fakeIo({ tty: true });
    expect(await ctx.run([], io)).toBe(0);
    expect(io.questions).toEqual([]);
    expect(io.out).toMatch(/Nothing to change or download automatically\. Cursor: see the step shown above/);
    expect(io.out).not.toMatch(/Everything is already set up/);
    expect(await readFile(ctx.cursorConfig, "utf8")).toBe("{ // mine\n}");
  });

  test("no project folder: the home directory is never used as the OSV target", async () => {
    const ctx = await setup();
    const io = fakeIo();
    await runInitCli(["--dry-run"], { io, env: ctx.env, cwd: ctx.home, buildPlan: ctx.buildPlan as never, install: ctx.install as never, inspect: ctx.inspect });
    expect(ctx.buildPlan.mock.calls[0]![0]).not.toHaveProperty("target");
    expect(io.out).toMatch(/--path <repo>/);
  });

  test.each([
    [["--bogus"], /Unknown init option: --bogus/],
    [["--clients", "emacs"], /Unknown client: emacs/],
    [["--clients"], /--clients needs a value/],
    [["--json"], /--json needs --yes/],
    [["--path", "/definitely/not/here"], /not a directory/],
  ])("usage error %j: exit 2, nothing changed", async (args, message) => {
    const ctx = await setup();
    const io = fakeIo({ tty: true });
    expect(await ctx.run(args, io)).toBe(2);
    expect(io.err).toMatch(message);
    expect(ctx.env.runs).toEqual([]);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(await exists(ctx.cursorConfig)).toBe(false);
  });

  test("a JSONC config holding a token never reaches the human or --json output", async () => {
    const ctx = await setup();
    const { writeFile } = await import("node:fs/promises");
    await writeFile(ctx.cursorConfig, `{\n  "mcpServers": { "gh": { "env": { "GITHUB_TOKEN":'ghp_SECRETVALUE123' } } }\n}\n`, "utf8");
    for (const args of [["--dry-run"], ["--dry-run", "--json"], ["--yes", "--skip-engines"], ["--yes", "--skip-engines", "--json"]]) {
      const io = fakeIo();
      await ctx.run(args, io);
      expect(io.out + io.err).toContain("mcp.json");
      expect(io.out + io.err).not.toContain("SECRETVALUE");
    }
  });

  test("a first install that downloads the Trivy DB: --yes alone is refused before anything changes; --yes --large proceeds", async () => {
    const ctx = await setup({ status: initStatus({ trivyDb: "missing" }) });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(2);
    expect(io.err).toMatch(/trivy-db \(~133\.5 MiB\) is over 100 MB and was not approved\. Re-run with --yes --large/);
    expect(ctx.env.runs).toEqual([]);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(await exists(ctx.cursorConfig)).toBe(false);

    const json = fakeIo();
    expect(await ctx.run(["--yes", "--json"], json)).toBe(2);
    expect(JSON.parse(json.out).plan.large_downloads).toEqual([{ id: "trivy-db", approx_size: "133.5 MiB" }]);
    expect(ctx.install).not.toHaveBeenCalled();

    expect(await ctx.run(["--yes", "--large"], fakeIo())).toBe(0);
    expect(ctx.install).toHaveBeenCalledTimes(1);
  });

  /** A plan that honours an explicit OSV list (as buildSetupPlan does), offering npm and PyPI by default. */
  const osvAwarePlan = (ecosystems: Array<"npm" | "PyPI">) => (args: PlanArgs) => setupPlan({
    ...(args?.selection ? { selection: args.selection } : {}),
    osv: ((args?.osvEcosystems as Array<"npm" | "PyPI"> | undefined) ?? ecosystems).map((ecosystem) => ({ ecosystem, state: "missing" as const })),
  });
  const largeQuestion = (skips: string): string =>
    `These include downloads over 100 MB (trivy-db (~133.5 MiB), osv:npm (~209.4 MiB)). ${skips}Download them too? [y/N] `;
  const SKIPS_TRIVY = "A no also skips Trivy, which needs the Trivy DB. ";
  const SKIPS_TRIVY_AND_OSV = "A no also skips Trivy, which needs the Trivy DB; and OSV-Scanner, which has no other OSV database to download. ";

  test("on a terminal the one screen marks each download over 100 MB and a second question asks about them", async () => {
    const ctx = await setup({ status: initStatus({ trivyDb: "missing" }), plan: osvAwarePlan(["npm"]) });
    const io = fakeIo({ tty: true, answers: ["y", "y"] });
    expect(await ctx.run([], io)).toBe(0);
    expect(io.out).toMatch(/plus the vulnerability DB \(~133\.5 MiB download \(over 100 MB\)/);
    expect(io.out).toMatch(/npm: missing; ~209\.4 MiB download \(over 100 MB\)/);
    expect(io.out).toMatch(/Over 100 MB each: trivy-db \(~133\.5 MiB\), osv:npm \(~209\.4 MiB\)/);
    expect(io.questions).toEqual(["Set all of this up? [y/N] ", largeQuestion(SKIPS_TRIVY_AND_OSV)]);
    expect(ctx.install).toHaveBeenCalledTimes(1);
    const [selection, , opts] = ctx.install.mock.calls[0]!;
    expect(selection).toEqual(["opengrep", "gitleaks", "trivy", "osv-scanner"]);
    expect(opts?.plan?.osv_databases.map((database: { ecosystem: string }) => database.ecosystem)).toEqual(["npm"]);
  });

  test("on a terminal --large skips the second question", async () => {
    const ctx = await setup({ status: initStatus({ trivyDb: "missing" }), plan: osvAwarePlan(["npm"]) });
    const io = fakeIo({ tty: true, answers: ["y"] });
    expect(await ctx.run(["--large"], io)).toBe(0);
    expect(io.questions).toEqual(["Set all of this up? [y/N] "]);
    expect(ctx.install.mock.calls[0]![0]).toEqual(["opengrep", "gitleaks", "trivy", "osv-scanner"]);
  });

  test("a no to the second question registers the assistants and installs everything else", async () => {
    const ctx = await setup({ status: initStatus({ trivyDb: "missing" }), plan: osvAwarePlan(["npm", "PyPI"]) });
    const io = fakeIo({ tty: true, answers: ["y", "n"] });
    expect(await ctx.run([], io)).toBe(0);
    expect(io.questions).toEqual(["Set all of this up? [y/N] ", largeQuestion(SKIPS_TRIVY)]);
    expect(ctx.env.runs).toEqual([CLAUDE_CODE_ARGV]);
    expect(await exists(ctx.cursorConfig)).toBe(true);
    expect(ctx.install).toHaveBeenCalledTimes(1);
    const [selection, , opts] = ctx.install.mock.calls[0]!;
    // Trivy goes (its first install downloads the Trivy DB); osv-scanner stays with PyPI only.
    expect(selection).toEqual(["opengrep", "gitleaks", "osv-scanner"]);
    expect(opts?.plan?.osv_databases.map((database: { ecosystem: string }) => database.ecosystem)).toEqual(["PyPI"]);
    expect(opts?.plan?.components.filter((item: SetupComponentPlan) => item.selected).map((item: SetupComponentPlan) => item.id))
      .toEqual(["opengrep", "gitleaks", "osv-scanner"]);
    expect(io.out).toMatch(/Left out \(over 100 MB, not approved\): trivy-db \(~133\.5 MiB\), osv:npm \(~209\.4 MiB\)/);
    expect(io.out).toContain("Also skipped: Trivy, which needs the Trivy DB.");
  });

  test("a no leaves out osv-scanner when its only database is over 100 MB", async () => {
    const ctx = await setup({ status: initStatus({ trivyDb: "missing" }), plan: osvAwarePlan(["npm"]) });
    const io = fakeIo({ tty: true, answers: ["y", "no"] });
    expect(await ctx.run([], io)).toBe(0);
    expect(ctx.install.mock.calls[0]![0]).toEqual(["opengrep", "gitleaks"]);
  });

  test("a no to a large Cosign verifier installs only the engines that do not need it", async () => {
    // Every engine but Gitleaks (checksums only) is verified with Cosign, per the packaged lockfile.
    const ctx = await setup({
      plan: (args) => {
        const plan = setupPlan({ ...(args?.selection ? { selection: args.selection } : {}) });
        const required = (args?.selection ?? SETUP_IDS).some((id) => id !== "gitleaks");
        return { ...plan, verifier: { ...plan.verifier, required, available: false, download_size_bytes: 139_600_000 } };
      },
    });
    const io = fakeIo({ tty: true, answers: ["y", "n"] });
    expect(await ctx.run([], io)).toBe(0);
    const skips = "A no also skips Opengrep, Trivy and OSV-Scanner, which need the Cosign verifier.";
    expect(io.questions[1]).toBe(`These include downloads over 100 MB (cosign (~133.1 MiB)). ${skips} Download them too? [y/N] `);
    expect(ctx.install.mock.calls[0]![0]).toEqual(["gitleaks"]);
    // The result note names them again.
    expect(io.out).toMatch(/Engines: .*Left out \(over 100 MB, not approved\): cosign \(~133\.1 MiB\)/);
    expect(io.out.split("Summary")[1]).toContain("Also skipped: Opengrep, Trivy and OSV-Scanner, which need the Cosign verifier.");
  });

  test("a no that leaves nothing to install still registers the assistants", async () => {
    const ctx = await setup({
      status: initStatus({ trivyDb: "missing" }),
      plan: (args) => setupPlan({ ...(args?.selection ? { selection: args.selection } : {}), ready: ["opengrep", "gitleaks", "osv-scanner"] }),
    });
    const io = fakeIo({ tty: true, answers: ["y", "n"] });
    expect(await ctx.run([], io)).toBe(0);
    expect(ctx.env.runs).toEqual([CLAUDE_CODE_ARGV]);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(io.out).toMatch(/Engines: nothing downloaded\. Left out \(over 100 MB, not approved\): trivy-db \(~133\.5 MiB\)/);
  });

  test("a single engine or verifier download over 100 MB is gated too", async () => {
    const ctx = await setup({
      plan: (args) => {
        const plan = setupPlan({ ...(args?.selection ? { selection: args.selection } : {}) });
        return { ...plan, verifier: { ...plan.verifier, required: true, available: false, download_size_bytes: 139_600_000 } };
      },
    });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(2);
    expect(io.err).toMatch(/cosign \(~133\.1 MiB\)/);
  });

  test("a config edited while the confirmation question is open is skipped as changed and left as edited", async () => {
    const ctx = await setup();
    const { writeFile } = await import("node:fs/promises");
    await writeFile(ctx.cursorConfig, "{}\n", "utf8");
    const edited = '{"mcpServers":{"mine":{"command":"mine"}}}\n';
    const io = fakeIo({ tty: true });
    io.question = async (prompt: string) => {
      io.questions.push(prompt);
      await writeFile(ctx.cursorConfig, edited, "utf8");
      return "y";
    };
    expect(await ctx.run(["--skip-engines"], io)).toBe(0);
    expect(io.out).toMatch(/Cursor: skipped — .*the file changed while init was running; run init again/);
    expect(await readFile(ctx.cursorConfig, "utf8")).toBe(edited);
    expect(await exists(`${ctx.cursorConfig}.codeinspectus-backup`)).toBe(false);
  });

  test("several downloads over 100 MB are named in the plural", async () => {
    const ctx = await setup({
      status: initStatus({ trivyDb: "missing" }),
      plan: (args) => setupPlan({ ...(args?.selection ? { selection: args.selection } : {}), osv: [{ ecosystem: "npm", state: "missing" }] }),
    });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(2);
    expect(io.err).toMatch(/trivy-db \(~133\.5 MiB\), osv:npm \(~209\.4 MiB\) are over 100 MB and were not approved/);
  });

  test("--help prints usage", async () => {
    const ctx = await setup();
    const io = fakeIo();
    expect(await ctx.run(["--help"], io)).toBe(0);
    expect(io.out).toMatch(/Usage: codeinspectus init/);
  });
});

describe("codeinspectus init --update", () => {
  const HOUR = 60 * 60 * 1000;
  const old = new Date(Date.now() - 48 * HOUR).toISOString();

  function engineStatus(options: { trivyDb?: boolean; osv?: Array<"PyPI" | "npm">; broken?: Array<"trivy" | "osv-scanner"> } = {}): EngineSetupStatus {
    return {
      state: "ready",
      platform: "linux-x64",
      engines: (["opengrep", "gitleaks", "trivy", "osv-scanner"] as const).map((engine) => ({
        engine, version: "1.0.0", state: options.broken?.includes(engine as "trivy") ? "hash_mismatch" as const : "ready" as const,
      })),
      trivy_db: options.trivyDb ? { state: "ready", downloaded_at: old } : { state: "missing" },
      osv_databases: (options.osv ?? []).map((ecosystem) => ({ ecosystem, state: "ready" as const, downloaded_at: old })),
      network_required: false,
    };
  }

  /** A configured preference file; `redownload` components have a new pin to fetch. */
  function updatePlan(args: PlanArgs, options: { configured?: boolean; enabled?: SetupComponentId[]; redownload?: SetupComponentId[] } = {}): SetupPlan {
    const enabled = options.enabled ?? ["opengrep", "gitleaks", "trivy", "osv-scanner"];
    const selection = args?.selection ?? enabled;
    const plan = setupPlan({ selection, ready: SETUP_IDS.filter((id) => !options.redownload?.includes(id)) });
    return {
      ...plan,
      preference_state: options.configured === false ? "unconfigured" : "configured",
      components: plan.components.map((item) => options.redownload?.includes(item.id)
        ? { ...item, action: "redownload" as const, state: "hash_mismatch" }
        : item),
    };
  }

  function updateResult(overrides: Partial<DatabaseUpdateResult> = {}): DatabaseUpdateResult {
    return {
      outcome: "updated",
      databases: [{ id: "osv:PyPI", before: old, after: new Date().toISOString(), changed: 3 }],
      skipped: [],
      package: { running: "4.0.0", latest: "4.0.0", newer: false, note: "CodeInspectus 4.0.0 is current." },
      message: "Updated osv:PyPI (3 changed record(s)). CodeInspectus 4.0.0 is current.",
      ...overrides,
    };
  }

  async function updateCtx(options: {
    plan?: (args: PlanArgs) => SetupPlan;
    status?: EngineSetupStatus;
    result?: DatabaseUpdateResult | Error;
    install?: typeof installSetupComponents;
  } = {}) {
    const order: string[] = [];
    const home = await tempDir();
    const env = fakeEnv(home, { onPath: ["claude"] });
    const buildPlan = vi.fn(async (args: PlanArgs = {}) => (options.plan ?? ((input: PlanArgs) => updatePlan(input)))(args));
    const install = vi.fn(async (...input: Parameters<typeof installSetupComponents>) => {
      order.push("install");
      if (options.install) return options.install(...input);
      return { outcome: "installed" as const, message: "Selected components installed and verified.", plan: input[2]!.plan! };
    });
    const runUpdate = vi.fn(async (_input: DatabaseUpdateOptions) => {
      order.push("update");
      if (options.result instanceof Error) throw options.result;
      return options.result ?? updateResult();
    });
    const inspect = vi.fn(async () => options.status ?? engineStatus({ osv: ["PyPI"] }));
    const run = (args: string[], io: ReturnType<typeof fakeIo>) => runInitCli(["--update", ...args], {
      io, env, cwd: home, buildPlan: buildPlan as never, install: install as never, inspect, runUpdate: runUpdate as never,
    });
    return { env, buildPlan, install, runUpdate, run, order };
  }

  test("nothing enabled and no database installed: nothing to do", async () => {
    const ctx = await updateCtx({ plan: (args) => updatePlan(args, { configured: false, redownload: ["trivy"] }), status: engineStatus() });
    const io = fakeIo({ tty: true });
    expect(await ctx.run([], io)).toBe(0);
    expect(io.out).toMatch(/Nothing to update/);
    expect(io.questions).toEqual([]);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(ctx.runUpdate).not.toHaveBeenCalled();
  });

  test("declined at the confirmation: no downloads", async () => {
    const ctx = await updateCtx({ plan: (args) => updatePlan(args, { redownload: ["gitleaks"] }) });
    const io = fakeIo({ tty: true, answers: ["n"] });
    expect(await ctx.run([], io)).toBe(0);
    expect(io.questions).toEqual(["Update all of this? [y/N] "]);
    expect(io.out).toMatch(/Gitleaks 1\.0\.0: re-download 8\.0 MiB/);
    expect(io.out).toMatch(/osv:PyPI: ~35\.8 MiB download/);
    expect(io.out).toMatch(/No update downloaded/);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(ctx.runUpdate).not.toHaveBeenCalled();
    expect(ctx.env.runs).toEqual([]);
  });

  test("without a terminal it needs --yes; --dry-run only prints", async () => {
    const ctx = await updateCtx();
    const io = fakeIo();
    expect(await ctx.run([], io)).toBe(2);
    expect(io.err).toMatch(/--yes/);
    const dry = fakeIo();
    expect(await ctx.run(["--dry-run"], dry)).toBe(0);
    expect(dry.out).toMatch(/Dry run: nothing was changed/);
    expect(ctx.runUpdate).not.toHaveBeenCalled();
  });

  test("--yes refreshes new engine pins first, then the databases, and never registers clients", async () => {
    const ctx = await updateCtx({ plan: (args) => updatePlan(args, { enabled: ["gitleaks", "osv-scanner"], redownload: ["gitleaks", "trivy"] }) });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(0);
    expect(ctx.order).toEqual(["install", "update"]);
    // Only enabled components with a new pin or a missing binary; Trivy is not enabled.
    expect(ctx.install.mock.calls[0]![0]).toEqual(["gitleaks"]);
    expect(ctx.install.mock.calls[0]![1]).toBe(true);
    expect(ctx.runUpdate.mock.calls[0]![0]).toMatchObject({ confirmDownloads: true, confirmLargeDownloads: false });
    expect(ctx.env.runs).toEqual([]);
    expect(io.out).toMatch(/Database update updated/);
  });

  test("databases over 100 MB need --large, as with `codeinspectus update`", async () => {
    const ctx = await updateCtx({ status: engineStatus({ trivyDb: true, osv: ["PyPI"] }) });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(2);
    expect(io.err).toMatch(/trivy-db \(~133\.5 MiB\) is over 100 MB.*--yes --large/);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(ctx.runUpdate).not.toHaveBeenCalled();

    const approved = fakeIo();
    expect(await ctx.run(["--yes", "--large"], approved)).toBe(0);
    expect(ctx.runUpdate.mock.calls[0]![0]).toMatchObject({ confirmDownloads: true, confirmLargeDownloads: true });
  });

  test("on a terminal a large database gets a second question", async () => {
    const ctx = await updateCtx({ status: engineStatus({ trivyDb: true }) });
    const declined = fakeIo({ tty: true, answers: ["y", "n"] });
    expect(await ctx.run([], declined)).toBe(0);
    expect(declined.questions[1]).toMatch(/trivy-db \(~133\.5 MiB\) is over 100 MB\. Download it too\? \[y\/N\] /);
    expect(ctx.runUpdate).not.toHaveBeenCalled();
    const accepted = fakeIo({ tty: true, answers: ["y", "y"] });
    expect(await ctx.run([], accepted)).toBe(0);
    expect(ctx.runUpdate.mock.calls[0]![0]).toMatchObject({ confirmLargeDownloads: true });
  });

  test("a database whose engine gets a new pin in the same run is shown and counted for the large rule", async () => {
    const ctx = await updateCtx({
      plan: (args) => updatePlan(args, { redownload: ["trivy"] }),
      status: engineStatus({ trivyDb: true, broken: ["trivy"] }),
    });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(2);
    expect(io.err).toMatch(/trivy-db/);
  });

  test("a refresh failure exits 1 and names the failed database", async () => {
    const ctx = await updateCtx({
      result: updateResult({
        outcome: "failed",
        databases: [{ id: "osv:PyPI", before: old, error: "download failed (503)" }],
        message: "Update failed: osv:PyPI (download failed (503)). The previous databases were kept.",
      }),
    });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(1);
    expect(io.out).toMatch(/osv:PyPI.*error: download failed \(503\)/);
  });

  test("an engine refresh failure is named and the databases still update: exit 1", async () => {
    const ctx = await updateCtx({
      plan: (args) => updatePlan(args, { redownload: ["opengrep"] }),
      install: async () => { throw new Error("Opengrep signature check failed"); },
    });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(1);
    expect(io.out + io.err).toMatch(/Engine update failed \(opengrep\): Opengrep signature check failed/);
    expect(ctx.runUpdate).toHaveBeenCalledTimes(1);
  });

  test("a newer CodeInspectus on npm: tells the user to run the latest init --update", async () => {
    const ctx = await updateCtx({
      result: updateResult({ package: { running: "4.0.0", latest: "4.1.0", newer: true, note: "CodeInspectus 4.1.0 is available." } }),
    });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(0);
    expect(io.out).toMatch(/npx may run a cached copy.*npx codeinspectus@latest init --update/);
  });

  test("--json needs --yes and prints one document", async () => {
    const ctx = await updateCtx();
    expect(await ctx.run(["--json"], fakeIo({ tty: true }))).toBe(2);
    const io = fakeIo();
    expect(await ctx.run(["--yes", "--json"], io)).toBe(0);
    const document = JSON.parse(io.out);
    expect(document.plan.databases.databases.map((database: { id: string }) => database.id)).toEqual(["osv:PyPI"]);
    expect(document.result.databases.outcome).toBe("updated");
  });

  test("reviewer scenario: Trivy binary and DB missing; --update --yes without --large is refused and installs nothing", async () => {
    const missing: EngineSetupStatus = { ...engineStatus(), engines: engineStatus().engines.map((engine) =>
      engine.engine === "trivy" ? { ...engine, state: "missing" as const } : engine), trivy_db: { state: "missing" } };
    const ctx = await updateCtx({
      plan: (args) => updatePlan(args, { redownload: ["trivy"] }),
      status: missing,
    });
    const io = fakeIo();
    expect(await ctx.run(["--yes"], io)).toBe(2);
    expect(io.err).toMatch(/trivy-db \(~133\.5 MiB\) is over 100 MB and was not approved/);
    expect(ctx.install).not.toHaveBeenCalled();
    expect(ctx.runUpdate).not.toHaveBeenCalled();

    const dry = fakeIo();
    expect(await ctx.run(["--dry-run"], dry)).toBe(0);
    expect(dry.out).toMatch(/Trivy 1\.0\.0: re-download 50\.0 MiB.*plus the vulnerability DB \(~133\.5 MiB download \(over 100 MB\)/);
  });

  describe("each database is downloaded once (real runDatabaseUpdate, fake repairs)", () => {
    const NEW = new Date().toISOString();

    /** A machine whose status the fake repairs change, counting every database each one downloads. */
    function machine(initial: EngineSetupStatus) {
      let current = structuredClone(initial);
      const fetched: string[] = [];
      const refresh = (trivy: boolean, ecosystems: readonly string[]) => {
        if (trivy) {
          fetched.push("trivy-db");
          current.trivy_db = { state: "ready", downloaded_at: NEW };
        }
        for (const ecosystem of ecosystems) {
          fetched.push(`osv:${ecosystem}`);
          current.osv_databases = (current.osv_databases ?? []).map((database) =>
            database.ecosystem === ecosystem ? { ...database, state: "ready" as const, downloaded_at: NEW } : database);
        }
      };
      // (a): installSetupComponents -> repairEngines(selection): re-pins the engine and, as repair does, refreshes
      // its databases that are not ready.
      const install = async (selection: readonly SetupComponentId[], _confirm: boolean, opts?: { plan?: SetupPlan }) => {
        const repairs = planEngineRepair(current, [...selection], false,
          (opts?.plan?.osv_databases ?? []).filter((database) => database.selected).map((database) => database.ecosystem));
        current.engines = current.engines.map((engine) => (selection.includes(engine.engine) ? { ...engine, state: "ready" as const } : engine));
        refresh(repairs.refresh_trivy_db, repairs.osv_ecosystems);
        return { outcome: "installed" as const, message: "Selected components installed and verified.", plan: opts!.plan! };
      };
      // (b): runDatabaseUpdate's own refresh through repairEngines([... "--refresh-db", "--osv-ecosystems", list]).
      const repair = async (args: string[]) => {
        const index = args.indexOf("--osv-ecosystems");
        refresh(args.includes("trivy"), index >= 0 ? args[index + 1]!.split(",") : []);
      };
      return { inspect: async () => structuredClone(current), install, repair, fetched };
    }

    async function runUpdateOnce(state: ReturnType<typeof machine>, plan: (args: PlanArgs) => SetupPlan) {
      const home = await tempDir();
      const fetch = vi.fn(async (input: string | URL | Request) => String(input).endsWith("/latest")
        ? new Response(JSON.stringify({ version: "0.0.1" }))
        : new Response(""));
      const io = fakeIo();
      const code = await runInitCli(["--update", "--yes", "--large"], {
        io,
        env: fakeEnv(home),
        cwd: home,
        buildPlan: (async (args: PlanArgs) => plan(args)) as never,
        install: state.install as never,
        inspect: state.inspect,
        runUpdate: ((input: DatabaseUpdateOptions) => runDatabaseUpdate({
          ...input, repair: state.repair as never, fetch: fetch as never, statePath: join(home, "update-prompt.json"),
        })) as never,
      });
      return { code, io };
    }

    test("Trivy hash_mismatch with a stale DB: the Trivy DB is fetched exactly once", async () => {
      const state = machine({
        ...engineStatus({ trivyDb: true, osv: ["PyPI"], broken: ["trivy"] }),
        trivy_db: { state: "stale", downloaded_at: old },
      });
      const { code, io } = await runUpdateOnce(state, (args) => updatePlan(args, { redownload: ["trivy"] }));
      expect(code, io.err).toBe(0);
      expect(state.fetched.filter((id) => id === "trivy-db")).toHaveLength(1);
      expect(state.fetched.sort()).toEqual(["osv:PyPI", "trivy-db"]);
      expect(io.out).toMatch(/Database update updated\. Updated osv:PyPI/);
    });

    test("a stale OSV database with an osv-scanner pin change: fetched exactly once", async () => {
      const state = machine({
        ...engineStatus({ trivyDb: true, osv: ["PyPI"], broken: ["osv-scanner"] }),
        osv_databases: [{ ecosystem: "PyPI", state: "stale", downloaded_at: old }],
      });
      const plan = (args: PlanArgs) => {
        const base = updatePlan(args, { redownload: ["osv-scanner"] });
        // As buildSetupPlan does without a target: an installed database due a refresh is offered with osv-scanner.
        const osvSelected = (args?.selection ?? []).includes("osv-scanner");
        return { ...base, osv_databases: [{ ecosystem: "PyPI" as const, state: "stale" as const, selected: osvSelected, estimated_download_bytes: 37_500_000 }] };
      };
      const { code, io } = await runUpdateOnce(state, plan);
      expect(code, io.err).toBe(0);
      expect(state.fetched.filter((id) => id === "osv:PyPI")).toHaveLength(1);
      expect(state.fetched.sort()).toEqual(["osv:PyPI", "trivy-db"]);
    });

    test("when the engine repair refreshed every database, the refresh step downloads nothing", async () => {
      const state = machine({
        ...engineStatus({ trivyDb: true, broken: ["trivy"] }),
        trivy_db: { state: "stale", downloaded_at: old },
      });
      const { code, io } = await runUpdateOnce(state, (args) => updatePlan(args, { redownload: ["trivy"] }));
      expect(code, io.err).toBe(0);
      expect(state.fetched).toEqual(["trivy-db"]);
      expect(io.out).toMatch(/trivy-db refreshed with the engine update; nothing else to download/);
    });
  });

  test("--update --help prints the update usage", async () => {
    const ctx = await updateCtx();
    const io = fakeIo();
    expect(await ctx.run(["--help"], io)).toBe(0);
    expect(io.out).toMatch(/Usage: codeinspectus init --update/);
    expect(ctx.buildPlan).not.toHaveBeenCalled();
  });

  test.each([["--clients", "claude"], ["--skip-engines"], ["--path", "."]])("--update with %s is a usage error", async (...flag) => {
    const ctx = await updateCtx();
    const io = fakeIo();
    expect(await ctx.run(flag, io)).toBe(2);
    expect(io.err).toMatch(/not used with --update/);
  });
});
