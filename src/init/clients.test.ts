import { chmod, lstat, mkdir, mkdtemp, readFile, readlink, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { afterEach, describe, expect, test } from "vitest";

import {
  applyRegistration,
  CLAUDE_CODE_ARGV,
  CLAUDE_CODE_ARGV_WIN32,
  CODEX_TOML_BLOCK,
  detectClients,
  planRegistration,
  VSCODE_ARGV,
  type DetectedClient,
  type InitEnv,
} from "./clients.js";

const directories: string[] = [];
async function tempHome(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "codeinspectus-init-"));
  directories.push(directory);
  return directory;
}
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

interface FakeEnv extends InitEnv {
  runs: Array<readonly string[]>;
}

function fakeEnv(home: string, options: {
  platform?: NodeJS.Platform;
  appData?: string;
  onPath?: string[];
  run?: (argv: readonly string[]) => { code: number; stderr: string; stdout?: string };
} = {}): FakeEnv {
  const runs: Array<readonly string[]> = [];
  return {
    home,
    platform: options.platform ?? "darwin",
    ...(options.appData ? { appData: options.appData } : {}),
    which: async (command) => (options.onPath ?? []).includes(command) ? `/fake/bin/${command}` : undefined,
    run: async (argv) => {
      runs.push([...argv]);
      return options.run?.(argv) ?? { code: 0, stderr: "" };
    },
    runs,
  };
}

async function write(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, text, "utf8");
}

async function only(env: InitEnv, id: DetectedClient["id"]): Promise<DetectedClient> {
  const client = (await detectClients(env)).find((item) => item.id === id);
  if (!client) throw new Error(`${id} not detected`);
  return client;
}

const exists = async (path: string): Promise<boolean> => lstat(path).then(() => true, () => false);

describe("detectClients", () => {
  test("nothing installed and nothing on PATH: no clients", async () => {
    expect(await detectClients(fakeEnv(await tempHome()))).toEqual([]);
  });

  test("Claude Code is registered only through its CLI, with the user scope", async () => {
    const home = await tempHome();
    const client = await only(fakeEnv(home, { onPath: ["claude"] }), "claude");
    expect(client.route).toEqual({ kind: "command", argv: CLAUDE_CODE_ARGV, check: { path: join(home, ".claude.json"), format: "json-mcpServers" } });
    expect(CLAUDE_CODE_ARGV).toEqual([
      "claude", "mcp", "add-json", "--scope", "user", "codeinspectus", '{"command":"npx","args":["-y","codeinspectus"]}',
    ]);
  });

  test("Codex: detected by ~/.codex or by `codex` on PATH, targeting ~/.codex/config.toml", async () => {
    const byDirectory = await tempHome();
    await mkdir(join(byDirectory, ".codex"));
    expect((await only(fakeEnv(byDirectory), "codex")).route).toEqual({
      kind: "file", path: join(byDirectory, ".codex", "config.toml"), format: "toml-append",
    });
    const byPath = await tempHome();
    expect((await only(fakeEnv(byPath, { onPath: ["codex"] }), "codex")).route).toEqual({
      kind: "file", path: join(byPath, ".codex", "config.toml"), format: "toml-append",
    });
  });

  test("Cursor and Windsurf: detected by their home folders", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    await mkdir(join(home, ".codeium", "windsurf"), { recursive: true });
    const env = fakeEnv(home);
    expect((await only(env, "cursor")).route).toEqual({ kind: "file", path: join(home, ".cursor", "mcp.json"), format: "json-mcpServers" });
    expect((await only(env, "windsurf")).route).toEqual({
      kind: "file", path: join(home, ".codeium", "windsurf", "mcp_config.json"), format: "json-mcpServers",
    });
  });

  test.each([
    ["darwin", ["Library", "Application Support", "Code", "User"]],
    ["linux", [".config", "Code", "User"]],
  ] as const)("VS Code and Cline on %s: the user settings folder", async (platform, parts) => {
    const home = await tempHome();
    const user = join(home, ...parts);
    await mkdir(join(user, "globalStorage", "saoudrizwan.claude-dev"), { recursive: true });
    const env = fakeEnv(home, { platform });
    expect((await only(env, "vscode")).route).toEqual({ kind: "file", path: join(user, "mcp.json"), format: "json-servers" });
    expect((await only(env, "cline")).route).toEqual({
      kind: "file",
      path: join(user, "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
      format: "json-mcpServers",
    });
  });

  test("VS Code and Cline on Windows: %APPDATA%\\Code\\User", async () => {
    const home = await tempHome();
    const appData = join(home, "AppData", "Roaming");
    const user = join(appData, "Code", "User");
    await mkdir(join(user, "globalStorage", "saoudrizwan.claude-dev"), { recursive: true });
    const env = fakeEnv(home, { platform: "win32", appData });
    expect((await only(env, "vscode")).route).toEqual({ kind: "file", path: join(user, "mcp.json"), format: "json-servers" });
    expect((await only(env, "cline")).route).toMatchObject({ kind: "file", format: "json-mcpServers" });
    // A macOS-style folder means nothing on Windows.
    const other = await tempHome();
    await mkdir(join(other, "Library", "Application Support", "Code", "User"), { recursive: true });
    expect(await detectClients(fakeEnv(other, { platform: "win32", appData: join(other, "AppData", "Roaming") }))).toEqual([]);
  });

  test("VS Code uses `code --add-mcp` when `code` is on PATH", async () => {
    const home = await tempHome();
    const client = await only(fakeEnv(home, { onPath: ["code"], platform: "linux" }), "vscode");
    expect(client.route).toEqual({
      kind: "command",
      argv: VSCODE_ARGV,
      check: { path: join(home, ".config", "Code", "User", "mcp.json"), format: "json-servers" },
    });
    expect(VSCODE_ARGV).toEqual(["code", "--add-mcp", '{"name":"codeinspectus","command":"npx","args":["-y","codeinspectus"]}']);
  });
});

describe("JSON configuration files", () => {
  test("merging keeps every other server, every other key and their order", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    const original = {
      theme: "dark",
      mcpServers: { alpha: { command: "a", args: ["1"], env: { TOKEN: "x" } }, beta: { url: "https://example.test/mcp" } },
      zeta: [1, 2, 3],
    };
    await write(path, `${JSON.stringify(original, null, 4)}\n`);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step).toMatchObject({ kind: "file", path, format: "json-mcpServers", status: "add" });

    const outcome = await applyRegistration(step, env);
    expect(outcome).toMatchObject({ client: "cursor", outcome: "registered" });
    const text = await readFile(path, "utf8");
    const written = JSON.parse(text);
    expect(written).toEqual({ ...original, mcpServers: { ...original.mcpServers, codeinspectus: { command: "npx", args: ["-y", "codeinspectus"] } } });
    expect(Object.keys(written)).toEqual(["theme", "mcpServers", "zeta"]);
    expect(Object.keys(written.mcpServers)).toEqual(["alpha", "beta", "codeinspectus"]);
    expect(text).toMatch(/^ {4}"theme"/m); // the file's own indentation is kept
    expect(text.endsWith("}\n")).toBe(true);
    expect(env.runs).toEqual([]);
  });

  test("a file without the servers key gains it; a missing file is created with only the entry", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".codeium", "windsurf"), { recursive: true });
    await write(join(home, ".codeium", "windsurf", "mcp_config.json"), '{"other":true}');
    await mkdir(join(home, ".cursor"));
    const env = fakeEnv(home);
    for (const id of ["windsurf", "cursor"] as const) {
      const step = await planRegistration(await only(env, id));
      expect(step.status).toBe("add");
      expect((await applyRegistration(step, env)).outcome).toBe("registered");
    }
    expect(JSON.parse(await readFile(join(home, ".codeium", "windsurf", "mcp_config.json"), "utf8"))).toEqual({
      other: true, mcpServers: { codeinspectus: { command: "npx", args: ["-y", "codeinspectus"] } },
    });
    expect(JSON.parse(await readFile(join(home, ".cursor", "mcp.json"), "utf8"))).toEqual({
      mcpServers: { codeinspectus: { command: "npx", args: ["-y", "codeinspectus"] } },
    });
    expect(await exists(join(home, ".cursor", "mcp.json.codeinspectus-backup"))).toBe(false); // nothing to back up
  });

  test("VS Code mcp.json uses the servers key and a stdio entry", async () => {
    const home = await tempHome();
    const user = join(home, ".config", "Code", "User");
    await mkdir(user, { recursive: true });
    const env = fakeEnv(home, { platform: "linux" });
    const step = await planRegistration(await only(env, "vscode"));
    expect((await applyRegistration(step, env)).outcome).toBe("registered");
    expect(JSON.parse(await readFile(join(user, "mcp.json"), "utf8"))).toEqual({
      servers: { codeinspectus: { type: "stdio", command: "npx", args: ["-y", "codeinspectus"] } },
    });
  });

  test.each([
    ["a comment", '{\n  // my servers\n  "mcpServers": {}\n}\n'],
    ["a trailing comma", '{ "mcpServers": { "a": { "command": "a" }, } }'],
    ["a non-object servers key", '{ "mcpServers": [] }'],
    ["a top-level array", "[]"],
  ])("a file with %s is unparseable: never rewritten, no backup, manual instruction given", async (_label, text) => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    await write(path, text);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("unparseable");
    const outcome = await applyRegistration(step, env);
    expect(outcome.outcome).toBe("skipped");
    expect(outcome.detail).toContain(path);
    expect(outcome.detail).toContain('"codeinspectus": {"command":"npx","args":["-y","codeinspectus"]}');
    expect(await readFile(path, "utf8")).toBe(text);
    expect(await exists(`${path}.codeinspectus-backup`)).toBe(false);
  });

  test("an existing identical entry is already registered and nothing is written", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    const text = '{"mcpServers":{"codeinspectus":{"command":"npx","args":["-y","codeinspectus"],"env":{}}}}';
    await write(path, text);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("already");
    expect((await applyRegistration(step, env)).outcome).toBe("already");
    expect(await readFile(path, "utf8")).toBe(text);
    expect(await exists(`${path}.codeinspectus-backup`)).toBe(false);
  });

  test("a different codeinspectus entry is a conflict and is left alone", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    const text = '{"mcpServers":{"codeinspectus":{"command":"node","args":["/opt/codeinspectus/dist/index.js"]}}}';
    await write(path, text);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("conflict");
    const outcome = await applyRegistration(step, env);
    expect(outcome.outcome).toBe("conflict");
    expect(outcome.detail).toMatch(/left unchanged/);
    expect(await readFile(path, "utf8")).toBe(text);
  });

  test("the backup is made once, before the first write, and never overwritten", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    const first = '{"mcpServers":{"alpha":{"command":"a"}}}';
    await write(path, first);
    const env = fakeEnv(home);
    const outcome = await applyRegistration(await planRegistration(await only(env, "cursor")), env);
    expect(outcome.backup).toBe(`${path}.codeinspectus-backup`);
    expect(await readFile(`${path}.codeinspectus-backup`, "utf8")).toBe(first);

    // The user removes the entry by hand; a second registration writes again but keeps the first backup.
    await write(path, '{"mcpServers":{"beta":{"command":"b"}}}');
    expect((await applyRegistration(await planRegistration(await only(env, "cursor")), env)).outcome).toBe("registered");
    expect(await readFile(`${path}.codeinspectus-backup`, "utf8")).toBe(first);
  });

  test.skipIf(process.platform === "win32")("the write keeps the file mode and leaves no temporary file", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    await write(path, "{}");
    await chmod(path, 0o640);
    const env = fakeEnv(home);
    await applyRegistration(await planRegistration(await only(env, "cursor")), env);
    expect((await stat(path)).mode & 0o777).toBe(0o640);
    const { readdir } = await import("node:fs/promises");
    expect((await readdir(join(home, ".cursor"))).sort()).toEqual(["mcp.json", "mcp.json.codeinspectus-backup"]);
  });

  test.skipIf(process.platform === "win32")("a symlinked config file stays a symlink; its target is updated", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const real = join(home, "dotfiles", "cursor-mcp.json");
    await write(real, "{}");
    const path = join(home, ".cursor", "mcp.json");
    await symlink(real, path);
    const env = fakeEnv(home);
    expect((await applyRegistration(await planRegistration(await only(env, "cursor")), env)).outcome).toBe("registered");
    expect((await lstat(path)).isSymbolicLink()).toBe(true);
    expect(await readlink(path)).toBe(real);
    expect(JSON.parse(await readFile(real, "utf8")).mcpServers.codeinspectus.command).toBe("npx");
  });

  test("a file changed between plan and apply is re-checked, never clobbered", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    await write(path, "{}");
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("add");
    await write(path, "{ // edited\n}");
    expect((await applyRegistration(step, env)).outcome).toBe("skipped");
    expect(await readFile(path, "utf8")).toBe("{ // edited\n}");
  });
});

describe("Codex config.toml", () => {
  test("appends the README block once, keeping the existing text exactly", async () => {
    const home = await tempHome();
    const path = join(home, ".codex", "config.toml");
    const original = '# my Codex settings\nmodel = "gpt-5"   # keep this comment\n\n[mcp_servers.other]\ncommand = "other"\n';
    await write(path, original);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "codex"));
    expect(step).toMatchObject({ kind: "file", format: "toml-append", status: "add" });
    expect((await applyRegistration(step, env)).outcome).toBe("registered");
    const text = await readFile(path, "utf8");
    expect(text).toBe(`${original}\n${CODEX_TOML_BLOCK}`);
    expect(CODEX_TOML_BLOCK).toBe('[mcp_servers.codeinspectus]\ncommand = "npx"\nargs = ["-y", "codeinspectus"]\ntool_timeout_sec = 600\n');
    const parsed = parseToml(text) as { mcp_servers: Record<string, unknown> };
    expect(parsed.mcp_servers.codeinspectus).toEqual({ command: "npx", args: ["-y", "codeinspectus"], tool_timeout_sec: 600 });
    expect(await readFile(`${path}.codeinspectus-backup`, "utf8")).toBe(original);

    const again = await planRegistration(await only(env, "codex"));
    expect(again.status).toBe("already");
    expect((await applyRegistration(again, env)).outcome).toBe("already");
    expect(await readFile(path, "utf8")).toBe(text);
  });

  test("a file without a final newline gets one before the block", async () => {
    const home = await tempHome();
    const path = join(home, ".codex", "config.toml");
    await write(path, 'model = "gpt-5"');
    const env = fakeEnv(home);
    await applyRegistration(await planRegistration(await only(env, "codex")), env);
    expect(await readFile(path, "utf8")).toBe(`model = "gpt-5"\n\n${CODEX_TOML_BLOCK}`);
  });

  test("absent file with `codex` on PATH: created with the block", async () => {
    const home = await tempHome();
    const env = fakeEnv(home, { onPath: ["codex"] });
    const step = await planRegistration(await only(env, "codex"));
    expect(step).toMatchObject({ status: "add", create: true });
    expect((await applyRegistration(step, env)).outcome).toBe("registered");
    expect(await readFile(join(home, ".codex", "config.toml"), "utf8")).toBe(CODEX_TOML_BLOCK);
    expect(env.runs).toEqual([]);
  });

  test("a different codeinspectus table is a conflict; an invalid file or an inline mcp_servers table is skipped", async () => {
    const cases: Array<[string, string]> = [
      ["conflict", '[mcp_servers.codeinspectus]\ncommand = "node"\nargs = ["/opt/ci.js"]\n'],
      ["unparseable", "model = \n"],
      ["unparseable", 'mcp_servers = { other = { command = "x" } }\n'],
    ];
    for (const [status, text] of cases) {
      const home = await tempHome();
      const path = join(home, ".codex", "config.toml");
      await write(path, text);
      const env = fakeEnv(home);
      const step = await planRegistration(await only(env, "codex"));
      expect(step.status, text).toBe(status);
      const outcome = await applyRegistration(step, env);
      expect(outcome.outcome).toBe(status === "conflict" ? "conflict" : "skipped");
      expect(await readFile(path, "utf8")).toBe(text);
      if (status === "unparseable") expect(outcome.detail).toContain("tool_timeout_sec = 600");
    }
  });
});

describe("client CLIs", () => {
  test("Claude Code runs exactly the add-json argv and never writes its config file", async () => {
    const home = await tempHome();
    const env = fakeEnv(home, { onPath: ["claude"] });
    const step = await planRegistration(await only(env, "claude"));
    expect(step).toMatchObject({ kind: "command", argv: CLAUDE_CODE_ARGV, status: "add" });
    expect((await applyRegistration(step, env)).outcome).toBe("registered");
    expect(env.runs).toEqual([CLAUDE_CODE_ARGV]);
    expect(await exists(join(home, ".claude.json"))).toBe(false);
  });

  test("Claude Code: an existing user-scope entry in ~/.claude.json is read, not rewritten, and the CLI is not run", async () => {
    const home = await tempHome();
    const same = '{"mcpServers":{"codeinspectus":{"type":"stdio","command":"npx","args":["-y","codeinspectus"],"env":{}}}}';
    await write(join(home, ".claude.json"), same);
    const env = fakeEnv(home, { onPath: ["claude"] });
    const step = await planRegistration(await only(env, "claude"));
    expect(step.status).toBe("already");
    expect((await applyRegistration(step, env)).outcome).toBe("already");

    await write(join(home, ".claude.json"), '{"mcpServers":{"codeinspectus":{"command":"node","args":["x.js"]}}}');
    const conflict = await planRegistration(await only(env, "claude"));
    expect(conflict.status).toBe("conflict");
    expect((await applyRegistration(conflict, env)).outcome).toBe("conflict");
    expect(env.runs).toEqual([]);
    expect(await readFile(join(home, ".claude.json"), "utf8")).toContain('"node"');
  });

  test("a failing client CLI is reported as failed with its error", async () => {
    const home = await tempHome();
    const env = fakeEnv(home, { onPath: ["claude", "code"], platform: "linux", run: () => ({ code: 1, stderr: "permission denied writing config\n" }) });
    for (const id of ["claude", "vscode"] as const) {
      const outcome = await applyRegistration(await planRegistration(await only(env, id)), env);
      expect(outcome.outcome).toBe("failed");
      expect(outcome.detail).toMatch(/exited with code 1.*permission denied/);
    }
    expect(env.runs).toEqual([CLAUDE_CODE_ARGV, VSCODE_ARGV]);
  });

  test("a CLI that cannot start is reported as failed", async () => {
    const home = await tempHome();
    const env: InitEnv = {
      ...fakeEnv(home, { onPath: ["claude"] }),
      run: async () => { throw new Error("spawn claude ENOENT"); },
    };
    const outcome = await applyRegistration(await planRegistration(await only(env, "claude")), env);
    expect(outcome).toMatchObject({ outcome: "failed" });
    expect(outcome.detail).toContain("ENOENT");
  });
});

describe("fix round 1: no file content in output", () => {
  const SECRET = "SECRETVALUE";

  test("a JSONC file holding a token never reaches the step or outcome text", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    await write(path, `{\n  "mcpServers": { "gh": { "command": "gh", "env": { "GITHUB_TOKEN":'ghp_${SECRET}123' } } }\n}\n`);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("unparseable");
    expect(step.detail).toContain("it is not plain JSON (comments, trailing commas or other syntax)");
    const outcome = await applyRegistration(step, env);
    expect(JSON.stringify([step, outcome])).not.toContain(SECRET);
  });

  test("a JSON syntax error reports at most a line and column", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    await write(join(home, ".cursor", "mcp.json"), `{"mcpServers":{"gh":{"env":{"T":"${SECRET}"}},}}`);
    const step = await planRegistration(await only(fakeEnv(home), "cursor"));
    expect(step.detail).toMatch(/plain JSON \(comments, trailing commas or other syntax\), at line 1, column \d+/);
    expect(step.detail).not.toContain(SECRET);
  });

  test("an invalid TOML file holding a token: only a line and column are reported", async () => {
    const home = await tempHome();
    await write(join(home, ".codex", "config.toml"), `[mcp_servers.gh.env]\nGITHUB_TOKEN = 'ghp_${SECRET}\n`);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "codex"));
    expect(step.status).toBe("unparseable");
    expect(step.detail).toMatch(/not valid TOML, at line \d+, column \d+/);
    expect(JSON.stringify([step, await applyRegistration(step, env)])).not.toContain(SECRET);
  });

  test("a conflicting entry's values are never printed", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    await write(join(home, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { codeinspectus: { command: "node", args: ["x"], env: { TOKEN: SECRET } } } }));
    await write(join(home, ".codex", "config.toml"), `[mcp_servers.codeinspectus]\ncommand = "node"\nenv = { TOKEN = "${SECRET}" }\n`);
    const env = fakeEnv(home);
    for (const id of ["cursor", "codex"] as const) {
      const step = await planRegistration(await only(env, id));
      expect(step.status).toBe("conflict");
      expect(JSON.stringify([step, await applyRegistration(step, env)])).not.toContain(SECRET);
    }
  });
});

describe("fix round 1: Claude Code", () => {
  test("CLAUDE_CONFIG_DIR moves the file read for the registration check", async () => {
    const home = await tempHome();
    const configDir = join(home, "claude-config");
    await write(join(configDir, ".claude.json"), JSON.stringify({ mcpServers: { codeinspectus: { command: "npx", args: ["-y", "codeinspectus"] } } }));
    const env: InitEnv = { ...fakeEnv(home, { onPath: ["claude"] }), claudeConfigDir: configDir };
    const client = await only(env, "claude");
    expect(client.route).toMatchObject({ check: { path: join(configDir, ".claude.json") } });
    expect((await planRegistration(client)).status).toBe("already");
  });

  test("a .claude.json over 50 MiB is not read: the status is unknown and the CLI decides", async () => {
    const home = await tempHome();
    const path = join(home, ".claude.json");
    // Valid JSON holding the identical entry: read, it would be "already"; over the cap it must stay unknown.
    const entry = JSON.stringify({ mcpServers: { codeinspectus: { command: "npx", args: ["-y", "codeinspectus"] } } });
    await write(path, `${entry}${" ".repeat(51 * 1024 * 1024)}`);
    const step = await planRegistration(await only(fakeEnv(home, { onPath: ["claude"] }), "claude"));
    expect(step.status).toBe("add");
  });

  test("the CLI saying the server already exists, unconfirmed by the read-only check, is a conflict, never already", async () => {
    const home = await tempHome();
    const env = fakeEnv(home, { onPath: ["claude"], run: () => ({ code: 1, stderr: "MCP server codeinspectus already exists in user config\n" }) });
    const outcome = await applyRegistration(await planRegistration(await only(env, "claude")), env);
    expect(outcome).toMatchObject({
      outcome: "conflict",
      detail: "an entry named codeinspectus already exists in Claude Code; it was not changed (check it with `claude mcp get codeinspectus`)",
    });
  });

  test("native Windows registers the npx server through cmd /c, and either form counts as already registered", async () => {
    const home = await tempHome();
    const env = fakeEnv(home, { onPath: ["claude"], platform: "win32", appData: join(home, "AppData", "Roaming") });
    const client = await only(env, "claude");
    expect(client.route).toMatchObject({ argv: CLAUDE_CODE_ARGV_WIN32 });
    expect(CLAUDE_CODE_ARGV_WIN32).toEqual([
      "claude", "mcp", "add-json", "--scope", "user", "codeinspectus", '{"command":"cmd","args":["/c","npx","-y","codeinspectus"]}',
    ]);
    for (const entry of [{ command: "cmd", args: ["/c", "npx", "-y", "codeinspectus"] }, { command: "npx", args: ["-y", "codeinspectus"] }]) {
      await write(join(home, ".claude.json"), JSON.stringify({ mcpServers: { codeinspectus: entry } }));
      expect((await planRegistration(client)).status).toBe("already");
    }
  });
});

describe("fix round 1: writes", () => {
  test("a file that changes just before the rename is not written", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    await write(path, "{}");
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    const outcome = await applyRegistration(step, env, { beforeCommit: async () => write(path, '{"mcpServers":{"other":{"command":"o"}}}') });
    expect(outcome.outcome).toBe("skipped");
    expect(outcome.detail).toMatch(/the file changed while init was running; run init again/);
    expect(outcome.backup).toBeUndefined();
    expect(await exists(`${path}.codeinspectus-backup`)).toBe(false); // a skipped file gets no backup
    expect(await readFile(path, "utf8")).toBe('{"mcpServers":{"other":{"command":"o"}}}');
    const { readdir } = await import("node:fs/promises");
    expect((await readdir(join(home, ".cursor"))).filter((name) => name.includes("tmp"))).toEqual([]);
  });

  test("a Codex file that gains the block just before the append is not appended again", async () => {
    const home = await tempHome();
    const path = join(home, ".codex", "config.toml");
    await write(path, 'model = "x"\n');
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "codex"));
    const outcome = await applyRegistration(step, env, { beforeCommit: async () => write(path, `model = "x"\n\n${CODEX_TOML_BLOCK}`) });
    expect(outcome.outcome).toBe("skipped");
    expect((await readFile(path, "utf8")).match(/\[mcp_servers\.codeinspectus\]/g)).toHaveLength(1);
  });

  test("a file created by someone else just before init creates it is not overwritten", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    const outcome = await applyRegistration(step, env, { beforeCommit: async () => write(path, '{"theirs":true}') });
    expect(outcome.outcome).toBe("skipped");
    expect(await readFile(path, "utf8")).toBe('{"theirs":true}');
  });

  test("apply honours the planned status: a file planned unparseable or conflicting is never written, even if fixed since", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    const env = fakeEnv(home);
    await write(path, "{ // mine\n}");
    const unparseable = await planRegistration(await only(env, "cursor"));
    await write(path, "{}");
    expect((await applyRegistration(unparseable, env)).outcome).toBe("skipped");
    expect(await readFile(path, "utf8")).toBe("{}");

    await write(path, '{"mcpServers":{"codeinspectus":{"command":"node"}}}');
    const conflict = await planRegistration(await only(env, "cursor"));
    await write(path, "{}");
    expect((await applyRegistration(conflict, env)).outcome).toBe("conflict");
    expect(await readFile(path, "utf8")).toBe("{}");
  });

  test("a config path that cannot be read (a directory) is skipped, not failed", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor", "mcp.json"), { recursive: true });
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("unparseable");
    expect(step.detail).toMatch(/could not be read \(EISDIR\)/);
    expect((await applyRegistration(step, env)).outcome).toBe("skipped");
  });

  test("CRLF line endings are kept for JSON and TOML", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const json = join(home, ".cursor", "mcp.json");
    await write(json, '{\r\n  "mcpServers": {\r\n    "a": { "command": "a" }\r\n  }\r\n}\r\n');
    const toml = join(home, ".codex", "config.toml");
    await write(toml, 'model = "x"\r\n');
    const env = fakeEnv(home);
    for (const id of ["cursor", "codex"] as const) {
      expect((await applyRegistration(await planRegistration(await only(env, id)), env)).outcome).toBe("registered");
    }
    for (const path of [json, toml]) {
      const text = await readFile(path, "utf8");
      expect(text.replace(/\r\n/g, "")).not.toContain("\n");
      expect(text.endsWith("\r\n")).toBe(true);
    }
    expect(await readFile(toml, "utf8")).toBe(`model = "x"\r\n\r\n${CODEX_TOML_BLOCK.replace(/\n/g, "\r\n")}`);
  });

  test.each([
    ["an integer above 2^53", '{"id": 12345678901234567890, "mcpServers": {}}'],
    ["a number written differently once re-serialised", '{"ratio": 1.0, "mcpServers": {}}'],
    ["a duplicate key", '{"a": 1, "a": 2, "mcpServers": {}}'],
    ["a duplicate server key", '{"mcpServers": {"x": {"command": "a"}, "x": {"command": "b"}}}'],
  ])("a JSON file with %s is skipped with the manual step", async (_label, text) => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    await write(path, text);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("unparseable");
    expect((await applyRegistration(step, env)).outcome).toBe("skipped");
    expect(await readFile(path, "utf8")).toBe(text);
  });

  test.skipIf(process.platform === "win32")("a dangling symlink is skipped, never replaced by a regular file", async () => {
    const home = await tempHome();
    await mkdir(join(home, ".cursor"));
    const path = join(home, ".cursor", "mcp.json");
    await symlink(join(home, "missing", "mcp.json"), path);
    const env = fakeEnv(home);
    const step = await planRegistration(await only(env, "cursor"));
    expect(step.status).toBe("unparseable");
    expect(step.detail).toMatch(/symbolic link to a missing file/);
    expect((await applyRegistration(step, env)).outcome).toBe("skipped");
    expect((await lstat(path)).isSymbolicLink()).toBe(true);
  });
});
