import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "vitest";

import { quoteWindows, runCommand } from "./run.js";

describe("quoteWindows", () => {
  test.each([
    ["plain", '"plain"'],
    ["two words", '"two words"'],
    ['{"command":"npx","args":["-y","codeinspectus"]}', '"{\\"command\\":\\"npx\\",\\"args\\":[\\"-y\\",\\"codeinspectus\\"]}"'],
    ["C:\\Program Files\\", '"C:\\Program Files\\\\"'],
    ['a\\"b', '"a\\\\\\"b"'],
    ["", '""'],
  ])("%j -> %j", (input, expected) => {
    expect(quoteWindows(input)).toBe(expected);
  });
});

const directories: string[] = [];
afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe.skipIf(process.platform === "win32")("runCommand (POSIX)", () => {
  async function script(body: string): Promise<{ path: string; log: string }> {
    const directory = await mkdtemp(join(tmpdir(), "codeinspectus-run-"));
    directories.push(directory);
    const path = join(directory, "fake-client");
    const log = join(directory, "argv.log");
    await writeFile(path, `#!/bin/sh\nfor a in "$@"; do printf '%s\\n' "$a" >> '${log}'; done\n${body}\n`, "utf8");
    await chmod(path, 0o755);
    return { path, log };
  }

  test("passes every argument intact, including JSON with quotes and spaces", async () => {
    const { path, log } = await script("exit 0");
    const args = ["mcp", "add-json", "--scope", "user", "codeinspectus", '{"command":"npx","args":["-y","codeinspectus"]}', "two words", "$HOME", "it's"];
    expect(await runCommand([path, ...args])).toEqual({ code: 0, stderr: "", stdout: "" });
    expect((await readFile(log, "utf8")).split("\n").slice(0, -1)).toEqual(args);
  });

  test("returns a non-zero exit code with stderr and stdout", async () => {
    const { path } = await script('echo "to stdout"\necho "MCP server codeinspectus already exists" >&2\nexit 7');
    expect(await runCommand([path])).toEqual({ code: 7, stderr: "MCP server codeinspectus already exists\n", stdout: "to stdout\n" });
  });

  test("a missing command rejects", async () => {
    await expect(runCommand(["/definitely/not/a/command"])).rejects.toThrow(/ENOENT/);
  });
});
