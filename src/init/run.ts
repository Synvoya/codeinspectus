/**
 * The real InitEnv for `codeinspectus init`: PATH lookup and a client-CLI runner. Tests inject fakes instead
 * (see InitEnv); this module is exercised directly only against temp scripts.
 */

import { spawn } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { access, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { delimiter, join } from "node:path";

import type { InitEnv } from "./clients.js";

const OUTPUT_LIMIT = 64 * 1024;
const TIMEOUT_MS = 120_000;

/** PATH lookup without running anything (PATHEXT on Windows). */
export async function which(command: string): Promise<string | undefined> {
  const extensions = process.platform === "win32"
    ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean)
    : [""];
  for (const directory of (process.env.PATH ?? "").split(delimiter).filter(Boolean)) {
    for (const extension of extensions) {
      const candidate = join(directory, `${command}${extension}`);
      try {
        const info = await stat(candidate);
        if (!info.isFile()) continue;
        if (process.platform !== "win32") await access(candidate, fsConstants.X_OK);
        return candidate;
      } catch {
        // not here
      }
    }
  }
  return undefined;
}

/** MSVCRT-style quoting of one argument, for a .cmd/.bat shim run through cmd.exe. */
export function quoteWindows(arg: string): string {
  return `"${arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, "$1$1")}"`;
}

/** Run a client CLI found on PATH (no shell, except cmd.exe for a Windows .cmd/.bat shim). */
export async function runCommand(argv: readonly string[]): Promise<{ code: number; stderr: string; stdout: string }> {
  const [command, ...args] = argv;
  if (!command) throw new Error("empty command");
  const resolved = (await which(command)) ?? command;
  const shim = process.platform === "win32" && /\.(cmd|bat)$/i.test(resolved);
  return new Promise((resolvePromise, reject) => {
    const child = shim
      ? spawn([resolved, ...args].map(quoteWindows).join(" "), { shell: true, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] })
      : spawn(resolved, args, { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill(), TIMEOUT_MS);
    child.stdout?.setEncoding("utf8");
    child.stderr?.setEncoding("utf8");
    child.stdout?.on("data", (chunk: string) => {
      if (stdout.length < OUTPUT_LIMIT) stdout += chunk;
    });
    child.stderr?.on("data", (chunk: string) => {
      if (stderr.length < OUTPUT_LIMIT) stderr += chunk;
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolvePromise({ code: code ?? (signal ? 1 : 0), stderr, stdout });
    });
  });
}

export function defaultInitEnv(): InitEnv {
  return {
    home: homedir(),
    platform: process.platform,
    ...(process.env.APPDATA ? { appData: process.env.APPDATA } : {}),
    ...(process.env.CLAUDE_CONFIG_DIR ? { claudeConfigDir: process.env.CLAUDE_CONFIG_DIR } : {}),
    which,
    run: runCommand,
  };
}
