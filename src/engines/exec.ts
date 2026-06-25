/**
 * Subprocess runner for engine binaries.
 *
 * - stdout/stderr captured (engines write SARIF to files, not stdout, but we
 *   still capture for diagnostics).
 * - Hard timeout + maxBuffer to bound resource use.
 * - Never inherits stdout of THIS process (would risk JSON-RPC pollution): the
 *   child's streams are piped and captured, never forwarded to our stdout.
 */

import { spawn } from "node:child_process";
import { ENGINE_TIMEOUT_MS, MAX_BUFFER_BYTES } from "../config.js";
import { log } from "../logger.js";

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface ExecOptions {
  cwd?: string;
  timeoutMs?: number;
  /** Extra env on top of a minimal inherited set. */
  env?: Record<string, string>;
  /** When true, attempt to neutralize network env (defense in depth, PRD §7.4). */
  offline?: boolean;
}

export async function execBinary(
  binPath: string,
  args: string[],
  opts: ExecOptions = {},
): Promise<ExecResult> {
  const timeoutMs = opts.timeoutMs ?? ENGINE_TIMEOUT_MS;

  // Build a clean env. For offline mode we blank common proxy vars and set a
  // dummy NO_PROXY; engines are already invoked with their own offline flags.
  const baseEnv: Record<string, string> = { ...process.env } as Record<string, string>;
  if (opts.offline) {
    baseEnv.HTTP_PROXY = "";
    baseEnv.HTTPS_PROXY = "";
    baseEnv.http_proxy = "";
    baseEnv.https_proxy = "";
    baseEnv.NO_PROXY = "*";
    baseEnv.no_proxy = "*";
  }
  const env = { ...baseEnv, ...(opts.env ?? {}) };

  return await new Promise<ExecResult>((resolve) => {
    log.debug(`exec: ${binPath} ${args.join(" ")}`);
    const child = spawn(binPath, args, {
      cwd: opts.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (d: Buffer) => {
      stdoutBytes += d.length;
      if (stdoutBytes <= MAX_BUFFER_BYTES) stdout += d.toString();
    });
    child.stderr.on("data", (d: Buffer) => {
      stderrBytes += d.length;
      if (stderrBytes <= MAX_BUFFER_BYTES) stderr += d.toString();
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ code: null, stdout, stderr: stderr + `\n[spawn error] ${err.message}`, timedOut });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });
  });
}
