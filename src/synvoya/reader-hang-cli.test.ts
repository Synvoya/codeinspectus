/**
 * M6 fix round 1, ruling 5: with the Synvoya readers running alone in front of the scan, nothing else keeps the
 * process alive. A reader that awaits a promise which never settles must still end in the declared partial
 * state at the hard cap, never in a silent exit. Run through the real CLI, in a child process, with an empty
 * HOME (no engines) and the verification-only switches.
 */
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, describe, expect, test } from "vitest";

import { INTERNAL_SYNVOYA_DEADLINE_ENV, INTERNAL_SYNVOYA_HANG_READER_ENV } from "./constants.js";

const execFileP = promisify(execFile);
const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("a hung Synvoya reader in a real CLI scan", () => {
  test("ends at the hard cap with the reader named, not in a silent exit", async () => {
    const home = await mkdtemp(join(tmpdir(), "ci-hang-home-"));
    const target = await mkdtemp(join(tmpdir(), "ci-hang-target-"));
    roots.push(home, target);
    await writeFile(join(target, ".nvmrc"), "20.1.0\n", "utf8");
    let stdout = "";
    try {
      ({ stdout } = await execFileP(process.execPath, ["--import", "tsx", "src/index.ts", "scan", target, "--scanner", "vuln", "--format", "json"], {
        timeout: 60_000,
        maxBuffer: 64 * 1024 * 1024,
        env: {
          ...process.env,
          HOME: home,
          USERPROFILE: home,
          CG_LOG_LEVEL: "silent",
          CODEINSPECTUS_INTERNAL_DISABLE_SCAN_PERSISTENCE: "1",
          [INTERNAL_SYNVOYA_DEADLINE_ENV]: "0",
          [INTERNAL_SYNVOYA_HANG_READER_ENV]: "library",
        },
      }));
    } catch (error) {
      // A partial scan may exit non-zero; its report is still on stdout.
      stdout = (error as { stdout?: string }).stdout ?? "";
    }
    expect(stdout).toContain("Readers that did not finish:");
    expect(stdout).toContain("library (still running at the hard cap)");
  }, 90_000);
});
