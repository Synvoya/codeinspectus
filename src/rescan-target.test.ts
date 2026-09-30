/**
 * A rescan is evidence that findings were fixed, so it must compare like with like: the prior
 * scan must be of the same canonical target. Findings from another repository must never be
 * reported as "resolved".
 */
import { describe, expect, test } from "vitest";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runScan } from "./scan.js";
import { runRescan } from "./rescan.js";

// Deliberately vulnerable fixture (LLM output rendered as raw HTML); assembled at runtime.
const RAW_HTML_PROP = ["dangerously", "SetInnerHTML"].join("");

async function project(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ci-rescan-target-"));
  await writeFile(join(dir, "Chat.tsx"),
    `export function Chat({ reply }: { reply: string }) {\n  return <div ${RAW_HTML_PROP}={{ __html: reply }} />;\n}\n`);
  return dir;
}

describe("rescan target identity", () => {
  test("refuses a prior scan_id that belongs to a different target", async () => {
    const first = await project();
    const other = await mkdtemp(join(tmpdir(), "ci-rescan-other-"));
    const prior = await runScan({ path: first, scanners: ["ai"] });

    await expect(runRescan({ path: other, prior_scan_id: prior.scan_id, scanners: ["ai"] })).rejects.toThrow(/different target/i);
  });

  test("finds the latest prior scan through a trailing-slash path", async () => {
    const dir = await project();
    await runScan({ path: dir, scanners: ["ai"] });

    const rescan = await runRescan({ path: `${dir}/`, scanners: ["ai"] });

    expect(rescan.summary.resolved).toBe(0);
  });
});
