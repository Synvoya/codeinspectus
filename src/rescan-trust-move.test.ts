/**
 * Moving a file that contains a hidden-Unicode marker into an excluded directory must not be
 * reported as fixing it.
 */
import { describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rename, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runScan } from "./scan.js";
import { runRescan } from "./rescan.js";

describe("repository-trust rescan after a move", () => {
  test.each([["into vendor/", "vendor/auth.js"], ["to a .cjs file", "src/auth.cjs"]])("moving the file %s is not reported resolved", async (_label, destination) => {
    const dir = await mkdtemp(join(tmpdir(), "ci-trust-move-"));
    await mkdir(join(dir, "src"), { recursive: true });
    await mkdir(join(dir, "vendor"), { recursive: true });
    await writeFile(join(dir, "src", "other.js"), "export const other = true;\n");
    await writeFile(join(dir, "src", "auth.js"), "const isAdmin = false; /* ‮ } ⁦if (isAdmin)⁩ ⁦ begin admins only */\n");
    const prior = await runScan({ path: dir, scanners: ["ai"] });
    expect(prior.repository_trust.artifacts.length).toBeGreaterThan(0);

    await rename(join(dir, "src", "auth.js"), join(dir, destination));
    const rescan = await runRescan({ path: dir, prior_scan_id: prior.scan_id, scanners: ["ai"] });

    expect(rescan.repository_trust_changes.summary.resolved).toBe(0);
  });

  test("a single-file target still confirms a fixed marker", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ci-trust-file-"));
    const file = join(dir, "app.ts");
    await writeFile(file, "const user\u200Bname = 1;\n");
    const prior = await runScan({ path: file, scanners: ["ai"] });
    expect(prior.repository_trust.artifacts.length).toBeGreaterThan(0);

    await writeFile(file, "const username = 1;\n");
    const rescan = await runRescan({ path: file, prior_scan_id: prior.scan_id, scanners: ["ai"] });

    expect(rescan.repository_trust_changes.summary).toMatchObject({ resolved: 1, not_rechecked: 0 });
  });
});
