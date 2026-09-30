/**
 * Git-sourced, custom-hosted, path and SDK Pub packages are not pub.dev packages. A Trivy advisory
 * for a pub.dev package with the same name is a name collision, not a finding (corpus contract).
 */
import { resolve } from "node:path";
import { describe, expect, test } from "vitest";
import { runScan } from "../scan.js";

describe("Trivy Pub advisories respect native Pub source exclusions", () => {
  test("no Trivy finding is reported for a git-sourced or custom-hosted Pub package", async () => {
    const result = await runScan({ path: resolve(process.cwd(), "fixtures/pub-sca-corpus/tp"), scanners: ["vuln"] });
    if (!result.engine_details.some((engine) => engine.engine === "trivy" && engine.ran)) return; // Trivy not installed

    const collisions = result.findings.filter((finding) =>
      finding.engines.includes("trivy") && /^Package: (dio|http)\n/.test(finding.message));

    expect(collisions).toEqual([]);
    expect(result.warnings.join(" ")).toMatch(/name collision/i);
  }, 120_000);
});
