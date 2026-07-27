import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let trivyMode: "unavailable" | "cyclonedx" | "spdx" | "malformed" = "unavailable";

vi.mock("../engines/trivy.js", () => ({
  runTrivySbom: vi.fn(async (_target: string, format: "cyclonedx" | "spdx", outputPath: string) => {
    if (trivyMode === "unavailable") {
      return { ran: false, version: "unknown", note: "test fixture: Trivy unavailable" };
    }
    const document = trivyMode === "malformed"
      ? {}
      : format === "cyclonedx"
      ? {
          bomFormat: "CycloneDX",
          specVersion: "1.7",
          serialNumber: "urn:uuid:trivy-test",
          version: 1,
          components: [
            { type: "library", name: "archive", version: "3.3.8", purl: "pkg:pub/archive@3.3.8" },
            { type: "library", name: "left-pad", version: "1.3.0", purl: "pkg:npm/left-pad@1.3.0" },
          ],
        }
      : {
          spdxVersion: "SPDX-2.3",
          dataLicense: "CC0-1.0",
          SPDXID: "SPDXRef-DOCUMENT",
          name: "Trivy test",
          documentNamespace: "https://example.test/trivy/test",
          creationInfo: { created: "2026-07-26T00:00:00Z", creators: ["Tool: Trivy"] },
          packages: [],
        };
    return { ran: true, version: "0.71.2", content: JSON.stringify(document) };
  }),
}));

const { generateSbom } = await import("../sbom.js");
const { sbomOutput } = await import("../schemas.js");

const CORPUS = resolve(process.cwd(), "fixtures/pub-sca-corpus");
const roots: string[] = [];

beforeEach(() => {
  trivyMode = "unavailable";
});
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function output(format: "cyclonedx" | "spdx"): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "ci-pub-sbom-"));
  roots.push(root);
  return join(root, `${format}.json`);
}

describe("native Pub SBOM integration", () => {
  it("generates a CycloneDX Pub inventory when Trivy is unavailable", async () => {
    const outputPath = await output("cyclonedx");
    const result = await generateSbom({
      path: resolve(CORPUS, "tp"),
      format: "cyclonedx",
      output_path: outputPath,
    });
    expect(sbomOutput.parse(result)).toEqual(result);
    expect(result).toMatchObject({
      generated: true,
      offline: true,
      providers: ["codeinspectus-pub"],
      ecosystems: ["Pub"],
      coverage_state: "native_only",
      lockfiles_analyzed: 1,
      component_count: 5,
    });
    const document = JSON.parse(await readFile(outputPath, "utf8"));
    expect(document).toMatchObject({ bomFormat: "CycloneDX", specVersion: "1.6" });
    expect(document.components).toHaveLength(5);
  });

  it("generates SPDX with encoded Pub purls using native fallback", async () => {
    const outputPath = await output("spdx");
    const result = await generateSbom({
      path: resolve(CORPUS, "fixed"),
      format: "spdx",
      output_path: outputPath,
    });
    expect(result).toMatchObject({ generated: true, coverage_state: "native_only", component_count: 5 });
    const document = JSON.parse(await readFile(outputPath, "utf8"));
    expect(document.spdxVersion).toBe("SPDX-2.3");
    const jose = document.packages.find((pkg: any) => pkg.name === "jose");
    expect(jose.externalRefs[0].referenceLocator).toBe("pkg:pub/jose@0.3.5%2B1");
  });

  it("merges native Pub metadata into Trivy without deleting its components or serial", async () => {
    trivyMode = "cyclonedx";
    const outputPath = await output("cyclonedx");
    const result = await generateSbom({
      path: resolve(CORPUS, "fixed"),
      format: "cyclonedx",
      output_path: outputPath,
    });
    expect(result).toMatchObject({
      generated: true,
      providers: ["trivy", "codeinspectus-pub"],
      coverage_state: "combined",
      component_count: 6,
      ecosystems: ["Pub", "npm"],
    });
    const document = JSON.parse(await readFile(outputPath, "utf8"));
    expect(document.serialNumber).toBe("urn:uuid:trivy-test");
    expect(document.specVersion).toBe("1.7");
    expect(document.components.some((component: any) => component.purl === "pkg:npm/left-pad@1.3.0"))
      .toBe(true);
    expect(document.components.filter((component: any) => component.purl === "pkg:pub/archive@3.3.8"))
      .toHaveLength(1);
  });

  it("returns unavailable when neither provider can produce an inventory", async () => {
    const target = await mkdtemp(join(tmpdir(), "ci-no-lock-"));
    roots.push(target);
    await writeFile(join(target, "app.txt"), "no dependencies\n", "utf8");
    const result = await generateSbom({ path: target, output_path: await output("cyclonedx") });
    expect(result).toMatchObject({
      generated: false,
      providers: [],
      coverage_state: "unavailable",
      component_count: 0,
      lockfiles_analyzed: 0,
    });
  });

  it("rejects malformed Trivy JSON objects instead of claiming a generated artifact", async () => {
    trivyMode = "malformed";
    const target = await mkdtemp(join(tmpdir(), "ci-malformed-trivy-"));
    roots.push(target);
    await writeFile(join(target, "app.txt"), "no dependencies\n", "utf8");
    const result = await generateSbom({ path: target, output_path: await output("cyclonedx") });
    expect(result).toMatchObject({
      generated: false,
      providers: [],
      coverage_state: "unavailable",
      component_count: 0,
    });
    expect(result.limitations.join(" ")).toMatch(/missing required format metadata/i);
  });

  it("falls back to a valid native Pub artifact when Trivy returns a malformed object", async () => {
    trivyMode = "malformed";
    const outputPath = await output("spdx");
    const result = await generateSbom({
      path: resolve(CORPUS, "fixed"),
      format: "spdx",
      output_path: outputPath,
    });
    expect(result).toMatchObject({
      generated: true,
      providers: ["codeinspectus-pub"],
      ecosystems: ["Pub"],
      coverage_state: "native_only",
    });
    const document = JSON.parse(await readFile(outputPath, "utf8"));
    expect(document.spdxVersion).toBe("SPDX-2.3");
  });

  it("discloses a skipped symbolic-link Pub lockfile when Trivy supplies the artifact", async () => {
    trivyMode = "cyclonedx";
    const target = await mkdtemp(join(tmpdir(), "ci-symlink-lock-"));
    roots.push(target);
    const real = join(target, "actual.lock");
    await writeFile(real, "packages: {}\n", "utf8");
    await symlink(real, join(target, "pubspec.lock"));

    const result = await generateSbom({
      path: target,
      format: "cyclonedx",
      output_path: await output("cyclonedx"),
    });

    expect(result).toMatchObject({
      generated: true,
      providers: ["trivy"],
      ecosystems: ["Pub", "npm"],
      coverage_state: "trivy_only",
      lockfiles_analyzed: 0,
    });
    expect(result.limitations.join(" ")).toMatch(/symbolic-link Pub lockfile/i);
    expect(result.limitations.join(" ")).not.toMatch(/resolved inventory/i);
  });
});
