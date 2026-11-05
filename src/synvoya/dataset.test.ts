import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { ParsedSynvoyaAdvisory, SynvoyaAdvisory, SynvoyaDataset } from "./dataset.js";

import { SYNVOYA_DATASET_DIR, loadSynvoyaDataset } from "./dataset.js";
import { sha256Hex } from "../util/hash.js";

const run = promisify(execFile);
const MANIFEST_SCRIPT = join(process.cwd(), "scripts", "synvoya-manifest.mjs");

let work: string;

beforeEach(async () => {
  work = await mkdtemp(join(tmpdir(), "ci-synvoya-"));
  await cp(SYNVOYA_DATASET_DIR, work, { recursive: true });
});

afterEach(async () => {
  await rm(work, { recursive: true, force: true });
});

/** Rewrite one dataset file and refresh its manifest digest so only the schema can reject it. */
async function replaceFile(name: string, content: string | Buffer): Promise<void> {
  await writeFile(join(work, name), content);
  const manifestPath = join(work, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as { files: Record<string, string> };
  manifest.files[name] = `sha256:${sha256Hex(content)}`;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

async function mutateAdvisories(
  mutate: (advisories: Array<Record<string, unknown>>) => void,
): Promise<void> {
  const file = JSON.parse(await readFile(join(work, "advisories.json"), "utf8")) as {
    advisories: Array<Record<string, unknown>>;
  };
  mutate(file.advisories);
  await replaceFile("advisories.json", `${JSON.stringify(file, null, 2)}\n`);
}

describe("Synvoya dataset loader", () => {
  it("loads the shipped dataset and every file matches the manifest digest", async () => {
    const manifest = JSON.parse(await readFile(join(SYNVOYA_DATASET_DIR, "manifest.json"), "utf8")) as {
      files: Record<string, string>;
    };
    for (const [name, digest] of Object.entries(manifest.files)) {
      const bytes = await readFile(join(SYNVOYA_DATASET_DIR, name));
      expect(`sha256:${sha256Hex(bytes)}`, name).toBe(digest);
    }
    const loaded = await loadSynvoyaDataset();
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) return;
    expect(loaded.dataset.version).toMatch(/^\d{4}\.\d{2}\.\d{2}\.\d+$/);
    // The seeded dataset (contents are checked in seed.test.ts): every kind, verified and provisional entries.
    expect(loaded.dataset.advisories.length).toBeGreaterThan(250);
    expect(new Set(loaded.dataset.advisories.map((advisory) => advisory.kind))).toEqual(
      new Set(["vulnerability", "malware", "runtime", "eol", "product", "config"]),
    );
    expect(loaded.dataset.advisories.some((advisory) => advisory.provisional)).toBe(true);
    expect(loaded.dataset.advisories.some((advisory) => !advisory.provisional)).toBe(true);
    expect(loaded.dataset.eol.length).toBeGreaterThan(100);
    expect(Object.keys(loaded.dataset.imageAliases).length).toBeGreaterThan(0);
    expect(Object.keys(loaded.dataset.productImages).length).toBeGreaterThan(0);
    // The locked Magento Open Source packages are checked under the name GitHub advisories use (M2 Task 3).
    expect(loaded.dataset.aliases).toEqual({
      "Packagist:magento/magento2-base": "Packagist:magento/community-edition",
      "Packagist:magento/product-community-edition": "Packagist:magento/community-edition",
    });
  });

  it("returns the manifest digest, which changes whenever any dataset file changes", async () => {
    const shipped = await loadSynvoyaDataset();
    expect(shipped.ok).toBe(true);
    if (!shipped.ok) return;
    const manifestBytes = await readFile(join(SYNVOYA_DATASET_DIR, "manifest.json"));
    expect(shipped.digest).toBe(`sha256:${sha256Hex(manifestBytes)}`);

    await mutateAdvisories((advisories) => {
      advisories[0]!.title = "Changed title";
    });
    const changed = await loadSynvoyaDataset(work);
    expect(changed.ok).toBe(true);
    if (!changed.ok) return;
    expect(changed.digest).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(changed.digest).not.toBe(shipped.digest);
  });

  it("accepts requires: M2 or platform-detection and rejects any other requires value", async () => {
    for (const requires of ["M2", "platform-detection"] as const) {
      await mutateAdvisories((advisories) => {
        advisories[0]!.requires = requires;
      });
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok, requires).toBe(true);
      if (loaded.ok) expect(loaded.dataset.advisories[0]!.requires).toBe(requires);
    }

    await mutateAdvisories((advisories) => {
      advisories[0]!.requires = "M3";
    });
    expect((await loadSynvoyaDataset(work)).ok).toBe(false);
  });

  it("a file whose SHA-256 differs from manifest.json returns ok:false naming the file", async () => {
    const original = await readFile(join(work, "eol.json"), "utf8");
    await writeFile(join(work, "eol.json"), `${original}\n`);
    const loaded = await loadSynvoyaDataset(work);
    expect(loaded.ok).toBe(false);
    if (loaded.ok) return;
    expect(loaded.reason).toContain("eol.json");
    expect(loaded.reason).toContain("SHA-256");
  });

  it("a missing file or manifest returns ok:false instead of throwing", async () => {
    await rm(join(work, "aliases.json"));
    const missingFile = await loadSynvoyaDataset(work);
    expect(missingFile.ok).toBe(false);
    if (!missingFile.ok) expect(missingFile.reason).toContain("aliases.json");

    await rm(join(work, "manifest.json"));
    const missingManifest = await loadSynvoyaDataset(work);
    expect(missingManifest.ok).toBe(false);
    if (!missingManifest.ok) expect(missingManifest.reason).toContain("manifest.json");
  });

  it("a file over 8 MiB returns ok:false", async () => {
    await replaceFile("aliases.json", Buffer.alloc(8 * 1024 * 1024 + 1, 0x20));
    const loaded = await loadSynvoyaDataset(work);
    expect(loaded.ok).toBe(false);
    if (loaded.ok) return;
    expect(loaded.reason).toContain("aliases.json");
    expect(loaded.reason).toContain("8 MiB");
  });

  it("invalid JSON with a matching digest returns ok:false", async () => {
    await replaceFile("eol.json", "{not json");
    const loaded = await loadSynvoyaDataset(work);
    expect(loaded).toMatchObject({ ok: false });
    if (!loaded.ok) expect(loaded.reason).toContain("eol.json");
  });

  describe("schema", () => {
    it("rejects a duplicate advisory id", async () => {
      await mutateAdvisories((advisories) => {
        advisories[1]!.id = advisories[0]!.id;
      });
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) expect(loaded.reason).toContain("Duplicate advisory id");
    });

    it("rejects an unknown kind", async () => {
      await mutateAdvisories((advisories) => {
        advisories[0]!.kind = "rootkit";
      });
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) {
        expect(loaded.reason).toContain("advisories.json");
        expect(loaded.reason).toMatch(/kind/);
      }
    });

    it("rejects an OSV event with two boundaries", async () => {
      await mutateAdvisories((advisories) => {
        advisories[0]!.affected = [{ line: "20", events: [{ introduced: "20.0.0", fixed: "20.18.1" }] }];
      });
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) expect(loaded.reason).toContain("exactly one boundary");
    });

    it("rejects a non-https source", async () => {
      await mutateAdvisories((advisories) => {
        advisories[0]!.sources = ["http://nodejs.org/en/blog/vulnerability/"];
      });
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) {
        expect(loaded.reason).toContain("advisories.json");
        expect(loaded.reason).toContain("https://");
      }
    });

    it("rejects an unknown field (strict)", async () => {
      await mutateAdvisories((advisories) => {
        advisories[0]!.surprise = true;
      });
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) expect(loaded.reason).toMatch(/Unrecognized key/);
    });

    it("rejects a non-provisional entry without fixed versions unless kind is eol or malware", async () => {
      await mutateAdvisories((advisories) => {
        const runtime = advisories.find((advisory) => advisory.kind === "runtime")!;
        runtime.provisional = false;
        runtime.fixed = [];
      });
      const rejected = await loadSynvoyaDataset(work);
      expect(rejected.ok).toBe(false);
      if (!rejected.ok) expect(rejected.reason).toContain("fixed version");

      // The same shape is allowed for an eol entry.
      await mutateAdvisories((advisories) => {
        const runtime = advisories.find((advisory) => advisory.kind === "runtime")!;
        runtime.provisional = true;
        const eol = advisories.find((advisory) => advisory.kind === "eol")!;
        eol.provisional = false;
        eol.fixed = [];
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(true);
    });
    it("accepts no_fix_available only on an entry with an empty fixed list", async () => {
      await mutateAdvisories((advisories) => {
        const runtime = advisories.find((advisory) => advisory.kind === "runtime")!;
        runtime.provisional = false;
        runtime.fixed = [];
        runtime.no_fix_available = true;
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(true);

      await mutateAdvisories((advisories) => {
        const runtime = advisories.find((advisory) => advisory.no_fix_available === true)!;
        runtime.fixed = ["1.0.0"];
      });
      const both = await loadSynvoyaDataset(work);
      expect(both.ok).toBe(false);
      if (!both.ok) expect(both.reason).toContain("no_fix_available");

      await mutateAdvisories((advisories) => {
        advisories.find((advisory) => advisory.no_fix_available === true)!.no_fix_available = false;
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(false);
    });

    it("lets a verify-hotfix product entry or a config entry ship without fixed versions", async () => {
      await mutateAdvisories((advisories) => {
        const runtime = advisories.find((advisory) => advisory.kind === "runtime")!;
        runtime.provisional = false;
        runtime.fixed = [];
        runtime.kind = "config";
        const product = advisories.find((advisory) => advisory.kind === "product")!;
        product.provisional = false;
        product.fixed = [];
        product.product_rule = "verify-hotfix";
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(true);
    });

    it("rejects product_rule on anything but a product target", async () => {
      await mutateAdvisories((advisories) => {
        const runtime = advisories.find((advisory) => advisory.kind === "runtime" && !advisory.requires)!;
        runtime.product_rule = "verify-hotfix";
      });
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) expect(loaded.reason).toContain("product_rule");
    });

    it("rejects an empty advisories array (no silent zero)", async () => {
      await replaceFile("advisories.json", `${JSON.stringify({ advisories: [] })}\n`);
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) expect(loaded.reason).toContain("advisories.json");
    });

    it("rejects an empty eol entries array (no silent zero)", async () => {
      await replaceFile("eol.json", `${JSON.stringify({ entries: [] })}\n`);
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) expect(loaded.reason).toContain("eol.json");
    });

    describe("libraries.json", () => {
      const entry = (overrides: Record<string, unknown> = {}) => ({
        npm: "left-pad",
        banners: ["^left-pad v(\\d+\\.\\d+\\.\\d+)"],
        fileStems: ["left-pad"],
        cdnPaths: ["left-pad", "npm/left-pad"],
        ...overrides,
      });
      const withLibraries = (...entries: Array<Record<string, unknown>>) => replaceFile("libraries.json", `${JSON.stringify({ libraries: entries })}\n`);
      const rejected = async (needle: string) => {
        const loaded = await loadSynvoyaDataset(work);
        expect(loaded.ok).toBe(false);
        if (!loaded.ok) {
          expect(loaded.reason).toContain("libraries.json");
          expect(loaded.reason).toContain(needle);
        }
      };

      it("ships the reviewed table, digested by the manifest", async () => {
        const loaded = await loadSynvoyaDataset();
        expect(loaded.ok).toBe(true);
        if (!loaded.ok) return;
        const names = loaded.dataset.libraries.libraries.map((library) => library.npm);
        expect(names).toEqual(expect.arrayContaining(["jquery", "jquery-ui", "bootstrap", "react", "react-dom", "@popperjs/core", "socket.io-client", "pdfjs-dist"]));
        expect(new Set(names).size).toBe(names.length);
        const manifest = JSON.parse(await readFile(join(SYNVOYA_DATASET_DIR, "manifest.json"), "utf8")) as { files: Record<string, string> };
        expect(Object.keys(manifest.files)).toContain("libraries.json");
      });

      it("accepts a well-formed table", async () => {
        await withLibraries(entry());
        expect((await loadSynvoyaDataset(work)).ok).toBe(true);
      });

      it("rejects an unanchored banner regex", async () => {
        await withLibraries(entry({ banners: ["left-pad v(\\d+)"] }));
        await rejected("anchored");
      });

      it("rejects a banner regex without exactly one capture group", async () => {
        await withLibraries(entry({ banners: ["^left-pad v\\d+"] }));
        await rejected("capture group");
        await withLibraries(entry({ banners: ["^(left)-(pad) v\\d+"] }));
        await rejected("capture group");
      });

      it("rejects a banner regex that repeats a group without an upper bound, and one that does not compile", async () => {
        await withLibraries(entry({ banners: ["^(?:a+)+(\\d+)"] }));
        await rejected("upper bound");
        await withLibraries(entry({ banners: ["^(left"] }));
        await rejected("compile");
      });

      it("rejects an entry with no evidence, a malformed npm name and a duplicated library or key", async () => {
        await withLibraries(entry({ banners: [], fileStems: [], cdnPaths: [] }));
        await rejected("at least one");
        await withLibraries(entry({ npm: "Left Pad" }));
        await rejected("libraries.0.npm");
        await withLibraries(entry(), entry());
        await rejected("Duplicate library");
        await withLibraries(entry(), entry({ npm: "right-pad", fileStems: ["left-pad"], cdnPaths: ["right-pad"] }));
        await rejected("stem:left-pad");
      });

      it("rejects an empty table (no silent zero)", async () => {
        await replaceFile("libraries.json", `${JSON.stringify({ libraries: [] })}\n`);
        await rejected("libraries.json");
      });
    });

    it("requires covered_by and covered_since exactly when status is covered", async () => {
      await mutateAdvisories((advisories) => {
        advisories[0]!.status = "covered";
      });
      const bare = await loadSynvoyaDataset(work);
      expect(bare.ok).toBe(false);
      if (!bare.ok) expect(bare.reason).toContain("covered_by");

      await mutateAdvisories((advisories) => {
        advisories[0]!.covered_by = "trivy";
        advisories[0]!.covered_since = "2026-11-01";
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(true);

      await mutateAdvisories((advisories) => {
        advisories[0]!.covered_since = "yesterday";
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(false);

      await mutateAdvisories((advisories) => {
        advisories[0]!.status = "active";
        advisories[0]!.covered_since = "2026-11-01";
      });
      const activeWithCover = await loadSynvoyaDataset(work);
      expect(activeWithCover.ok).toBe(false);
      if (!activeWithCover.ok) expect(activeWithCover.reason).toContain("covered_by");
    });

    it("requires a non-empty affected list unless the kind is eol", async () => {
      await mutateAdvisories((advisories) => {
        advisories.find((advisory) => advisory.kind === "runtime")!.affected = [];
      });
      const rejected = await loadSynvoyaDataset(work);
      expect(rejected.ok).toBe(false);
      if (!rejected.ok) expect(rejected.reason).toContain("affected");

      await mutateAdvisories((advisories) => {
        advisories.find((advisory) => advisory.kind === "runtime")!.affected = [
          { line: "20", events: [{ introduced: "20.0.0" }] },
        ];
        advisories.find((advisory) => advisory.kind === "eol")!.affected = [];
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(true);
    });
  });

  describe("file hygiene", () => {
    it("oversized and tampered manifest.json files return ok:false", async () => {
      const original = await readFile(join(work, "manifest.json"));
      await writeFile(join(work, "manifest.json"), Buffer.alloc(8 * 1024 * 1024 + 1, 0x20));
      const oversized = await loadSynvoyaDataset(work);
      expect(oversized.ok).toBe(false);
      if (!oversized.ok) expect(oversized.reason).toContain("manifest.json");

      await writeFile(join(work, "manifest.json"), original.toString("utf8").replace(/"version": "[^"]+"/, '"version": "bad"'));
      const tampered = await loadSynvoyaDataset(work);
      expect(tampered.ok).toBe(false);
      if (!tampered.ok) expect(tampered.reason).toContain("manifest.json");
    });

    it("refuses a symlinked data file, naming the file", async (ctx) => {
      const outside = join(work, "outside.json");
      await cp(join(work, "eol.json"), outside);
      await rm(join(work, "eol.json"));
      try {
        await symlink(outside, join(work, "eol.json"));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EPERM") ctx.skip(); // Windows without symlink privilege
        throw error;
      }
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) {
        expect(loaded.reason).toContain("eol.json");
        expect(loaded.reason).toContain("regular file");
      }
    });

    it("refuses a directory in place of a data file", async () => {
      await rm(join(work, "aliases.json"));
      await mkdir(join(work, "aliases.json"));
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) {
        expect(loaded.reason).toContain("aliases.json");
        expect(loaded.reason).toContain("regular file");
      }
    });

    it.skipIf(process.platform === "win32")("refuses a FIFO in place of a data file without hanging", async () => {
      await rm(join(work, "eol.json"));
      await run("mkfifo", [join(work, "eol.json")]);
      const loaded = await loadSynvoyaDataset(work);
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) {
        expect(loaded.reason).toContain("eol.json");
        expect(loaded.reason).toContain("regular file");
      }
    });
  });

  it("keeps the dataset types assignable from the loaded shape", async () => {
    const loaded = await loadSynvoyaDataset();
    if (!loaded.ok) throw new Error(loaded.reason);
    const dataset: SynvoyaDataset = loaded.dataset;
    const advisory: SynvoyaAdvisory = dataset.advisories[0]!;
    expect(advisory.id).toMatch(/^SYN-/);
    // Compile-time guard (tsc --noEmit): what the schema accepts must be a SynvoyaAdvisory, with no cast.
    const parsed = undefined as unknown as ParsedSynvoyaAdvisory;
    const typed: SynvoyaAdvisory | undefined = parsed;
    expect(typed).toBeUndefined();
  });

  it("repo .gitattributes keeps the dataset bytes untouched by line-ending conversion", async () => {
    const attributes = await readFile(join(process.cwd(), ".gitattributes"), "utf8");
    expect(attributes).toMatch(/^detection-db\/synvoya\/\*\*\s+-text\s*$/m);
  });

  describe("scripts/synvoya-manifest.mjs", () => {
    it("the committed manifest is current", async () => {
      const result = await run(process.execPath, [MANIFEST_SCRIPT, "--check", SYNVOYA_DATASET_DIR]);
      expect(result.stderr + result.stdout).toContain("current");
    });

    it("--check fails on drift and a plain run rewrites digests so the loader accepts them", async () => {
      const original = await readFile(join(work, "eol.json"), "utf8");
      await writeFile(join(work, "eol.json"), `${original}\n`);
      await expect(run(process.execPath, [MANIFEST_SCRIPT, "--check", work])).rejects.toMatchObject({
        code: 1,
      });
      expect((await loadSynvoyaDataset(work)).ok).toBe(false);

      await run(process.execPath, [MANIFEST_SCRIPT, work]);
      expect((await loadSynvoyaDataset(work)).ok).toBe(true);
    });
  });
});
