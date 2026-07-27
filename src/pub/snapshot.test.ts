import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { matchPubPackage } from "./matcher.js";
import { fixedVersions, loadPubSnapshot } from "./snapshot.js";
import { OSV_PUB_SNAPSHOT } from "../config.js";
import { signature } from "../provenance.js";

describe("bundled OSV Pub snapshot", () => {
  it("loads a consistent, attributed, exact-version snapshot", async () => {
    const loaded = await loadPubSnapshot();
    expect(loaded.data.snapshot.ecosystem).toBe("Pub");
    expect(loaded.data.snapshot.matching).toBe("exact-enumerated-versions");
    expect(loaded.data.snapshot.license).toBe("CC-BY-4.0");
    expect(loaded.data.snapshot.advisory_count).toBe(loaded.data.advisories.length);
    expect(loaded.data.advisories.every((advisory) => advisory.affected.length === 1)).toBe(true);
    expect(loaded.content_signature).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("signs the exact bytes parsed even if the path is atomically replaced afterward", async () => {
    const root = await mkdtemp(join(tmpdir(), "ci-pub-snapshot-race-"));
    const path = join(root, "snapshot.json");
    try {
      const original = await readFile(OSV_PUB_SNAPSHOT);
      await writeFile(path, original);
      const loaded = await loadPubSnapshot(path, {
        readBytes: async (snapshotPath) => {
          const parsedBytes = await readFile(snapshotPath);
          await writeFile(snapshotPath, Buffer.concat([parsedBytes, Buffer.from("\n")]));
          return parsedBytes;
        },
      });
      expect(loaded.content_signature).toBe(signature(original));
      expect(signature(await readFile(path))).not.toBe(loaded.content_signature);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("matches exact enumerated versions and preserves Pub build suffix behavior", async () => {
    const { data } = await loadPubSnapshot();
    expect(matchPubPackage(data, { name: "jose", version: "0.3.5" }).map((match) => match.advisory.id))
      .toEqual(["GHSA-vm9r-h74p-hg97"]);
    expect(matchPubPackage(data, { name: "jose", version: "0.3.5+1" })).toEqual([]);
    expect(matchPubPackage(data, { name: "archive", version: "3.3.7" }).map((match) => match.advisory.id))
      .toEqual(["GHSA-9v85-q87q-g4vg", "GHSA-r285-q736-9v95"]);
  });

  it("exposes upstream fixed boundaries only as remediation metadata", async () => {
    const { data } = await loadPubSnapshot();
    const [match] = matchPubPackage(data, { name: "jose", version: "0.3.5" });
    expect(match).toBeDefined();
    expect(fixedVersions(match!.affected)).toEqual(["0.3.5+1"]);
  });
});
