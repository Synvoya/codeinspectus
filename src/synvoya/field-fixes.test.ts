/**
 * Regressions from the M1 field re-scan (2026-11-03): each case is a minimal repository modelled on a
 * public repository where the shipped dataset and readers produced a false positive or a wrong location
 * or note. Runs the real scanner over the shipped dataset.
 */

import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { Finding } from "../types.js";
import type { PackageInventory } from "./evaluate.js";
import { runSynvoyaScan, type SynvoyaScanResult } from "./scanner.js";

const NOW = new Date("2026-11-03T12:00:00Z");
const NONE: PackageInventory = { packages: [] };
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

async function repo(files: Record<string, string>): Promise<string> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "ci-synvoya-field-")));
  roots.push(root);
  for (const [path, content] of Object.entries(files)) {
    await mkdir(join(root, ...path.split("/").slice(0, -1)), { recursive: true });
    await writeFile(join(root, ...path.split("/")), content, "utf8");
  }
  return root;
}

async function scan(files: Record<string, string>, inventory: PackageInventory = NONE): Promise<SynvoyaScanResult> {
  const result = await runSynvoyaScan(await repo(files), inventory, {}, { now: NOW });
  expect(result.info).toMatchObject({ available: true, ran: true });
  return result;
}

const at = (findings: Finding[]): string[] => findings.map((f) => `${f.rule_id} ${f.location.file}:${f.location.start_line}`).sort();
const ids = (findings: Finding[]): string[] => [...new Set(findings.map((f) => f.rule_id))].sort();

describe("class A: Windows-only PHP-CGI advisory (SYN-2026-150, CVE-2024-4577)", () => {
  it("never fires on a Linux image or a Composer value; the EOL and PHP2Shell findings stay (tinyfilemanager)", async () => {
    const result = await scan({
      Dockerfile: "FROM php:7.4-cli-alpine\nRUN echo hi\n",
      "composer.json": JSON.stringify({ require: { php: ">=5.5" }, config: { platform: { php: "7.3" } } }, null, 2),
    });
    expect(ids(result.findings)).not.toContain("SYN-2026-150");
    expect(at(result.findings)).toEqual(expect.arrayContaining([
      "SYN-2026-008 Dockerfile:1", "SYN-2026-014 Dockerfile:1", "SYN-2026-015 Dockerfile:1",
    ]));
    for (const note of result.notes) expect(note).not.toContain("SYN-2026-150");
  });
});

describe("class B: Composer platform PHP is a release line, not a patch release", () => {
  it("platform 8.2.0 resolves along the supported 8.2 line: a note, no finding (pterodactyl)", async () => {
    const composerJson = JSON.stringify({ require: { php: "^8.2 || ^8.3" }, config: { platform: { php: "8.2.0" } } }, null, 2);
    const composerLock = JSON.stringify({ packages: [], platform: { php: "^8.2 || ^8.3" }, "platform-overrides": { php: "8.2.0" } }, null, 2);
    const result = await scan({
      "composer.json": composerJson,
      "composer.lock": composerLock,
      Dockerfile: "FROM php:8.3-fpm-alpine\n",
    });
    expect(at(result.findings)).toEqual([]);
    expect(result.notes).toEqual(expect.arrayContaining([
      expect.stringMatching(/^composer\.json:\d+: composer\.json config\.platform\.php declares PHP 8\.2, which can still resolve to a release affected by SYN-2026-008/),
      expect.stringMatching(/^composer\.lock:\d+: composer\.lock platform-overrides declares PHP 8\.2, which can still resolve/),
    ]));
  });

  it("an end-of-life platform line keeps its findings (cap-collectif 8.1, geoip-detect 7.3.0)", async () => {
    const result = await scan({
      "composer.json": JSON.stringify({ config: { platform: { php: "8.1" } } }, null, 2),
      "composer.lock": JSON.stringify({ packages: [], "platform-overrides": { php: "7.3.0" } }, null, 2),
    });
    expect(at(result.findings)).toEqual([
      "SYN-2026-008 composer.json:4", "SYN-2026-008 composer.lock:4",
      "SYN-2026-014 composer.json:4", "SYN-2026-014 composer.lock:4",
      "SYN-2026-015 composer.json:4", "SYN-2026-015 composer.lock:4",
    ]);
    for (const finding of result.findings) expect(finding.confidence).toBe("high");
  });
});

describe("class C: the go.mod go directive is a minimum, the toolchain line is exact", () => {
  it("go 1.22.4 / go 1.25.0 give no finding; the golang image pin keeps its EOL finding (nostroots, moments, wallabag)", async () => {
    const result = await scan({
      "nr-relay/go.mod": "module example.com/relay\n\ngo 1.22.4\n\nrequire github.com/x/y v1.0.0\n",
      "vibe/go.mod": "module example.com/vibe\n\ngo 1.25.0\n",
      "nr-relay/Dockerfile": "FROM golang:1.22-alpine AS build\n",
    });
    expect(at(result.findings)).toEqual(["SYN-2026-021 nr-relay/Dockerfile:1"]);
  });

  it("a toolchain line on an end-of-life Go stays a finding", async () => {
    const result = await scan({ "go.mod": "module example.com/app\n\ngo 1.22.0\n\ntoolchain go1.24.3\n" });
    expect(at(result.findings)).toEqual(["SYN-2026-021 go.mod:5"]);
  });
});

describe("class D: a vendored SDK under vendors/ is not the project's runtime", () => {
  it("includes/vendors/<sdk>/composer.json is skipped; the plugin's own composer.json is read (elementor-mcp)", async () => {
    const result = await scan({
      "composer.json": JSON.stringify({ require: { php: ">=7.4" } }, null, 2),
      "includes/vendors/fremius/composer.json": JSON.stringify({ config: { platform: { php: "8.0" } } }, null, 2),
      "vendors/sdk/.nvmrc": "16\n",
    });
    expect(at(result.findings)).toEqual([]);
    expect(result.evidence.parsed).toEqual(["composer.json"]);
  });
});

describe("output: a locked package is cited at its own lockfile entry", () => {
  it("electron is located at node_modules/electron, not at electron-updater (cortext)", async () => {
    const lock = JSON.stringify({
      name: "desktop", lockfileVersion: 3, packages: {
        "": { dependencies: { "electron-updater": "^6.8.9" }, devDependencies: { electron: "^42.11.16" } },
        "node_modules/electron-updater": { version: "6.8.9" },
        "node_modules/electron": { version: "42.11.16", dev: true },
      },
    }, null, 2);
    const entryLine = lock.split("\n").findIndex((line) => line.includes('"node_modules/electron":')) + 1;
    const inventory: PackageInventory = { packages: [
      { ecosystem: "npm", name: "electron", version: "42.11.16", file: "apps/desktop/package-lock.json", line: 0, producer: "inventory:osv-scanner" },
      { ecosystem: "npm", name: "electron-updater", version: "6.8.9", file: "apps/desktop/package-lock.json", line: 0, producer: "inventory:osv-scanner" },
    ] };
    const result = await scan({ "apps/desktop/package-lock.json": lock }, inventory);
    expect(at(result.findings)).toEqual([`SYN-2026-027 apps/desktop/package-lock.json:${entryLine}`]);
    expect(result.findings[0]!.message).toContain(`apps/desktop/package-lock.json:${entryLine}`);
  });
});

describe("output: vendor registries that publish official images, and one note per image", () => {
  it("docker.elastic.co Elasticsearch 7.17.27 is an end-of-life Elasticsearch, not a private-registry image (cap-collectif)", async () => {
    const result = await scan({
      "infrastructure/services/elasticsearch/Dockerfile": "FROM docker.elastic.co/elasticsearch/elasticsearch:7.17.27\n",
      "deploy/elasticsearch/docker-compose.yml": "services:\n  es:\n    image: docker.elastic.co/elasticsearch/elasticsearch:${ELASTICSEARCH_VERSION:-8.19.12}\n",
    });
    expect(at(result.findings)).toEqual(["SYN-EOL-elasticsearch-7 infrastructure/services/elasticsearch/Dockerfile:1"]);
    expect(result.notes.filter((note) => /private registry|not a resolvable version/.test(note))).toEqual([]);
  });

  it("a Docker Hardened Images node behind an ARG resolves like the official node image (directus)", async () => {
    const result = await scan({
      "Dockerfile.dhi": [
        "ARG NODE_VERSION=26.12.1", "ARG ALPINE_VERSION=3.23", "ARG DHI_RUNTIME=dhi.io/node:${NODE_VERSION}-alpine${ALPINE_VERSION}",
        "FROM node:${NODE_VERSION}-alpine${ALPINE_VERSION} AS builder", "FROM ${DHI_RUNTIME} AS runtime", "",
      ].join("\n"),
    });
    expect(at(result.findings)).toEqual([]);
    expect(result.notes.filter((note) => note.startsWith("Dockerfile.dhi"))).toEqual([]);
    expect(result.evidence.checked.images).toEqual(["Dockerfile.dhi"]);
  });

  it("an official name on another registry gets one note, not a second 'not a resolvable version' (immich)", async () => {
    const result = await scan({
      "docker/docker-compose.yml": "services:\n  db:\n    image: ghcr.io/immich-app/postgres:14-vectorchord0.4.3\n",
    });
    expect(at(result.findings)).toEqual([]);
    expect(result.notes.filter((note) => note.startsWith("docker/docker-compose.yml"))).toEqual([
      'docker/docker-compose.yml:3: compose image "ghcr.io/immich-app/postgres:14-vectorchord0.4.3" is an image on a private registry — cannot confirm it is the official postgres image; no finding is possible for it.',
    ]);
  });
});
