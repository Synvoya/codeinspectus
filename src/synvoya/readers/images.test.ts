import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { Declaration, RuntimeId, SynvoyaDataset } from "../types.js";

import { readImageTags } from "./images.js";

const FIXTURES = join(process.cwd(), "fixtures", "synvoya", "images");

/** Small explicit tables, independent of the shipped dataset. */
const DATASET: Pick<SynvoyaDataset, "imageAliases" | "productImages" | "eol"> = {
  imageAliases: {
    "jenkins/jenkins": { ecosystem: "maven", name: "org.jenkins-ci.main:jenkins-core" },
    tomcat: { ecosystem: "maven", name: "org.apache.tomcat:tomcat" },
    "n8nio/n8n": { ecosystem: "npm", name: "n8n" },
  },
  productImages: {
    "atlassian/confluence": "confluence",
    httpd: "httpd",
    kibana: "kibana",
  },
  eol: [
    { product: "mysql", cycle: "5.7", eol: "2023-10-31", source: "test" },
    { product: "postgres", cycle: "12", eol: "2024-11-14", source: "test" },
    { product: "redis", cycle: "6.0", eol: "2023-07-31", source: "test" },
    { product: "elasticsearch", cycle: "7", eol: "2026-01-15", source: "test" },
  ],
};

type Subject = Declaration["subject"];

function decl(
  subject: Subject,
  spec: string,
  precision: Declaration["precision"],
  file: string,
  line: number,
  source: string,
  resolved?: string,
): Declaration {
  return { subject, spec, ...(resolved === undefined ? {} : { resolved }), precision, file, line, source };
}

const runtime = (id: RuntimeId): Subject => ({ type: "runtime", runtime: id });

async function read(name: string) {
  return readImageTags(join(FIXTURES, name), DATASET);
}

describe("readImageTags: fixtures", () => {
  it("Dockerfile: ARG defaults, stages, scratch, platform, prefixes, lookup order", async () => {
    const result = await read("dockerfile");
    expect(result.declarations).toEqual([
      decl(runtime("node"), "20.11.1", "exact", "Dockerfile", 5, "Dockerfile FROM", "20.11.1"),
      decl(runtime("php"), "8.3", "floating", "Dockerfile", 8, "Dockerfile FROM"),
      decl(runtime("dotnet"), "8.0.4", "exact", "Dockerfile", 10, "Dockerfile FROM", "8.0.4"),
      decl(runtime("python"), "3.12", "floating", "Dockerfile", 11, "Dockerfile FROM"),
      decl({ type: "package", ecosystem: "maven", name: "org.jenkins-ci.main:jenkins-core" }, "2.426.1", "exact", "Dockerfile", 12, "Dockerfile FROM", "2.426.1"),
      decl({ type: "image-eol", product: "postgres" }, "12", "floating", "Dockerfile", 13, "Dockerfile FROM"),
    ]);
    expect(result.parsed).toEqual(["Dockerfile"]);
    expect(result.skipped).toEqual([]);
    // FROM ${BASE_IMAGE}: no repository to look up, so a note and no declaration.
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain("Dockerfile:9");
    expect(result.notes[0]).toContain("BASE_IMAGE");
  });

  it("compose: image keys, ${VAR:-default}, no tag, unmatched images ignored", async () => {
    const result = await read("compose");
    const file = "docker-compose.yml";
    expect(result.declarations).toEqual([
      decl(runtime("node"), "22", "floating", file, 3, "compose image"),
      decl({ type: "image-eol", product: "mysql" }, "5.7", "floating", file, 5, "compose image"),
      decl({ type: "image-eol", product: "redis" }, "7.2.4", "exact", file, 7, "compose image", "7.2.4"),
      decl({ type: "product", product: "confluence" }, "8.5.4", "exact", file, 9, "compose image", "8.5.4"),
      decl({ type: "product", product: "httpd" }, "latest", "unresolved", file, 14, "compose image"),
    ]);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain("docker-compose.yml:14");
    expect(result.notes[0]).toContain('docker-compose.yml:14: compose image "httpd" has no tag');
  });

  it("Kubernetes: multi-document, only documents with apiVersion and kind", async () => {
    const result = await read("k8s");
    expect(result.declarations).toEqual([
      decl(runtime("dotnet"), "6.0.30", "exact", "deploy.yaml", 15, "Kubernetes image", "6.0.30"),
      decl(runtime("java"), "21.0.4", "exact", "deploy.yaml", 17, "Kubernetes image", "21.0.4"),
    ]);
    expect(result.parsed).toEqual(["deploy.yaml"]);
    expect(result.notes).toEqual([]);
  });

  it("Helm values: image.repository + image.tag, registry ignored when docker.io", async () => {
    const result = await read("helm");
    expect(result.declarations).toEqual([
      decl({ type: "image-eol", product: "redis" }, "7.2.4", "exact", "values.yaml", 3, "Helm values image", "7.2.4"),
      decl({ type: "package", ecosystem: "npm", name: "n8n" }, "1.45.0", "exact", "values.yaml", 7, "Helm values image", "1.45.0"),
    ]);
  });

  it("GitHub Actions: container and services.*.image", async () => {
    const result = await read("workflow");
    const file = ".github/workflows/ci.yml";
    expect(result.declarations).toEqual([
      decl(runtime("node"), "18", "floating", file, 4, "GitHub Actions container.image"),
      decl({ type: "image-eol", product: "postgres" }, "13.4", "floating", file, 7, "GitHub Actions services.db.image"),
      decl({ type: "image-eol", product: "redis" }, "latest", "unresolved", file, 9, "GitHub Actions services.cache.image"),
      decl(runtime("python"), "3.9", "floating", file, 12, "GitHub Actions container.image"),
    ]);
    expect(result.notes).toHaveLength(1);
  });
});

describe("readImageTags: tags and references", () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-img-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  async function dockerfile(text: string) {
    await writeFile(join(work, "Dockerfile"), text);
    return readImageTags(work, DATASET);
  }
  const froms = (result: Awaited<ReturnType<typeof dockerfile>>) => result.declarations.map((d) => [d.spec, d.precision, d.resolved]);

  it.each([
    ["an unresolved repository variable", "ARG BASE\nFROM ${BASE}\n"],
    ["a reference past the length bound after substitution", `ARG A=${"a".repeat(400)}\nFROM \${A}\${A}:1\n`],
    ["an unparseable reference", "FROM bad!image:1\n"],
  ])("%s leaves the file not fully judged (unjudged), with a note", async (_name, text) => {
    const result = await dockerfile(text);
    expect(result.declarations).toEqual([]);
    expect(result.parsed).toEqual(["Dockerfile"]);
    expect(result.unjudged).toEqual(["Dockerfile"]);
    expect(result.notes.some((note) => note.includes("no finding is possible for it"))).toBe(true);
  });

  it.each([
    ["registry.internal/php:8.0.30-fpm", { type: "runtime", runtime: "php" }, "php"],
    ["myacr.azurecr.io/library/node:20", { type: "runtime", runtime: "node" }, "node"],
    ["registry.internal/team/jenkins:2.426.1", { type: "package", ecosystem: "maven", name: "org.jenkins-ci.main:jenkins-core" }, "jenkins/jenkins"],
  ])("%s on an unknown registry is an unresolved declaration, never a finding source", async (image, subject, name) => {
    const result = await dockerfile(`FROM ${image}\n`);
    expect(result.declarations).toHaveLength(1);
    // `noted`: the reader's note is the one explanation; the evaluator adds no "not a resolvable version" note.
    expect(result.declarations[0]).toMatchObject({ subject, precision: "unresolved", file: "Dockerfile", line: 1, noted: true });
    expect(result.notes).toEqual([
      `Dockerfile:1: Dockerfile FROM image "${image}" is an image on a private registry — cannot confirm it is the official ${name} image; no finding is possible for it.`,
    ]);
  });

  it("a vendor registry that publishes the official image is looked up as that image (docker.elastic.co, dhi.io)", async () => {
    const result = await dockerfile(
      "FROM docker.elastic.co/elasticsearch/elasticsearch:7.17.27\nFROM dhi.io/node:26.12.1-alpine3.23\nFROM docker.elastic.co/kibana/kibana:8.15.0\nFROM dhi.io/team/node:22\n",
    );
    expect(result.declarations).toEqual([
      decl({ type: "image-eol", product: "elasticsearch" }, "7.17.27", "exact", "Dockerfile", 1, "Dockerfile FROM", "7.17.27"),
      decl(runtime("node"), "26.12.1", "exact", "Dockerfile", 2, "Dockerfile FROM", "26.12.1"),
      decl({ type: "product", product: "kibana" }, "8.15.0", "exact", "Dockerfile", 3, "Dockerfile FROM", "8.15.0"),
      // dhi.io mirrors official names only: a nested path is another image, on what is then a private registry.
      { ...decl(runtime("node"), "22", "unresolved", "Dockerfile", 4, "Dockerfile FROM"), noted: true },
    ]);
    expect(result.notes).toEqual([
      'Dockerfile:4: Dockerfile FROM image "dhi.io/team/node:22" is an image on a private registry — cannot confirm it is the official node image; no finding is possible for it.',
    ]);
  });

  it("an unrelated image on another registry is still ignored", async () => {
    const result = await dockerfile("FROM registry.internal/team/api:1.2.3\n");
    expect(result.declarations).toEqual([]);
    expect(result.unjudged ?? []).toEqual([]);
  });

  it.each([
    ["golang:1.22.5", "go", "1.22.5", "exact"],
    ["golang:1.22", "go", "1.22", "floating"],
    ["openjdk:8u402-jre", "java", "8u402", "exact"],
    ["openjdk:8-jre", "java", "8", "floating"],
    ["eclipse-temurin:21.0.4_7-jdk", "java", "21.0.4", "exact"],
    ["amazoncorretto:17-alpine", "java", "17", "floating"],
    ["python:3.12.1-slim-bookworm", "python", "3.12.1", "exact"],
    ["ruby:3.3", "ruby", "3.3", "floating"],
    ["php:8.3-fpm", "php", "8.3", "floating"],
    ["library/node:22", "node", "22", "floating"],
    ["docker.io/library/node:22.1.0-alpine", "node", "22.1.0", "exact"],
    ["bitnami/node:20.11.1", "node", "20.11.1", "exact"],
    ["mcr.microsoft.com/dotnet/sdk:8.0.100", "dotnet", "8.0", "floating"],
    ["mcr.microsoft.com/dotnet/runtime:8.0", "dotnet", "8.0", "floating"],
  ])("%s -> %s %s %s", async (image, id, spec, precision) => {
    const result = await dockerfile(`FROM ${image}\n`);
    expect(result.declarations).toHaveLength(1);
    expect(result.declarations[0]!.subject).toEqual(runtime(id as RuntimeId));
    expect(result.declarations[0]!.spec).toBe(spec);
    expect(result.declarations[0]!.precision).toBe(precision);
    expect(result.declarations[0]!.resolved).toBe(precision === "exact" ? spec : undefined);
  });

  it.each(["node:20240101", "node:2024.01.01", "node:99999999999", "postgres:20240101", "node:20240101-alpine", "node:08.1.2", "node:12345.1"])(
    "%s is not a plausible version: unresolved with a note",
    async (image) => {
      const result = await dockerfile(`FROM ${image}\n`);
      expect(result.declarations).toHaveLength(1);
      expect(result.declarations[0]).toMatchObject({ precision: "unresolved" });
      expect(result.declarations[0]!.resolved).toBeUndefined();
      expect(result.notes).toHaveLength(1);
    },
  );

  it("a first component of 0 or up to four digits without a leading zero is plausible", async () => {
    const result = await dockerfile("FROM tomcat:0.49.1\nFROM tomcat:9999.1.1\nFROM tomcat:10.1\n");
    expect(froms(result)).toEqual([
      ["0.49.1", "exact", "0.49.1"],
      ["9999.1.1", "exact", "9999.1.1"],
      ["10.1", "floating", undefined],
    ]);
  });

  it("a leading v is accepted for package, product and EOL images, but not for runtime images", async () => {
    const dataset = {
      imageAliases: { "kestra/kestra": { ecosystem: "maven", name: "io.kestra:kestra" } },
      productImages: { "metabase/metabase": "metabase" },
      eol: [{ product: "mysql", cycle: "5.7", eol: "2023-10-31", source: "test" }],
    };
    await writeFile(join(work, "Dockerfile"), "FROM kestra/kestra:v0.15.0\nFROM metabase/metabase:v0.49.1\nFROM mysql:v5.7\nFROM node:v22.1.0\n");
    const result = await readImageTags(work, dataset);
    expect(result.declarations.map((d) => [d.spec, d.precision, d.resolved])).toEqual([
      ["0.15.0", "exact", "0.15.0"],
      ["0.49.1", "exact", "0.49.1"],
      ["5.7", "floating", undefined],
      ["v22.1.0", "unresolved", undefined],
    ]);
  });

  it.each([
    ["python:3.13.0-rc-slim", "3.13.0"],
    ["python:3.13.0-rc1", "3.13.0"],
    ["ruby:3.3.0-preview1", "3.3.0"],
    ["node:22.1.0-beta.2", "22.1.0"],
    ["node:22.1.0-alpha", "22.1.0"],
    ["openjdk:23.0.1-ea", "23.0.1"],
    ["openjdk:8u402-ea-jre", "8u402"],
  ])("%s is a pre-release: floating, never exact", async (image, spec) => {
    const result = await dockerfile(`FROM ${image}\n`);
    expect(result.declarations).toHaveLength(1);
    expect(result.declarations[0]).toMatchObject({ spec, precision: "floating" });
    expect(result.declarations[0]!.resolved).toBeUndefined();
  });

  it("a release whose suffix merely starts like a marker stays exact", async () => {
    const result = await dockerfile("FROM node:22.1.0-earlybird\nFROM node:22.1.0-alpine3.19\n");
    expect(result.declarations.map((d) => d.precision)).toEqual(["exact", "exact"]);
  });

  it("latest, no tag and digest-only are unresolved declarations with a note", async () => {
    const result = await dockerfile(
      "FROM node:latest\nFROM node\nFROM node@sha256:" + "a".repeat(64) + "\nFROM node:lts-alpine\nFROM python:3.13.0rc1\n",
    );
    expect(result.declarations.map((d) => d.precision)).toEqual(["unresolved", "unresolved", "unresolved", "unresolved", "unresolved"]);
    expect(result.declarations.every((d) => d.resolved === undefined)).toBe(true);
    expect(result.notes).toHaveLength(5);
  });

  it("a tag with a digest uses the tag", async () => {
    const result = await dockerfile("FROM node:22.1.0@sha256:" + "b".repeat(64) + "\n");
    expect(froms(result)).toEqual([["22.1.0", "exact", "22.1.0"]]);
  });

  it("unmatched images produce nothing, not even a note", async () => {
    const result = await dockerfile("FROM ghcr.io/acme/app:1.2.3\nFROM alpine:3.19\n");
    expect(result.declarations).toEqual([]);
    expect(result.notes).toEqual([]);
    expect(result.parsed).toEqual(["Dockerfile"]);
  });

  it("lookup order: runtime, then package alias, then product, then EOL", async () => {
    const dataset = {
      imageAliases: { node: { ecosystem: "npm", name: "node-as-package" }, tomcat: { ecosystem: "maven", name: "tomcat" } },
      productImages: { tomcat: "tomcat-product", mysql: "mysql-product" },
      eol: [{ product: "mysql", cycle: "5.7", eol: "2023-10-31", source: "test" }],
    };
    await writeFile(join(work, "Dockerfile"), "FROM node:22\nFROM tomcat:9.0.89\nFROM mysql:5.7\n");
    const result = await readImageTags(work, dataset);
    expect(result.declarations.map((d) => d.subject)).toEqual([
      runtime("node"),
      { type: "package", ecosystem: "maven", name: "tomcat" },
      { type: "product", product: "mysql-product" },
    ]);
  });

  it("prototype-polluting repository names are not table hits", async () => {
    const result = await dockerfile("FROM constructor:1\nFROM __proto__:1\nFROM toString:1\n");
    expect(result.declarations).toEqual([]);
  });

  it("ARG: no default is unresolved; no recursion; self-reference is unresolved", async () => {
    const result = await dockerfile(
      [
        "ARG NODE",
        "ARG A=${A}",
        "ARG B=22",
        "ARG C=${B}",
        "FROM node:${NODE}",
        "FROM node:${A}",
        "FROM node:${C}-slim",
        "FROM node:$B",
        "FROM node:${MISSING:-18}",
        "FROM node:${C",
      ].join("\n") + "\n",
    );
    expect(result.declarations.map((d) => [d.line, d.spec, d.precision])).toEqual([
      [5, "${NODE}", "unresolved"],
      [6, "${A}", "unresolved"],
      [7, "22", "floating"],
      [8, "22", "floating"],
      [9, "18", "floating"],
      [10, "${C", "unresolved"],
    ]);
  });

  it("ARG declared after FROM is not visible to a later FROM", async () => {
    const result = await dockerfile("FROM alpine\nARG V=22\nFROM node:${V}\n");
    expect(result.declarations.map((d) => d.precision)).toEqual(["unresolved"]);
  });

  it("stage aliases are skipped case-insensitively; --platform stripped; line continuations joined", async () => {
    const result = await dockerfile(
      "FROM --platform=linux/amd64 \\\n  node:22 AS Base\nFROM base\nFROM BASE AS final\n# comment\nFROM scratch\n",
    );
    expect(result.declarations).toHaveLength(1);
    expect(result.declarations[0]).toMatchObject({ spec: "22", line: 1 });
  });

  it("honours a backtick escape directive", async () => {
    const result = await dockerfile("# escape=`\nFROM `\n  node:22\n");
    expect(result.declarations.map((d) => d.spec)).toEqual(["22"]);
  });

  it("matches Dockerfile.* and *.Dockerfile, nested, with forward-slash paths", async () => {
    await mkdir(join(work, "svc"), { recursive: true });
    await writeFile(join(work, "svc", "Dockerfile.dev"), "FROM node:20\n");
    await writeFile(join(work, "svc", "api.Dockerfile"), "FROM php:8.2\n");
    const result = await readImageTags(work, DATASET);
    expect(result.declarations.map((d) => d.file)).toEqual(["svc/Dockerfile.dev", "svc/api.Dockerfile"]);
  });

  it("compose: templated repository is a note only; Helm values without a tag is unresolved", async () => {
    await writeFile(join(work, "compose.yaml"), "services:\n  a:\n    image: ${REGISTRY}/node:22\n  b:\n    image: ${NODE_IMAGE}\n");
    await writeFile(join(work, "values-prod.yaml"), "image:\n  repository: tomcat\n");
    const result = await readImageTags(work, DATASET);
    expect(result.declarations).toEqual([
      decl({ type: "package", ecosystem: "maven", name: "org.apache.tomcat:tomcat" }, "latest", "unresolved", "values-prod.yaml", 2, "Helm values image"),
    ]);
    expect(result.notes.filter((n) => n.startsWith("compose.yaml:"))).toHaveLength(2);
  });

  it("Kubernetes-looking YAML is only read when apiVersion and kind are both top-level", async () => {
    await writeFile(join(work, "a.yaml"), "kind: Pod\nspec:\n  containers:\n    - image: node:22\n");
    await writeFile(join(work, "b.yaml"), "apiVersion: v1\nspec:\n  containers:\n    - image: node:22\n");
    await writeFile(join(work, "c.yaml"), "metadata:\n  apiVersion: v1\n  kind: Pod\nimage: node:22\n");
    const result = await readImageTags(work, DATASET);
    expect(result.declarations).toEqual([]);
  });

  it("a Helm template that is not valid YAML is skipped as templated, not malformed", async () => {
    await writeFile(join(work, "deploy.yaml"), "apiVersion: apps/v1\nkind: Deployment\nspec:\n  image: {{ .Values.image }}\n  bad: [\n");
    const result = await readImageTags(work, DATASET);
    expect(result.skipped).toEqual([{ file: "deploy.yaml", reason: "templated" }]);
  });

  it("skips a symlinked Dockerfile and an oversized compose file", async (ctx) => {
    await writeFile(join(work, "real"), "FROM node:22\n");
    try {
      await symlink(join(work, "real"), join(work, "Dockerfile"));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EPERM") return ctx.skip();
      throw error;
    }
    await writeFile(join(work, "docker-compose.yml"), `services: {}\n# ${"x".repeat(2 * 1024 * 1024)}\n`);
    const result = await readImageTags(work, DATASET);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([
      { file: "Dockerfile", reason: "symlink" },
      { file: "docker-compose.yml", reason: "oversized" },
    ]);
  });

  it("never throws on malformed YAML", async () => {
    await writeFile(join(work, "docker-compose.yml"), "services: [unclosed\n  - : :\n");
    await writeFile(join(work, "values.yaml"), "image: {\n");
    const result = await readImageTags(work, DATASET);
    expect(result.declarations).toEqual([]);
    expect(result.skipped).toEqual([
      { file: "docker-compose.yml", reason: "malformed" },
      { file: "values.yaml", reason: "malformed" },
    ]);
  });

  it("an empty target yields an empty result", async () => {
    expect(await readImageTags(work, DATASET)).toEqual({ declarations: [], parsed: [], skipped: [], notes: [] });
  });
});

describe("readImageTags: hostile inputs", { timeout: 20_000 }, () => {
  let work: string;
  beforeEach(async () => {
    work = await mkdtemp(join(tmpdir(), "ci-synvoya-img-hostile-"));
  });
  afterEach(async () => {
    await rm(work, { recursive: true, force: true });
  });

  async function timed() {
    const started = Date.now();
    const result = await readImageTags(work, DATASET);
    return { result, ms: Date.now() - started };
  }

  it("a 1 MiB Dockerfile of FROM node:22 is capped at 64 declarations", async () => {
    await writeFile(join(work, "Dockerfile"), "FROM node:22\n".repeat(80_000));
    const { result, ms } = await timed();
    expect(result.declarations).toHaveLength(64);
    expect(result.notes).toEqual(["Dockerfile: more than 64 image declarations; extra ignored"]);
    expect(result.parsed).toEqual([]);
    expect(result.skipped).toEqual([{ file: "Dockerfile", reason: "capped" }]);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("a compose file with ~50k services is capped", async () => {
    let text = "services:\n";
    for (let index = 0; text.length < 1024 * 1024 - 64; index++) text += `  s${index}:\n    image: node:22\n`;
    await writeFile(join(work, "docker-compose.yml"), text);
    const { result } = await timed();
    expect(result.declarations).toHaveLength(64);
    expect(result.notes.some((n) => n.includes("more than 64 image declarations"))).toBe(true);
  });

  it("100k single-line services in flow style do not hang", async () => {
    const services = Array.from({ length: 100_000 }, (_, i) => `s${i}: {image: x}`).join(", ").slice(0, 1024 * 1000);
    await writeFile(join(work, "docker-compose.yml"), `services: {${services}}\n`);
    const { result } = await timed();
    expect(result.declarations).toEqual([]);
  });

  it("Helm values nested 10k deep are bounded, never thrown", async () => {
    await writeFile(join(work, "values.yaml"), `${"{a: ".repeat(10_000)}1${"}".repeat(10_000)}\n`);
    const { result } = await timed();
    expect(result.declarations).toEqual([]);
    expect(result.skipped.length + result.parsed.length).toBe(1);
  });

  it("Helm values with an image block 5k levels deep is not followed past the depth limit", async () => {
    await writeFile(join(work, "values.yaml"), `${"{a: ".repeat(5_000)}{image: {repository: node, tag: "22"}}${"}".repeat(5_000)}\n`);
    const { result } = await timed();
    expect(result.declarations).toEqual([]);
  });

  it("ARG A=${A} self-reference terminates", async () => {
    await writeFile(join(work, "Dockerfile"), "ARG A=${A}\nARG B=${A}${B}\nFROM node:${A}\nFROM ${B}\n");
    const { result } = await timed();
    expect(result.declarations.map((d) => d.precision)).toEqual(["unresolved"]);
  });

  it("a 10k-alias YAML is not expanded", async () => {
    const aliases = Array.from({ length: 10_000 }, () => "  - *a").join("\n");
    await writeFile(join(work, "docker-compose.yml"), `x-a: &a ["x", "y"]\nservices:\n  web:\n    image: node:22\n    list:\n${aliases.replace(/ {2}- /g, "      - ")}\n`);
    const { result, ms } = await timed();
    expect(result.declarations.map((d) => d.spec)).toEqual(["22"]);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("an alias bomb (nested anchors) is not expanded", async () => {
    let text = "a0: &a0 [x, x, x, x, x, x, x, x, x]\n";
    for (let index = 1; index < 30; index++) {
      const previous = `*a${index - 1}`;
      text += `a${index}: &a${index} [${Array.from({ length: 9 }, () => previous).join(", ")}]\n`;
    }
    text += "services:\n  web:\n    image: node:22\n";
    await writeFile(join(work, "docker-compose.yml"), text);
    const { result, ms } = await timed();
    expect(result.declarations.map((d) => d.spec)).toEqual(["22"]);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("caps documents per file at 256 with a note", async () => {
    await writeFile(join(work, "all.yaml"), "apiVersion: v1\nkind: Pod\n---\n".repeat(20_000));
    const { result } = await timed();
    expect(result.notes).toEqual(["all.yaml: more than 256 YAML documents; extra ignored"]);
    expect(result.skipped).toContainEqual({ file: "all.yaml", reason: "capped" });
    expect(result.parsed).not.toContain("all.yaml");
  });

  it("caps declarations per scan at 2000 and stops", async () => {
    for (let index = 0; index < 40; index++) {
      await mkdir(join(work, `d${String(index).padStart(2, "0")}`));
      await writeFile(join(work, `d${String(index).padStart(2, "0")}`, "Dockerfile"), "FROM node:22\n".repeat(70));
    }
    const { result } = await timed();
    expect(result.declarations).toHaveLength(2000);
    expect(result.notes.some((n) => n.includes("more than 2000 image declarations; extra ignored"))).toBe(true);
    expect(result.priorityNotes).toEqual([expect.stringContaining("more than 2000 image declarations; extra ignored")]);
  });

  it("bounds notes from many unresolved images", async () => {
    await writeFile(join(work, "Dockerfile"), "FROM node\n".repeat(100_000));
    const { result } = await timed();
    expect(result.notes.length).toBeLessThanOrEqual(65);
  });

  it("an ARG chain that would multiply (80 doublings) is bounded and later FROM lines are still read", async () => {
    const lines = ["ARG A0=" + "x".repeat(300)];
    for (let index = 1; index <= 80; index++) lines.push(`ARG A${index}=\${A${index - 1}}\${A${index - 1}}`);
    lines.push("FROM node:${A80}", "FROM node:22", "FROM python:${A1}");
    await writeFile(join(work, "Dockerfile"), lines.join("\n") + "\n");
    const { result, ms } = await timed();
    expect(result.parsed).toEqual(["Dockerfile"]);
    expect(result.skipped).toEqual([]);
    expect(result.declarations.map((d) => [d.line, d.spec.length <= 128, d.precision])).toEqual([
      [82, true, "unresolved"],
      [83, true, "floating"],
      [84, true, "unresolved"],
    ]);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("an ARG that doubles itself 60 times is bounded", async () => {
    const lines = ["ARG A=" + "x".repeat(2000)];
    for (let index = 0; index < 60; index++) lines.push("ARG A=${A}${A}");
    lines.push("FROM node:${A}", "FROM node:22");
    await writeFile(join(work, "Dockerfile"), lines.join("\n") + "\n");
    const { result, ms } = await timed();
    expect(result.parsed).toEqual(["Dockerfile"]);
    expect(result.declarations.map((d) => [d.line, d.precision])).toEqual([
      [62, "unresolved"],
      [63, "floating"],
    ]);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("a 500-line chain of ARG references repeated three levels deep is bounded", async () => {
    const lines = ["ARG A0=" + "x".repeat(400)];
    for (let level = 1; level <= 3; level++) {
      for (let index = 0; index < 500; index++) lines.push(`ARG A${level}=\${A${level - 1}}\${A${level - 1}}`);
    }
    lines.push("FROM node:${A3}", "FROM node:22");
    await writeFile(join(work, "Dockerfile"), lines.join("\n") + "\n");
    const { result, ms } = await timed();
    expect(result.parsed).toEqual(["Dockerfile"]);
    expect(result.declarations.map((d) => d.precision)).toEqual(["unresolved", "floating"]);
    expect(ms).toBeLessThan(15_000); // loose wall-clock bound: the pre-fix code took minutes or ran out of memory
  });

  it("an over-long ARG default is unresolved and a FROM using it says so", async () => {
    await writeFile(join(work, "Dockerfile"), `ARG BIG=${"9".repeat(600)}\nFROM node:\${BIG}\n`);
    const { result } = await timed();
    expect(result.declarations.map((d) => d.precision)).toEqual(["unresolved"]);
    expect(result.notes).toHaveLength(1);
    expect(result.notes[0]).toContain("BIG");
  });

  it("stops reading after 64 MiB in total and says so once", async () => {
    const line = "# " + "x".repeat(1022) + "\n";
    const body = line.repeat(1024).slice(0, 1_048_000);
    for (let index = 0; index < 70; index++) {
      await mkdir(join(work, `d${String(index).padStart(2, "0")}`));
      await writeFile(join(work, `d${String(index).padStart(2, "0")}`, "Dockerfile"), body);
    }
    const { result } = await timed();
    expect(result.skipped.filter((s) => s.reason === "budget")).toHaveLength(5);
    expect(result.skipped).toHaveLength(5);
    expect(result.notes.filter((n) => n.includes("budget"))).toHaveLength(1);
    expect(result.parsed).toHaveLength(65);
  });
});
