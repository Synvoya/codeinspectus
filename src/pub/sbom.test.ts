import { describe, expect, it } from "vitest";

import {
  generatePubSbom,
  mergePubSbom,
  pubPackagePurl,
  selectOfficialHostedPubPackages,
  type PubSbomPackage,
} from "./sbom.js";

const VALID_SHA256 = "A".repeat(64);

function lockPackage(overrides: Partial<PubSbomPackage> = {}): PubSbomPackage {
  return {
    name: "archive",
    version: "3.3.7",
    version_line: 12,
    dependency: "direct main",
    direct: true,
    source: "hosted",
    description: {
      name: "archive",
      url: "https://pub.dev",
      sha256: VALID_SHA256,
    },
    registry: "official",
    lockfile: "apps/mobile/pubspec.lock",
    ...overrides,
  };
}

function object(value: unknown): Record<string, unknown> {
  expect(value).not.toBeNull();
  expect(typeof value).toBe("object");
  expect(Array.isArray(value)).toBe(false);
  return value as Record<string, unknown>;
}

function array(value: unknown): unknown[] {
  expect(Array.isArray(value)).toBe(true);
  return value as unknown[];
}

describe("native Pub SBOM generation", () => {
  it("selects official hosted packages and builds deterministic CycloneDX 1.6 components", () => {
    const packages = [
      lockPackage({ lockfile: "z/pubspec.lock" }),
      lockPackage({
        version_line: 40,
        dependency: "transitive",
        direct: false,
        lockfile: "a/pubspec.lock",
        description: { name: "archive", url: "https://pub.dev", sha256: VALID_SHA256.toLowerCase() },
      }),
      lockPackage({
        name: "jose",
        version: "0.3.5+1",
        description: { name: "jose", url: "https://pub.dev", sha256: "not-a-digest" },
      }),
      lockPackage({
        name: "archive",
        registry: "custom",
        description: { name: "archive", url: "https://packages.example.test" },
      }),
      lockPackage({
        name: "local_package",
        source: "path",
        registry: "non_hosted",
        description: {},
      }),
      lockPackage({ name: "Invalid-Name" }),
      lockPackage({
        name: "_fe_analyzer_shared",
        version: "31.0.0",
        description: { name: "_fe_analyzer_shared", url: "https://pub.dev" },
      }),
    ];

    expect(selectOfficialHostedPubPackages(packages)).toHaveLength(5);
    expect(pubPackagePurl("jose", "0.3.5+1")).toBe("pkg:pub/jose@0.3.5%2B1");

    const generated = generatePubSbom(packages, "cyclonedx");
    const repeated = generatePubSbom([...packages].reverse(), "cyclonedx");
    expect(repeated).toEqual(generated);
    expect(generated.coverage).toEqual({
      input_package_count: 7,
      official_hosted_package_count: 5,
      native_component_count: 3,
      duplicate_component_count: 1,
      skipped_non_official_count: 2,
      skipped_invalid_identity_count: 1,
      invalid_sha256_count: 1,
    });
    expect(generated.limitations).toEqual(expect.arrayContaining([
      expect.stringContaining("official Pub registry"),
      expect.stringContaining("Dependency relationships are not emitted"),
      expect.stringContaining("licenses and suppliers are not inferred"),
      expect.stringContaining("2 non-official or non-hosted"),
      expect.stringContaining("malformed SHA-256"),
    ]));

    const document = generated.document;
    expect(document).toMatchObject({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
    });
    expect(document).not.toHaveProperty("dependencies");
    const components = array(document.components).map(object);
    expect(components.map((component) => component.purl)).toEqual([
      "pkg:pub/_fe_analyzer_shared@31.0.0",
      "pkg:pub/archive@3.3.7",
      "pkg:pub/jose@0.3.5%2B1",
    ]);

    const archive = components[1]!;
    expect(archive).not.toHaveProperty("licenses");
    expect(archive).not.toHaveProperty("supplier");
    expect(archive.hashes).toEqual([{ alg: "SHA-256", content: VALID_SHA256.toLowerCase() }]);
    expect(archive.properties).toEqual([
      { name: "codeinspectus:pub:dependency", value: "direct main" },
      { name: "codeinspectus:pub:dependency", value: "transitive" },
      { name: "codeinspectus:pub:direct", value: "true" },
      { name: "codeinspectus:pub:direct", value: "false" },
      { name: "codeinspectus:pub:lockfile", value: "a/pubspec.lock" },
      { name: "codeinspectus:pub:lockfile", value: "z/pubspec.lock" },
    ]);
    expect(components[2]).not.toHaveProperty("hashes");
  });

  it("builds a deterministic minimal SPDX 2.3 document without inferred package metadata", () => {
    const packages = [
      lockPackage({
        name: "jose",
        version: "0.3.5+1",
        description: { name: "jose", url: "https://pub.dev", sha256: VALID_SHA256 },
      }),
    ];
    const options = {
      created: "2026-07-27T00:00:00.000Z",
      document_name: "mobile Pub dependencies",
    };

    const generated = generatePubSbom(packages, "spdx", options);
    expect(generatePubSbom(packages, "spdx", options)).toEqual(generated);
    expect(generated.document).toMatchObject({
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: "mobile Pub dependencies",
      creationInfo: {
        created: options.created,
        creators: ["Tool: CodeInspectus"],
      },
    });
    expect(generated.document.documentNamespace).toMatch(
      /^https:\/\/codeinspectus\.com\/sbom\/pub\/[a-f0-9]{64}$/,
    );
    expect(generated.document).not.toHaveProperty("relationships");

    const pkg = object(array(generated.document.packages)[0]);
    expect(pkg).toMatchObject({
      name: "jose",
      versionInfo: "0.3.5+1",
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      externalRefs: [
        {
          referenceCategory: "PACKAGE-MANAGER",
          referenceType: "purl",
          referenceLocator: "pkg:pub/jose@0.3.5%2B1",
        },
      ],
    });
    expect(pkg).not.toHaveProperty("supplier");
    expect(pkg).not.toHaveProperty("licenseConcluded");
    expect(pkg).not.toHaveProperty("licenseDeclared");
    expect(pkg.comment).toContain('"dependencies":["direct main"]');
    expect(pkg.comment).toContain('"lockfiles":["apps/mobile/pubspec.lock"]');

    expect(() => generatePubSbom(packages, "spdx")).toThrow(
      "requires an RFC 3339 UTC created timestamp",
    );
  });
});

describe("native Pub SBOM merge", () => {
  it("enriches the first matching CycloneDX component and preserves every Trivy field/component", () => {
    const existing = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: "urn:uuid:trivy-kept",
      version: 7,
      metadata: { timestamp: "2026-07-26T10:00:00Z", tools: [{ name: "trivy" }] },
      components: [
        {
          type: "library",
          "bom-ref": "trivy-archive-first",
          name: "archive",
          version: "3.3.7",
          purl: "pkg:pub/archive@3.3.7",
          hashes: [{ alg: "SHA-1", content: "abc" }],
          licenses: [{ license: { id: "BSD-3-Clause" } }],
          properties: [{ name: "aquasecurity:trivy:LayerDigest", value: "sha256:layer" }],
        },
        {
          type: "library",
          "bom-ref": "trivy-archive-duplicate-kept",
          name: "archive",
          version: "3.3.7",
          purl: "pkg:pub/archive@3.3.7",
          properties: [{ name: "trivy:duplicate", value: "keep" }],
        },
        {
          type: "library",
          name: "left-pad",
          version: "1.3.0",
          purl: "pkg:npm/left-pad@1.3.0",
        },
      ],
    };
    const before = JSON.stringify(existing);
    const packages = [
      lockPackage({ lockfile: "z/pubspec.lock" }),
      lockPackage({ dependency: "transitive", direct: false, lockfile: "a/pubspec.lock" }),
      lockPackage({
        name: "jose",
        version: "0.3.5+1",
        description: { name: "jose", url: "https://pub.dev" },
      }),
    ];

    const result = mergePubSbom(existing, packages, "cyclonedx");
    expect(JSON.stringify(existing)).toBe(before);
    expect(result.added_component_count).toBe(1);
    expect(result.merged_component_count).toBe(1);
    expect(result.document.serialNumber).toBe(existing.serialNumber);
    expect(result.document.metadata).toBe(existing.metadata);
    expect(result.document.specVersion).toBe("1.5");
    expect(result.document.version).toBe(7);

    const components = array(result.document.components).map(object);
    expect(components).toHaveLength(4);
    expect(components[0]).toMatchObject({
      "bom-ref": "trivy-archive-first",
      licenses: [{ license: { id: "BSD-3-Clause" } }],
    });
    expect(array(components[0]!.hashes)).toEqual([
      { alg: "SHA-1", content: "abc" },
      { alg: "SHA-256", content: VALID_SHA256.toLowerCase() },
    ]);
    expect(array(components[0]!.properties)).toEqual(expect.arrayContaining([
      { name: "aquasecurity:trivy:LayerDigest", value: "sha256:layer" },
      { name: "codeinspectus:pub:lockfile", value: "a/pubspec.lock" },
      { name: "codeinspectus:pub:lockfile", value: "z/pubspec.lock" },
    ]));
    expect(components[1]).toEqual(existing.components[1]);
    expect(components[2]).toEqual(existing.components[2]);
    expect(components[3]!.purl).toBe("pkg:pub/jose@0.3.5%2B1");

    expect(mergePubSbom(existing, [...packages].reverse(), "cyclonedx")).toEqual(result);
  });

  it("merges SPDX purls canonically and retains Trivy namespace, creation metadata, and relationships", () => {
    const existing = {
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: "Trivy report",
      documentNamespace: "https://trivy.example.test/report/123",
      creationInfo: {
        created: "2026-07-26T10:00:00Z",
        creators: ["Tool: Trivy-0.65.0"],
      },
      packages: [
        {
          SPDXID: "SPDXRef-Trivy-jose",
          name: "jose",
          versionInfo: "0.3.5+1",
          downloadLocation: "NOASSERTION",
          filesAnalyzed: false,
          licenseConcluded: "MIT",
          licenseDeclared: "MIT",
          copyrightText: "NOASSERTION",
          supplier: "NOASSERTION",
          checksums: [{ algorithm: "SHA1", checksumValue: "abc" }],
          externalRefs: [
            {
              referenceCategory: "PACKAGE-MANAGER",
              referenceType: "purl",
              referenceLocator: "pkg:pub/jose@0.3.5+1",
            },
          ],
          comment: "Trivy package metadata remains intact.",
        },
      ],
      relationships: [
        {
          spdxElementId: "SPDXRef-DOCUMENT",
          relationshipType: "DESCRIBES",
          relatedSpdxElement: "SPDXRef-Trivy-jose",
        },
      ],
    };
    const before = JSON.stringify(existing);
    const packages = [
      lockPackage({
        name: "jose",
        version: "0.3.5+1",
        description: { name: "jose", url: "https://pub.dev", sha256: VALID_SHA256 },
      }),
      lockPackage(),
    ];

    const result = mergePubSbom(existing, packages, "spdx");
    expect(JSON.stringify(existing)).toBe(before);
    expect(result.added_component_count).toBe(1);
    expect(result.merged_component_count).toBe(1);
    expect(result.document.documentNamespace).toBe(existing.documentNamespace);
    expect(result.document.creationInfo).toBe(existing.creationInfo);
    expect(result.document.relationships).toBe(existing.relationships);

    const mergedPackages = array(result.document.packages).map(object);
    expect(mergedPackages).toHaveLength(2);
    const jose = mergedPackages[0]!;
    expect(jose.SPDXID).toBe("SPDXRef-Trivy-jose");
    expect(jose.licenseConcluded).toBe("MIT");
    expect(jose.licenseDeclared).toBe("MIT");
    expect(jose.supplier).toBe("NOASSERTION");
    expect(jose.checksums).toEqual([
      { algorithm: "SHA1", checksumValue: "abc" },
      { algorithm: "SHA256", checksumValue: VALID_SHA256.toLowerCase() },
    ]);
    expect(array(jose.externalRefs)).toHaveLength(1);
    expect(jose.comment).toContain("Trivy package metadata remains intact.");
    expect(jose.comment).toContain("CodeInspectus Pub lockfile metadata:");
    expect(mergedPackages[1]!.name).toBe("archive");
  });

  it("fails closed instead of overwriting malformed component collections", () => {
    expect(() => mergePubSbom({ components: "not-an-array" }, [lockPackage()], "cyclonedx"))
      .toThrow("CycloneDX components must be an array");
    expect(() => mergePubSbom({ packages: {} }, [lockPackage()], "spdx"))
      .toThrow("SPDX packages must be an array");
  });

  it("does not coordinate-merge an explicit non-Pub purl with the same name and version", () => {
    const cyclone = mergePubSbom(
      {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        components: [
          {
            type: "library",
            name: "archive",
            version: "3.3.7",
            purl: "pkg:npm/archive@3.3.7",
          },
        ],
      },
      [lockPackage()],
      "cyclonedx",
    );
    expect(cyclone.added_component_count).toBe(1);
    expect(cyclone.merged_component_count).toBe(0);
    expect(array(cyclone.document.components).map((entry) => object(entry).purl)).toEqual([
      "pkg:npm/archive@3.3.7",
      "pkg:pub/archive@3.3.7",
    ]);

    const spdx = mergePubSbom(
      {
        spdxVersion: "SPDX-2.3",
        packages: [
          {
            SPDXID: "SPDXRef-NpmArchive",
            name: "archive",
            versionInfo: "3.3.7",
            externalRefs: [
              {
                referenceCategory: "PACKAGE-MANAGER",
                referenceType: "purl",
                referenceLocator: "pkg:npm/archive@3.3.7",
              },
            ],
          },
        ],
      },
      [lockPackage()],
      "spdx",
    );
    expect(spdx.added_component_count).toBe(1);
    expect(spdx.merged_component_count).toBe(0);
    expect(array(spdx.document.packages)).toHaveLength(2);
  });

  it("does not coordinate-merge an ecosystem-unknown component with a Pub package", () => {
    const cyclone = mergePubSbom(
      {
        bomFormat: "CycloneDX",
        specVersion: "1.6",
        components: [{ type: "library", name: "archive", version: "3.3.7" }],
      },
      [lockPackage()],
      "cyclonedx",
    );
    expect(cyclone.added_component_count).toBe(1);
    expect(cyclone.merged_component_count).toBe(0);
    expect(array(cyclone.document.components)).toHaveLength(2);

    const spdx = mergePubSbom(
      {
        spdxVersion: "SPDX-2.3",
        packages: [{ SPDXID: "SPDXRef-UnknownArchive", name: "archive", versionInfo: "3.3.7" }],
      },
      [lockPackage()],
      "spdx",
    );
    expect(spdx.added_component_count).toBe(1);
    expect(spdx.merged_component_count).toBe(0);
    expect(array(spdx.document.packages)).toHaveLength(2);
  });
});
