import { describe, expect, test } from "vitest";

import type { SynvoyaAdvisory } from "./types.js";
import { compareVersions, isAffected, schemeFor, type VersionScheme } from "./versions.js";

type Affected = SynvoyaAdvisory["affected"];

const sign = (n: number | undefined): number | undefined => (n === undefined ? undefined : Math.sign(n));

describe("compareVersions per scheme", () => {
  test("semver orders numerically and puts a prerelease below its release", () => {
    expect(compareVersions("semver", "22.11.0", "22.12.0")).toBeLessThan(0);
    expect(compareVersions("semver", "22.9.0", "22.10.0")).toBeLessThan(0);
    expect(compareVersions("semver", "22.12.0-rc.1", "22.12.0")).toBeLessThan(0);
    expect(compareVersions("semver", "1.0.0-alpha", "1.0.0-alpha.1")).toBeLessThan(0);
    expect(compareVersions("semver", "1.0.0-alpha.1", "1.0.0-alpha.beta")).toBeLessThan(0);
    expect(compareVersions("semver", "v22.11.0", "22.11.0")).toBe(0);
    expect(compareVersions("semver", "1.0.0+build.5", "1.0.0")).toBe(0);
  });

  test("php orders patch numbers numerically and RC below the release", () => {
    expect(compareVersions("php", "8.3.9", "8.3.10")).toBeLessThan(0);
    expect(compareVersions("php", "8.4.0RC1", "8.4.0")).toBeLessThan(0);
    expect(compareVersions("php", "8.4.0RC1", "8.4.0-RC2")).toBeLessThan(0);
    expect(compareVersions("php", "8.4.0alpha1", "8.4.0beta1")).toBeLessThan(0);
    expect(compareVersions("php", "8.4.0", "8.4.0pl1")).toBeLessThan(0);
  });

  test("pep440 orders pre, final, post and dev releases", () => {
    expect(compareVersions("pep440", "3.12.0rc1", "3.12.0")).toBeLessThan(0);
    expect(compareVersions("pep440", "3.12.0a1", "3.12.0b1")).toBeLessThan(0);
    expect(compareVersions("pep440", "1.0.dev1", "1.0a1")).toBeLessThan(0);
    expect(compareVersions("pep440", "1.0", "1.0.post1")).toBeLessThan(0);
    expect(compareVersions("pep440", "1.0.post1.dev1", "1.0.post1")).toBeLessThan(0);
    expect(compareVersions("pep440", "1!0.1", "2.0")).toBeGreaterThan(0);
    expect(compareVersions("pep440", "3.12", "3.12.0")).toBe(0);
  });

  test("go accepts toolchain and module spellings", () => {
    expect(compareVersions("go", "go1.22.5", "go1.22.10")).toBeLessThan(0);
    expect(compareVersions("go", "1.22", "1.22.0")).toBe(0);
    expect(compareVersions("go", "go1.22.0", "1.22.0")).toBe(0);
    expect(compareVersions("go", "go1.23rc1", "go1.23.0")).toBeLessThan(0);
    expect(compareVersions("go", "v1.9.0", "v1.10.0")).toBeLessThan(0);
  });

  test("ruby puts a prerelease segment below the release", () => {
    expect(compareVersions("ruby", "3.3.0.preview1", "3.3.0")).toBeLessThan(0);
    expect(compareVersions("ruby", "3.3.4", "3.3.10")).toBeLessThan(0);
    expect(compareVersions("ruby", "3.3", "3.3.0")).toBe(0);
    expect(compareVersions("ruby", "3.3.0.preview1", "3.3.0.preview2")).toBeLessThan(0);
  });

  test("java normalises the legacy 1.8.0_401 and 8u401 spellings", () => {
    expect(compareVersions("java", "17.0.9", "17.0.12")).toBeLessThan(0);
    expect(compareVersions("java", "1.8.0_401", "8u401")).toBe(0);
    expect(compareVersions("java", "1.8.0_391", "8u401")).toBeLessThan(0);
    expect(compareVersions("java", "8u401", "11.0.1")).toBeLessThan(0);
    expect(compareVersions("java", "21", "21.0.4")).toBeLessThan(0);
    expect(compareVersions("java", "21", "21.0.0")).toBe(0);
    expect(compareVersions("java", "21.0.4+7", "21.0.4")).toBe(0);
    expect(compareVersions("java", "21-ea", "21")).toBeLessThan(0);
  });

  test("maven orders library versions numerically, never as a JDK with a legacy leading 1", () => {
    expect(compareVersions("maven", "1.9.0", "2.3.0")).toBeLessThan(0);
    expect(compareVersions("maven", "1.2.17", "2.14.1")).toBeLessThan(0);
    expect(compareVersions("maven", "1.9.0", "1.10.0")).toBeLessThan(0);
    expect(compareVersions("maven", "5.3.39", "6.0.0")).toBeLessThan(0);
    expect(compareVersions("maven", "5.2.9.RELEASE", "5.2.9")).toBe(0);
    expect(compareVersions("maven", "1.0.Final", "1.0")).toBe(0);
    expect(compareVersions("maven", "1", "1.0.0")).toBe(0);
    expect(compareVersions("maven", "2.0.0-M1", "2.0.0-RC1")).toBeLessThan(0);
    expect(compareVersions("maven", "2.0.0-RC1", "2.0.0")).toBeLessThan(0);
    expect(compareVersions("maven", "9.0.0.M1", "9.0.0")).toBeLessThan(0);
    expect(compareVersions("maven", "1.0-SNAPSHOT", "1.0")).toBeLessThan(0);
    expect(compareVersions("maven", "1.0", "1.0-sp1")).toBeLessThan(0);
    expect(compareVersions("maven", "1.0-alpha-2", "1.0-beta-1")).toBeLessThan(0);
    expect(compareVersions("maven", "1.0-alpha-1", "1.0-alpha-2")).toBeLessThan(0);
    // the java scheme is the JDK: 1.8 means Java 8 there and nowhere else
    expect(compareVersions("java", "1.9.0", "2.3.0")).toBeGreaterThan(0);
  });

  test("maven: unknown qualifiers are not comparable", () => {
    expect(compareVersions("maven", "32.0.0-jre", "32.0.0")).toBeUndefined();
    expect(compareVersions("maven", "1.0-foo", "1.0")).toBeUndefined();
  });

  test("ruby follows Gem::Version: a lettered segment is a prerelease at its own position", () => {
    expect(compareVersions("ruby", "3.3.0.1a", "3.3.0")).toBeGreaterThan(0);
    expect(compareVersions("ruby", "3.3.0.1a", "3.3.0.1")).toBeLessThan(0);
    expect(compareVersions("ruby", "3.3.0.preview1", "3.3.0")).toBeLessThan(0);
  });

  test("magento orders patches after the base release and below the next release", () => {
    expect(compareVersions("magento", "2.4.7-p2", "2.4.7-p3")).toBeLessThan(0);
    expect(compareVersions("magento", "2.4.7-p3", "2.4.8")).toBeLessThan(0);
    expect(compareVersions("magento", "2.4.7", "2.4.7-p1")).toBeLessThan(0);
    expect(compareVersions("magento", "2.4.7-p9", "2.4.7-p10")).toBeLessThan(0);
    expect(compareVersions("magento", "2.4.8-beta1", "2.4.8")).toBeLessThan(0);
  });

  test("dotnet compares four-part and prerelease versions", () => {
    expect(compareVersions("dotnet", "8.0.10", "8.0.11")).toBeLessThan(0);
    expect(compareVersions("dotnet", "8.0.0-rc.2.24473.5", "8.0.0")).toBeLessThan(0);
    expect(compareVersions("dotnet", "8.0", "8.0.0.0")).toBe(0);
    expect(compareVersions("dotnet", "8.0.0-RC.1", "8.0.0-rc.1")).toBe(0);
  });

  test("generic compares dot-separated numbers only", () => {
    expect(compareVersions("generic", "1.2", "1.10")).toBeLessThan(0);
    expect(compareVersions("generic", "1.2", "1.2.0")).toBe(0);
    expect(compareVersions("generic", "1.2.x", "1.2.0")).toBeUndefined();
  });

  const GARBAGE = ["latest", "lts/*", "${X}", "", "   ", "^1.2.3", ">=1.0", "1.2.3.4.5.6.7.8.9".repeat(30), "99999999999999999999.0.0"];
  const SCHEMES: VersionScheme[] = ["semver", "php", "pep440", "go", "ruby", "dotnet", "java", "maven", "magento", "generic"];

  test.each(SCHEMES)("%s returns undefined (not comparable) for garbage on either side", (scheme) => {
    for (const bad of GARBAGE) {
      expect(compareVersions(scheme, bad, "1.0.0"), `${scheme} ${JSON.stringify(bad.slice(0, 20))} left`).toBeUndefined();
      expect(compareVersions(scheme, "1.0.0", bad), `${scheme} ${JSON.stringify(bad.slice(0, 20))} right`).toBeUndefined();
    }
  });

  test("semver does not guess partial versions", () => {
    expect(compareVersions("semver", "22", "22.0.0")).toBeUndefined();
    expect(compareVersions("semver", "22.11", "22.11.0")).toBeUndefined();
  });
});

describe("compareVersions order properties", () => {
  // Each list is written in strictly ascending order, so the expected sign is known independently of the implementation.
  const ASCENDING: Record<VersionScheme, string[]> = {
    semver: ["0.0.1", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "1.9.0", "1.10.0", "2.0.0"],
    php: ["7.4.33", "8.0.0dev", "8.0.0alpha1", "8.0.0beta2", "8.0.0RC1", "8.0.0RC2", "8.0.0", "8.0.0pl1", "8.0.1", "8.3.9", "8.3.10", "8.4.0RC1", "8.4.0"],
    pep440: ["0.9", "1.0.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1.dev1", "1.0.post1", "1.0.1", "1.10", "1!0.1"],
    go: ["1.20.14", "1.21rc2", "1.21.0", "1.22.0", "1.22.5", "1.22.10", "1.23rc1", "1.23.0"],
    ruby: ["2.7.8", "3.3.0.preview1", "3.3.0.preview2", "3.3.0.rc1", "3.3.0", "3.3.0.1a", "3.3.0.1", "3.3.1", "3.3.10", "3.4.0"],
    dotnet: ["6.0.36", "8.0.0-preview.1", "8.0.0-rc.1", "8.0.0-rc.2", "8.0.0", "8.0.0.1", "8.0.10", "8.0.11", "9.0.0"],
    java: ["1.7.0_80", "8", "8u391", "8u401", "11.0.1", "17.0.9", "17.0.12", "21-ea", "21", "21.0.4", "21.1"],
    maven: ["0.9", "1.0-alpha-1", "1.0-beta-1", "1.0-m1", "1.0-rc1", "1.0-snapshot", "1.0", "1.0-sp1", "1.0.1", "1.2.17", "1.9.0", "1.10.0", "2.0.0-M1", "2.0.0-RC1", "2.0.0", "2.14.1", "5.2.9.RELEASE", "5.3.39", "6.0.0"],
    magento: ["2.4.6-p13", "2.4.7-beta1", "2.4.7-rc1", "2.4.7", "2.4.7-p1", "2.4.7-p2", "2.4.7-p10", "2.4.8"],
    generic: ["0.1", "1", "1.0.1", "1.2", "1.10", "2"],
  };

  test.each(SCHEMES_OF(ASCENDING))("%s: list is strictly ascending, reflexive, antisymmetric and transitive", (scheme) => {
    const list = ASCENDING[scheme];
    const at = (n: number): string => list[n] ?? "";
    for (let i = 0; i < list.length; i++) {
      expect(compareVersions(scheme, at(i), at(i)), `${scheme} ${at(i)} reflexive`).toBe(0);
      for (let j = 0; j < list.length; j++) {
        const ab = sign(compareVersions(scheme, at(i), at(j)));
        const ba = sign(compareVersions(scheme, at(j), at(i)));
        expect(ab, `${scheme} ${at(i)} vs ${at(j)} defined`).not.toBeUndefined();
        expect(ab, `${scheme} antisymmetry ${at(i)} / ${at(j)}`).toBe(-(ba as number) || 0);
        if (i !== j) {
          expect(ab, `${scheme} ${at(i)} vs ${at(j)} follows list order`).toBe(i < j ? -1 : 1);
        }
        for (let k = 0; k < list.length; k++) {
          const bc = sign(compareVersions(scheme, at(j), at(k)));
          const ac = sign(compareVersions(scheme, at(i), at(k)));
          if (ab !== undefined && bc !== undefined && ab <= 0 && bc <= 0) {
            expect(ac, `${scheme} transitivity ${at(i)} <= ${at(j)} <= ${at(k)}`).toBeLessThanOrEqual(0);
          }
        }
      }
    }
  });
});

function SCHEMES_OF(table: Record<VersionScheme, string[]>): VersionScheme[] {
  return Object.keys(table) as VersionScheme[];
}

describe("isAffected", () => {
  test("introduced..fixed is inclusive at the start and exclusive at the fix", () => {
    const ranges: Affected = [{ events: [{ introduced: "20.0.0" }, { fixed: "20.18.1" }] }];
    expect(isAffected("semver", "19.9.9", ranges)).toBe(false);
    expect(isAffected("semver", "20.0.0", ranges)).toBe(true);
    expect(isAffected("semver", "20.18.0", ranges)).toBe(true);
    expect(isAffected("semver", "20.18.1", ranges)).toBe(false);
    expect(isAffected("semver", "21.0.0", ranges)).toBe(false);
  });

  test("introduced 0 means from the beginning", () => {
    const ranges: Affected = [{ events: [{ introduced: "0" }, { fixed: "3.12.4" }] }];
    expect(isAffected("pep440", "0.0.1", ranges)).toBe(true);
    expect(isAffected("pep440", "3.12.3", ranges)).toBe(true);
    expect(isAffected("pep440", "3.12.4", ranges)).toBe(false);
  });

  test("last_affected is inclusive", () => {
    const ranges: Affected = [{ events: [{ introduced: "0" }, { last_affected: "8.1.29" }] }];
    expect(isAffected("php", "8.1.29", ranges)).toBe(true);
    expect(isAffected("php", "8.1.30", ranges)).toBe(false);
  });

  test("introduced and last_affected at the same version is exactly that version (an OSV point range)", () => {
    // Malware entries list exact versions this way; the next release must never read as affected.
    const ranges: Affected = [
      { events: [{ introduced: "1.82.7" }, { last_affected: "1.82.7" }] },
      { events: [{ introduced: "1.107.0" }, { last_affected: "1.107.0" }] },
    ];
    expect(isAffected("pep440", "1.82.7", ranges)).toBe(true);
    expect(isAffected("pep440", "1.107.0", ranges)).toBe(true);
    expect(isAffected("pep440", "1.82.8", ranges)).toBe(false);
    expect(isAffected("pep440", "1.106.2", ranges)).toBe(false);
    expect(isAffected("pep440", "1.107.1", ranges)).toBe(false);
    // Listed in reverse, the result is the same.
    expect(isAffected("pep440", "1.107.1", [{ events: [{ last_affected: "1.107.0" }, { introduced: "1.107.0" }] }])).toBe(false);
    // last_affected X then introduced X inside an open interval is contiguous: the next interval stays affected.
    const contiguous: Affected = [{ events: [{ introduced: "1.0.0" }, { last_affected: "2.0.0" }, { introduced: "2.0.0" }, { fixed: "2.1.0" }] }];
    expect(isAffected("semver", "1.5.0", contiguous)).toBe(true);
    expect(isAffected("semver", "2.0.0", contiguous)).toBe(true);
    expect(isAffected("semver", "2.0.5", contiguous)).toBe(true);
    expect(isAffected("semver", "2.1.0", contiguous)).toBe(false);
    // A fix at the version where the next interval opens still ends the previous one first.
    const reopen: Affected = [{ events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }, { introduced: "2.0.0" }, { fixed: "2.1.0" }] }];
    expect(isAffected("semver", "2.0.0", reopen)).toBe(true);
  });

  test("an introduced event with no end is open-ended", () => {
    expect(isAffected("semver", "99.0.0", [{ events: [{ introduced: "5.0.0" }] }])).toBe(true);
    expect(isAffected("semver", "4.9.9", [{ events: [{ introduced: "5.0.0" }] }])).toBe(false);
  });

  test("limit caps the interval like fixed", () => {
    const ranges: Affected = [{ events: [{ introduced: "1.0.0" }, { limit: "1.5.0" }] }];
    expect(isAffected("semver", "1.4.9", ranges)).toBe(true);
    expect(isAffected("semver", "1.5.0", ranges)).toBe(false);
  });

  test("events are evaluated in version order whatever order they are listed", () => {
    const ranges: Affected = [{ events: [{ fixed: "2.0.0" }, { introduced: "1.0.0" }] }];
    expect(isAffected("semver", "1.5.0", ranges)).toBe(true);
    expect(isAffected("semver", "2.0.0", ranges)).toBe(false);
  });

  test("multiple lines: each element is restricted to its own release line", () => {
    const ranges: Affected = [
      { line: "22", events: [{ introduced: "22.0.0" }, { fixed: "22.12.0" }] },
      { line: "20", events: [{ introduced: "20.0.0" }, { fixed: "20.18.1" }] },
    ];
    expect(isAffected("semver", "22.11.0", ranges)).toBe(true);
    expect(isAffected("semver", "22.12.0", ranges)).toBe(false);
    expect(isAffected("semver", "20.18.0", ranges)).toBe(true);
    expect(isAffected("semver", "20.18.1", ranges)).toBe(false);
  });

  test("a version on an unlisted line is not affected", () => {
    const ranges: Affected = [
      { line: "22", events: [{ introduced: "22.0.0" }, { fixed: "22.12.0" }] },
      { line: "20", events: [{ introduced: "20.0.0" }, { fixed: "20.18.1" }] },
    ];
    expect(isAffected("semver", "18.0.0", ranges)).toBe(false);
    expect(isAffected("semver", "21.5.0", ranges)).toBe(false);
  });

  test("a two-component line matches major and minor", () => {
    const ranges: Affected = [{ line: "8.3", events: [{ introduced: "0" }, { fixed: "8.3.10" }] }];
    expect(isAffected("php", "8.3.9", ranges)).toBe(true);
    expect(isAffected("php", "8.3.10", ranges)).toBe(false);
    expect(isAffected("php", "8.30.0", ranges)).toBe(false);
    expect(isAffected("php", "8.2.0", ranges)).toBe(false);
  });

  test("a line restriction uses the normalised Java release", () => {
    const ranges: Affected = [{ line: "8", events: [{ introduced: "0" }, { fixed: "8u401" }] }];
    expect(isAffected("java", "1.8.0_391", ranges)).toBe(true);
    expect(isAffected("java", "8u401", ranges)).toBe(false);
    expect(isAffected("java", "11.0.1", ranges)).toBe(false);
  });

  test("maven: a known-affected 1.x library version is affected", () => {
    const ranges: Affected = [{ events: [{ introduced: "0" }, { fixed: "2.3.0" }] }];
    expect(isAffected("maven", "1.9.0", ranges)).toBe(true);
    expect(isAffected("maven", "2.3.0", ranges)).toBe(false);
    expect(isAffected("maven", "1.2.17", [{ events: [{ introduced: "0" }, { fixed: "2.14.1" }] }])).toBe(true);
  });

  test("java runtime line 1.8 is the same line as 8", () => {
    const ranges: Affected = [{ line: "1.8", events: [{ introduced: "0" }, { fixed: "8u401" }] }];
    expect(isAffected("java", "1.8.0_391", ranges)).toBe(true);
    expect(isAffected("java", "8u391", ranges)).toBe(true);
    expect(isAffected("java", "8u401", ranges)).toBe(false);
    expect(isAffected("java", "11.0.1", ranges)).toBe(false);
  });

  test("an element with empty events, or with no introduced event, is unknown, not false", () => {
    expect(isAffected("semver", "1.0.0", [{ events: [] }])).toBeUndefined();
    expect(isAffected("semver", "1.0.0", [{ events: [{ fixed: "2.0.0" }] }])).toBeUndefined();
    expect(isAffected("semver", "1.0.0", [{ events: [{ last_affected: "2.0.0" }] }])).toBeUndefined();
  });

  test("magento patch levels", () => {
    const ranges: Affected = [{ line: "2.4.7", events: [{ introduced: "0" }, { fixed: "2.4.7-p3" }] }];
    expect(isAffected("magento", "2.4.7", ranges)).toBe(true);
    expect(isAffected("magento", "2.4.7-p2", ranges)).toBe(true);
    expect(isAffected("magento", "2.4.7-p3", ranges)).toBe(false);
    expect(isAffected("magento", "2.4.8", ranges)).toBe(false);
  });

  test("an unparseable version is unknown, never affected", () => {
    const ranges: Affected = [{ events: [{ introduced: "0" }, { fixed: "22.12.0" }] }];
    for (const bad of ["latest", "lts/*", "${X}", "22", ""]) {
      expect(isAffected("semver", bad, ranges), bad).toBeUndefined();
    }
  });

  test("an unparseable event is unknown, but another element can still prove affected", () => {
    const broken: Affected = [{ events: [{ introduced: "0" }, { fixed: "not-a-version" }] }];
    expect(isAffected("semver", "1.0.0", broken)).toBeUndefined();
    const mixed: Affected = [...broken, { events: [{ introduced: "0" }, { fixed: "2.0.0" }] }];
    expect(isAffected("semver", "1.0.0", mixed)).toBe(true);
  });

  test("an unparseable line is unknown", () => {
    expect(isAffected("semver", "1.0.0", [{ line: "x", events: [{ introduced: "0" }] }])).toBeUndefined();
  });

  test("malformed events (none or several boundaries) are unknown", () => {
    const none = [{ events: [{} as never] }] as Affected;
    const two = [{ events: [{ introduced: "0", fixed: "1.0.0" } as never] }] as Affected;
    expect(isAffected("semver", "0.5.0", none)).toBeUndefined();
    expect(isAffected("semver", "0.5.0", two)).toBeUndefined();
  });

  test("no ranges means nothing is proven affected", () => {
    expect(isAffected("semver", "1.0.0", [])).toBe(false);
  });
});

describe("schemeFor", () => {
  test("runtimes", () => {
    const cases: Array<[SynvoyaAdvisory["target"], VersionScheme]> = [
      [{ type: "runtime", runtime: "node" }, "semver"],
      [{ type: "runtime", runtime: "php" }, "php"],
      [{ type: "runtime", runtime: "python" }, "pep440"],
      [{ type: "runtime", runtime: "ruby" }, "ruby"],
      [{ type: "runtime", runtime: "go" }, "go"],
      [{ type: "runtime", runtime: "dotnet" }, "dotnet"],
      [{ type: "runtime", runtime: "java" }, "java"],
    ];
    for (const [target, scheme] of cases) expect(schemeFor(target)).toBe(scheme);
  });

  test("products", () => {
    expect(schemeFor({ type: "product", product: "adobe-commerce" })).toBe("magento");
    expect(schemeFor({ type: "product", product: "magento-open-source" })).toBe("magento");
    expect(schemeFor({ type: "product", product: "wordpress" })).toBe("generic");
  });

  test("package ecosystems", () => {
    const cases: Array<[string, VersionScheme]> = [
      ["npm", "semver"], ["Packagist", "php"], ["PyPI", "pep440"], ["RubyGems", "ruby"],
      ["Go", "go"], ["NuGet", "dotnet"], ["Maven", "maven"], ["GitHub Actions", "semver"], ["crates.io", "generic"], ["", "generic"],
    ];
    for (const [ecosystem, scheme] of cases) {
      expect(schemeFor({ type: "package", ecosystem, name: "x" }), ecosystem).toBe(scheme);
    }
  });
});
