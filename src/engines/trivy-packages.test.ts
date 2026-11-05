import { describe, expect, it } from "vitest";

import { trivyReportPackages } from "./trivy.js";

describe("trivyReportPackages (the Synvoya inventory from Trivy's --list-all-pkgs report)", () => {
  it("lists every package of a lockfile result with its OSV ecosystem, file and line, vulnerable or not", () => {
    const report = {
      Results: [
        {
          Target: "web/package-lock.json",
          Class: "lang-pkgs",
          Type: "npm",
          Packages: [
            { Name: "lodash", Version: "4.17.4", Locations: [{ StartLine: 12, EndLine: 15 }] },
            { Name: "left-pad", Version: "1.3.0" },
          ],
          Vulnerabilities: [{ VulnerabilityID: "CVE-1", PkgName: "lodash" }],
        },
        { Target: "composer.lock", Class: "lang-pkgs", Type: "composer", Packages: [{ Name: "magento/framework", Version: "103.0.7" }] },
      ],
    };
    expect(trivyReportPackages(report)).toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "web/package-lock.json", line: 12 },
      { ecosystem: "npm", name: "left-pad", version: "1.3.0", file: "web/package-lock.json", line: 0 },
      { ecosystem: "Packagist", name: "magento/framework", version: "103.0.7", file: "composer.lock", line: 0 },
    ]);
  });

  it("reports a Windows-style Target with forward slashes", () => {
    const report = { Results: [{ Target: "web\\app\\package-lock.json", Packages: [{ Name: "lodash", Version: "4.17.4" }] }] };
    expect(trivyReportPackages(report)).toEqual([
      { ecosystem: "npm", name: "lodash", version: "4.17.4", file: "web/app/package-lock.json", line: 0 },
    ]);
  });

  it("skips results whose file is not a lockfile of an allow-listed ecosystem and unreadable entries", () => {
    const report = {
      Results: [
        { Target: "Node.js", Class: "lang-pkgs", Type: "node-pkg", Packages: [{ Name: "a", Version: "1.0.0" }] },
        { Target: "Dockerfile", Class: "config", Misconfigurations: [] },
        { Target: "yarn.lock", Packages: [{ Name: 1, Version: "1.0.0" }, { Name: "b" }, { Name: "c", Version: "" }, null] },
      ],
    };
    expect(trivyReportPackages(report)).toEqual([]);
    expect(trivyReportPackages(undefined)).toEqual([]);
    expect(trivyReportPackages({ Results: "x" })).toEqual([]);
  });
});
