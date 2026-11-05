import { describe, expect, test } from "vitest";

import { directoryPrefixAllowlisted, filePrefixAllowlisted } from "./gitleaks-allowlist.js";

// Review I-7, re-checked on Gitleaks 8.30.1 with the same secret file: plain/ → 1 finding,
// node_modules/pkg and lib/python3.12/site-packages/pkg → 0. The review also measured
// bower_components/, vendor/bundle/ and vendor/ruby/ → 0, and vendor/, .venv/, venv/, bare
// site-packages/, build/, dist/ and tests/ → found.
describe("Gitleaks default allowlist above the target", () => {
  test.each([
    "/work/node_modules/pkg",
    "/work/app/node_modules/@scope/pkg/dist",
    "/work/bower_components/lib",
    "/work/vendor/bundle/ruby/3.2.0/gems/x",
    "/work/vendor/ruby",
    "/work/lib/python3.12/site-packages/pkg",
    "/work/venv/lib/python3.12/site-packages/pkg",
    "/work/site-packages/pkg-1.0.dist-info",
    "C:\\work\\node_modules\\pkg",
    // Folder-anchored patterns that complete inside the target.
    "/work/venv",
    "/work/lib",
    "/work/vendor",
  ])("%s is allowlisted by its own folders", (directory) => {
    expect(directoryPrefixAllowlisted(directory)).toBe(true);
  });

  test.each(["/work/repo", "/work/.venv", "/work/site-packages/pkg", "/work/build", "/work/tests", "/work/vendor-tools"])(
    "%s is not",
    (directory) => {
      expect(directoryPrefixAllowlisted(directory)).toBe(false);
    },
  );

  test("a single file counts only when the folders above it match", () => {
    expect(filePrefixAllowlisted("/work/node_modules/pkg/config.yml")).toBe(true);
    expect(filePrefixAllowlisted("/work/repo/config.yml")).toBe(false);
    expect(filePrefixAllowlisted("/work/repo/logo.png")).toBe(false);
  });
});
