import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";

const execFileP = promisify(execFile);

describe("real CLI entry dispatch", () => {
  test("routes export to the CLI instead of rejecting it as an unknown subcommand", async () => {
    try {
      await execFileP(process.execPath, ["--import", "tsx", "src/index.ts", "export", "invalid", "--format", "json"]);
      throw new Error("expected export to reject the invalid scan id");
    } catch (error) {
      const failure = error as { code?: number; stderr?: string };
      expect(failure.code).toBe(2);
      expect(failure.stderr).toMatch(/scan_id must be/i);
      expect(failure.stderr).not.toMatch(/unknown subcommand/i);
    }
  });

  test("routes scans to history CLI instead of rejecting it as an unknown subcommand", async () => {
    try {
      await execFileP(process.execPath, ["--import", "tsx", "src/index.ts", "scans", "show", "../../etc/passwd"]);
      throw new Error("expected scans show to reject the traversal-shaped scan id");
    } catch (error) {
      const failure = error as { code?: number; stderr?: string };
      expect(failure.code).toBe(2);
      expect(failure.stderr).toMatch(/scan_id must be|generated id/i);
      expect(failure.stderr).not.toMatch(/unknown subcommand/i);
    }
  });

  test("routes bundle to the sealed-evidence CLI", async () => {
    try {
      await execFileP(process.execPath, ["--import", "tsx", "src/index.ts", "bundle", "create", "../../bad", "--output-dir", "/tmp/evidence"]);
      throw new Error("expected bundle create to reject the invalid scan id");
    } catch (error) {
      const failure = error as { code?: number; stderr?: string };
      expect(failure.code).toBe(2);
      expect(failure.stderr).toMatch(/scan_id must be/i);
      expect(failure.stderr).not.toMatch(/unknown subcommand/i);
    }
  });

  test("routes bulk to the bounded local-repository CLI", async () => {
    try {
      await execFileP(process.execPath, ["--import", "tsx", "src/index.ts", "bulk", "scan"]);
      throw new Error("expected bulk scan to reject the missing parent");
    } catch (error) {
      const failure = error as { code?: number; stderr?: string };
      expect(failure.code).toBe(2);
      expect(failure.stderr).toMatch(/requires a parent directory/i);
      expect(failure.stderr).not.toMatch(/unknown subcommand/i);
    }
  });

  test("routes history to the bounded repository-history CLI", async () => {
    try {
      await execFileP(process.execPath, ["--import", "tsx", "src/index.ts", "history", "scan", "/tmp/repository"]);
      throw new Error("expected history scan to reject missing explicit bounds");
    } catch (error) {
      const failure = error as { code?: number; stderr?: string };
      expect(failure.code).toBe(2);
      expect(failure.stderr).toMatch(/requires explicit.*--from.*--to.*--since.*--until.*--max-commits/i);
      expect(failure.stderr).not.toMatch(/unknown subcommand/i);
    }
  });

  test("routes issue to the review-only payload CLI", async () => {
    try {
      await execFileP(process.execPath, ["--import", "tsx", "src/index.ts", "issue", "submit", "scan-00000000-0000-4000-8000-000000000001", "CI-0001"]);
      throw new Error("expected issue submit to remain unsupported");
    } catch (error) {
      const failure = error as { code?: number; stderr?: string };
      expect(failure.code).toBe(2);
      expect(failure.stderr).toMatch(/submission is not supported/i);
      expect(failure.stderr).not.toMatch(/unknown subcommand/i);
    }
  });
});
