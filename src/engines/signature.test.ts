import { beforeEach, describe, expect, test, vi } from "vitest";

const harness = vi.hoisted(() => ({
  calls: [] as Array<{ cmd: string; args: string[] }>,
  cosignInstalled: true,
  cosign: { code: 0 as number | null, out: "Verified OK" },
}));

// A managed cosign never exists at this path, so resolution always falls through to the
// (mocked) system lookup and the test never touches the real ~/.codeinspectus.
vi.mock("../config.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../config.js")>();
  return { ...actual, MANAGED_BIN: "/nonexistent/codeinspectus-signature-test/bin" };
});

vi.mock("node:child_process", async () => {
  const { EventEmitter } = await import("node:events");
  return {
    spawn: vi.fn((cmd: string, args: string[]) => {
      harness.calls.push({ cmd, args });
      const child = Object.assign(new EventEmitter(), {
        stdout: new EventEmitter(),
        stderr: new EventEmitter(),
      });
      setImmediate(() => {
        if (cmd === "which" || cmd === "where") {
          if (harness.cosignInstalled) child.stdout.emit("data", "/opt/test/cosign\n");
          child.emit("close", harness.cosignInstalled ? 0 : 1);
          return;
        }
        child.stderr.emit("data", harness.cosign.out);
        child.emit("close", harness.cosign.code);
      });
      return child;
    }),
  };
});

const { verifySlsaAttestation } = await import("./signature.js");

const IDENTITY =
  "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0";
const ISSUER = "https://token.actions.githubusercontent.com";

const input = {
  blob: "/stage/osv-scanner_darwin_arm64",
  bundlePath: "/stage/multiple.intoto.jsonl",
  identity: IDENTITY,
  issuer: ISSUER,
  workflowRepository: "google/osv-scanner",
};

function cosignCalls() {
  return harness.calls.filter((call) => call.cmd === "/opt/test/cosign");
}

beforeEach(() => {
  harness.calls = [];
  harness.cosignInstalled = true;
  harness.cosign = { code: 0, out: "Verified OK" };
});

describe("verifySlsaAttestation", () => {
  test("verifySlsaAttestation passes the pinned identity, issuer, type and workflow repository to cosign", async () => {
    const result = await verifySlsaAttestation(input);

    expect(result.ok).toBe(true);
    const calls = cosignCalls();
    expect(calls).toHaveLength(1);
    expect(calls[0]?.args).toEqual([
      "verify-blob-attestation",
      "--bundle",
      input.bundlePath,
      "--type",
      "slsaprovenance02",
      "--certificate-identity",
      IDENTITY,
      "--certificate-oidc-issuer",
      ISSUER,
      "--certificate-github-workflow-repository",
      "google/osv-scanner",
      input.blob,
    ]);
  });

  test("a non-zero cosign exit is reported as not ok and keeps the cosign output", async () => {
    harness.cosign = { code: 1, out: "Error: none of the attestations matched the predicate type" };

    const result = await verifySlsaAttestation(input);

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/cosign FAILED/);
    expect(result.detail).toMatch(/none of the attestations matched/);
  });

  test("fails closed when cosign is not installed", async () => {
    harness.cosignInstalled = false;

    const result = await verifySlsaAttestation(input);

    expect(result.ok).toBe(false);
    expect(result.detail).toMatch(/cosign is not installed/);
    expect(cosignCalls()).toHaveLength(0);
  });

  test("a zero exit without cosign's verification confirmation is not trusted", async () => {
    harness.cosign = { code: 0, out: "" };

    const result = await verifySlsaAttestation(input);

    expect(result.ok).toBe(false);
  });
});
