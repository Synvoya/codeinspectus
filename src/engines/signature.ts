/**
 * Cosign keyless signature verification (PRD §0.2).
 *
 * MANDATORY + FAIL-CLOSED for opengrep and trivy: a binary is trusted only if its
 * publisher signature verifies against the pinned OIDC identity + issuer. If
 * cosign is missing, the signature artifacts are absent, or verification fails,
 * the caller must refuse to install/trust the binary.
 *
 * - opengrep: per-asset cosign `.sig` + `.cert` (the `.cert` is base64-of-PEM);
 *   the blob is the raw binary asset.
 * - trivy:    a sigstore bundle (`*.sigstore.json`) over `checksums.txt`; the
 *   authenticated checksums then gate the archive SHA.
 */

import { spawn } from "node:child_process";
import { access, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { MANAGED_BIN } from "../config.js";
import { loadLockfile, platformKey } from "./lockfile.js";
import { sha256Hex } from "../util/hash.js";

export interface SigResult {
  ok: boolean;
  detail: string;
}

async function systemCosign(): Promise<string | undefined> {
  return await new Promise((resolve) => {
    const c = spawn(process.platform === "win32" ? "where" : "which", ["cosign"], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    let stdout = "";
    c.stdout.on("data", (data) => (stdout += data.toString()));
    c.on("error", () => resolve(undefined));
    c.on("close", (code) => resolve(code === 0 ? stdout.split(/\r?\n/).find(Boolean) : undefined));
  });
}

export async function resolveCosign(): Promise<string | undefined> {
  const managed = join(MANAGED_BIN, process.platform === "win32" ? "cosign.exe" : "cosign");
  if (await hasManagedCosign()) return managed;
  return await systemCosign();
}

export async function hasManagedCosign(): Promise<boolean> {
  const managed = join(MANAGED_BIN, process.platform === "win32" ? "cosign.exe" : "cosign");
  if (!await access(managed).then(() => true).catch(() => false)) return false;
  const expected = (await loadLockfile().catch(() => undefined))?.verifiers?.cosign.platforms[platformKey()]?.sha256;
  if (!expected) return false;
  const actual = sha256Hex(await readFile(managed).catch(() => Buffer.alloc(0)));
  return actual.toLowerCase() === expected.toLowerCase();
}

export async function hasCosign(): Promise<boolean> {
  return Boolean(await resolveCosign());
}

async function runCosign(args: string[]): Promise<{ code: number | null; out: string }> {
  const executable = await resolveCosign();
  if (!executable) return { code: null, out: "cosign is not installed" };
  return await new Promise((resolve) => {
    const captured = spawn(executable, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    captured.stdout.on("data", (d) => (out += d.toString()));
    captured.stderr.on("data", (d) => (out += d.toString()));
    captured.on("error", (e) => resolve({ code: null, out: e.message }));
    captured.on("close", (code) => resolve({ code, out }));
  });
}

/** Decode a base64-of-PEM cert (opengrep `.cert`) to a PEM file; pass through if already PEM. */
async function ensurePem(certPath: string): Promise<string> {
  const raw = (await readFile(certPath, "utf8")).trim();
  if (raw.startsWith("-----BEGIN")) return certPath;
  const pem = Buffer.from(raw, "base64").toString("utf8");
  if (!pem.startsWith("-----BEGIN")) {
    throw new Error(`cert at ${certPath} is neither PEM nor base64-of-PEM`);
  }
  const pemPath = `${certPath}.pem`;
  await writeFile(pemPath, pem, "utf8");
  return pemPath;
}

/** opengrep-style verification: cert + detached sig over the binary blob. */
export async function verifyCertSig(opts: {
  blob: string;
  certPath: string;
  sigPath: string;
  identity: string;
  issuer: string;
}): Promise<SigResult> {
  const pem = await ensurePem(opts.certPath);
  const { code, out } = await runCosign([
    "verify-blob",
    "--certificate",
    pem,
    "--signature",
    opts.sigPath,
    "--certificate-identity",
    opts.identity,
    "--certificate-oidc-issuer",
    opts.issuer,
    opts.blob,
  ]);
  const ok = code === 0 && /Verified OK/i.test(out);
  return { ok, detail: ok ? "cosign Verified OK" : `cosign FAILED: ${out.trim().slice(0, 400)}` };
}

/** trivy-style verification: sigstore bundle over a blob (checksums.txt). */
export async function verifyBundle(opts: {
  blob: string;
  bundlePath: string;
  identity: string;
  issuer: string;
}): Promise<SigResult> {
  const { code, out } = await runCosign([
    "verify-blob",
    "--bundle",
    opts.bundlePath,
    "--certificate-identity",
    opts.identity,
    "--certificate-oidc-issuer",
    opts.issuer,
    opts.blob,
  ]);
  const ok = code === 0 && /Verified OK/i.test(out);
  return { ok, detail: ok ? "cosign Verified OK" : `cosign FAILED: ${out.trim().slice(0, 400)}` };
}
