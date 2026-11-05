/** Shared types for the Synvoya gap-advisory dataset. Schemas live in dataset.ts. */

import type { Engine, Severity } from "../types.js";

export type RuntimeId = "node" | "php" | "python" | "ruby" | "go" | "dotnet" | "java";

export type SynvoyaKind = "vulnerability" | "malware" | "runtime" | "eol" | "product" | "config";

/** OSV-style range event: exactly one boundary per event. */
export type OsvEvent =
  | { introduced: string }
  | { fixed: string }
  | { last_affected: string }
  | { limit: string };

export type SynvoyaTarget =
  | { type: "package"; ecosystem: string; name: string }
  | { type: "runtime"; runtime: RuntimeId }
  | { type: "product"; product: string };

export interface SynvoyaAdvisory {
  /** SYN-YYYY-NNN */
  id: string;
  slug: string;
  title: string;
  kind: SynvoyaKind;
  aliases: string[];
  target: SynvoyaTarget;
  affected: Array<{ line?: string; events: OsvEvent[] }>;
  fixed: string[];
  severity: Severity;
  exploited: boolean;
  exploited_source?: string;
  remediation_steps: string[];
  sources: string[];
  status: "active" | "covered";
  covered_by?: Engine;
  covered_since?: string;
  provisional: boolean;
  /**
   * Product targets only. With "verify-hotfix" a finding asks the user to verify the vendor fix, unless the
   * version is in a range with no `fixed` and no `limit` event: that range is a line the vendor does not
   * patch, proven by the version alone. A `limit` event therefore means vendor-patched by a hotfix that does
   * not change the version string (hotfix-only), never "no patch".
   */
  product_rule?: "version-proves" | "verify-hotfix";
  /** The vendor ships no fixed release (only with an empty `fixed`): remediation is to replace or remove. */
  no_fix_available?: true;
  /**
   * Never evaluated in M1. "M2": needs a later milestone's reader or matcher. "platform-detection": the flaw
   * needs an operating-system or deployment precondition (e.g. PHP-CGI on Windows) that no reader can see yet.
   */
  requires?: "M2" | "platform-detection";
}

export interface EolEntry {
  /** Runtime id or image product, e.g. "mysql". */
  product: string;
  cycle: string;
  /** YYYY-MM-DD */
  eol: string;
  latest?: string;
  source: string;
}

/** One reviewed front-end library: the npm package it is published as and the evidence that names it. */
export interface LibraryEntry {
  /** The package name exactly as published on npm. */
  npm: string;
  /** Anchored regex sources with exactly one capture group (the version), matched against a leading comment. */
  banners: string[];
  /** Lower-case file-name stems: `<stem>-<version>(.min).js`. */
  fileStems: string[];
  /** Lower-case CDN path keys, e.g. "jquery" (unpkg), "npm/jquery" (jsDelivr), "ajax/libs/jquery" (cdnjs, Google). */
  cdnPaths: string[];
}

/** Reviewed, bundled mapping from banners, file names and CDN paths to npm packages (never guessed from free text). */
export interface LibraryTable {
  libraries: LibraryEntry[];
}

export interface SynvoyaDataset {
  version: string;
  date: string;
  advisories: SynvoyaAdvisory[];
  /** "<ecosystem>:<name>" → "<ecosystem>:<name>" */
  aliases: Record<string, string>;
  /** image repo → package */
  imageAliases: Record<string, { ecosystem: string; name: string }>;
  /** image repo → product */
  productImages: Record<string, string>;
  eol: EolEntry[];
  libraries: LibraryTable;
}

/** What a reader found a repository declaring: a runtime pin, a product, a package or an image. */
export interface Declaration {
  subject:
    | { type: "runtime"; runtime: RuntimeId }
    | { type: "product"; product: string }
    | { type: "package"; ecosystem: string; name: string }
    | { type: "image-eol"; product: string };
  /** The version text the evaluator parses (wrapper tokens such as `v`, `go`, `net` removed). */
  spec: string;
  /** Exact version when known; set only for `exact`. */
  resolved?: string;
  precision: "exact" | "floating" | "range" | "unresolved";
  /** Target-relative, forward slashes on every OS. */
  file: string;
  /** 1-based line of the value (or its key); 1 when unknown. */
  line: number;
  /** e.g. ".nvmrc", "Dockerfile FROM". */
  source: string;
  /** Unresolved only: the reader's own note already says why it cannot be judged, so the evaluator adds none. */
  noted?: true;
  /** The reader that found it; the scanner sets it, and the finding records it as `synvoya:<producer>`. */
  producer?: "runtime" | "images" | "products" | "vendored" | "actions";
}

export interface ReaderResult {
  declarations: Declaration[];
  /** Target-relative files a reader parsed. */
  parsed: string[];
  skipped: Array<{ file: string; reason: string }>;
  notes: string[];
  /** Notes no cap may drop (e.g. the per-scan declaration cap was reached); also present in `notes`. */
  priorityNotes?: string[];
  /**
   * Parsed files holding something the reader could not turn into a declaration it can judge (a repository
   * or property behind an unresolved variable, an unparseable reference): never counted as fully checked.
   */
  unjudged?: string[];
}

export interface ReaderOptions {
  /** Shared wall-clock deadline for every Synvoya reader: once aborted, no new file is started. */
  signal?: AbortSignal;
  /** A single-file scan: read only this target-relative path (forward slashes), if the reader reads it. */
  only?: string;
}
