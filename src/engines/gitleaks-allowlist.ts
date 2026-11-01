/**
 * Gitleaks 8.30.1 matches its default global allowlist paths against the absolute path of each file it
 * reports, so the folders ABOVE a scan target count: a target under node_modules/, bower_components/,
 * vendor/bundle/, vendor/ruby/ or lib/python3.12/site-packages/ reported no secrets while secret
 * coverage read verified (review I-7). These are the `[allowlist] paths` of the default config embedded
 * in the 8.30.1 binary, translated from RE2 (`(?i)` becomes the `i` flag). Re-copy them on a bump.
 */

import { basename } from "node:path";

export const GITLEAKS_DEFAULT_ALLOWLIST_PATHS: readonly RegExp[] = [
  /gitleaks\.toml/,
  /\.(?:bmp|gif|jpe?g|png|svg|tiff?)$/i,
  /\.(?:eot|[ot]tf|woff2?)$/i,
  /\.(?:docx?|xlsx?|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$/i,
  /go\.(?:mod|sum|work(?:\.sum)?)$/,
  /(?:^|\/)vendor\/modules\.txt$/,
  /(?:^|\/)vendor\/(?:github\.com|golang\.org\/x|google\.golang\.org|gopkg\.in|istio\.io|k8s\.io|sigs\.k8s\.io)(?:\/.*)?$/,
  /(?:^|\/)gradlew(?:\.bat)?$/,
  /(?:^|\/)gradle\.lockfile$/,
  /(?:^|\/)mvnw(?:\.cmd)?$/,
  /(?:^|\/)\.mvn\/wrapper\/MavenWrapperDownloader\.java$/,
  /(?:^|\/)node_modules(?:\/.*)?$/,
  /(?:^|\/)(?:deno\.lock|npm-shrinkwrap\.json|package-lock\.json|pnpm-lock\.yaml|yarn\.lock)$/,
  /(?:^|\/)bower_components(?:\/.*)?$/,
  /(?:^|\/)(?:angular|bootstrap|jquery(?:-?ui)?|plotly|swagger-?ui)[a-zA-Z0-9.-]*(?:\.min)?\.js(?:\.map)?$/,
  /(?:^|\/)javascript\.json$/,
  /(?:^|\/)(?:Pipfile|poetry)\.lock$/,
  /(?:^|\/)(?:v?env|virtualenv)\/lib(?:64)?(?:\/.*)?$/i,
  /(?:^|\/)(?:lib(?:64)?\/python[23](?:\.\d{1,2})+|python\/[23](?:\.\d{1,2})+\/lib(?:64)?)(?:\/.*)?$/i,
  /(?:^|\/)[a-z0-9_.]+-[0-9.]+\.dist-info(?:\/.+)?$/i,
  /(?:^|\/)vendor\/(?:bundle|ruby)(?:\/.*?)?$/,
  /\.gem$/,
  /verification-metadata\.xml/,
  /Database.refactorlog/,
  /(?:^|\/)\.git$/,
];

/**
 * Relative names that complete each folder-anchored pattern across the target boundary (a target
 * ending in `vendor` plus `github.com/…`, `venv` plus `lib/…`, `lib` plus `python3.12/…`, and so on).
 */
const BOUNDARY_PROBES = [
  "x", "github.com/x", "modules.txt", "lib/x", "python3.12/x", "3.12/lib/x", "bundle/x", "ruby/x",
  "wrapper/MavenWrapperDownloader.java", "MavenWrapperDownloader.java",
];

function allowlisted(path: string): boolean {
  return GITLEAKS_DEFAULT_ALLOWLIST_PATHS.some((pattern) => pattern.test(path));
}

const posixPath = (path: string): string => path.replace(/\\/g, "/").replace(/\/+$/, "");

/**
 * Whether the absolute path of the folders above (and including) a directory target makes the default
 * allowlist match files inside it that a target-relative path would not match.
 */
export function directoryPrefixAllowlisted(directory: string): boolean {
  const prefix = posixPath(directory);
  return BOUNDARY_PROBES.some((probe) => allowlisted(`${prefix}/${probe}`) && !allowlisted(probe));
}

/** Whether a single-file target is allowlisted only because of the folders above it. */
export function filePrefixAllowlisted(file: string): boolean {
  return allowlisted(posixPath(file)) && !allowlisted(basename(file));
}
