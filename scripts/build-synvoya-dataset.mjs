/**
 * Maintainer-only: build the Synvoya gap-advisory dataset (detection-db/synvoya/advisories.json,
 * aliases.json and eol.json) from the reviewed seed research. Never shipped in the npm package and never
 * run during a scan. Every input path is an argument; no private path is written here.
 *
 *   node scripts/build-synvoya-dataset.mjs \
 *     --candidates <synvoya-candidates.json> --candidates <kev-sweep-candidates.json> \
 *     --verification <seed-verification-runtime.json> --verification <seed-verification-products.json> \
 *     --approved <seed-list.md> [--eol-cache <dir>] [--out <dir>]
 *   node scripts/synvoya-manifest.mjs      # then refresh the digests
 *
 * Rules (design §3, §10.3, §10.4, §10.10 and the approved seed list):
 * - verdict `verified` / `corrected` ships non-provisional with the verified affected, fixed and sources;
 *   `provisional` ships `provisional: true` with the candidate range, where a fixed release the verifier
 *   did not confirm becomes a `limit` (the range stays, the fix claim goes); `drop` never ships.
 * - Entries whose reader is a later milestone's (GitHub Actions, the Go stdlib via SBOM) get `requires: "M2"`;
 *   entries whose flaw needs a platform no reader can see (Windows PHP-CGI) get `requires: "platform-detection"`.
 * - Adobe Commerce, ColdFusion, WebLogic and WSO2 fixes are hotfixes or patch levels a version string does
 *   not show: `product_rule: "verify-hotfix"` with the bulletin id in `aliases`; a range bounded by `limit`
 *   marks a hotfix-only fix, a range with no bound is a line with no patch.
 * - EOL cycles come from endoflife.date (MIT, see LICENSE-PROVENANCE.md), fetched here at build time with
 *   a generic User-Agent; only cycles with an end-of-life date and a latest release are kept.
 *
 * Exit 0 after writing; 1 with the reasons when any validation fails (nothing is written then).
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_OUT = resolve(dirname(fileURLToPath(import.meta.url)), "../detection-db/synvoya");
const KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
const USER_AGENT = "Mozilla/5.0";

// ---- arguments ----

function parseArgs(argv) {
  const out = { candidates: [], verification: [], approved: undefined, eolCache: undefined, out: DEFAULT_OUT };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (value === undefined) throw new Error(`${flag} needs a value`);
    if (flag === "--candidates") out.candidates.push(value);
    else if (flag === "--verification") out.verification.push(value);
    else if (flag === "--approved") out.approved = value;
    else if (flag === "--eol-cache") out.eolCache = value;
    else if (flag === "--out") out.out = resolve(value);
    else throw new Error(`unknown argument ${flag}`);
    i++;
  }
  if (out.candidates.length === 0 || out.verification.length === 0 || !out.approved) {
    throw new Error("usage: --candidates <file>... --verification <file>... --approved <seed-list.md> [--eol-cache <dir>] [--out <dir>]");
  }
  return out;
}

const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));

// ---- tables ----

/** Candidate ecosystem → runtime id. */
const RUNTIME_OF = {
  "PHP runtime": "php",
  "Node.js runtime": "node",
  "Python runtime": "python",
  "Ruby runtime": "ruby",
  "Go toolchain": "go",
  "Go toolchain (stdlib)": "go",
  ".NET runtime": "dotnet",
  ".NET runtime / NuGet runtime packs": "dotnet",
  "Java runtime": "java",
};

/** Candidate ecosystem → OSV ecosystem name (package targets matched against the engines' inventory). */
const PACKAGE_ECOSYSTEM = {
  npm: "npm",
  PyPI: "PyPI",
  NuGet: "NuGet",
  Maven: "Maven",
  Packagist: "Packagist",
  Go: "Go",
  CPAN: "CPAN",
  RubyGems: "RubyGems",
  "crates.io": "crates.io",
};

/**
 * Image repository → package already covered by package advisories (design §10.10). Every Docker Hub name
 * was confirmed to exist on 2026-11-03 (hub.docker.com/v2/repositories/<repo>).
 */
const IMAGE_ALIASES = {
  "jenkins/jenkins": { ecosystem: "Maven", name: "org.jenkins-ci.main:jenkins-core" },
  "bitnami/jenkins": { ecosystem: "Maven", name: "org.jenkins-ci.main:jenkins-core" },
  tomcat: { ecosystem: "Maven", name: "org.apache.tomcat.embed:tomcat-embed-core" },
  "apache/activemq-classic": { ecosystem: "Maven", name: "org.apache.activemq:activemq-broker" },
  "rmohr/activemq": { ecosystem: "Maven", name: "org.apache.activemq:activemq-broker" },
  "gitea/gitea": { ecosystem: "Go", name: "gitea.dev" },
  "bitnami/gitea": { ecosystem: "Go", name: "gitea.dev" },
  "n8nio/n8n": { ecosystem: "npm", name: "n8n" },
  "langflowai/langflow": { ecosystem: "PyPI", name: "langflow" },
  "gogs/gogs": { ecosystem: "Go", name: "gogs.io/gogs" },
};

/**
 * Image repository → product (design §10.3, §10.10). Docker Hub names were confirmed to exist on
 * 2026-11-03; the vendor-registry names (ghcr.io, docker.osgeo.org, releases-docker.jfrog.io,
 * container-registry.oracle.com, docker.elastic.co) are the verified candidates' own detection signals.
 * `bitnami/<x>` is looked up as `<x>` by the image reader, so it is listed only where the names differ.
 */
const PRODUCT_IMAGES = {
  "ghcr.io/berriai/litellm": "litellm",
  "litellm/litellm": "litellm",
  "ghcr.io/mlflow/mlflow": "mlflow",
  "bitnami/mlflow": "mlflow",
  "rayproject/ray": "ray",
  "docker.osgeo.org/geoserver": "geoserver",
  xwiki: "xwiki",
  flink: "flink",
  "apache/superset": "superset",
  "bitnami/superset": "superset",
  "apache/rocketmq": "rocketmq",
  "apache/airflow": "airflow",
  "bitnami/airflow": "airflow",
  solr: "solr",
  "mongo-express": "mongo-express",
  "sonatype/nexus3": "nexus",
  "plexinc/pms-docker": "plex-media-server",
  "atlassian/confluence": "confluence",
  "atlassian/confluence-server": "confluence",
  "wso2/wso2am": "wso2-api-manager",
  "releases-docker.jfrog.io/jfrog/artifactory-oss": "artifactory",
  "adobecoldfusion/coldfusion2018": "coldfusion",
  "adobecoldfusion/coldfusion2021": "coldfusion",
  "adobecoldfusion/coldfusion2023": "coldfusion",
  "adobecoldfusion/coldfusion2025": "coldfusion",
  "splunk/splunk": "splunk",
  "container-registry.oracle.com/middleware/weblogic": "weblogic",
  "jetbrains/teamcity-server": "teamcity",
  "roundcube/roundcubemail": "roundcube",
  "gitlab/gitlab-ce": "gitlab",
  "gitlab/gitlab-ee": "gitlab",
  mongo: "mongodb",
  "grafana/grafana": "grafana",
  "bitnami/grafana": "grafana",
  "wazuh/wazuh-manager": "wazuh",
  httpd: "httpd",
  "bitnami/apache": "httpd",
  "ghcr.io/apache/ofbiz": "ofbiz",
  "atlassian/jira-software": "jira-software",
  "metabase/metabase": "metabase",
  "nextgenhealthcare/connect": "mirth-connect",
  joomla: "joomla",
  "glpi/glpi": "glpi",
  "atlassian/bitbucket": "bitbucket",
  "atlassian/bitbucket-server": "bitbucket",
  "dotcms/dotcms": "dotcms",
  couchdb: "couchdb",
  "apache/apisix": "apisix",
  "bitnami/apisix": "apisix",
  phpmyadmin: "phpmyadmin",
  "phpmyadmin/phpmyadmin": "phpmyadmin",
  "atlassian/crowd": "crowd",
  "zabbix/zabbix-web-nginx-mysql": "zabbix",
  "ibmcom/websphere-traditional": "websphere-traditional",
  "docker.elastic.co/kibana/kibana": "kibana",
  kibana: "kibana",
  "pihole/pihole": "pihole",
  "kestra/kestra": "kestra",
  wordpress: "wordpress",
  erlang: "erlang",
};

/** Candidate image names with no image-table key: the product is still named, nothing maps an image to it. */
const UNMAPPED_PRODUCT_IMAGES = {
  // minio/minio is gone from Docker Hub (404 on 2026-11-03) and MinIO tags (RELEASE.<timestamp>) are not versions.
  "minio/minio": "minio",
};

/** endoflife.date product → our EOL product key(s); runtimes use the runtime id. */
const EOL_PRODUCTS = [
  { slug: "nodejs", keys: ["node"], runtimeParts: 1 },
  { slug: "php", keys: ["php"], runtimeParts: 2 },
  { slug: "python", keys: ["python"], runtimeParts: 2 },
  { slug: "ruby", keys: ["ruby"], runtimeParts: 2 },
  { slug: "go", keys: ["go"], runtimeParts: 2 },
  { slug: "dotnet", keys: ["dotnet"], runtimeParts: 2 },
  // Java runtime lines (openjdk, eclipse-temurin, amazoncorretto images, .java-version, ...) follow Temurin.
  { slug: "eclipse-temurin", keys: ["java"], runtimeParts: 1 },
  { slug: "mysql", keys: ["mysql"] },
  { slug: "mariadb", keys: ["mariadb"] },
  // `postgres` is the official image; `bitnami/postgresql` is looked up as `postgresql`.
  { slug: "postgresql", keys: ["postgres", "postgresql"] },
  { slug: "redis", keys: ["redis"] },
  // `mongo` maps to the `mongodb` product (SYN-2026-237); `bitnami/mongodb` is looked up as `mongodb`.
  { slug: "mongodb", keys: ["mongodb"] },
  { slug: "elasticsearch", keys: ["elasticsearch"] },
  { slug: "rabbitmq", keys: ["rabbitmq"] },
  { slug: "nginx", keys: ["nginx"] },
  { slug: "apache-http-server", keys: ["httpd"] },
];

/** Later-milestone readers: GitHub Actions matcher and Go stdlib via SBOM (design §10.1, §4.4). */
const REQUIRES_M2 = new Set([
  "SYN-2026-019", "SYN-2026-020", "SYN-2026-219", // Go stdlib (go.mod → pkg:golang/stdlib SBOM)
  "SYN-2026-068", "SYN-2026-069", "SYN-2026-070", "SYN-2026-076", "SYN-2026-077", "SYN-2026-326", // GitHub Actions
]);

/**
 * Flaws with a platform precondition no M1 reader can see: never evaluated until one can (`requires`).
 * SYN-2026-150, CVE-2024-4577: PHP-CGI on Windows with certain code pages only (NVD, php.net advisory
 * GHSA-3qgc-jrrr-25jv); a version alone fires on every Linux image and Composer platform value.
 */
const REQUIRES_PLATFORM = new Set(["SYN-2026-150"]);

/**
 * Approved but not representable without inventing data: no version, range or tag in any source.
 * SYN-2026-080 (Joomla extension bundle): no fixed or affected version verified, and no reader for
 * Joomla extensions. SYN-2026-325 (reviewdog/action-setup): the exposure is a time window on a moved tag.
 */
const UNREPRESENTABLE = {
  "SYN-2026-080": "no affected or fixed version in any source; no Joomla extension reader",
  "SYN-2026-325": "exposure is a 2025-03-11 time window on a re-pointed tag, not a version range",
};

/** Adobe Commerce / Magento Open Source release lines 2.4.4–2.4.9 as hotfix-only ranges. */
function magentoLines(from, to, options = {}) {
  const out = [];
  for (let minor = from; minor <= to; minor++) {
    const line = `2.4.${minor}`;
    const noPatch = options.noPatch?.includes(line);
    out.push({ line, events: noPatch ? [{ introduced: line }] : [{ introduced: line }, { limit: `2.4.${minor + 1}` }] });
  }
  return out;
}

/** Per-entry decisions the generic mapping cannot make. Each is traced to the verification record. */
const MAGENTO = {
  // APSB26-146: Commerce 2.4.4–2.4.9, Open Source 2.4.6–2.4.9; fix is hotfix VULN-39341 (no release).
  "SYN-2026-004": { commerce: magentoLines(4, 9), openSource: magentoLines(6, 9), fixed: [], extraAliases: ["VULN-39341"] },
  // APSB26-92: Commerce 2.4.4–2.4.9, Open Source 2.4.6–2.4.9; fix is the 2026-aug isolated patch.
  "SYN-2026-005": { commerce: magentoLines(4, 9), openSource: magentoLines(6, 9), fixed: [] },
  // APSB26-73: Commerce 2.4.4–2.4.9, Open Source 2.4.6–2.4.9; fix is the 2026-jul isolated patch.
  "SYN-2026-006": { commerce: magentoLines(4, 9), openSource: magentoLines(6, 9), fixed: [] },
  // APSB26-153: Commerce 2.4.4–2.4.9 fixed by the 2026-oct isolated patch; Open Source 2.4.6 gets no patch.
  "SYN-2026-007": { commerce: magentoLines(4, 9), openSource: magentoLines(6, 9, { noPatch: ["2.4.6"] }), fixed: [] },
  // APSB25-88 SessionReaper: fixed in 2.4.5-p15 / 2.4.6-p13 / 2.4.7-p8 / 2.4.8-p3, hotfix for older stores.
  "SYN-2026-084": { both: "verified", fixed: ["2.4.5-p15", "2.4.6-p13", "2.4.7-p8", "2.4.8-p3"] },
  // APSB24-40 CosmicSting: fixed in 2.4.4-p9 / 2.4.5-p8 / 2.4.6-p6 / 2.4.7-p1, plus the 2024-07 hotfix.
  "SYN-2026-108": { both: "verified", fixed: ["2.4.4-p9", "2.4.5-p8", "2.4.6-p6", "2.4.7-p1"] },
  // APSB22-12 (provisional): affected 2.3.3-p1..2.3.7-p2 and 2.4.0..2.4.3-p1; remedy is isolated patches.
  "SYN-2026-125": {
    both: [{ events: [{ introduced: "2.3.3-p1" }, { limit: "2.3.7-p3" }, { introduced: "2.4.0" }, { limit: "2.4.3-p2" }] }],
    fixed: [],
  },
};

/** WebLogic / WSO2 provisional entries whose candidate range is a CPE artefact: the vendor's own list. */
const VENDOR_VERSIONS = {
  "SYN-2026-300": ["10.3.6.0", "12.1.3.0"], // Oracle Security Alert CVE-2019-2725
  "SYN-2026-317": ["10.3.6.0", "12.1.2.0", "12.1.3.0", "12.2.1.0"], // Oracle Security Alert CVE-2015-4852
  "SYN-2026-288": ["2.2.0", "2.5.0", "2.6.0", "3.0.0", "3.1.0", "3.2.0", "4.0.0"], // WSO2-2021-1738
};

/** Steps that named a fix the verifier did not confirm (or a stale state), replaced from the verified record. */
const STEP_OVERRIDES = {
  "SYN-2026-081": {
    replace: [/^Upgrade the product image/, "Upgrade GitLab CE/EE to 19.2.8, 19.3.5 or 19.4.2 or later on your release line (update the image tag), then pull, recreate and redeploy."],
  },
  "SYN-2026-027": {
    replace: [/^Upgrade to the newest Electron stable/, "Upgrade electron to 45.0.0 or later (the first release with all seven Chromium fixes) and ship a new app build."],
  },
  "SYN-2026-057": {
    replace: [/^Upgrade as soon as a release containing/, "Upgrade node-forge to 1.4.1 or later and regenerate the lockfile."],
  },
  "SYN-2026-059": {
    replace: [/^Upgrade transformers/, "The vendor advisory lists transformers 4.49.0 through 5.8.1 as affected and names no patched release; move to a release outside that range and confirm it with the vendor advisory."],
  },
  "SYN-2026-061": {
    replace: [/^Upgrade mlflow/, "The vendor advisory lists mlflow 3.13.0 through 3.15.2 as affected and names no patched release for this flaw; move to a release outside that range and confirm it with the vendor advisory."],
  },
  "SYN-2026-079": {
    replace: [/^Upgrade Gogs/, "The vendor advisory lists Gogs 0.13.3 and earlier as affected and names no patched release for CVE-2025-8110; move to a release outside that range and confirm it with the vendor advisory."],
  },
  "SYN-2026-082": {
    replace: [/^Upgrade langflow/, "The vendor advisory lists langflow 1.7.3 and earlier as affected and names no patched release for this flaw; move to a release outside that range and confirm it with the vendor advisory."],
  },
};

/** Plain titles where the candidate title carried research notes (they become finding titles). */
const TITLE_OVERRIDES = {
  "SYN-2026-082": "Langflow untrusted functionality inclusion (KEV 2026-07-21)",
  "SYN-2026-083": "Malicious release published from a hijacked package account (2026)",
  "SYN-2026-084": "Adobe Commerce and Magento Open Source SessionReaper flaw (CVE-2025-54236, KEV 2025-10-24)",
  "SYN-2026-057": "node-forge RSA PKCS#1 v1.5 signature verification accepts extra DigestAlgorithm elements",
  // Only the GitLab item of the multi-product bundle has a verified range (CVE-2026-97229).
  "SYN-2026-081": "GitLab CE/EE critical vulnerability CVE-2026-97229 in self-hosted instances",
  // The candidate title lost "MongoDB" from the KEV name "MongoDB and MongoDB Server Improper Handling of ...".
  "SYN-2026-237": "MongoDB Server: Improper Handling of Length Parameter Inconsistency Vulnerability (KEV 2025-12-29)",
};

// ---- helpers ----

const isHttps = (url) => typeof url === "string" && /^https:\/\/[^\s]+$/.test(url);
const unique = (items) => [...new Set(items)];
const stripNote = (text) => text.replace(/\s*\([^()]*\)\s*$/, "").trim();
const slugify = (text) => text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
const NUMERIC = /^\d+(?:\.\d+)*$/;

/** "12.2.1.4.0" → "12.2.1.4.1": the next version after a listed one on the same last component. */
function bump(version) {
  if (!NUMERIC.test(version)) throw new Error(`cannot bound non-numeric version ${version}`);
  const parts = version.split(".").map(Number);
  parts[parts.length - 1] += 1;
  return parts.join(".");
}

function cleanAliases(raw) {
  const out = [];
  for (const alias of raw ?? []) {
    const text = stripNote(String(alias));
    if (/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(text)) out.push(text);
  }
  return out;
}

/** Vendor bulletin ids named by the advisory's own sources (apsb26-68 → APSB26-68, .../WSO2-2026-5328/). */
function bulletinAliases(sources) {
  const out = [];
  for (const url of sources) {
    const adobe = /apsb(\d{2})-(\d+)/i.exec(url);
    if (adobe) out.push(`APSB${adobe[1]}-${adobe[2]}`);
    const wso2 = /\/(WSO2-\d{4}-\d+)\//.exec(url);
    if (wso2) out.push(wso2[1]);
  }
  return out;
}

function cleanEvents(events, context) {
  const out = [];
  for (const event of events ?? []) {
    const entries = Object.entries(event);
    if (entries.length !== 1) throw new Error(`${context}: event ${JSON.stringify(event)} is not one boundary`);
    const [kind, value] = entries[0];
    if (!["introduced", "fixed", "last_affected", "limit"].includes(kind) || typeof value !== "string" || value === "") {
      throw new Error(`${context}: bad event ${JSON.stringify(event)}`);
    }
    out.push({ [kind]: value });
  }
  return out;
}

/** A version list as ranges: malware versions are exact points; elsewhere each listed release bounded by a limit. */
function versionRanges(versions, malware) {
  const bases = unique(versions.map((v) => String(v).split(":")[0].trim()).filter((v) => v !== ""));
  return bases.map((v) =>
    malware ? { events: [{ introduced: v }, { last_affected: v }] } : { events: [{ introduced: v }, { limit: bump(v) }] },
  );
}

/** "ColdFusion 2025 Update 10" / "ColdFusion (2016 release) Update 4" → a line range on the image tag scheme. */
function coldFusionRange(fixedText) {
  const match = /ColdFusion\s+\(?(\d{2,4})(?:\s+release\))?\s+Update\s+(\d+)/i.exec(fixedText);
  if (!match) throw new Error(`unrecognised ColdFusion fix "${fixedText}"`);
  const [, line, update] = match;
  // Docker Hub adobecoldfusion/coldfusion<line> tags are <line>.0.<update> (verification, SYN-2026-230).
  return { line, events: [{ introduced: `${line}.0.0` }, { fixed: `${line}.0.${update}` }] };
}

// ---- mapping ----

/**
 * Split parts in a fixed order (ecosystem, then package name), so a part's id (<parent><NN>) and fingerprint
 * never depend on the key order of the input files.
 */
function byPackage(parts) {
  const key = (part) => `${part.target.ecosystem}\0${part.target.name}`;
  return [...parts].sort((a, b) => (key(a) < key(b) ? -1 : key(a) > key(b) ? 1 : 0));
}

function exploitedOf(candidate, primary) {
  if (candidate.kev) return { exploited: true, exploited_source: KEV_URL };
  const text = String(candidate.recheck_2026_11_01?.exploited ?? "");
  if (/^KEV/.test(text)) return { exploited: true, exploited_source: KEV_URL };
  if (/^(malware|yes)/i.test(text)) {
    const source = [...primary, ...candidate.sources].find(isHttps);
    return { exploited: true, ...(source ? { exploited_source: source } : {}) };
  }
  return { exploited: false };
}

function productOfImage(image) {
  if (Object.hasOwn(PRODUCT_IMAGES, image)) return PRODUCT_IMAGES[image];
  if (Object.hasOwn(UNMAPPED_PRODUCT_IMAGES, image)) return UNMAPPED_PRODUCT_IMAGES[image];
  return undefined;
}

/** Label used in generated steps. */
function targetLabel(target) {
  if (target.type === "package") return target.name;
  if (target.type === "runtime") return { node: "Node.js", php: "PHP", python: "Python", ruby: "Ruby", go: "Go", dotnet: ".NET", java: "Java" }[target.runtime];
  return target.product;
}

/** The upgrade step for a KEV-sweep entry, from the verified fixed list only. */
function upgradeStep(target, fixed, flags) {
  const label = targetLabel(target);
  if (flags.verifyHotfix) {
    return `Apply the vendor's security update or hotfix for your ${label} release line${fixed.length ? ` (${fixed.join(", ")})` : ""}; the declared version or image tag alone does not show the patch level.`;
  }
  if (flags.noFix) return `No fixed release of ${label} exists; replace or remove it.`;
  if (fixed.length === 0) return `No vendor-confirmed fixed version is recorded; check the vendor advisory for the fix on your ${label} release line.`;
  const list = fixed.join(", ");
  if (flags.image) return `Upgrade the ${flags.image} image (or the ${label} package) to ${list} or later on your release line, then pull, recreate and redeploy.`;
  if (target.type === "package") return `Upgrade ${label} to ${list} or later on your release line and regenerate the lockfile.`;
  if (target.type === "runtime") return `Upgrade the ${label} runtime to ${list} or later on your release line in every pin (version files, Dockerfile FROM, CI), then rebuild and redeploy.`;
  return `Upgrade ${label} to ${list} or later on your release line (update the image tag or product version), then pull, recreate and redeploy.`;
}

/** Shipped id → the approved id it came from (a split part's parent), recorded as entries are mapped. */
const PARENT = new Map();

const STALE_STEP = /^(Upgrade |Bump |Update the extension|Pin the action|No fixed )|\(inferred\)|; verify\)/;

function mapEntry(candidate, verification, verdict) {
  const id = candidate.id;
  const provisional = verdict === "provisional";
  const kev = Boolean(candidate.kev);
  const primary = (verification.primary_sources ?? []).filter(isHttps);
  // A provisional entry whose vendor bulletin the verifier could not open keeps the candidate's sources.
  if (primary.length === 0 && !provisional) throw new Error(`${id}: verification names no https primary source`);
  const sources = unique([...primary, ...candidate.sources.filter(isHttps)]);
  const malware = candidate.kind === "malware";
  const affectedIn = provisional ? candidate.affected : verification.affected;
  // Provisional entries keep only the fixes the verifier confirmed (an unconfirmed fix never ships).
  const fixedIn = (verification.fixed ?? []).map((f) => stripNote(String(f)));

  const base = {
    id,
    slug: candidate.slug,
    title: TITLE_OVERRIDES[id] ?? candidate.title.replace(/ - container image \/ product-version form$/, ""),
    kind: candidate.kind,
    aliases: unique([...cleanAliases(candidate.aliases), ...bulletinAliases(sources)]),
    severity: candidate.severity,
    ...exploitedOf(candidate, primary),
    sources,
    status: "active",
    provisional,
  };

  const eco = candidate.ecosystem;
  let parts; // [{ target, affected, fixed, extraAliases?, slugSuffix? }]
  let productRule;

  if (Object.hasOwn(MAGENTO, id)) {
    const m = MAGENTO[id];
    productRule = "verify-hotfix";
    const shared = m.both === "verified" ? verification.affected.map((a) => ({ events: cleanEvents(a.events, id) })) : m.both;
    parts = [
      { target: { type: "product", product: "adobe-commerce" }, affected: shared ?? m.commerce, fixed: m.fixed, extraAliases: m.extraAliases },
      { target: { type: "product", product: "magento-open-source" }, affected: shared ?? m.openSource, fixed: m.fixed, extraAliases: m.extraAliases, slugSuffix: "open-source" },
    ];
  } else if (id === "SYN-2026-081") {
    // The verifier confirmed the GitLab item only: CE/EE 19.2 < 19.2.8, 19.3 < 19.3.5, 19.4 < 19.4.2.
    base.slug = "gitlab-cve-2026-97229";
    base.aliases = ["CVE-2026-97229"]; // the bundle's other CVEs belong to products this entry no longer covers
    parts = [{
      target: { type: "product", product: "gitlab" },
      affected: [{ events: [{ introduced: "19.2.0" }, { fixed: "19.2.8" }, { introduced: "19.3.0" }, { fixed: "19.3.5" }, { introduced: "19.4.0" }, { fixed: "19.4.2" }] }],
      fixed: ["19.2.8", "19.3.5", "19.4.2"],
    }];
  } else if (malware && (id === "SYN-2026-062" || id === "SYN-2026-064" || id === "SYN-2026-065" || id === "SYN-2026-066" || id === "SYN-2026-083")) {
    const map = affectedIn[0].versions;
    const fixedByName = new Map();
    for (const text of verification.fixed ?? []) {
      // "memoryos 2.0.33", "@memtensor/memos-cloud-openclaw-plugin 0.1.22 / 0.1.24 / 0.2.0", "lightning 2.6.4 (...)"
      const clean = stripNote(text);
      const split = clean.search(/\s\d/);
      if (split < 0) throw new Error(`${id}: unreadable fixed entry "${text}"`);
      fixedByName.set(clean.slice(0, split), clean.slice(split).split("/").map((v) => v.trim()).filter(Boolean));
    }
    parts = Object.entries(map).map(([key, versions]) => {
      const m = /^(.*?)\s*\((npm|PyPI)\)$/.exec(key);
      const name = m ? m[1] : key;
      const ecosystem = m ? m[2] : PACKAGE_ECOSYSTEM[affectedIn[0].ecosystem];
      if (!ecosystem) throw new Error(`${id}: no ecosystem for ${key}`);
      return { target: { type: "package", ecosystem, name }, affected: versionRanges(versions, true), fixed: fixedByName.get(name) ?? [], slugSuffix: slugify(name) };
    });
    parts = byPackage(parts);
  } else if (id === "SYN-2026-067") {
    // Typosquat gems: every version of each name is malicious (names from the verified MAL ids).
    const names = ["bundler-rb", "bundler-lib", "bundler-ruby", "biundler-rb", "bumdler", "bundlef"];
    parts = byPackage(names.map((name) => ({ target: { type: "package", ecosystem: "RubyGems", name }, affected: [{ events: [{ introduced: "0" }] }], fixed: [], slugSuffix: slugify(name) })));
  } else if (id === "SYN-2026-001") {
    parts = [{ target: { type: "package", ecosystem: "PyPI", name: "litellm" }, affected: versionRanges(affectedIn[0].versions, true), fixed: fixedIn }];
  } else if (id === "SYN-2026-002") {
    parts = [{ target: { type: "product", product: "litellm" }, affected: versionRanges(["1.107.0"], true), fixed: fixedIn.map((f) => f.replace(/^v/, "")) }];
  } else if (id === "SYN-2026-063") {
    parts = [{ target: { type: "package", ecosystem: "npm", name: "tensorlake" }, affected: versionRanges(affectedIn[0].versions, true), fixed: fixedIn }];
  } else if (id === "SYN-2026-078") {
    parts = [{ target: { type: "package", ecosystem: "Go", name: "github.com/aquasecurity/trivy" }, affected: versionRanges(affectedIn[0].versions, true), fixed: fixedIn }];
  } else if (id === "SYN-2026-026") {
    const affected = verification.affected.map((a) => ({ events: cleanEvents(a.events, id) }));
    parts = ["org.springframework:spring-webmvc", "org.springframework:spring-webflux"].map((name, i) => ({
      target: { type: "package", ecosystem: "Maven", name }, affected, fixed: fixedIn, ...(i ? { slugSuffix: "webflux" } : {}),
    }));
  } else if (id === "SYN-2026-055") {
    // Module renamed: the fix ships under gitea.dev only.
    parts = [
      { target: { type: "package", ecosystem: "Go", name: "gitea.dev" }, affected: [{ events: [{ introduced: "0" }, { fixed: "1.27.1" }] }], fixed: ["1.27.1"] },
      // No release under the old module path carries the fix: no_fix_available, and the steps say to switch to gitea.dev.
      { target: { type: "package", ecosystem: "Go", name: "code.gitea.io/gitea" }, affected: [{ events: [{ introduced: "1.17.0" }] }], fixed: [], slugSuffix: "old-module-path" },
    ];
  } else if (id === "SYN-2026-076") {
    parts = [
      { target: { type: "package", ecosystem: "GitHub Actions", name: "aquasecurity/trivy-action" }, affected: [{ events: [{ introduced: "0" }, { fixed: "0.35.0" }] }], fixed: ["0.35.0"] },
      { target: { type: "package", ecosystem: "GitHub Actions", name: "aquasecurity/setup-trivy" }, affected: [{ events: [{ introduced: "0" }, { fixed: "0.2.6" }] }], fixed: ["0.2.6"], slugSuffix: "setup-trivy" },
    ];
  } else if (id === "SYN-2026-070") {
    // Config hygiene class: every third-party action referenced by a mutable tag (pattern, no version).
    parts = [{ target: { type: "package", ecosystem: "GitHub Actions", name: "*" }, affected: [{ events: [{ introduced: "0" }] }], fixed: [] }];
  } else if (id === "SYN-2026-013" || id === "SYN-2026-023") {
    // EOL lines from the verified cycle list; the evaluator gates each on eol.json's date.
    const runtime = id === "SYN-2026-013" ? "node" : "dotnet";
    const affected = [];
    for (const { cycle } of verification.affected[0].cycles) {
      const below = /^<=(\d+)$/.exec(cycle);
      if (below) {
        affected.push({ events: [{ introduced: "0" }, { limit: `${Number(below[1]) + 1}.0.0` }] });
        continue;
      }
      if (!/^\d+$/.test(cycle)) throw new Error(`${id}: unreadable cycle ${cycle}`);
      // .NET lines are major.minor ("8.0"); Node.js lines are majors.
      affected.push({ line: runtime === "dotnet" ? `${cycle}.0` : cycle, events: [{ introduced: `${cycle}.0.0` }] });
    }
    parts = [{ target: { type: "runtime", runtime }, affected, fixed: fixedIn }];
  } else if (eco === "Container images / self-hosted product" || eco === "Container images") {
    const image = candidate.package;
    const coldFusion = image.startsWith("adobecoldfusion/");
    const weblogic = image === "container-registry.oracle.com/middleware/weblogic";
    const wso2 = image === "wso2/wso2am";
    if (coldFusion || weblogic || wso2) productRule = "verify-hotfix";
    let target;
    if (Object.hasOwn(IMAGE_ALIASES, image)) target = { type: "package", ...IMAGE_ALIASES[image] };
    else if (coldFusion) target = { type: "product", product: "coldfusion" };
    else {
      const product = productOfImage(image);
      if (!product) throw new Error(`${id}: no product for image ${image}`);
      target = { type: "product", product };
    }
    let affected;
    let fixed = fixedIn;
    if (coldFusion && fixedIn.some((f) => /Update\s+\d+/i.test(f))) {
      affected = fixedIn.map(coldFusionRange);
    } else if (Object.hasOwn(VENDOR_VERSIONS, id)) {
      affected = versionRanges(VENDOR_VERSIONS[id], false);
    } else {
      affected = mapAffected(affectedIn, { id, provisional, malware, verifyHotfix: productRule === "verify-hotfix", genericProduct: target.type === "product" });
    }
    if (wso2) fixed = [];
    parts = [{ target, affected, fixed, ...(target.type === "package" ? { image } : {}) }];
  } else {
    let target;
    if (Object.hasOwn(RUNTIME_OF, eco)) target = { type: "runtime", runtime: RUNTIME_OF[eco] };
    else if (eco === "npm (Electron bundled Chromium)") target = { type: "package", ecosystem: "npm", name: "electron" };
    else if (eco === "Erlang/OTP runtime") target = { type: "product", product: "erlang" };
    else if (eco === "GitHub Actions") target = { type: "package", ecosystem: "GitHub Actions", name: candidate.package };
    else if (eco === "CMS extension") {
      // WordPress.org plugins as Composer packages (WPackagist); the slug comes from the verified record.
      const slug = verification.affected[0]?.product ?? { "SYN-2026-323": "duplicator" }[id];
      if (!slug) throw new Error(`${id}: no plugin slug`);
      target = { type: "package", ecosystem: "Packagist", name: `wpackagist-plugin/${slug}` };
    } else if (/WordPress core/.test(eco)) target = { type: "product", product: "wordpress" };
    else if (eco === "Go / container image") target = { type: "package", ecosystem: "Go", name: "gogs.io/gogs" };
    else if (eco === "Packagist (repo.mirasvit.com)") target = { type: "package", ecosystem: "Packagist", name: candidate.package };
    else if (Object.hasOwn(PACKAGE_ECOSYSTEM, eco)) target = { type: "package", ecosystem: PACKAGE_ECOSYSTEM[eco], name: candidate.package };
    else throw new Error(`${id}: unmapped ecosystem ${eco}`);
    let affectedSrc = affectedIn;
    if (id === "SYN-2026-323") {
      // Lite (wordpress.org, 1.3.28) only; the Pro line (3.8.7.1) is not distributed through WPackagist.
      affectedSrc = [{ events: [{ introduced: "0" }, { fixed: "1.3.28" }] }];
    }
    let fixed = fixedIn;
    if (id === "SYN-2026-117") fixed = ["6.7.1"]; // Community Edition: the only line published to Maven Central.
    parts = [{ target, affected: mapAffected(affectedSrc, { id, provisional, malware, verifyHotfix: false, genericProduct: target.type === "product" }), fixed }];
  }

  const verifyHotfix = productRule === "verify-hotfix";
  const out = [];
  parts.forEach((part, index) => {
    const childId = index === 0 ? id : `${id}${String(index).padStart(2, "0")}`;
    const fixed = unique(part.fixed ?? []);
    const noFix = !provisional && candidate.kind === "vulnerability" && fixed.length === 0 && !verifyHotfix && part.target.ecosystem !== "GitHub Actions";
    const advisory = {
      ...base,
      id: childId,
      slug: part.slugSuffix ? `${base.slug}-${part.slugSuffix}` : base.slug,
      aliases: unique([...base.aliases, ...(part.extraAliases ?? []), ...(index > 0 ? [id] : [])]),
      target: part.target,
      affected: part.affected,
      fixed,
      remediation_steps: remediationFor(candidate, part.target, fixed, { kev, verifyHotfix, noFix, provisional, image: part.image }),
      ...(verifyHotfix ? { product_rule: "verify-hotfix" } : {}),
      ...(REQUIRES_M2.has(id) ? { requires: "M2" } : REQUIRES_PLATFORM.has(id) ? { requires: "platform-detection" } : {}),
      ...(noFix ? { no_fix_available: true } : {}),
    };
    PARENT.set(childId, id);
    out.push(order(advisory));
  });
  return out;
}

/** Verified / provisional affected elements → schema ranges (keys other than line/events dropped). */
function mapAffected(elements, { id, provisional, malware, verifyHotfix, genericProduct }) {
  const out = [];
  for (const element of elements ?? []) {
    if (Array.isArray(element.versions)) {
      out.push(...versionRanges(element.versions, malware));
      continue;
    }
    if (!Array.isArray(element.events) || element.events.length === 0) throw new Error(`${id}: affected element has no events`);
    let events = cleanEvents(element.events, id);
    if (provisional) {
      // A fixed release the verifier did not confirm is not a fix claim: keep the range, bound it with a limit.
      events = events.map((e) => ("fixed" in e ? { limit: e.fixed } : e));
    }
    if (verifyHotfix) {
      // A patch-level product's fix is a hotfix: a listed last version bounds the range, it is not "no patch".
      events = events.map((e) => ("last_affected" in e ? { limit: bump(e.last_affected) } : e));
    }
    if (genericProduct) {
      // Product tags compare as plain numbers: a pre-release `introduced` narrows to its release (never widens).
      events = events.map((e) => ("introduced" in e && e.introduced !== "0" && !NUMERIC.test(e.introduced) ? { introduced: e.introduced.match(/^\d+(?:\.\d+)*/)?.[0] ?? e.introduced } : e));
    }
    out.push({ ...(element.line ? { line: element.line } : {}), events });
  }
  return out;
}

function remediationFor(candidate, target, fixed, flags) {
  const id = candidate.id;
  let steps = [...candidate.remediation_steps];
  const override = STEP_OVERRIDES[id];
  if (override) {
    const [pattern, text] = override.replace;
    const at = steps.findIndex((step) => pattern.test(step));
    if (at < 0) throw new Error(`${id}: step override did not match`);
    steps[at] = text;
  }
  const actions = target.type === "package" && target.ecosystem === "GitHub Actions";
  if (flags.kev && !actions) {
    steps = steps.filter((step) => !STALE_STEP.test(step));
    steps.unshift(upgradeStep(target, fixed, flags));
  }
  return unique(steps.map((s) => s.trim()).filter(Boolean));
}

const KEY_ORDER = [
  "id", "slug", "title", "kind", "aliases", "target", "affected", "fixed", "severity", "exploited", "exploited_source",
  "remediation_steps", "sources", "status", "provisional", "product_rule", "no_fix_available", "requires",
];

function order(advisory) {
  const out = {};
  for (const key of KEY_ORDER) if (advisory[key] !== undefined) out[key] = advisory[key];
  return out;
}

// ---- approved list ----

async function readApproved(path) {
  const text = await readFile(path, "utf8");
  const verdicts = new Map();
  let section;
  for (const line of text.split(/\r?\n/)) {
    const heading = /^## (provisional|drop|corrected|verified)\b/.exec(line);
    if (heading) section = heading[1];
    else if (/^## /.test(line)) section = undefined;
    const row = /^\| (SYN-\d{4}-\d{3,}) \|/.exec(line);
    if (row && section) {
      if (verdicts.has(row[1])) throw new Error(`approved list names ${row[1]} twice`);
      verdicts.set(row[1], section);
    }
  }
  return verdicts;
}

// ---- EOL ----

async function eolProduct(slug, cacheDir) {
  const cached = cacheDir ? join(cacheDir, `${slug}.json`) : undefined;
  if (cached && existsSync(cached)) return { cycles: await readJson(cached), fetched: false };
  const response = await fetch(`https://endoflife.date/api/${slug}.json`, { headers: { "User-Agent": USER_AGENT, Accept: "application/json" } });
  if (!response.ok) throw new Error(`endoflife.date ${slug}: HTTP ${response.status}`);
  const body = await response.text();
  if (cached) {
    await mkdir(cacheDir, { recursive: true });
    await writeFile(cached, body);
  }
  return { cycles: JSON.parse(body), fetched: true };
}

/** A runtime cycle at the evaluator's granularity: dotnet "8" → "8.0", ruby "2.0.0" → "2.0". */
function runtimeCycle(cycle, parts) {
  const split = String(cycle).split(".");
  while (split.length < parts) split.push("0");
  return split.slice(0, parts).join(".");
}

async function buildEol(cacheDir) {
  const entries = [];
  const skipped = [];
  for (const { slug, keys, runtimeParts } of EOL_PRODUCTS) {
    const { cycles } = await eolProduct(slug, cacheDir);
    for (const c of cycles) {
      const eol = typeof c.eol === "string" && /^\d{4}-\d{2}-\d{2}$/.test(c.eol) ? c.eol : undefined;
      let latest = typeof c.latest === "string" && c.latest !== "" ? c.latest : undefined;
      if (!eol || !latest) {
        skipped.push(`${slug} ${c.cycle} (eol ${JSON.stringify(c.eol)}, latest ${JSON.stringify(c.latest)})`);
        continue;
      }
      // Temurin 8 lists "8u504-b01": the `-bNN` build suffix is not part of the release version.
      if (slug === "eclipse-temurin") latest = latest.replace(/-b\d+$/, "");
      const cycle = runtimeParts ? runtimeCycle(c.cycle, runtimeParts) : String(c.cycle);
      for (const product of keys) entries.push({ product, cycle, eol, latest, source: `https://endoflife.date/${slug}` });
    }
  }
  return { entries, skipped };
}

// ---- validation ----

function validate(advisories, verdicts, eol) {
  const problems = [];
  const ids = new Set();
  const slugs = new Set();
  for (const a of advisories) {
    if (ids.has(a.id)) problems.push(`duplicate id ${a.id}`);
    ids.add(a.id);
    if (slugs.has(a.slug)) problems.push(`duplicate slug ${a.slug}`);
    slugs.add(a.slug);
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(a.slug)) problems.push(`${a.id}: bad slug ${a.slug}`);
    if (a.product_rule !== undefined && a.target.type !== "product") problems.push(`${a.id}: product_rule on a ${a.target.type} target`);
    if (!a.sources.some(isHttps)) problems.push(`${a.id}: no https source`);
    if (!a.provisional && a.fixed.length === 0 && !["eol", "malware", "config"].includes(a.kind) && !a.no_fix_available && a.product_rule !== "verify-hotfix") {
      problems.push(`${a.id}: non-provisional without a fixed version`);
    }
    if (a.no_fix_available && a.fixed.length > 0) problems.push(`${a.id}: no_fix_available with fixed versions`);
    if (a.kind !== "eol" && a.affected.length === 0) problems.push(`${a.id}: no affected range`);
    const text = [a.title, ...a.remediation_steps, ...a.fixed].join("\n");
    if (/\(inferred\)|; verify\)/.test(text)) problems.push(`${a.id}: carries an inferred fix`);
    const parent = PARENT.get(a.id);
    if (parent === undefined) problems.push(`${a.id}: no recorded parent id`);
    if (verdicts.get(parent) === "drop") problems.push(`${a.id}: dropped entry shipped`);
    if (verdicts.get(parent) === "provisional" && !a.provisional) problems.push(`${a.id}: provisional entry shipped as verified`);
  }
  for (const [id, verdict] of verdicts) {
    if (verdict === "drop" || Object.hasOwn(UNREPRESENTABLE, id)) continue;
    if (!ids.has(id)) problems.push(`approved ${id} missing`);
  }
  const cycles = new Set();
  for (const e of eol) {
    const key = `${e.product}\0${e.cycle}`;
    if (cycles.has(key)) problems.push(`duplicate eol cycle ${e.product} ${e.cycle}`);
    cycles.add(key);
  }
  return problems;
}

// ---- main ----

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const candidates = (await Promise.all(args.candidates.map(readJson))).flat();
  const verifications = (await Promise.all(args.verification.map(readJson))).flat();
  const verdicts = await readApproved(args.approved);

  const byId = new Map(verifications.map((v) => [v.id, v]));
  const problems = [];
  for (const candidate of candidates) {
    const v = byId.get(candidate.id);
    if (!v) problems.push(`${candidate.id}: no verification record`);
    else if (verdicts.get(candidate.id) !== v.verdict) problems.push(`${candidate.id}: approved list says ${verdicts.get(candidate.id)}, verification says ${v.verdict}`);
  }
  if (verdicts.size !== candidates.length) problems.push(`approved list has ${verdicts.size} entries, candidates ${candidates.length}`);
  if (problems.length > 0) throw new Error(problems.join("\n"));

  const advisories = [];
  for (const candidate of candidates) {
    const verdict = verdicts.get(candidate.id);
    if (verdict === "drop" || Object.hasOwn(UNREPRESENTABLE, candidate.id)) continue;
    advisories.push(...mapEntry(candidate, byId.get(candidate.id), verdict));
  }
  advisories.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const eol = await buildEol(args.eolCache);
  const issues = validate(advisories, verdicts, eol.entries);
  if (issues.length > 0) throw new Error(issues.join("\n"));

  const aliases = { packages: {}, imageAliases: IMAGE_ALIASES, productImages: PRODUCT_IMAGES };
  await mkdir(args.out, { recursive: true });
  await writeFile(join(args.out, "advisories.json"), `${JSON.stringify({ advisories }, null, 2)}\n`);
  await writeFile(join(args.out, "aliases.json"), `${JSON.stringify(aliases, null, 2)}\n`);
  await writeFile(join(args.out, "eol.json"), `${JSON.stringify({ entries: eol.entries }, null, 2)}\n`);

  const count = (pred) => advisories.filter(pred).length;
  const kinds = {};
  for (const a of advisories) kinds[a.kind] = (kinds[a.kind] ?? 0) + 1;
  const eolPerProduct = {};
  for (const e of eol.entries) eolPerProduct[e.product] = (eolPerProduct[e.product] ?? 0) + 1;
  console.error(JSON.stringify({
    advisories: advisories.length,
    kinds,
    provisional: count((a) => a.provisional),
    requiresM2: count((a) => a.requires === "M2"),
    requiresPlatform: count((a) => a.requires === "platform-detection"),
    verifyHotfix: count((a) => a.product_rule === "verify-hotfix"),
    noFixAvailable: count((a) => a.no_fix_available),
    unrepresentable: Object.keys(UNREPRESENTABLE),
    imageAliases: Object.keys(IMAGE_ALIASES).length,
    productImages: Object.keys(PRODUCT_IMAGES).length,
    eolCycles: eol.entries.length,
    eolPerProduct,
    eolSkipped: eol.skipped,
  }, null, 2));
  console.error("[build-synvoya-dataset] wrote advisories.json, aliases.json, eol.json; run scripts/synvoya-manifest.mjs next");
}

main().catch((error) => {
  console.error(`[build-synvoya-dataset] ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
