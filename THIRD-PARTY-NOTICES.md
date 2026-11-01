# Third-party notices

This document records third-party software and data used by CodeInspectus. CodeInspectus itself
is licensed under Apache-2.0; third-party components retain their own licenses. The exact engine
versions are the ones pinned in `engines.lock.json`.

## Separately downloaded security engines

The following executables are **not included in the CodeInspectus npm package**. The explicit
`repair-engines` command downloads them from their upstream GitHub release, verifies the pinned
publisher/checksum evidence and exact binary SHA-256 from `engines.lock.json`, and stores them in a
per-user managed directory. CodeInspectus is not affiliated with or endorsed by these projects.

### Cosign 3.1.2 (verification helper)

- Project: <https://github.com/sigstore/cosign>
- Exact source: <https://github.com/sigstore/cosign/tree/v3.1.2>
- License: Apache License 2.0
- License text: <https://github.com/sigstore/cosign/blob/v3.1.2/LICENSE>
- Copyright: The Sigstore Authors

Guided setup downloads Cosign only when Opengrep, Trivy, or osv-scanner needs publisher-signature
or build-provenance verification and no usable system copy exists. Its platform binary SHA-256 is pinned from the upstream checksum
manifest after that manifest's Sigstore bundle verified successfully. Cosign is stored separately
under `~/.codeinspectus/bin`; it is not included in the npm package.

### Opengrep 1.33.1

- Project: <https://github.com/opengrep/opengrep>
- Exact source: <https://github.com/opengrep/opengrep/tree/v1.33.1>
- License: GNU Lesser General Public License 2.1
- License text: <https://github.com/opengrep/opengrep/blob/v1.33.1/LICENSE>
- Copyright notice: Semgrep, Copyright (C) 2019-2024 Semgrep Inc., as preserved in the
  upstream `COPYRIGHT` file.

CodeInspectus invokes the separate executable through its command-line interface. It does not
incorporate Opengrep source code and does not download or redistribute the restricted
`opengrep/opengrep-rules` corpus. The local first-party `security-baseline` rules are independently
authored and licensed under Apache-2.0.

### Gitleaks 8.30.1

- Project: <https://github.com/gitleaks/gitleaks>
- Exact source: <https://github.com/gitleaks/gitleaks/tree/v8.30.1>
- License: MIT
- License text: <https://github.com/gitleaks/gitleaks/blob/v8.30.1/LICENSE>
- Copyright (c) 2019 Zachary Rice

CodeInspectus supplies its own configuration while enabling Gitleaks' upstream MIT-licensed default
rules. The separately downloaded executable and its upstream rules remain Gitleaks work.

### Trivy 0.76.1

- Project: <https://github.com/aquasecurity/trivy>
- Exact source: <https://github.com/aquasecurity/trivy/tree/v0.76.1>
- License: Apache License 2.0
- License text: <https://github.com/aquasecurity/trivy/blob/v0.76.1/LICENSE>
- Upstream notice: Trivy, Copyright 2019-2020 Aqua Security Software Ltd. This product includes
  software developed by Aqua Security (<https://aquasec.com>).

Trivy's vulnerability database is separately downloaded by Trivy and aggregates advisory data from
multiple sources with heterogeneous licenses. Neither the executable nor that database is included
in the CodeInspectus npm package.

### osv-scanner 2.7.0

- Project: <https://github.com/google/osv-scanner>
- Exact source: <https://github.com/google/osv-scanner/tree/v2.7.0>
- License: Apache License 2.0
- License text: <https://github.com/google/osv-scanner/blob/v2.7.0/LICENSE>
- Copyright notice: the upstream `LICENSE` is the unmodified Apache-2.0 text and names no
  copyright holder, and the repository ships no `NOTICE` file. The project is maintained by Google.

CodeInspectus invokes the separate executable through its command-line interface with `--offline`,
so it matches lockfiles only against OSV databases already on disk and makes no network request.
It does not incorporate osv-scanner source code. The executable's SHA-256 is pinned from the
upstream `SHA256SUMS` manifest after the release's SLSA build-provenance attestation was verified
with Cosign. The executable is not included in the CodeInspectus npm package.

## OSV vulnerability databases (downloaded after approval)

osv-scanner reads per-ecosystem OSV databases from the OSV.dev bulk export. After explicit
approval, `setup` or `repair-engines` downloads
`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip` directly from that host,
only for the ecosystems you approve (those the scanned repository's lockfiles name, or an explicit
`--osv-ecosystems` list), and stores it under `~/.codeinspectus/osv-db/`. CodeInspectus does not
re-host or redistribute this data, and none of these downloaded databases is included in the npm
package (the separate offline Pub snapshot described below is). Scans never download anything.

Only language-package ecosystems are on the download allow-list: npm, PyPI, Packagist, Go,
crates.io, RubyGems, Maven, NuGet, and Pub. Distribution ecosystems are never downloaded. OSV
publishes no signature for these archives, so integrity rests on TLS to that one host plus a
SHA-256 CodeInspectus records at install time.

OSV records keep the license of the source that published them; there is no single OSV license.
The OSV sources CodeInspectus attributes, and the license each publishes under, are:

| Source (record prefix) | Data license |
|---|---|
| GitHub Advisory Database (`GHSA-`) | CC BY 4.0 |
| PyPA Advisory Database (`PYSEC-`) | CC BY 4.0 |
| OSS-Fuzz (`OSV-`) | CC BY 4.0 |
| Go Vulnerability Database (`GO-`) | CC BY 4.0 |
| OpenSSF Malicious Packages (`MAL-`) | Apache License 2.0 |
| Drupal (`DRUPAL-`) | MIT |
| RustSec (`RUSTSEC-`) | CC0 1.0 |

- Licenses: <https://creativecommons.org/licenses/by/4.0/> (CC BY 4.0),
  <https://www.apache.org/licenses/LICENSE-2.0> (Apache License 2.0),
  <https://opensource.org/license/mit> (MIT),
  <https://creativecommons.org/publicdomain/zero/1.0/> (CC0 1.0)
- Documentation: <https://google.github.io/osv.dev/data/>
- Attribution: OSV.dev and its sources: GitHub Advisory Database, PyPA Advisory Database, OSS-Fuzz,
  Go Vulnerability Database, OpenSSF Malicious Packages, Drupal, and RustSec contributors.

This table is an attribution record, not legal advice or a legal review. A source that OSV adds
later keeps its own license. Findings that come from this data are matched locally and carry the
advisory identifier of the source that published them.

## Offline OSV Pub advisory snapshot

`detection-db/osv-pub/snapshot.json` is a normalized offline snapshot of the OSV.dev Pub ecosystem
export. The record source is the GitHub Advisory Database and the data is provided under Creative
Commons Attribution 4.0 International.

- Source: <https://storage.googleapis.com/osv-vulnerabilities/Pub/>
- Documentation: <https://google.github.io/osv.dev/data/>
- License: <https://creativecommons.org/licenses/by/4.0/>
- Attribution: OSV.dev and GitHub Advisory Database contributors

See `detection-db/osv-pub/LICENSE-PROVENANCE.md` for the captured snapshot provenance.

## npm runtime dependencies

These are installed as separate npm packages alongside CodeInspectus. The CodeInspectus build keeps
runtime dependencies external rather than copying their source into its generated JavaScript. Each
package distributed by npm retains its own package metadata and license file.

| Package | Version | License | Copyright / project |
|---|---:|---|---|
| `@modelcontextprotocol/sdk` | 1.30.0 | MIT | Copyright (c) 2024 Anthropic, PBC |
| `@contentauth/c2pa-node` | 0.9.3 | MIT | Content Authenticity Initiative / Adobe contributors; optional native C2PA validator |
| `@contentauth/c2pa-types` | 0.7.4 | MIT | Copyright 2025 Adobe (package LICENSE) |
| `@contentauth/c2pa-utilities` | 0.2.2 | MIT | Content Authenticity Initiative / Adobe contributors |
| `exifreader` | 4.44.0 | MPL-2.0 | Copyright Mattias Wallander and contributors; EXIF/XMP/IPTC parser |
| `@lezer/python` | 1.1.19 | MIT | Copyright (C) 2020 Marijn Haverbeke and others |
| `@lezer/common` | 1.5.2 | MIT | Copyright (C) 2018 Marijn Haverbeke and others |
| `@lezer/lr` | 1.4.10 | MIT | Copyright (C) 2018 Marijn Haverbeke and others |
| `@lezer/highlight` | 1.2.3 | MIT | Copyright (C) 2018 Marijn Haverbeke and others |
| `smol-toml` | 1.7.1 | BSD-3-Clause | Copyright (c) Squirrel Chat et al. |
| `yaml` | 2.9.0 | ISC | Copyright Eemeli Aro |
| `zod` | 3.25.76 | MIT | Copyright (c) 2025 Colin McDonnell |

Transitive npm dependencies remain separately installed packages and retain their own licenses and
copyright notices. The exact resolved dependency graph is recorded in `package-lock.json`; generated
CycloneDX SBOM output provides the machine-readable package inventory.

`@contentauth/c2pa-node` is an optional peer. Normal CodeInspectus installation does not install it;
users who explicitly install that upstream package allow its platform-native lifecycle download.
CodeInspectus invokes it only for local, read-only C2PA validation and disables remote-manifest and
revocation fetching during scans. `exifreader` remains a separately installed npm package;
CodeInspectus does not modify or redistribute its source.

## Trademark statement

Apache, Opengrep, Gitleaks, Trivy, osv-scanner, OSV.dev, Google, Semgrep, Supabase, and other
project or company names are the property of their respective owners. Their names are used only to identify interoperability,
provenance, and license obligations. No endorsement is implied.
