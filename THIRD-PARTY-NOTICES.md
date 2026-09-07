# Third-party notices

This document records third-party software and data used by CodeInspectus 3.2.0. CodeInspectus
itself is licensed under Apache-2.0; third-party components retain their own licenses.

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

Guided setup downloads Cosign only when Opengrep or Trivy needs publisher-signature verification
and no usable system copy exists. Its platform binary SHA-256 is pinned from the upstream checksum
manifest after that manifest's Sigstore bundle verified successfully. Cosign is stored separately
under `~/.codeinspectus/bin`; it is not included in the npm package.

### Opengrep 1.23.0

- Project: <https://github.com/opengrep/opengrep>
- Exact source: <https://github.com/opengrep/opengrep/tree/v1.23.0>
- License: GNU Lesser General Public License 2.1
- License text: <https://github.com/opengrep/opengrep/blob/v1.23.0/LICENSE>
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

### Trivy 0.71.2

- Project: <https://github.com/aquasecurity/trivy>
- Exact source: <https://github.com/aquasecurity/trivy/tree/v0.71.2>
- License: Apache License 2.0
- License text: <https://github.com/aquasecurity/trivy/blob/v0.71.2/LICENSE>
- Upstream notice: Trivy, Copyright 2019-2020 Aqua Security Software Ltd. This product includes
  software developed by Aqua Security (<https://aquasec.com>).

Trivy's vulnerability database is separately downloaded by Trivy and aggregates advisory data from
multiple sources with heterogeneous licenses. Neither the executable nor that database is included
in the CodeInspectus npm package.

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
| `@contentauth/c2pa-types` | 0.7.4 | MIT OR Apache-2.0 | Content Authenticity Initiative / Adobe contributors |
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

Apache, Opengrep, Gitleaks, Trivy, Semgrep, Supabase, and other project or company names are the
property of their respective owners. Their names are used only to identify interoperability,
provenance, and license obligations. No endorsement is implied.
