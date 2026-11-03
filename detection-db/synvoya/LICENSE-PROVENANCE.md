# Synvoya gap-advisory dataset provenance

The files in this directory are an offline dataset of vulnerabilities that no bundled engine
reports: declared runtimes, end-of-life lines, exploited products and malicious package versions.
They ship inside the npm package. CodeInspectus scans never contact any network service to read
them.

## advisories.json

- Authorship: the entries are authored by CodeInspectus from cited sources. Each advisory lists
  its sources as https URLs, the vendor's own advisory first where one was opened.
- Licence: Apache-2.0, like the rest of `detection-db/`. Upstream facts (version numbers, dates,
  identifiers) are cited, not copied as text.
- Review: every entry was re-checked against the vendor's primary source on 2026-11-03 and the
  entry list was approved by the maintainer the same day. Entries the check confirmed or corrected
  ship as normal advisories. Entries it could not confirm ship with `provisional: true`: their
  findings are low confidence and their titles say "verify with the vendor", and a fixed version
  the check did not confirm is not listed. Rejected entries are not shipped.
- Patch-level products (Adobe Commerce, Magento Open Source, ColdFusion, WebLogic, WSO2) are
  fixed by hotfixes or update levels that a version string or image tag does not show. Their
  findings ask the user to verify the vendor fix (`product_rule: "verify-hotfix"`), except on a
  release line the vendor does not patch at all. ColdFusion image tags `<release>.0.<n>` are read as
  Update `<n>`. The tags for the fixed updates exist on Docker Hub, but Adobe does not state the
  mapping.
- Entries that need a reader from a later release (GitHub Actions, the Go standard library via
  SBOM) carry `requires: "M2"` and are not evaluated yet. Entries whose flaw needs a platform no
  reader can see yet (CVE-2024-4577: PHP-CGI on Windows) carry `requires: "platform-detection"` and
  are not evaluated either.

## aliases.json

Maps container image names to the package or product they run, so an image tag is checked against
the same advisories. Every Docker Hub name was confirmed to exist on 2026-11-03. Names on vendor
registries (ghcr.io, docker.osgeo.org, releases-docker.jfrog.io, container-registry.oracle.com,
docker.elastic.co) come from the reviewed entries' own detection notes.

## eol.json — endoflife.date (MIT)

- Source: endoflife.date (https://endoflife.date, data repository
  https://github.com/endoflife-date/endoflife.date), read through its public API
  `https://endoflife.date/api/<product>.json`.
- Retrieved: 2026-11-03, by `scripts/build-synvoya-dataset.mjs` on a maintainer machine. Scans
  never fetch it.
- Licence: MIT. The repository's `LICENSE` file
  (https://github.com/endoflife-date/endoflife.date/blob/master/LICENSE) was checked on 2026-11-03.
  Its notice is reproduced below as the licence requires.
- Products: nodejs (as `node`), php, python, ruby, go, dotnet, eclipse-temurin (as `java`), mysql,
  mariadb, postgresql (as `postgres` and `postgresql`), redis, mongodb, elasticsearch, rabbitmq,
  nginx and apache-http-server (as `httpd`).
- Only cycles with an end-of-life date and a latest release are kept. A cycle with no date (still
  supported with no end announced, or an end with no recorded date) is left out, never guessed.
  The only changes made are format conversions to the evaluator's line format:
  - .NET `8` is written `8.0`.
  - Ruby `2.0.0` is written `2.0`.
  - The build suffix of Temurin `8u504-b01` is dropped.
- Each entry's `source` is the endoflife.date product page.

```
Copyright 2020 endoflife.date contributors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Integrity

`manifest.json` holds a SHA-256 digest for every data file, and the loader refuses any file that
does not match. The data files are rebuilt with `node scripts/build-synvoya-dataset.mjs` (a
maintainer-only script that takes the reviewed research files as arguments). After editing a data
file, run `node scripts/synvoya-manifest.mjs`. To verify the digests, run
`node scripts/synvoya-manifest.mjs --check`.
