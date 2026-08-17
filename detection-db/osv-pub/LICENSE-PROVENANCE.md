# OSV Pub snapshot provenance

`snapshot.json` is a normalized, offline snapshot of the OSV.dev `Pub` ecosystem export.
It is refreshed only by an explicit maintainer action; CodeInspectus scans never contact OSV,
GitHub, pub.dev, or any other network service.

- Aggregate source: <https://storage.googleapis.com/osv-vulnerabilities/Pub/>
- Source documentation: <https://google.github.io/osv.dev/data/>
- Record source: GitHub Advisory Database
- Data license: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Attribution: OSV.dev and GitHub Advisory Database contributors

The generated snapshot records the upstream index and record-content SHA-256 digests, retrieval
time, upstream modification version, withdrawn-record filtering, and exact affected versions used
for matching. CodeInspectus does not claim authorship of the advisory data. Its lockfile parser,
matching logic, finding normalization, provenance model, SBOM generation, fixtures, and tests are
CodeInspectus-original Apache-2.0-licensed code.

Do not hand-edit `snapshot.json`. Run `node scripts/update-osv-pub-snapshot.mjs`, inspect the diff,
run the Pub corpus and MCP evals, and review any new source license before releasing a refresh.
