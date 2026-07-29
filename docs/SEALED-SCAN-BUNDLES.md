# Sealed scan bundles

Create portable, tamper-evident evidence from an existing stored scan:

```bash
codeinspectus bundle create SCAN_ID --output-dir /outside/repository/scan-results
codeinspectus bundle verify /outside/repository/scan-results
codeinspectus bundle export /outside/repository/scan-results --format json
codeinspectus bundle compare OLD_BUNDLE NEW_BUNDLE --format json
```

Creation is additive: it reads an existing scan and never migrates, rewrites, or deletes that
record. The destination must not exist, its parent must already exist, and it must be outside the
scanned repository. The complete directory is assembled beside the destination and renamed into
place only after every artifact is written.

```text
scan-results/
├── scan-manifest.json
├── findings.json
├── coverage.json
├── report.md
├── results.sarif
└── artifacts/
    ├── export.json
    └── scan-record.json
```

The versioned manifest records CodeInspectus, schema, detection-database, native-engine and
commodity-engine versions; verified platform SHA-256 pins where the stored scan proves them;
component signatures; target and exact Git revision when available; scan configuration/scope;
start/completion/seal timestamps; and byte length plus SHA-256 for every retained artifact.

All public content is redacted before hashing and persistence. The canonical export is retained
as an artifact so a later CodeInspectus version can return the exact sealed JSON contract without
recomputing coverage against a newer detector registry. The redacted tolerant scan record supports
comparison while preserving older stored-scan compatibility.

Verification is mandatory before bundle export or comparison. It rejects missing, extra, corrupt,
swapped, symbolic, traversal-shaped, oversized, schema-invalid, identity-mismatched, or concurrently
changed artifacts. Artifact paths are a fixed allowlist and cannot escape the bundle directory.

The manifest contains a SHA-256 seal over its payload. This provides deterministic integrity and
accidental/casual tamper detection, not third-party authenticity: it is not a digital signature and
an attacker able to replace the entire bundle can recompute unkeyed hashes. Preserve bundles in a
trusted artifact store or add an external signature when independent attestation is required.
