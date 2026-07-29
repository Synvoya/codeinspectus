# V2 workflow design provenance

CodeInspectus 2.0's CLI, CI, export, history, baseline, bundle, SDK, issue-payload, and optional
agent-workflow concepts were informed by publicly visible security-tool and agent-workflow patterns,
including the Apache-2.0-licensed OpenAI Codex Security repository.

The CodeInspectus implementations in this repository were independently designed for its existing
local-first architecture. No Codex Security source code or documentation text was copied into these
features. No new runtime dependency was added for the V2 workflow layer. Existing third-party engine,
library, and ruleset licensing remains recorded in `THIRD-PARTY-NOTICES.md`, lockfiles, and the
rule-provenance documents.

Architectural differences are deliberate:

- deterministic local engines and first-party bounded analyzers remain the only scan-finding source;
- scans require no account, cloud service, telemetry, or model call;
- repository source and Git state remain read-only;
- optional agent interpretation is labelled separately and cannot change scanner truth;
- external tracker support produces review-only redacted payloads, not live submissions;
- bulk mode scans existing local repositories and performs no remote organization discovery or cloning.

If future work reuses Apache-2.0 source rather than a general product concept, it must retain the
required notices and record the exact files, upstream revision, licence, modifications, and shipped
artifact path before release.
