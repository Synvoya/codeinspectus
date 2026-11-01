CodeInspectus scan of /fixture/repo
6 findings — 2 critical, 4 high, 0 medium, 0 low, 0 info.
Engines: gitleaks@8.30.1, codeinspectus-ai@5.20.0 | offline: true

Detected technologies: typescript, sql, supabase
Native pack execution (registered rules only; not complete language coverage):
  javascript-typescript=ran (12/12 analyzers, 29/29 rules)
  flutter=not_applicable (0/6 analyzers, 0/6 rules) — No detected project technology matched this native pack; its analyzers did not run.
  android=not_applicable (0/1 analyzers, 0/4 rules) — No detected project technology matched this native pack; its analyzers did not run.
  ios=not_applicable (0/1 analyzers, 0/4 rules) — No detected project technology matched this native pack; its analyzers did not run.
  react-native=not_applicable (0/4 analyzers, 0/4 rules) — No detected project technology matched this native pack; its analyzers did not run.
  expo=not_applicable (0/2 analyzers, 0/2 rules) — No detected project technology matched this native pack; its analyzers did not run.
  python-ai-api=not_applicable (0/10 analyzers, 0/10 rules) — No detected project technology matched this native pack; its analyzers did not run.
  javascript-baseline=ran (1/1 analyzers, 2/2 rules) — Opengrep did not run; promoted rules used the native fallback.
  go-ai=not_applicable (0/1 analyzers, 0/1 rules) — No detected project technology matched this native pack; its analyzers did not run.
  java-ai=not_applicable (0/1 analyzers, 0/1 rules) — No detected project technology matched this native pack; its analyzers did not run.
  csharp-ai=not_applicable (0/1 analyzers, 0/1 rules) — No detected project technology matched this native pack; its analyzers did not run.
  php-ai=not_applicable (0/1 analyzers, 0/1 rules) — No detected project technology matched this native pack; its analyzers did not run.
  rust-ai=not_applicable (0/1 analyzers, 0/1 rules) — No detected project technology matched this native pack; its analyzers did not run.
  ruby-ai=not_applicable (0/1 analyzers, 0/1 rules) — No detected project technology matched this native pack; its analyzers did not run.
  firebase=not_applicable (0/1 analyzers, 0/3 rules) — No detected project technology matched this native pack; its analyzers did not run.
  github-actions=not_applicable (0/1 analyzers, 0/2 rules) — No detected project technology matched this native pack; its analyzers did not run.

Repository trust: partial (0 artifact(s), schema 1.0.0)
  source_integrity: ran via codeinspectus-source-integrity@1.0.0
  explicit_ai_attribution: ran via codeinspectus-explicit-ai-attribution@1.0.0
  content_provenance: not_applicable via no validator
  statistical_watermark: unavailable via no validator
  States: 0 verified, 0 probable, 0 informational, 0 not verifiable
  Limits: Statistical watermark verification remains unavailable; V3.3 cleanup is limited to separately approved deterministic records and never performs statistical rewriting.

Native dependency coverage (exact locked-version matching only):
  Pub/codeinspectus-pub=not_applicable (0/0 lockfiles, 0/0 eligible packages, 0 unverifiable git/custom-hosted) — No Dart project signal was detected, so native Pub dependency analysis was not applicable.

Top findings:
  • [critical] Hard-coded secret in client-reachable code — src/config.ts:5 (CWE-798, CWE-312, codeinspectus-ai)
  • [critical] RLS permits SELECT on sensitive table 'profiles' for anonymous and authenticated clients — supabase/migrations/0001_init.sql:18 (CWE-863, CWE-285, codeinspectus-ai)
  • [high] Model-produced tool argument reaches shell execution — src/agent.ts:9 (CWE-78, CWE-1426, codeinspectus-ai)
  • [high] Secret exposed via client-visible env prefix — src/components/PaymentForm.tsx:6 (CWE-798, CWE-312, codeinspectus-ai)
  • [high] Potential prompt-injection sink with tool/function-calling access — src/llm.ts:11 (CWE-1427, codeinspectus-ai)
  • [high] Repository-defined public table 'payments' lacks Row Level Security — supabase/migrations/0001_init.sql:22 (CWE-862, CWE-285, codeinspectus-ai)

Runtime-control evidence (metadata; no absence penalty):
  0 verified in repository | 0 explicit insecure configuration | 8 not verifiable from repository

Machine setup:
  Engine setup repair_required; engines opengrep:missing, trivy:missing; Trivy DB missing. After user approval, run `npx codeinspectus setup` (or the codeinspectus_setup tool, planning first).

Before you fix:
  No git repository detected here. Before applying any fixes, consider initializing git and committing a checkpoint so changes can be undone.

Engine status:
  ! opengrep: Engine 'opengrep' is not available. Run `codeinspectus setup` (or the codeinspectus_setup tool) once per machine to review, fetch and SHA-pin the engine binaries; downloads happen only after approval. Expected at: /fixture/home/.codeinspectus/bin/opengrep.
  ! trivy: Engine 'trivy' is not available. Run `codeinspectus setup` (or the codeinspectus_setup tool) once per machine to review, fetch and SHA-pin the engine binaries; downloads happen only after approval. Expected at: /fixture/home/.codeinspectus/bin/trivy.

Warnings:
  - opengrep did not run: Engine 'opengrep' is not available. Run `codeinspectus setup` (or the codeinspectus_setup tool) once per machine to review, fetch and SHA-pin the engine binaries; downloads happen only after approval. Expected at: /fixture/home/.codeinspectus/bin/opengrep.
  - trivy did not run: Engine 'trivy' is not available. Run `codeinspectus setup` (or the codeinspectus_setup tool) once per machine to review, fetch and SHA-pin the engine binaries; downloads happen only after approval. Expected at: /fixture/home/.codeinspectus/bin/trivy.

AI-drafted, reviewed by a cybersecurity practitioner (Synvoya) — code-level coverage only, not an audit or certification. Community review welcome.
