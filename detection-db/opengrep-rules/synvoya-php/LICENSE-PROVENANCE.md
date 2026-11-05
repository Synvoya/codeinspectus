# Synvoya PHP pack -- license & provenance

**License:** Apache-2.0 (same as CodeInspectus). (c) Synvoya.

These Opengrep rules (`syn-php-*`) were **written from first principles** for CodeInspectus 4.0
(design: Synvoya PHP pack, plain PHP + Laravel + Symfony + WordPress). The author worked from the
PHP manual, the framework documentation (Laravel, Symfony, WordPress developer handbook) and the
CWE/OWASP descriptions of each weakness. **No rule text, pattern list, message or metadata was
copied or adapted** from any third-party rule corpus, in particular:

- `opengrep/opengrep-rules` (LGPL-2.1 **+ Commons Clause**), and
- `semgrep/semgrep-rules` (Semgrep Rules License v1.0),

neither of which was opened while authoring this pack (legal gate CG-63). What resembles other
rulesets is the **forced functional form** of a check -- the PHP function names a sink has
(`mysqli_query`, `shell_exec`, `unserialize`), the superglobals a source has (`$_GET`, `$_POST`),
or a configuration key (`CURLOPT_SSL_VERIFYPEER`, `permission_callback`) -- which is the only way to
express the check and is therefore not protectable expression.

Design choices that are specific to this pack (and evidence of independent authorship):

- **One shared taint vocabulary** in `taint.yaml` (YAML anchors): request sources for
  superglobals, Laravel (`$request->input()`, `request()`, `Request::`), Symfony
  (`$request->query->get()`) and WordPress REST (`$request->get_param()`); a scalar-result
  sanitizer set; and an explicit **propagator list** combined with
  `taint_assume_safe_functions`, chosen after field triage showed that letting every call
  propagate (getters on request-derived objects, database loaders keyed by a request id) was the
  main false-positive source.
- **Sink-specific sanitizers** (no name-based sanitizer applies to every sink; project helpers named
  as path cleaners count for path, phar and include sinks only, redirect validators for redirects
  only): WordPress `sanitize_text_field()` sanitizes nothing for SQL, shell,
  path or HTML-attribute output (it keeps quotes) and is treated as a propagator; `sanitize_key()`
  and `absint()` are sanitizers everywhere; `esc_sql()` only for SQL; `esc_*()` only for output.
- **Prefix-aware URL sinks**: SSRF sinks (and the experimental open-redirect rule) ignore input placed after a literal
  scheme-and-host or a relative path, because the destination host is then fixed.
- **Handler-aware WordPress access checks**: REST and admin-ajax rules read the handler body in
  the same file and stay quiet when it verifies a nonce, capability, token or signature; handlers
  that cannot be read are not reported.
- Example and test environment files (`.env.example`, `.env.dist`, `.env.test`) never match.

Every rule carries `metadata.cwe` so the normalizer and compliance mapper work unchanged, and
`metadata.synvoya_pack: synvoya-php`. Each rule has true-positive and false-positive fixtures under
`fixtures/synvoya-php/<rule-id>/{tp,fp}/` (files named `dot-env*` are copied to `.env*` by the eval,
because the repository never commits `.env` files), checked by eval E100. Field precision (agent
triage plus independent agent re-triage, design section 4.5) is recorded in the private triage file
`docs/research/2026-11-04-php-pack-triage.md`. A rule that fails the gate, or on which the independent re-triage disagrees, is kept in
`experimental/opengrep-rules/synvoya-php-experimental/` (outside `detection-db/`: neither loaded, nor in
the npm package, nor in the public seed) until a field re-run and another independent re-triage pass.
At the 4.0 M3 gate that held `syn-php-xss-echo`. The 4.0 final field run then measured every rule on 12
holdout repositories it was never tuned on (gate: false positives at most 1 in 5 of a rule's holdout
hits). `syn-php-path-traversal` (0 of 11 true), `syn-php-preg-replace-eval-modifier` (0/5),
`syn-php-laravel-mass-assignment-unguarded` (0/2), `syn-php-open-redirect` (0/1) and
`syn-php-xxe-entity-expansion` (0/1) failed and moved there for 4.1, to be fixed and re-measured on a new
holdout set.

Files are plain local YAML -- fully offline, no scan-time fetch. Keep all files ASCII-only (Opengrep
reads rule files as ASCII).
