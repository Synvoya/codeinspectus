---
name: Bug report
about: Something CodeInspectus does wrong — a crash, a wrong/missing finding, or output that contradicts the docs
title: "[bug] "
labels: bug
---

<!-- CodeInspectus is local-first and offline. Please DO NOT paste real secrets, tokens, or
     proprietary source. Redact them, or use a minimal synthetic repro. -->

## What happened
A clear description of the bug.

## Minimal repro
The smallest synthetic file(s) (no real secrets) and the exact tool call that triggers it.

```
# e.g. the file scanned + the codeinspectus_scan arguments
```

## Expected vs actual
- **Expected:**
- **Actual** (paste the finding/output, secrets redacted):

## Which kind of bug?
- [ ] **False positive** — flagged something safe (include the safe code it should not flag)
- [ ] **False negative** — missed something dangerous (include the code it should flag)
- [ ] **Crash / error**
- [ ] **Docs mismatch** — output disagrees with a README/docs claim (quote the claim)

## Environment
- CodeInspectus version (`codeinspectus_list_rules` reports engine + DB versions):
- OS:
- Agent / client (Claude Code, Cursor, VS Code, …):
- Did you run `install-engines`? (engine-dependent findings need it):
