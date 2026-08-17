## Summary

Describe the change and the repository-visible requirement it addresses.

## Verification

- [ ] `npm run typecheck`
- [ ] Relevant focused tests
- [ ] `npm test`
- [ ] `npm run build`
- [ ] `npm run eval` when detection behavior changes
- [ ] I added both true-positive and realistic safe/near-miss fixtures for detector changes

## Provenance and licensing

- [ ] Every commit has a `Signed-off-by:` line (`git commit -s`)
- [ ] I created this contribution or have the right to submit it under Apache-2.0
- [ ] I did not copy restricted third-party rule expressions, fixtures, or documentation
- [ ] I identified and attributed any third-party material introduced by this change
- [ ] If AI tooling materially assisted, I name it below and confirm I reviewed its output

AI assistance and provenance notes:

## Security and compatibility

- [ ] No raw secrets enter logs, findings, snapshots, or fixtures
- [ ] Scan-time zero-egress and fail-closed engine verification remain intact
- [ ] Existing rule IDs and export/storage schema contracts remain compatible, or the break is explicit
