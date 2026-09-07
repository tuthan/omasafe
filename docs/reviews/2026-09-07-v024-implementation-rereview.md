# v0.2.4 implementation re-review — 2026-09-07

Scope: the updated, uncommitted implementation against `92ed9c6`, following the first implementation review. The user authorized Luna agents at extra-high reasoning to fix confirmed issues. The first review remains a historical record.

## Initial verification

The original redaction crash, fragment-only URL, quoted-call, assigned-sink, ordinary-argv, unrelated-import, and parameter-shadowing reproductions passed on the updated implementation. The 70-file coverage test now reports 64 emitted records, six omissions, and incomplete presentation correctly. Current feature identities and declaration selection are present, and the checked-in four-projection declaration check passes.

The family flood still failed: a review with 1,030 Python findings and one shell finding emitted 512 Python findings and no shell finding. Initial family selection had been corrected, but later canonical-tail trimming erased that diversity.

## Confirmed remaining issues sent for correction

1. **Report byte trimming drops selected families.** Preserve the severity/family/file priority through reductions, then restore canonical output order.
2. **Report size is measured before final sanitization and excludes the newline.** Validate the actual output envelope with a captured timestamp and complete display transformation.
3. **Shortened evidence fields do not disclose their loss consistently.** Update field, observation, and overall completeness accounting after shaping.
4. **Python sink resolution bypasses shadowing.** Rebound `os` and `subprocess` still trigger through raw spelling fallbacks; an imported custom `exec` is treated as the builtin.
5. **Ordinary Python comments and escaped quotes can hide subsequent execution.** A leading `# author's note` or an unrelated escaped-quote string prevents detection of the baseline download/exec chain.
6. **Subprocess keyword arguments hide interpreter code.** `subprocess.run(['sh', '-c', code], check=True)` loses the otherwise supported connection.
7. **Unreachable Python statements manufacture a connection.** A download and exec after an unconditional function `return` are reported as connected execution.
8. **Redaction still leaks supported secret contexts.** A comma in a query value leaks its tail; multiple `@` characters expose a userinfo suffix; `password = 'MY_PASSWORD'` survives both display transforms.
9. **Semantic changes invalidate unrelated reviews.** Compatibility requires the whole current declaration to be `review-compatible`, preventing reuse of unchanged rule identities when another rule changes.
10. **Declaration validation omits semantic transition checks.** A canonical declaration digest alone does not establish appropriate affected-rule revision changes or valid compatible history.
11. **Build fingerprint rerun tracking omits directories.** Existing-file watches do not detect newly added source files until some other watched input changes.
12. **Per-field display caps are incomplete.** Review legacy evidence needs its 512-byte limit, and truncation must reserve space for the ellipsis and preserve complete escapes. Boundary-sized losses must set truncation metadata.

All twelve issue groups above were corrected by Luna agents using extra-high reasoning and checked by the parent reviewer. Temporary probe scripts are `/tmp/omasafe-v024-review.py`, `/tmp/omasafe-v024-flood.py`, `/tmp/omasafe-v024-round2-probes.py`, and `/tmp/omasafe-v024-verify-round2.py`. Inputs are inert and were analyzed, never executed.

## Final verification

- Combined Python and secret-redaction assertions pass (`errors: []`); final captured reports are in `/tmp/omasafe-v024-verify2-sjzk_ach`.
- The 1,031-finding flood retains 511 Python findings and the sole shell finding in 1,338,627 bytes, below the 1,572,864-byte ceiling. Complete counts and omissions remain in the summary. Captured reports: `/tmp/omasafe-v024-flood-ez9cfce9`.
- The 70-file coverage case emits 64 records, reports six omissions, and marks presentation incomplete.
- A long-URL case verifies 512-byte legacy evidence in review, 96-byte review step details, and 256-byte full step details. Both profiles report incomplete presentation when details are shortened. Fixture: `/tmp/omasafe-final-caps-j502xi5b`.
- Compatibility history preserves the four previous declarations and appends four declarations for the corrected detector. The Python download-execute review revision is 3. Declaration metadata explicitly identifies AI-assisted review and does not represent human signoff.
- The legacy suppression integration fixture now removes the new semantic/declaration fields to model an actual legacy record. A separate case verifies reuse when only full-policy provenance changes while valid current rule semantics remain unchanged.
- Focused analyzer, CLI, semantic-validator, and fingerprint tests pass.
- `scripts/release-gate.sh --skip-network` passed after the last integration-fixture adjustment: formatting, default and no-default Clippy/tests, generated assets, current semantic declarations, determinism canary, corpus-tooling self-tests, H7 ground-truth fixtures, self-scan generation, and provenance generation. The run log is `/tmp/omasafe-v024-final-gate.log`; generated evidence is under `release-reports/`. Existing corpus/parity artifacts in that directory were not refreshed by this offline run.

Network corpus/parity checks, package extraction validation, sibling consumer verification, and VM release checks are outside this re-review's executed validation. This record does not authorize a release or claim the full v0.2.4 plan has passed every operational gate.
