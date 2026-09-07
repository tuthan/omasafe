# v0.2.4 plan assessment — second-round response

Date: 2026-09-06. Scope: review of the supplied seven-point verdict against
current source and the proposed design. This records documentation decisions;
no detector, cache format, suppression behavior, or release gate was implemented.
See the updated [plan](../plans/v0.2.4-rule-detection-clarity.md) and
[report contract](../reference/v0.2.4-review-report-contract.md).

The verdict identifies real remaining work. The strongest issue is review churn:
a byte hash is appropriate for caches but should not force users to accept the
same reviewed behavior again after a comment edit. The proposed remedy needs a
narrower semantic identity and a safeguard against undeclared predicate changes.

| Verdict item | Assessment and decision |
| --- | --- |
| 1. Full identity invalidates suppressions/triage | Accept the problem; refine the solution. Exclude package version and prose-sensitive catalog identity as well as raw code bytes from review compatibility. Introduce per-rule semantic identities and reviewed declarations bound to actual detector builds. Caches still use full identity. |
| 2. Confidence in occurrence ID | Accept for the new occurrence key. Keep confidence in the existing analysis fingerprint. Corrected confidence/method still changes the affected rule's review revision; a stable occurrence ID does not automatically validate its previous assessment. |
| 3. Cross-package build input/helper tests | Accept the package boundary and missing test-home concerns. Core hashes its own source and exports a constant; analyzer combines it at policy construction. Explicit path inclusion compiles each helper into its build script and integration test. |
| 4. Legacy snapshot redaction | Accept and broaden the output audit. Transform display copies for all snapshot generations, including both `alerts` and `snapshot.alerts` in JSON. Preserve raw disk history and identities. New-cache persistence alone cannot close the old hydration path. |
| 5. Size-accountant failure | Accept bounded recovery. Remove optional context and lowest-priority details using actual serialization, preserving counts and threshold. Mandatory-only overflow still errors; unexpected recovery fails release checks. |
| 6. No-parser true-positive loss | Accept. Name the inline Python regression, `python-parser-disabled` gap, default-feature distinction, packager/release note, and P09 test. Do not restore an unsound co-occurrence rule merely to retain its true positives. |
| 7. Determinism canary | Accept the missing test coverage; correct the explanation. Selected findings are inside `result.analysis`, but the current script invokes only the default full profile. Extend invocations and compare the summary/profile fields too. |
| Minor: grammar dependency preparation | Accept. Python grammar was absent from the local Cargo source cache inspected for this review. C0 must fetch/lock dependencies before claiming an offline build. Keep the grammar-load smoke test. |

## Points worth pushing back on

**The suggested semantic tier still contains two churn sources.** Package version
changes every release, and the catalog fingerprint changes with guidance prose.
Removing only `detector_logic_fingerprint` would therefore not solve ordinary
patch-release or documentation churn. The revised projection includes the rule's
actual severity, declared predicate/evidence revision, relevant parser/method and
limit inputs, and normalization/runtime semantics. Unrelated catalog entries and
presentation metadata do not redefine an accepted occurrence.

**A semantic version alone cannot safely carry old suppressions forward.** If a
predicate changes without a revision bump, automatic cache invalidation produces
a fresh finding that an old suppression could then hide. The updated plan requires
an exact same-build acceptance or a declared semantic compatibility match. An
unlisted detector build cannot reuse reviews across builds. Declarations record
the actual hash, semantic maps, baseline, reviewer, rationale, and test evidence;
they are maintainer assertions, not mathematical proof or a new security authority.
This increases C0 from M to L and is an explicit engineering cost of reducing
user-facing reconfirmation noise without silently broadening acceptance.

**“Precision never accumulates” is too absolute.** Historical labels still exist,
and a single build can publish a valid measured denominator. The problem is that
none of those labels can be reused under the original full-policy key. The revised
ledger reuses compatible occurrence labels, while measuring precision only over
the current emitted sample. Changed predicates, changed attribution, new matches,
and incomplete scans still require fresh accounting; historical counts are not
added to inflate current sample size.

**The canary explanation mislocates the selected array.** In
[`determinism-canary.sh`](../../scripts/determinism-canary.sh), the two default
scans compare `result.analysis`; a review invocation would include the selected
finding array in that same object. What is absent today is that invocation and
comparison of `review_summary`/`report_profile`. Normalize only the known analysis
timestamp; do not discard arbitrary changing fields until a test passes.

Two small factual qualifications: `cargo vendor` does not itself necessarily
remove workspace source, so the cross-package input is a packaging/pruned-layout
risk rather than a claim that every vendor operation breaks. Also,
`scan-cache show` currently returns raw cached alerts through JSON (including a
nested snapshot), while its text view prints cache status/limitations. The cited
live `scan` and notification rendering paths do use `safe_text`. The redaction
requirement is valid, but tests must target the actual hydration paths.

## Verification performed

Read the current suppression matcher, snapshot reader/JSON hydration, live scan
and notification presentation, package manifests, and determinism script. Checked
local Cargo sources for the parser dependencies. The source anchors in the supplied
verdict were sufficient to confirm the design gaps; no plugin code was executed,
no dependency was fetched, and no production tests were claimed for these proposed
changes. Documentation links, cross-references, and bounded-retry arithmetic were
checked after editing.
