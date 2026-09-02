# ADR 0003: Enforcement staging and decision identity

Status: accepted for the H8a/H8b enforcement slices (2026-09-01)

## Context

OmaSafe's analyzer already publishes a `PolicyIdentity` for inputs that can
change analysis output. Lifecycle enforcement has a different change surface:
the blocking threshold, the set of H7-admitted rule families, coverage
requirements, installed-tree postconditions, and the override schema. Mixing
those inputs with analyzer identity would turn an enforcement-policy change
into a false source-drift event.

The first enforcement increment must also remain useful when H7 admits no rule
family. Coverage loss, stale identities, unapproved executable payloads, and
failed installed-tree postconditions are precision-independent and can be
evaluated without guessing at ecosystem false-positive rates.

## Decision

`omasafe-report::enforcement` owns the versioned wire types and a pure
fail-closed evaluator. `EnforcementPolicy::identity()` is a SHA-256 over the
canonical serialized policy, including an empty blocking-family list when that
is the measured H7 result. Decisions carry three orthogonal fields:

* `evaluation_state`: `evaluated` or `not-evaluated`;
* `outcome`: `allow` or `block`;
* `authorization_basis`: `policy`, `override`, or `null`.

A valid exact-identity override may turn a hardened block into an allow, but
the decision retains every blocking reason and rule ID. An absent, expired, or
mismatched override never weakens a block. Override records bind plugin ID,
commit/tree/content digest, analyzer identity, enforcement-policy identity,
rule IDs, coverage limitations, operator reason, and an expiry.

The evaluator is side-effect free. The CLI remains responsible for collecting
installed bytes, validating exact override bindings, persisting decisions and
audit events, sending best-effort notifications, and performing lifecycle
mutations. H8a now wires the advisory/hardened review-update and enable gates,
durable decision history, and read-only decision status; override validation,
interactive override creation/listing, audit-event persistence, notifications,
and explicit advisory/hardened schedule policy are wired into the CLI as well.

H8b adds no CLI surface or analyzer behavior. Its pure admission helper accepts
only families with complete precision and independently labelled fixture
detection measurements at the fixed 1.0 thresholds. The checked-in H7 ledger
has no triaged records, so the published H8b result and the compiled policy
both carry an empty blocking-family set. Future admissions change the
enforcement-policy identity through the family metrics while leaving analyzer
identity untouched.

## Consequences

Advisory mode can continue to report and allow without changing the v0.2
contract. Hardened mode has an explicit, testable block decision even while
the H7 blocking-family set is empty. Policy changes produce an enforcement
identity delta, while analyzer changes continue to use the analyzer identity.
The model is additive and can later be nested under `result.enforcement` in
the existing `omasafe.report.v1` envelope.
