# ADR 0002: Bounded intra-file dataflow and analyzer-improvement events

Status: accepted (2026-09-01)

Deciders: OmaSafe v0.2.1 H4 hardening slice

## Context

The QML/JavaScript detector previously classified a sink argument from the
text of that argument alone. That allowed a simple indirection such as
`var data = xhr.responseText; Quickshell.execDetached(data)` to lose its
network provenance, while also allowing unrelated property names containing
`response` to look suspicious. Shell payloads have a different grammar and
need a separate lexical state tracker for a staged `fetch -> chmod +x ->
execute` chain.

Analysis must remain deterministic and bounded. A limit exhaustion cannot be
reported as a clean file, and changing those limits changes the analyzer's
observable policy.

## Decision

Use a small abstract interpreter over each QML/JavaScript file. It tracks
local declarations and assignments in source order, recognizes static values,
network-response producers, and user-input producers, and understands
callback parameters for promise/XHR callback shapes. It is deliberately
intra-file: cross-file or whole-program dataflow would require runtime import
resolution and scope semantics that are outside v0.2.1's deterministic raw
object analysis contract.

The shell staged-chain detector is independent and lexical. It carries only
exact static output paths between physical lines and never claims that the
QML/JavaScript interpreter parsed shell syntax.

### Bounds and coverage

The bounds are shared constants in `omasafe-core::bounds` and are included in
the analyzer policy identity:

- 2,048 statement/declaration nodes per QML/JavaScript file;
- 16 recursive expression/assignment levels;
- 50 ms per-file QML/JavaScript dataflow wall-clock budget;
- 1,024 physical shell lines and 25 ms for staged-chain tracking.

When a bound is reached, the detector returns an unknown value for the
unvisited portion and records a `dataflow-*` or
`staged-script-analysis-budget-exhausted` limitation. Inventory coverage is
therefore `Partial`; no exhausted analysis can produce a clean coverage
state. The limits are serialized through `LimitsConfiguration` and hashed
into `PolicyIdentity`, so a bound change is an analyzer-policy change rather
than plugin source drift.

### Reference and execution provenance

Earlier literal assignments resolve H2 sink positions (`Loader.source` and
`FileView.path`) to ordinary invocation edges. A value tainted by a recognized
network response or user input produces the existing dynamic-reference rule
with a typed provenance reason. Network-tainted execution values produce the
existing execution rule; ordinary computed values remain capability-only.
The AST sink classifier no longer uses raw substring checks for `responseText`,
`.response`, and `.text(`. The standalone-JavaScript lexical fallback retains
its direct, low-confidence line check because that build has no AST; it does
not claim multi-line dataflow. `LexFlags`, which had no readers, is removed.

### Analyzer-improvement event and suppression migration

When an unchanged source identity is re-evaluated under a different analyzer
policy and the finding set or analysis fingerprint changes, the CLI emits an
`analyzer-improvement` warning. Its wording requests re-review and never
describes the result as plugin/source drift. The existing policy-update event
is retained for compatibility. Trust baselines are not invalidated by this
event.

New suppression records carry the canonical serialized analyzer policy
identity. A record whose scoped finding is evaluated under another identity
is not applied; the report lists it under `reconfirmation_required` and asks
for explicit re-confirmation. Legacy records without an identity remain
usable for compatibility and are not silently rewritten.

## Consequences

- One-assignment network-to-execution evasions become evidence-backed without
  pretending to model arbitrary JavaScript.
- Static computed references can form invocation edges, while untrusted
  computed references remain visible as findings rather than being resolved
  optimistically.
- Bound and comment/near-miss regressions are tested in the analyzer suite;
  parser-backed behavior remains feature-gated and lexical fallback remains
  explicit.
- Future cross-file taint, richer callback semantics, and shell dataflow are
  intentionally deferred to a later slice.

## References

- `docs/plans/v0.2.1-hardening-implementation.md` (H4)
- `crates/omasafe-analyzer/src/detect/qml/dataflow.rs`
- `crates/omasafe-analyzer/src/detect/script/mod.rs`
