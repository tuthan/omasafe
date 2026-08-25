# ADR 0001: QML parser selection

Status: accepted (2026-08-25)

Deciders: OmaSafe v0.2 S2 slice (M3 milestone)

## Context

The v0.2 capability engine must understand QML source: imports, object
hierarchies, property bindings, and embedded JavaScript. Three candidate
approaches existed:

1. **tree-sitter-qmljs** — a real grammar producing a concrete syntax tree
   with byte-precise spans and error recovery.
2. **Lexical/regex scanning** — no dependency, but no syntax understanding;
   higher false-positive/negative risk on anything non-trivial.
3. **Qt's own tooling** — `qmllint --json` as an external process, or QQmlSA
   (the QML static analyzer library) linked in.

The plan set a kill criterion for the tree-sitter spike: ≥99% of pinned
marketplace entry-point files and ≥95% of all relevant QML files must parse
without material uncovered regions; otherwise S3+S4 proceed with explicitly
labelled lower-confidence lexical detection.

## Decision

Adopt **tree-sitter-qmljs 0.3.1 on tree-sitter 0.26.13** behind the analyzer
crate feature `qml-parser` (on by default for the CLI build). The measured
coverage decisively passes the kill criterion.

### Measurement method

`scripts/generate-entry-point-corpus.py` derived a deterministic stratified
sample from the frozen marketplace catalog snapshot
(commit `964dc08df2a3450578727b665908272cd3a277e5`, file digest
`ddb3809c…795a6`), pinned per plugin by `upstreamObservedCommit`
(`corpus/entry-points.json`). `cargo run -p omasafe-analyzer --features
qml-parser --example qml-coverage` fetched each pinned revision through the
production `ensure_pinned_repository` path into a disposable bare cache, read
QML blobs as raw objects (no checkout), and parsed them with the production
measurement API (`qml::measure_qml_coverage`). Full raw numbers:
`corpus/coverage-report.json`.

### Measured results (2026-08-25, grammar 0.3.1 / tree-sitter 0.26.13, grammar ABI 14)

| Metric | Result | Criterion |
| --- | --- | --- |
| Plugins ingested | 50 / 50 | — |
| Entry-point files parsing cleanly | **119 / 119 (100%)** | ≥ 99% |
| All QML files parsing cleanly | **594 / 594 (100%)** | ≥ 95% |
| Non-whitespace uncovered bytes | **0 / 5,828,386** | "no material regions" |

A file counts as clean when it has zero ERROR nodes, zero missing-item
insertions, and zero non-whitespace gap bytes — every meaningful byte is
claimed by some token. Inter-token whitespace is expected trivia and excluded
from the materiality judgment while still being reported.

## Consequences

### Unsupported-syntax behavior

Files that do not parse cleanly still yield partial trees. Findings derived
from recovered regions are emitted at low confidence, and the file-level
report carries explicit error/missing/gap counts so nothing fails silently.
A file whose parse fails entirely produces a disclosed coverage limitation,
never an apparently-clean result.

### Lexical fallback semantics

Builds compiled without the `qml-parser` feature have no real parser. Their
policy identity reports `parserVersions.qml = "lexical-fallback-unassigned"`
instead of `tree-sitter-qmljs/0.3.1`, so any consumer can tell from report
metadata alone which engine produced it. Rules that would otherwise rely on
syntax carry lower-confidence labels under fallback (wired when detectors
land in S3/S4).

### Report metadata fields

- `analysis.policy_identity.parser_versions.qml`: parser identity string
  (`tree-sitter-qmljs/0.3.1` or `lexical-fallback-unassigned`) — shipped now;
  serialization is snake_case to match the existing report schema.
- `analysis.parser` (S3 wiring): `{grammar, grammar_version,
  tree_sitter_version, language_abi_version}` plus per-file parse state where
  findings reference spans, so evidence can be traced to parser behavior.

### qmllint probe result: advisory signal only, never the engine

Probing Qt 6.11.2's `qmllint --json -` against corpus files showed its output
dominated by environment-dependent import resolution (`Failed to import
qs.Commons` without project-specific `-I` paths). Reasons it cannot be the
capability engine:

- Determinism requires pinning Qt version, import paths, and qmldirs per
  scanned repository — external state OmaSafe does not control.
- It resolves types and imports by reading the scanned tree, which conflicts
  with the raw-object, no-checkout ingestion model.
- PATH hazards are real: this machine also ships a Qt5-era `/usr/bin/qmllint`
  (v1.0) without `--json`.

It remains documented as an optional human-advisory correctness/import check;
QQmlSA linkage stays a future option, not a dependency.

### Risks

- **Grammar rot**: mitigated by pinned versions in `qml.rs`, the policy
  identity surfacing them, and re-running the measurement example as a CI
  canary when grammar or tree-sitter versions change.
- **ABI drift**: grammar loads fail loudly via `set_language`; the feature
  gate keeps such builds possible to exclude rather than silently degrade.

## References

- Plan: `docs/plans/v0.2-implementation.md` (S2, M3)
- Manifest: `corpus/entry-points.json`; raw results:
  `corpus/coverage-report.json`
- Measurement API: `omasafe-analyzer::qml`; harness:
  `crates/omasafe-analyzer/examples/qml-coverage.rs`
