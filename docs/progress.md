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


