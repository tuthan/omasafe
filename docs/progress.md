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
