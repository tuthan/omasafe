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
