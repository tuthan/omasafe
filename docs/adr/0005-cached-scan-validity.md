# ADR 0005: Cached installed-scan validity

Status: accepted · 2026-09-04

## Context

The bar widget needs to remain useful after a shell restart, but a retained
scan cannot be presented as current merely because its JSON is readable. The
installed tree, trust history, marketplace snapshot, analyzer policy,
enforcement state, and supported runtime can all change independently. The
widget also runs inside the shared shell process and must not become a second
filesystem scanner.

## Decision

`omasafe-cli` owns two private, profile-specific snapshots below
`$XDG_CACHE_HOME/omasafe/scan-snapshots/`:

- `installed-basic.json` for the advisory/lightweight scan;
- `installed-analysis.json` for `--include-analysis`, hardened schedules, and
  the widget's analysis scan.

Each snapshot carries a monotonic generation, producer CLI version, bounded
normalized alerts, typed enforcement summary, inventory fingerprint, and a
context fingerprint whose components cover inventory, trust history,
marketplace metadata, analyzer policy, enforcement/override context, and the
runtime stamp. Absolute paths, raw process output, and full analysis payloads
are excluded. Writes reserve the generation before scan work, use a per-profile
private lock, write a `0600` same-directory temporary file, sync, rename, and
never let a failed cache write change the scan's exit status.

The only read surface is `scan-cache show`. Without `--validate` it performs a
bounded snapshot read and returns `cached-unvalidated`. With `--validate` it
uses bounded filesystem metadata plus shared state locks and returns
`cached-valid`, `cached-stale` with named reasons, or `cached-unvalidated` when
validation is unavailable or raced. Corrupt, incompatible, oversized, foreign,
or symlinked snapshots are refused and never quarantined. Cache deletion is
therefore a safe loss of startup hydration, not a deletion of trust or
enforcement history.

The QML plugin invokes this CLI surface and keeps only the normalized response
in memory. It displays cached provenance and age permanently; cached quiet is
never an unqualified current-clean claim. `--only-new` affects presentation and
notification only: the canonical snapshot always contains the complete alert
set.

## Consequences

This adds a small schema and lifecycle surface, but keeps ownership and trust
boundaries explicit. A snapshot can be useful while stale, and a failed new
scan can retain the previous evidence without silently refreshing its age.
Advisory and analysis producers can share a profile safely because the
monotonic generation guard prevents an older in-flight result from replacing a
newer one. The cache is disposable and must not be used as authorization for
trust, enable, review, or update actions.
