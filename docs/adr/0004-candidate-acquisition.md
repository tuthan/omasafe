# ADR 0004: Candidate acquisition and pre-install review boundaries

Status: accepted (2026-09-04)

## Context

OmaSafe needs a read-only workflow for reviewing an Omarchy plugin before
installation. The input may be a public GitHub repository URL, a copied
`omarchy plugin add|install` command, or a plugin ID from the cached legacy
marketplace catalog. These inputs are mutable references or registry claims;
neither is itself evidence that a plugin is safe.

## Decision

The CLI owns a deliberately small, bounded parser for `--request`. It accepts
one public HTTPS GitHub repository URL or one plain install command with only
the `--enable` and `--yes` flags. The command is data: OmaSafe never invokes a
shell or `omarchy` and records discarded install intent separately.

Every remote candidate resolves to one full Git commit before acquisition. The
CLI fetches only that commit into its private, quota-bounded XDG analysis
cache, reads raw Git objects without checkout, hooks, filters, submodules, or
LFS, and records cache/network facts. Exact `--git URL --revision COMMIT`
remains the reproducible form.

Marketplace IDs may use only a cryptographically reverified cached catalog.
The selected entry must have one supported layout, one valid
`listingValidatedCommit`, and one credential-free repository. Exact GitHub
SSH/scp catalog values are converted to public HTTPS while both the listed and
effective values remain visible in provenance. Unverified snapshots cannot
direct a fetch.

Candidate reports use `omasafe.acquisition.v1`, state
`installation_performed: false`, and select `candidate-unsuppressed` findings.
Configured suppressions, trust history, installed-plugin state, enablement,
notifications, and lifecycle actions are not read or changed. The `review`
profile omits payload entries, bounds repeated analysis lists, and reports
total/emitted/omitted counts plus coverage limitations. Fingerprints and
`--fail-on` decisions are computed before presentation shaping.

Remote archive and registry-coordinate support are deferred until a separate
release has a signed index/artifact format and an independently reviewed
transport and dependency boundary.

## Consequences

- Candidate analysis is useful as immutable, attributable evidence but is not
  an approval, trust baseline, safety verdict, or install continuation.
- A moved default branch cannot silently change the commit being analyzed;
  the report retains both the moving request and resolved identity.
- Cache corruption is detected through reachability verification and the
  affected URL-scoped repository is rebuilt before a pinned refetch.
- Malformed unrelated manifests do not prevent a requested, uniquely matching
  plugin root from being reviewed; no matching or ambiguous manifest fails
  closed.
- A sibling desktop panel and agent skill consume this contract but do not
  duplicate parsing or acquire/install candidates themselves.

## References

- `../../../omasafe-docs/Cli/plans/v0.2.2-candidate-source-scan.md`
- `crates/omasafe-core/src/source.rs`
- `crates/omasafe-report/src/acquisition.rs`
