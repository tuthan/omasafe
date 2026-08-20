# OmaSafe Implementation Plans

Status: reviewed implementation sequence, 2026-08-20

This directory turns the product brainstorm into independently shippable releases. Each
version must deliver a useful vertical slice; unfinished future architecture must not
leak into the current release. These plans are the source of truth for scope and sequence;
[`brainstorm.md`](../brainstorm.md) is the frozen thesis and decision record.

## Release Map

| Version | Outcome | Depends on |
|---------|---------|------------|
| [v0.1](v0.1.md) | Inventory installed plugins, correlate registry commits, pin trust, and disclose drift | — |
| [v0.2](v0.2.md) | Analyze shipped payloads/capabilities and review candidate updates before activation | v0.1 identity/diff/state contracts |
| [v0.3](v0.3.md) | Review PKGBUILDs and AUR updates without executing build files | v0.1 identity/diff; v0.2 analyzer/report contracts |
| [v0.4](v0.4.md) | Detect machine-posture regressions and vulnerable/outdated packages | v0.1 state/notification; v0.2 report contract |
| [v0.5](v0.5.md) | Perform a narrow set of explicit remediations and export reports | v0.4 checks; audited polkit boundary |
| [Later](later.md) | Hold deliberately deferred experiments and optional integrations | Validated demand |

## Proposed Technical Baseline

- **Engine:** a Rust workspace producing `omasafe-cli`. A single compiled binary keeps
  runtime dependencies small and suits untrusted Git/catalog input, identity/diff work,
  and the parser-heavy v0.2 analyzer. Confirm the toolchain in v0.1 M0; parser selection is
  a separate v0.2 decision.
- **UI:** a thin Omarchy `bar-widget` plugin. `BarWidget.qml` loads `Panel.qml`; the panel
  invokes bounded CLI subcommands with argv-style arguments and renders versioned JSON.
- **State:** XDG paths only:
  - `${XDG_CONFIG_HOME:-~/.config}/omasafe/` for user policy and suppressions.
  - `${XDG_STATE_HOME:-~/.local/state}/omasafe/` for trusted baselines and reports.
  - `${XDG_CACHE_HOME:-~/.cache}/omasafe/` for disposable Git objects and metadata.
- **Scheduling:** systemd user timers for expensive or periodic work. The QML process
  never performs a repository scan itself.
- **Privileges:** none through v0.4. v0.5 may add a root-owned, non-daemon helper with
  separate polkit actions, fixed action IDs, and typed argument validation.

## Shared Engineering Contracts

### Report contract

Every analyzer/check emits a versioned JSON report. Inventory/trust records use the same
envelope but omit analyzer-only fields. Reports include, where applicable:

- Tool/schema version and scan timestamps.
- Target identity, immutable revision where available, and input provenance.
- Detected capabilities, each linked to evidence.
- Findings with stable rule ID, severity, confidence, explanation, and remediation.
- Evidence containing a normalized relative path, line/column where known, and a bounded
  excerpt that is safe to display.
- Coverage/limitations, including skipped files, parser fallbacks, permission failures,
  timeouts, and unavailable dependencies.

Reports never declare a target “safe” or “malicious.” A successful scan with findings is
still a successful command. CI policy is opt-in through `--fail-on <severity>`.

### Identity contract

Never use one digest for unrelated events:

- Source identity captures commit/tree/current-content state only.
- Registry identity captures the exact catalog repository commit, catalog-file digest,
  retrieval time, and commit-bound claims made by that snapshot.
- Analysis fingerprint captures normalized semantic results, excluding prose/timestamps.
- Policy identity captures rule/parser/limit versions, the severity-table version, and the
  supported Omarchy security-surface version.

Source drift, registry refresh, and analyzer improvement are different event types and
must never trigger the same alert wording.

### Untrusted-input contract

- Never execute, source, import, or render code from a scanned repository.
- Never run Git hooks, submodules, Git LFS filters, package build functions, or project
  tooling from the target.
- Apply limits for elapsed time, file count, aggregate bytes, individual file size,
  nesting depth, and generated evidence.
- Normalize paths, reject traversal, and treat symlinks as metadata rather than following
  them.
- Use argv-style process execution; never interpolate target data into `sh -c`.
- Write reports atomically and create private state directories/files.

### Registry-input contract

- Retrieve the marketplace catalog from its GitHub repository at a recorded repository
  commit, then address/cache the file by that commit and content digest. Do not treat the
  mutable rendered-site or branch URL as a pinned trust root.
- Describe `verificationStatus`, validated revisions, and upstream observations as claims
  made by the named registry snapshot, with retrieval time and age—not timeless local facts.
- Registry data may add provenance and review context. It can never downgrade, suppress,
  acknowledge, or clear a local drift, capability, finding, or coverage failure.

### Drift-target contract

- A collector returns a target ID, normalized path/scope descriptors, digest,
  classification, and coverage. Storage and notification policy consume that common result.
- The common baseline stores identities, digests, safe metadata, and decisions—not file
  contents. Target-specific review may use immutable Git objects already present locally.
- v0.1 registers only the plugin collector. Later target collectors must not require a
  redesign of baseline, acknowledge/rebaseline, exclusion, or deduplication behavior.

### Rule contract

- Rule IDs and meanings are stable after publication.
- Capability detection is separate from suspicious behavior. For example, spawning a
  process is a capability; spawning a shell with encoded input may also be a finding.
- Every finding has visible evidence and confidence.
- Suppressions require a rule ID, scoped target/path, human reason, and creation time.
- Parser failure lowers coverage/confidence; it never silently becomes “no findings.”
- Automated results and policy are deterministic code paths. LLM output cannot decide
  findings, severity, enforcement, verification, approval, or trust.
- OmaSafe owns its public rule IDs and meanings. An equivalent external rule is recorded
  through a versioned mapping such as `baseline_v4_equivalent`; a stale mapping is visible
  when the external definition changes and cannot silently redefine an OmaSafe finding.

### UX contract

- Quiet means no new actionable change, not proof of security.
- Alerts prioritize new capabilities and regressions over unchanged baseline findings.
- Every drift alert offers review, acknowledge/rebaseline, and scoped exclusion.
- Destructive or privileged effects require explicit preview and confirmation.
- The UI never exposes raw secret values or unbounded command output.
- Critical alerts have a desktop-notification/CLI path independent of the bar widget,
  because a third-party full-bar plugin can omit that widget.

## Repository Shape by v0.1

```text
omasafe/
├── Cargo.toml
├── crates/
│   ├── omasafe-cli/
│   ├── omasafe-core/
│   ├── omasafe-plugin-trust/
│   ├── omasafe-marketplace/
│   └── omasafe-report/
├── fixtures/
│   ├── plugins/
│   └── marketplace/
├── packaging/
│   └── arch/
└── docs/
```

The Omarchy UI is maintained in the sibling `omasafe-plugin/` project so its
repository root can carry the plugin `manifest.json` required for publishing.
The main repository remains the CLI engine and release/package source.

Add crates only when a release needs them; do not pre-build v0.3–v0.5 subsystems.

## Release Gate Used by Every Version

A release is done only when:

1. Its in-scope CLI/UI workflow works in the provisioned clean-Omarchy VM harness.
2. Unit, fixture, integration, and negative security tests pass.
3. JSON schemas and CLI behavior are documented and backward-compatible within v0.x, or
   a migration is supplied.
4. Resource-limit and malformed-input behavior is tested.
5. User-facing limitations and false-positive expectations are documented.
6. The plugin passes `omarchy plugin validate` and `qmllint` against the supported
   Omarchy release.
7. Package install, upgrade, and removal leave no unexpected privileged or persistent
   components behind.
8. Source tags and release artifacts are signed, verification is documented/tested, and a
   self-inventory/self-scan appropriate to the release is published.
9. The recorded supported Omarchy/Quickshell versions and security-surface coverage are
   current; a newer unverified runtime degrades coverage rather than silently passing.

## Planning and Ownership

- Release owner: Hung Vo unless reassigned in the individual plan.
- Sizes are coarse risk/effort signals, not duration promises: v0.1 L, v0.2 XL, v0.3 L,
  v0.4 L, v0.5 XL.
- Calendar dates are assigned only after v0.1 M0 establishes environment and delivery
  capacity.
- M0 records the maintainer's sustainable hours-per-week capacity; sequencing gates and
  measured throughput drive forecasts rather than speculative dates.
- Initialize Git and commit the reviewed docs before implementation. Provenance tooling
  must develop inside a provenance-controlled repository.
- Every release owns its VM/corpus fixtures and cannot defer required test infrastructure
  to an unspecified future task.

## Explicit Cross-Release Non-Goals

- Antivirus, runtime sandboxing, EDR, or a claim to prevent all malicious plugins.
- A universal security score.
- A hosted reputation service before local-only value is proven.
- Automatic privileged remediation.
- Compatibility with every Arch derivative before Omarchy and plain Arch workflows are
  stable.
