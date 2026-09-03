<p align="center">
  <img src="media/logo.png" alt="OmaSafe" width="520">
</p>

# OmaSafe

OmaSafe is a local trust and drift-review tool for [Omarchy](https://omarchy.org)
community plugins. After a plugin is installed, it answers four questions on your
own machine:

1. What exact plugin revision is installed here?
2. Is that revision listed, verified, or the commit the marketplace actually validated?
3. What changed since you trusted or last reviewed it?
4. What is out of coverage and should not be read as clean?

OmaSafe helps surface unusual patterns, risky capabilities, and source changes
for review. It never labels a plugin safe or malicious, never executes plugin
code, and never emits a single security score. Quiet means "no new actionable
change," not "proven secure."

Why this matters: Omarchy plugins are QML + JavaScript loaded **unsandboxed, with
full user permissions, inside the shared shell process**, installed as mutable Git
repositories. The marketplace validates an exact commit at listing time, but later
upstream commits fall outside that check. OmaSafe closes the gap between what was
validated once and what is running now.

## How it works

The CLI is the engine; the Omarchy bar-widget is a thin QML interface over bounded
CLI commands.

- **Inventory** — collects installed plugins filesystem-first from
  `~/.config/omarchy/plugins`, reconciles with `omarchy plugin list`, classifies
  each (built-in, Git-managed, cloned/local, backup, malformed, unscannable), and
  records Git URL, `HEAD`, tree OID, and dirty state. Symlinks are recorded as
  metadata, never followed.
- **Marketplace correlation** — retrieves the community catalog pinned to a
  recorded repository commit and file digest, then correlates by plugin ID and
  repository. Verification status, validated commit, and upstream observations are
  attributed to that snapshot as claims — never treated as timeless local facts,
  and never able to clear a local drift.
- **Source identity & trust** — computes immutable Git commit/tree identity plus a
  deterministic normalized content digest for dirty and non-Git plugins, then pins
  it as a trust baseline in private XDG state.
- **Drift review** — `status`, `diff`, and `scan` compare the installed identity to
  the baseline and surface source drift, missing trusted plugins, unscannable
  plugins, and coverage loss. Alerts deduplicate, and critical alerts reach a
  desktop notification path independent of the bar widget.

## Status

**v0.2.1 is the current release** — the signed CLI now combines the v0.1 local
trust layer with bounded payload analysis, capability and finding reports,
reviewed updates, and opt-in enforcement controls. v0.3 and later work remain on
the [roadmap](docs/plans/README.md).

See [`docs/brainstorm.md`](docs/brainstorm.md) for the product thesis and
[`docs/plans/`](docs/plans/) for the release plans.

## CLI usage

The CLI is intentionally explicit about the difference between observation,
analysis, and mutation. Analysis reports findings but does not automatically
fail; pass `--fail-on <severity>` when using `plugins analyze` or `scan-plugin`
as a CI gate. `scan` uses exit code 3 when actionable drift or coverage alerts
remain, while analyzer commands use exit code 4 only when their explicit
`--fail-on` threshold is met.

```sh
# Where OmaSafe keeps config, state, and cache
omasafe-cli paths

# Installed plugin inventory
omasafe-cli plugins inventory --format json

# Correlate against the marketplace: refresh the pinned catalog once, then inventory
omasafe-cli marketplace refresh --commit CATALOG_COMMIT
omasafe-cli plugins inventory --format json

# Or manually resolve the official main branch to an exact commit and refresh
omasafe-cli marketplace refresh --latest

# Pin a trust baseline (interactive review, or unattended with --yes + exact identity)
omasafe-cli plugins trust PLUGIN_ID \
  --yes --expected-head HEAD --expected-tree TREE --expected-digest SHA256

# Review drift for one plugin
omasafe-cli plugins status PLUGIN_ID --format json
omasafe-cli plugins diff PLUGIN_ID

# Analyze an installed plugin's complete shipped payload
omasafe-cli plugins analyze PLUGIN_ID --format json

# Analyze a local directory or an immutable remote Git revision
omasafe-cli scan-plugin --path ./plugin --format json --fail-on high
omasafe-cli scan-plugin --git https://github.com/OWNER/REPO.git \
  --revision COMMIT --format json

# Inspect the owned rule catalog and marketplace equivalence coverage
omasafe-cli rules list --format text
omasafe-cli rules coverage --format json
omasafe-cli rules explain RULE_ID --format text

# Record a review decision: acknowledge | rebaseline | restore | untrust | exclude
omasafe-cli plugins review PLUGIN_ID --action acknowledge --reason "reviewed" --yes

# Suppress or reinstate one finding, optionally within a payload path
omasafe-cli plugins review PLUGIN_ID --action suppress \
  --rule RULE_ID --reason "reviewed and accepted" --yes
omasafe-cli plugins review PLUGIN_ID --action reinstate \
  --rule RULE_ID --reason "review again" --yes

# Remove the active trust baseline while keeping the historical record
omasafe-cli plugins review PLUGIN_ID --action untrust --reason "no longer trusted" --yes

# Review an exact candidate before allowing the native updater to mutate a plugin
omasafe-cli plugins review-update PLUGIN_ID --expected-commit COMMIT
omasafe-cli plugins review-update PLUGIN_ID --expected-commit COMMIT \
  --policy hardened --yes

# Gate an already-installed inactive plugin, or inspect the last decision
omasafe-cli plugins enable PLUGIN_ID --policy hardened --format json
omasafe-cli plugins enforcement-status PLUGIN_ID --format json

# Create/list exact-identity, expiring overrides for hardened policy
omasafe-cli plugins override create PLUGIN_ID --rule RULE_ID \
  --commit COMMIT --reason "operator-reviewed" --expires TIMESTAMP
omasafe-cli plugins override list --format json

# Post-change drift scan across all plugins (optionally include analysis and notify only new alerts)
omasafe-cli scan --format json --include-analysis --notify --only-new

# Deterministic self-inventory / provenance report
omasafe-cli provenance --format json

# Opt in to a daily report-only systemd user timer
omasafe-cli schedule install --policy advisory
omasafe-cli schedule install --policy hardened
omasafe-cli schedule status --format json
```

`advisory` is the compatibility default: it reports the enforcement contract
without blocking the lifecycle operation. `hardened` enables fail-closed checks
for coverage, stale identities, unsupported executable payloads, admitted rule
families, and installed-tree postconditions. The current evidence-gated
blocking-family set is empty; hardened mode still applies the
precision-independent checks. Overrides are exact-identity, expiring, and
auditable, and are never created unattended.

Runtime state uses XDG paths only:

- Configuration: `${XDG_CONFIG_HOME:-~/.config}/omasafe`
- State (trust baselines, decisions): `${XDG_STATE_HOME:-~/.local/state}/omasafe`
- Cache (disposable catalog/Git objects): `${XDG_CACHE_HOME:-~/.cache}/omasafe`

These directories are created privately on first use. Baselines store identities,
digests, and decisions — never plugin file contents.

## Installation

The CLI and the Omarchy UI plugin are released separately with independent update
and removal lifecycles.

- **CLI** — install `omasafe-cli` from the
  [GitHub releases](https://github.com/tuthan/omasafe/releases) (or the future Arch
  package), place it on the `omarchy-shell` session `PATH`. For x86_64 Linux, the
  version-pinned helper verifies the Sigstore bundle and SHA-256 digest before
  installing to `~/.local/bin`:

  ```sh
  # Download the pinned installer, review it, then run it locally
  curl --fail --proto '=https' --tlsv1.2 --location \
    https://raw.githubusercontent.com/tuthan/omasafe/v0.2.1/scripts/install-cli.sh \
    --output install-cli.sh
  less install-cli.sh
  bash install-cli.sh --version latest

  # Or review and run it for an exact release
  curl --fail --proto '=https' --tlsv1.2 --location \
    https://raw.githubusercontent.com/tuthan/omasafe/v0.2.1/scripts/install-cli.sh \
    --output install-cli.sh
  less install-cli.sh
  bash install-cli.sh --version v0.2.1
  ```

  The URL is pinned to the release tag, so the installer you review is the exact
  one that produced that release's signed assets; reviewing it locally avoids
  piping a network response directly to the shell. `latest` selects the current
  signed release, while `v0.2.1` selects an exact signed archive. When installing
  an exact release, pin the URL to the same tag you pass to `--version`. From a
  repository checkout, run `./scripts/install-cli.sh --version latest` or
  `./scripts/install-cli.sh --version v0.2.1`.

  Release signatures and detached verification instructions are in
  [`docs/release-signing.md`](docs/release-signing.md).
- **UI plugin** — the standalone bar-widget lives in the
  [`omasafe-plugin`](https://github.com/tuthan/omasafe-plugin) repository, which
  carries a repository-root `manifest.json` for direct Omarchy publishing. It is
  listed in the [Omarchy plugin marketplace](https://plugins.omarchy.org/index.html),
  whose catalog is maintained in the [marketplace repository](https://github.com/omacom/omarchy-plugin-marketplace).

Installing an Omarchy plugin only clones and validates the plugin checkout; it does
**not** install native binaries or run dependency installers. If the plugin is
present but the CLI is not, the widget reports `?`/unavailable — that is an explicit
unknown state, not a clean result.

## Development

Requirements: Rust and Cargo (toolchain pinned in `rust-toolchain.toml`).

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p omasafe-cli -- --version
```

Workspace layout:

```text
crates/
├── omasafe-cli/           # the binary and command surface
├── omasafe-analyzer/      # bounded payload/capability analysis and rules
├── omasafe-core/          # shared error type, XDG path discovery
├── omasafe-marketplace/   # pinned catalog fetch, parse, and correlation
├── omasafe-plugin-trust/  # source identity and trust/decision history
└── omasafe-report/        # versioned JSON report envelope
```

The release archive additionally contains the generated man page, shell
completions, and a deterministic `omasafe-provenance.json` report. Validate the UI
plugin from its own checkout with `omarchy plugin validate .` and
`qmllint BarWidget.qml Panel.qml` on the supported Omarchy release.

Every command treats scanned repositories as untrusted input: no plugin code is
executed, sourced, or rendered; Git hooks/submodules/LFS filters never run;
process execution is argv-only; and elapsed-time, file-count, and byte limits are
enforced throughout. Long-running commands (`plugins analyze`, `scan-plugin`,
`plugins review-update`) handle SIGINT/SIGTERM cooperatively: bounded children
are stopped, temporary checkouts are swept (including ones orphaned by hard
deaths of earlier runs), and no partial state is committed — a reviewed update
interrupted mid-flow stays disabled with recovery guidance.

### Release gate

Run the full release checklist locally before tagging:

```sh
scripts/release-gate.sh              # add --skip-network only for quick iterations
```

It runs both test configurations, lint/format gates, generated-asset checks,
the determinism canary, corpus-tooling self-tests, a bounded pinned-corpus
sample, native-validator parity, the self-scan, and writes the evidence
reports (`self-scan.json`, `corpus-sample.json`, `validator-parity.json`)
that are also published with every GitHub release. The tag-triggered
workflow builds and Sigstore-signs artifacts; clean-VM lifecycle checks
(install/upgrade/downgrade/uninstall, panel lifecycle, schedule coexistence,
notification independence) are codified in `scripts/vm-lifecycle.sh` and run
against a fresh VM snapshot per release.

## Scope

v0.2.1 delivers installed inventory, marketplace correlation, source identity,
trust baselines, diffs, bounded payload analysis, capability/findings reports,
scoped suppressions, reviewed candidate updates, advisory/hardened lifecycle
gates, exact expiring overrides, and report-only scheduled scans.

Analysis is deliberately conservative: QML/JavaScript uses bounded
intra-file dataflow when the parser feature is enabled; shell and Python use
minimal high-signal lexical analysis; native binaries are inventoried and
referenced binaries are reported; skipped, unsupported, truncated, or
unreferenced payloads remain visible as coverage state. A clean report is not a
malware verdict, and the current hardened blocking-family set is empty until
complete precision evidence exists.

The v0.2 and v0.2.1 implementation records are available in
[`docs/plans/v0.2.md`](docs/plans/v0.2.md),
[`docs/plans/v0.2.1-hardening-implementation.md`](docs/plans/v0.2.1-hardening-implementation.md),
and [`docs/progress.md`](docs/progress.md).

Explicit non-goals: antivirus, runtime sandboxing, EDR, a universal security
score, a hosted reputation service, and automatic privileged remediation.

## License

MIT — see [`LICENSE`](LICENSE).
