# OmaSafe

OmaSafe is a local trust and drift-review tool for [Omarchy](https://omarchy.org)
community plugins. After a plugin is installed, it answers four questions on your
own machine:

1. What exact plugin revision is installed here?
2. Is that revision listed, verified, or the commit the marketplace actually validated?
3. What changed since you trusted or last reviewed it?
4. What is out of coverage and should not be read as clean?

OmaSafe **reports** source identity, marketplace context, and drift against a
baseline you establish. It never declares a plugin safe or malicious, never
executes plugin code, and never emits a single security score. Quiet means "no
new actionable change," not "proven secure."

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

**v0.1 is the current release** — installed inventory, marketplace correlation,
source identity, trust baselines, diffs, and drift notifications, distributed as a
signed CLI. Capability analysis and later work are on the
[roadmap](docs/plans/README.md).

See [`docs/brainstorm.md`](docs/brainstorm.md) for the product thesis and
[`docs/plans/`](docs/plans/) for the release plans.

## CLI usage

```sh
# Where OmaSafe keeps config, state, and cache
omasafe-cli paths

# Installed plugin inventory
omasafe-cli plugins inventory --format json

# Correlate against the marketplace: refresh the pinned catalog once, then inventory
omasafe-cli marketplace refresh --commit CATALOG_COMMIT
omasafe-cli plugins inventory --format json

# Pin a trust baseline (interactive review, or unattended with --yes + exact identity)
omasafe-cli plugins trust PLUGIN_ID \
  --yes --expected-head HEAD --expected-tree TREE --expected-digest SHA256

# Review drift for one plugin
omasafe-cli plugins status PLUGIN_ID --format json
omasafe-cli plugins diff PLUGIN_ID

# Record a review decision: acknowledge | rebaseline | restore | untrust | exclude
omasafe-cli plugins review PLUGIN_ID --action acknowledge --reason "reviewed" --yes

# Remove the active trust baseline while keeping the historical record
omasafe-cli plugins review PLUGIN_ID --action untrust --reason "no longer trusted" --yes

# Post-change drift scan across all plugins (optionally desktop-notify only new alerts)
omasafe-cli scan --format json --notify --only-new

# Deterministic self-inventory / provenance report
omasafe-cli provenance --format json

# Opt in to a daily systemd user timer that runs `scan --notify --only-new`
omasafe-cli schedule install
```

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
  package), place it on the `omarchy-shell` session `PATH`. Release signatures and
  detached verification instructions are in
  [`docs/release-signing.md`](docs/release-signing.md).
- **UI plugin** — the standalone bar-widget lives in the sibling project
  [`../omasafe-plugin/`](../omasafe-plugin/), which carries a repository-root
  `manifest.json` for direct Omarchy publishing.

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
enforced throughout.

## Scope

v0.1 delivers installed inventory, marketplace correlation, source identity, trust
baselines, diffs, and drift notifications. Static capability analysis is
deliberately deferred to v0.2 ([`docs/plans/v0.2.md`](docs/plans/v0.2.md)).

Explicit non-goals: antivirus, runtime sandboxing, EDR, a universal security
score, a hosted reputation service, and automatic privileged remediation.

## License

MIT — see [`LICENSE`](LICENSE).
