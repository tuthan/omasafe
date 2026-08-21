# OmaSafe

OmaSafe is a local trust and drift-review tool for Omarchy community plugins.
It reports installed source identity, marketplace context, and changes since a
user-established baseline. It does not declare plugins safe or malicious.

## Status

Implementation follows the versioned plans in [`docs/plans/`](docs/plans/).
Milestone progress and verification results are recorded in
[`docs/progress.md`](docs/progress.md). Each milestone is committed before the
next milestone begins.

Current milestone: **v0.1 M6 in progress**. The CLI collects filesystem inventory,
records Git provenance, correlates pinned marketplace claims, and supports
explicit trust baselines and review/diff workflows.

## Development

Requirements: Rust and Cargo.

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p omasafe-cli -- --version
cargo run -p omasafe-cli -- plugins inventory --format json
cargo run -p omasafe-cli -- plugins inventory --format json \
  --catalog fixtures/marketplace/catalog.json --catalog-commit FIXTURE_COMMIT
cargo run -p omasafe-cli -- plugins trust PLUGIN_ID \
  --yes --expected-head HEAD --expected-tree TREE --expected-digest SHA256
cargo run -p omasafe-cli -- plugins status PLUGIN_ID --format json
cargo run -p omasafe-cli -- plugins diff PLUGIN_ID
cargo run -p omasafe-cli -- scan --format json
cargo run -p omasafe-cli -- provenance --format json
# Opt in to a daily systemd user timer:
omasafe-cli schedule install
```

The release archive contains the generated man page, shell completions, and a
deterministic `omasafe-provenance.json` report. Release signatures and detached
verification instructions are in [`docs/release-signing.md`](docs/release-signing.md).

The Omarchy UI plugin is maintained as the sibling project
[`../omasafe-plugin/`](../omasafe-plugin/) so it has a repository-root
`manifest.json` for direct Omarchy publishing. Validate it from the sibling
directory with `omarchy plugin validate .` and `qmllint BarWidget.qml
Panel.qml` on the supported Omarchy release.

The CLI is the engine. The Omarchy bar-widget is a thin QML interface
over bounded CLI commands. Runtime state uses XDG paths:

- Configuration: `${XDG_CONFIG_HOME:-~/.config}/omasafe`
- State: `${XDG_STATE_HOME:-~/.local/state}/omasafe`
- Cache: `${XDG_CACHE_HOME:-~/.cache}/omasafe`

## Installation boundary

The CLI and Omarchy UI are maintained and released separately. The standalone
plugin lives in [`../omasafe-plugin/`](../omasafe-plugin/) and can be installed
from the Omarchy plugin marketplace before the CLI is present. In that state the
widget reports `?`/unavailable; it must not be read as a clean result.

Installing an Omarchy plugin only clones and validates the plugin checkout. It
does not install native binaries or run dependency installers. Install
`omasafe-cli` separately from the [GitHub releases](https://github.com/tuthan/omasafe/releases)
or the future Arch package, place it on the `omarchy-shell` session `PATH`, and
then reload or re-enable the plugin. The CLI creates its XDG configuration,
state, and cache directories automatically on first use. The complete
marketplace-first flow is documented in the standalone plugin README in the
`../omasafe-plugin/` checkout and summarized in
[`docs/m7-release-checklist.md`](docs/m7-release-checklist.md).

## Scope

The v0.1 release delivers installed plugin inventory, marketplace correlation,
source identity, trust baselines, diffs, and drift notifications. Static
capability analysis is deliberately deferred to v0.2.

See [`docs/brainstorm.md`](docs/brainstorm.md) for the product thesis and
[`docs/plans/README.md`](docs/plans/README.md) for the release sequence.
